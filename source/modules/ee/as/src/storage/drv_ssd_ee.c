/*
 * drv_ssd_ee.c
 *
 * Copyright (C) 2008-2021 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#include "storage/drv_ssd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"

#include "arenax_ee.h"
#include "bits.h"
#include "cf_mutex.h"
#include "cf_thread.h"
#include "hardware.h"
#include "hist.h"
#include "log.h"
#include "vmapx.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "base/index_ee.h"
#include "base/record_ee.h"
#include "base/set_index.h"
#include "base/set_index_ee.h"
#include "base/stats.h"
#include "base/truncate.h"
#include "fabric/partition.h"
#include "fabric/partition_balance.h"
#include "sindex/secondary_index.h"
#include "storage/drv_common.h"
#include "storage/drv_common_ee.h"
#include "storage/flat.h"
#include "storage/flat_ee.h"
#include "storage/storage.h"
#include "transaction/re_replicate_ee.h"
#include "transaction/rw_utils.h"
#include "xdr/dc_manager.h"


//==========================================================
// One-phase warm and cool restart.
//

#define PROGRESS_RESOLUTION 10000

typedef struct per_cpu_info_s {
	uint32_t		stage_id;
	uint32_t		now;
	drv_ssds*		ssds;
	const bool*		sets_not_evicting;
	const uint64_t*	set_truncate_luts;
	const bool*		sets_indexed;

	// For progress ticker only.
	uint64_t		n_elements;
	cf_atomic64*	overall_n_elements;

	// For warm restart information only.
	uint64_t		n_dropped;
	uint64_t		n_erased;
	uint64_t		n_expired;
	uint64_t		n_evicted;
	uint64_t		n_truncated;

	// For restoring per-namespace only.
	uint64_t		n_xdr_tombstones;
	uint64_t		n_xdr_bin_cemeteries;
	uint64_t		n_unreplicated_records;

	// For restoring per-partition, per-set, and per-device stats.
	uint64_t		n_elements_per_tree[AS_PARTITIONS];
	uint64_t		n_tombstones_per_partition[AS_PARTITIONS];
	uint64_t		n_objects_per_set[AS_SET_MAX_COUNT];
	uint64_t		n_tombstones_per_set[AS_SET_MAX_COUNT];
	uint64_t		used_size_per_set[AS_SET_MAX_COUNT];
	uint64_t		used_size_per_ssd[AS_STORAGE_MAX_DEVICES];
} per_cpu_info;

// We can often avoid all writes to an index element, meaning we won't write
// back to its cache line. This makes a measurable difference.
#define set_if_needed(x, y) \
	if (x != y) { \
		x = y; \
	}

static cf_arenax_element_result
resume_element_cb(void* pv_element, cf_arenax_handle h, void* udata)
{
	per_cpu_info* per_cpu = (per_cpu_info*)udata;

	if (++per_cpu->n_elements == PROGRESS_RESOLUTION) {
		cf_atomic64_add(per_cpu->overall_n_elements, PROGRESS_RESOLUTION);
		per_cpu->n_elements = 0;
	}

	cf_arenax_element_result result = { .free_it = false };

	if (! pv_element) {
		return result; // result not checked by caller
	}

	as_index* r = (as_index*)pv_element;
	uint32_t now = per_cpu->now;
	drv_ssds* ssds = per_cpu->ssds;

	as_namespace* ns = ssds->ns;
	uint32_t pid = as_partition_getid(&r->keyd);
	as_partition* p = &ns->partitions[pid];
	as_index_tree* tree = p->tree;

	// Directly free elements in un-owned or otherwise dropped trees.
	if (! tree || r->tree_id != p->tree_id) {
		per_cpu->n_dropped++;
		result.free_it = true; // causes element to be freed
		return result;
	}

	if (r->generation == 0) {
		if (ns->xmem_type == CF_XMEM_TYPE_FLASH &&
				! (r->rc == 1 && r->in_sindex == 1)) {
			// Record was deleted and removed from tree, but was not freed.
			// Must not happen because flash indexes never ref-count, except
			// for being in the sindex.
			cf_crash(AS_DRV_SSD, "generation 0");
		}

		// Record was deleted and removed from tree while ref-counted.
		result.free_it = true; // causes element to be freed
		return result;
	}

	// If cool restart, clear now-meaningless previous memory storage info.
	if (as_namespace_cool_restarts(ns)) {
		r->key_stored = 0;
		r->dim = NULL;

		if (ns->single_bin) {
			as_bin_set_empty(as_index_get_single_bin(r));
		}
	}

	if (ns->data_in_index) {
		as_bin* b = as_index_get_single_bin(r);

		// Note - tombstone record has unused bin - that's ok.
		if (! (as_bin_is_embedded_particle(b) || as_bin_is_unused(b))) {
			cf_crash(AS_DRV_SSD, "{%s} data-in-index has non-embedded bin",
					ns->name);
		}
	}

	// Sanity-check storage info.
	uint16_t file_id = r->file_id;
	uint64_t rblock_id = r->rblock_id;
	uint32_t n_rblocks = r->n_rblocks;

	// Happens when drives are removed, or a subset of drives was dd'd.
	if (ssds->device_translation[file_id] < 0) {
		per_cpu->n_erased++;
		drv_delete_element(tree, r);
		result.free_it = true; // causes element to be freed
		return result;
	}

	set_if_needed(r->file_id, ssds->device_translation[file_id]);

	drv_ssd* ssd = &ssds->ssds[r->file_id];

	uint32_t wblock_id = RBLOCK_ID_TO_WBLOCK_ID(ssd, rblock_id);
	uint32_t record_size = N_RBLOCKS_TO_SIZE(n_rblocks);

	if (wblock_id >= ssd->n_wblocks || wblock_id < ssd->first_wblock_id) {
		cf_crash(AS_DRV_SSD, "bad wblock-id %u", wblock_id);
	}

	if (record_size > ssd->write_block_size ||
			record_size < DRV_RECORD_MIN_SIZE) {
		cf_crash(AS_DRV_SSD, "bad size %u", record_size);
	}

	if (r->void_time > ns->startup_max_void_time) {
		cf_crash(AS_DRV_SSD, "bad void-time %u", r->void_time);
	}

	// Expire objects with void-times in the past.
	if (r->void_time != 0 && now > r->void_time) {
		per_cpu->n_expired++;
		drv_delete_element(tree, r);
		result.free_it = true; // causes element to be freed
		return result;
	}

	uint32_t set_id = as_index_get_set_id(r);

	if (set_id > cf_vmapx_count(ns->p_sets_vmap)) {
		cf_crash(AS_DRV_SSD, "bad set-id %u", set_id);
	}

	// If we stopped while evicting, this finishes eviction.
	if (r->void_time != 0 && ns->evict_void_time > r->void_time &&
			! per_cpu->sets_not_evicting[set_id]) {
		per_cpu->n_evicted++;
		drv_delete_element(tree, r);
		result.free_it = true; // causes element to be freed
		return result;
	}

	// If we stopped while truncating, this finishes the truncate.
	if (ns->truncate.lut > r->last_update_time ||
			per_cpu->set_truncate_luts[set_id] > r->last_update_time) {
		per_cpu->n_truncated++;
		drv_delete_element(tree, r);
		result.free_it = true; // causes element to be freed
		return result;
	}

	// We will resume this record - zero the ref-count.
	set_if_needed(r->rc, 0);

	set_if_needed(r->in_sindex, 0);

	// May now accumulate stats that deletes would have needed to decrement.

	// Reconstruct record counts (tree element counts).
	per_cpu->n_elements_per_tree[pid]++;

	// Reconstruct tombstone counts.
	if (r->tombstone == 1) {
		per_cpu->n_tombstones_per_partition[pid]++;

		if (r->xdr_tombstone == 1) {
			per_cpu->n_xdr_tombstones++;
		}
		else if (r->xdr_bin_cemetery == 1) {
			per_cpu->n_xdr_bin_cemeteries++;
		}
	}

	// Unmark cenotaphs.
	set_if_needed(r->cenotaph, 0);

	// Insert in set index and increment set stats if relevant.
	if (set_id != INVALID_SET_ID) {
		uint32_t set_ix = set_id - 1;

		if (r->tombstone == 0) {
			if (per_cpu->sets_indexed[set_id]) {
				as_set_index_insert_warm_restart(tree, (uint16_t)set_id, h);
			}

			per_cpu->n_objects_per_set[set_ix]++;
		}
		else {
			per_cpu->n_tombstones_per_set[set_ix]++;
		}

		per_cpu->used_size_per_set[set_ix] += record_size;
	}

	// Adjust the partition's max void time.
	cf_atomic32_setmax(&p->max_void_time, (int32_t)r->void_time);

	// For CP - if necessary, adjust replication state.
	if (r->repl_state != AS_REPL_STATE_REPLICATED) {
		set_if_needed(r->repl_state, AS_REPL_STATE_UNREPLICATED);
		per_cpu->n_unreplicated_records++;
	}

	// Adjust the device info using record's storage info.
	per_cpu->used_size_per_ssd[r->file_id] += record_size;
	cf_atomic32_add(&ssd->wblock_state[wblock_id].inuse_sz,
			(int32_t)record_size);

	as_index_locked_puddle locked_puddle =
			as_index_puddle_for_element(tree, &r->keyd);

	result.puddle = locked_puddle.puddle;
	result.lock = locked_puddle.lock;

	return result;
}

typedef struct overall_info_s {
	cf_atomic32		n_threads_done;
	cf_atomic32		i_cpu;
	cf_atomic32		stage_id;
	uint32_t		now;
	drv_ssds*		ssds;
	const bool*		sets_not_evicting;
	const uint64_t*	set_truncate_luts;
	const bool*		sets_indexed;

	// For progress ticker only.
	cf_atomic64		n_elements;

	// For warm restart information only.
	cf_atomic64		n_dropped;
	cf_atomic64		n_erased;
	cf_atomic64		n_expired;
	cf_atomic64		n_evicted;
	cf_atomic64		n_truncated;
} overall_info;

void*
run_scan_stages(void* pv_data)
{
	overall_info* overall = (overall_info*)pv_data;
	as_namespace* ns = overall->ssds->ns;

	cf_topo_pin_to_cpu(
			(cf_topo_cpu_index)cf_atomic32_incr(&overall->i_cpu));

	per_cpu_info per_cpu = {
			.stage_id = 0, // reset for every stage
			.now = overall->now,
			.ssds = overall->ssds,
			.sets_not_evicting = overall->sets_not_evicting,
			.set_truncate_luts = overall->set_truncate_luts,
			.sets_indexed = overall->sets_indexed,

			.n_elements = 0,
			.overall_n_elements = &overall->n_elements,

			.n_dropped = 0,
			.n_erased = 0,
			.n_expired = 0,
			.n_evicted = 0,
			.n_truncated = 0,

			.n_xdr_tombstones = 0,
			.n_xdr_bin_cemeteries = 0,
			.n_unreplicated_records = 0,

			.n_elements_per_tree = { 0 },
			.n_tombstones_per_partition = { 0 },
			.n_objects_per_set = { 0 },
			.n_tombstones_per_set = { 0 },
			.used_size_per_set = { 0 },
			.used_size_per_ssd = { 0 }
	};

	while (true) {
		uint32_t stage_id = (uint32_t)cf_atomic32_incr(&overall->stage_id);

		per_cpu.stage_id = stage_id;

		if (! cf_arenax_resume_stage(ns->arena, stage_id, resume_element_cb,
				&per_cpu)) {
			break;
		}

		cf_debug(AS_DRV_SSD, "... scanned arena stage %u", stage_id);
	}

	cf_atomic64_add(per_cpu.overall_n_elements, (int64_t)per_cpu.n_elements);

	cf_atomic64_add(&overall->n_dropped, (int64_t)per_cpu.n_dropped);
	cf_atomic64_add(&overall->n_erased, (int64_t)per_cpu.n_erased);
	cf_atomic64_add(&overall->n_expired, (int64_t)per_cpu.n_expired);
	cf_atomic64_add(&overall->n_evicted, (int64_t)per_cpu.n_evicted);
	cf_atomic64_add(&overall->n_truncated, (int64_t)per_cpu.n_truncated);

	as_add_uint64(&ns->n_xdr_tombstones, (int64_t)per_cpu.n_xdr_tombstones);
	as_add_uint64(&ns->n_xdr_bin_cemeteries,
			(int64_t)per_cpu.n_xdr_bin_cemeteries);
	as_add_uint64(&ns->n_unreplicated_records,
			(int64_t)per_cpu.n_unreplicated_records);

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition* p = &ns->partitions[pid];

		if (p->tree != NULL) {
			as_add_uint64(&p->tree->n_elements,
					(int64_t)per_cpu.n_elements_per_tree[pid]);
		}

		cf_atomic64_add(&p->n_tombstones,
				(int64_t)per_cpu.n_tombstones_per_partition[pid]);
	}

	uint32_t n_sets = cf_vmapx_count(ns->p_sets_vmap);

	for (uint32_t set_ix = 0; set_ix < n_sets; set_ix++) {
		as_set* p_set;

		if (cf_vmapx_get_by_index(ns->p_sets_vmap, set_ix, (void**)&p_set) !=
				CF_VMAPX_OK) {
			cf_crash(AS_DRV_SSD, "can't get set index %u from vmap", set_ix);
		}

		cf_atomic64_add(&p_set->n_objects,
				(int64_t)per_cpu.n_objects_per_set[set_ix]);
		cf_atomic64_add(&p_set->n_tombstones,
				(int64_t)per_cpu.n_tombstones_per_set[set_ix]);
		cf_atomic64_add(&p_set->n_bytes_device,
				(int64_t)per_cpu.used_size_per_set[set_ix]);
	}

	for (int ssd_ix = 0; ssd_ix < overall->ssds->n_ssds; ssd_ix++) {
		drv_ssd* ssd = &overall->ssds->ssds[ssd_ix];

		cf_atomic64_add(&ssd->inuse_size,
				(int64_t)per_cpu.used_size_per_ssd[ssd_ix]);
	}

	cf_atomic32_incr(&overall->n_threads_done);

	return NULL;
}

#define WARM_START_TICKER_INTERVAL 5 // seconds
#define WARM_START_TICKER_SLEEP_US (1000 * 10)
#define WARM_START_TICKER_EVERY_N \
	((WARM_START_TICKER_INTERVAL * 1000000) / WARM_START_TICKER_SLEEP_US)

static void
discover_pristine_wblock_ids(drv_ssds* ssds)
{
	for (int i = 0; i < ssds->n_ssds; i++) {
		drv_ssd* ssd = &ssds->ssds[i];

		if (ssd->pristine_wblock_id != 0) {
			continue; // normal - already set from device header
		}
		// else - legacy device with data - scan to find pristine-wblock-id.

		uint32_t last_id = ssd->n_wblocks - 1;
		uint32_t first_id = ssd->first_wblock_id;
		uint32_t last_used_id;

		for (last_used_id = last_id; last_used_id >= first_id; last_used_id--) {
			if (ssd->wblock_state[last_used_id].inuse_sz != 0) {
				break;
			}
		}

		int fd = ssd_fd_get(ssd);

		// Make use of fact that flat magic must be first.
		size_t read_size = ssd->io_min_size;
		uint32_t* magic = cf_valloc(read_size);

		uint32_t id;

		for (id = last_used_id + 1; id < ssd->n_wblocks; id++) {
			uint64_t offset = (uint64_t)id * ssd->write_block_size;

			if (! pread_all(fd, (void*)magic, read_size, offset)) {
				cf_crash(AS_DRV_SSD, "%s: read failed: errno %d (%s)",
						ssd->name, errno, cf_strerror(errno));
			}

			if (*magic != AS_FLAT_MAGIC) {
				break; // unused wblock is pristine
			}
		}

		ssd->pristine_wblock_id = id;

		cf_free(magic);
		ssd_fd_put(ssd, fd);

		cf_info(AS_DRV_SSD, "%s: legacy device - found pristine-wblock-id %u",
				ssd->name, id);
	}
}

void
ssd_resume_devices(drv_ssds* ssds)
{
	as_namespace* ns = ssds->ns;

	// Sanity check that treex agrees with stored partition versions. Also set
	// restored tree-ids on the tree structs.
	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition* p = &ns->partitions[pid];

		bool owned = ssds->get_state_from_storage[pid];
		bool has_tree = p->tree != NULL;

		cf_assert(owned == has_tree, AS_DRV_SSD, "{%s} pid %u %s but %s",
				ns->name, pid, owned ? "owned" : "not owned",
				has_tree ? "has tree" : "no tree");

		if (has_tree) {
			p->tree->id = p->tree_id;
		}
	}

	// Initialize cached per-set information.
	bool sets_not_evicting[AS_SET_MAX_COUNT + 1] = { false };
	uint64_t set_truncate_luts[AS_SET_MAX_COUNT + 1] = { 0 };
	bool sets_indexed[AS_SET_MAX_COUNT + 1] = { false };

	drv_init_sets_info(ns, sets_not_evicting, set_truncate_luts, sets_indexed);

	uint32_t n_cpus = cf_topo_count_cpus();
	uint64_t total_n_elements = cf_arenax_hwm(ns->arena);

	// Process non-free arena elements.
	cf_info(AS_DRV_SSD, "{%s} scanning arena stages for %lu index elements ...",
			ns->name, total_n_elements);

	// Split this task across multiple threads.
	overall_info overall = {
			.n_threads_done = 0,
			.i_cpu = -1,
			.stage_id = -1,
			.now = as_record_void_time_get(),
			.ssds = ssds,
			.sets_not_evicting = sets_not_evicting,
			.set_truncate_luts = set_truncate_luts,
			.sets_indexed = sets_indexed,

			.n_elements = 0,

			.n_dropped = 0,
			.n_expired = 0,
			.n_erased = 0,
			.n_evicted = 0,
			.n_truncated = 0
	};

	for (uint32_t n = 0; n < n_cpus; n++) {
		cf_thread_create_transient(run_scan_stages, (void*)&overall);
	}

	// Show progress in the log.
	uint32_t i = 0;

	while (overall.n_threads_done < n_cpus) {
		usleep(WARM_START_TICKER_SLEEP_US);

		if (++i % WARM_START_TICKER_EVERY_N == 0) {
			uint64_t n_elements = overall.n_elements;
			float pct = (float)(n_elements * 100) / (float)total_n_elements;

			cf_info(AS_DRV_SSD, "{%s} ... scanned %lu index elements [%.1f%%]",
					ns->name, n_elements, pct);
		}
	}

	// Now we're single-threaded again.
	cf_info(AS_DRV_SSD, "{%s} ... scanned %lu index elements [100.0%%]",
			ns->name, total_n_elements);

	// If we're NUMA pinning, we may need to migrate arena stage memory.
	cf_arenax_force_map_memory(ns->arena);

	// Restore counts that we didn't accumulate during the stage scans.
	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition* p = &ns->partitions[pid];

		if (p->tree != NULL) {
			ns->n_objects += p->tree->n_elements - p->n_tombstones;
			ns->n_tombstones += p->n_tombstones;
		}
	}

	ns->n_durable_tombstones = ns->n_tombstones - ns->n_xdr_tombstones;

	if (overall.n_dropped != 0) {
		cf_info(AS_DRV_SSD, "{%s} freed %lu elements in dropped trees",
				ns->name, overall.n_dropped);
	}

	if (overall.n_erased != 0) {
		cf_warning(AS_DRV_SSD, "{%s} deleted %lu records on wiped and/or missing devices",
				ns->name, overall.n_erased);
	}

	if (overall.n_expired != 0) {
		cf_info(AS_DRV_SSD, "{%s} deleted %lu expired records", ns->name,
				overall.n_expired);
	}

	if (overall.n_evicted != 0) {
		cf_info(AS_DRV_SSD, "{%s} deleted %lu evicted records", ns->name,
				overall.n_evicted);
	}

	if (overall.n_truncated != 0) {
		cf_info(AS_DRV_SSD, "{%s} deleted %lu truncated records", ns->name,
				overall.n_truncated);
	}

	// Finished rebuilding stats and storage state. The wblock free and defrag
	// queues will be created and loaded later.
	cf_info(AS_DRV_SSD, "{%s} scanned: objects %lu tombstones %lu free %lu",
			ns->name, ns->n_objects, ns->n_tombstones,
			total_n_elements - (ns->n_objects + ns->n_tombstones));

	// If upgrading from < 4.6, device headers won't contain pristine-wblock-id.
	// Must scan devices to discover these ids. (Done after rebuilding wblock
	// used-size stats so scan starting points are optimized.)
	discover_pristine_wblock_ids(ssds);
}


//==========================================================
// Cool start.
//

// If index indicates record on drive is current version, load it to memory.
void
ssd_cool_start_load_record(drv_ssds* ssds, drv_ssd* ssd, as_flat_record* flat,
		uint64_t rblock_id, uint32_t record_size)
{
	uint32_t pid = as_partition_getid(&flat->keyd);

	// When resuming the index, we force-emptied trees that we don't own.
	if (! ssds->get_state_from_storage[pid]) {
		return;
	}

	as_namespace* ns = ssds->ns;

	// Includes round rblock padding, so may not literally exclude the mark.
	const uint8_t* end = (const uint8_t*)flat + record_size - END_MARK_SZ;

	as_flat_opt_meta opt_meta = { { 0 } };

	const uint8_t* p_read = as_flat_unpack_record_meta(flat, end, &opt_meta,
			ns->single_bin);

	if (! p_read) {
		cf_warning(AS_DRV_SSD, "bad metadata for %pD", &flat->keyd);
		return;
	}

	if (! as_flat_decompress_buffer(&opt_meta.cm, ns->storage_write_block_size,
			&p_read, &end, NULL)) {
		cf_warning(AS_DRV_SSD, "bad compressed data for %pD", &flat->keyd);
		return;
	}

	// TODO - shouldn't need this after we can unwind.
	if (as_flat_check_packed_bins(p_read, end, opt_meta.n_bins,
			ns->single_bin) == NULL) {
		cf_warning(AS_DRV_SSD, "bad flat record %pD", &flat->keyd);
		return;
	}

	as_partition* p = &ns->partitions[pid];

	as_index_ref r_ref;

	if (as_record_get(p->tree, &flat->keyd, &r_ref) != 0) {
		return; // record not in index, move along
	}

	as_index* r = r_ref.r;

	if (r->file_id != ssd->file_id || r->rblock_id != rblock_id) {
		as_record_done(&r_ref, ns);
		return; // not the current version of this record
	}
	// else - found the current version, load it into memory.

	// Sanity check current version metadata.
	if (r->n_rblocks != flat->n_rblocks ||
			r->last_update_time != flat->last_update_time ||
			r->generation != flat->generation ||
			r->xdr_write != flat->xdr_write ||
			r->xdr_tombstone != opt_meta.extra_flags.xdr_tombstone ||
			r->xdr_nsup_tombstone != opt_meta.extra_flags.xdr_nsup_tombstone ||
			r->xdr_bin_cemetery != opt_meta.extra_flags.xdr_bin_cemetery ||
			r->void_time != opt_meta.void_time) {
		cf_warning(AS_DRV_SSD, "metadata mismatch - removing %pD", &flat->keyd);
		as_set_index_delete_live(ns, p->tree, r, r_ref.r_h);
		as_index_delete(p->tree, &flat->keyd);
		as_record_done(&r_ref, ns);
		return;
	}

	// Skip records that have expired since resuming the index.
	if (as_record_is_expired(r)) {
		// AER-6363 - use live for "six months" in case of tombstone with TTL.
		as_set_index_delete_live(ns, p->tree, r, r_ref.r_h);
		as_index_delete(p->tree, &flat->keyd);
		as_record_done(&r_ref, ns);
		ssd->record_add_expired_counter++;
		return;
	}

	// Load bins and particles, load sindex. Remember - we are data-in-memory!

	as_storage_rd rd;

	as_storage_record_open(ns, r, &rd); // FIXME - only for r, ns - bother?

	as_storage_rd_load_bins(&rd, NULL); // FIXME - does nothing useful - bother?

	uint16_t n_new_bins = (uint16_t)opt_meta.n_bins;
	as_bin new_bins[n_new_bins];

	rd.n_bins = n_new_bins;
	rd.bins = new_bins;

	if (as_flat_unpack_bins(ns, p_read, end, rd.n_bins, rd.bins) < 0) {
		cf_crash(AS_DRV_SSD, "%pD - unpack bins failed", &r->keyd);
	}

	// Do this early since set-id is needed for the secondary index update.
	drv_apply_opt_meta(r, ns, &opt_meta);

	if (ns->single_bin) {
		if (rd.n_bins == 1) {
			as_single_bin_copy(as_index_get_single_bin(r), rd.bins);
		}
		else if (! as_bin_is_unused(as_index_get_single_bin(r))) {
			cf_warning(AS_DRV_SSD, "bin mismatch - removing %pD", &r->keyd);
			as_set_index_delete(ns, p->tree, as_index_get_set_id(r), r_ref.r_h);
			as_index_delete(p->tree, &r->keyd);
			as_storage_record_close(&rd);
			as_record_done(&r_ref, ns);
			return;
		}
	}
	else {
		if (set_has_sindex(r, ns)) {
			update_sindex(ns, &r_ref, NULL, 0, rd.bins, rd.n_bins);
		}

		as_storage_rd_update_bin_space(&rd);
	}

	as_storage_record_adjust_mem_stats(&rd, 0);
	as_storage_record_close(&rd);
	as_record_done(&r_ref, ns);

	ssd->record_add_unique_counter++;
}

// Sweep through a storage device to load record data.
void
ssd_cool_start_sweep(drv_ssds* ssds, drv_ssd* ssd)
{
	size_t wblock_size = ssd->write_block_size;

	uint8_t* buf = cf_valloc(wblock_size);
	int fd = ssd_fd_get(ssd);
	uint64_t file_offset = DRV_HEADER_SIZE;

	bool prefetch = cf_arenax_want_prefetch(ssd->ns->arena);

	// Loop over all wblocks (excluding header) in device.
	for (ssd->sweep_wblock_id = ssd->first_wblock_id;
			ssd->sweep_wblock_id < ssd->n_wblocks;
			ssd->sweep_wblock_id++, file_offset += wblock_size) {

		// Don't read unused wblocks.
		if (ssd->wblock_state[ssd->sweep_wblock_id].inuse_sz == 0) {
			continue;
		}

		if (! pread_all(fd, buf, wblock_size, (off_t)file_offset)) {
			cf_crash(AS_DRV_SSD, "%s: read failed: errno %d (%s)", ssd->name,
					errno, cf_strerror(errno));
		}

		if (prefetch) {
			ssd_prefetch_wblock(ssd, file_offset, buf);
		}

		size_t indent = 0; // current offset within the wblock, in bytes

		while (indent < wblock_size) {
			as_flat_record* flat = (as_flat_record*)&buf[indent];

			if (! prefetch) {
				ssd_decrypt(ssd, file_offset + indent, flat);
			}

			// Look for record magic.
			if (flat->magic != AS_FLAT_MAGIC) {
				// Should always find a record at beginning of used wblock.
				cf_assert(indent != 0, AS_DRV_SSD, "%s: no magic at beginning of used wblock %u",
						ssd->name, ssd->sweep_wblock_id);

				// Nothing more in this wblock, but keep looking for magic -
				// necessary if we want to be able to increase write-block-size
				// across restarts.
				indent += RBLOCK_SIZE;
				continue; // try next rblock
			}

			uint32_t record_size = N_RBLOCKS_TO_SIZE(flat->n_rblocks);

			if (record_size < DRV_RECORD_MIN_SIZE) {
				cf_warning(AS_DRV_SSD, "%s: record too small: size %u",
						ssd->name, record_size);
				indent += RBLOCK_SIZE;
				continue; // try next rblock
			}

			size_t next_indent = indent + record_size;

			// Sanity-check for wblock overruns.
			if (next_indent > wblock_size) {
				cf_warning(AS_DRV_SSD, "%s: record crosses wblock boundary: size %u",
						ssd->name, record_size);
				break; // skip this record, try next wblock
			}

			// Found a record - verify it's in the index, and load it.
			ssd_cool_start_load_record(ssds, ssd, flat,
					OFFSET_TO_RBLOCK_ID(file_offset + indent), record_size);

			indent = next_indent;
		}
	}

	ssd_fd_put(ssd, fd);
	cf_free(buf);
}

void*
run_ssd_cool_start(void* udata)
{
	ssd_load_records_info* lri = (ssd_load_records_info*)udata;
	drv_ssd* ssd = lri->ssd;
	drv_ssds* ssds = lri->ssds;
	cf_queue* complete_q = lri->complete_q;
	void* complete_rc = lri->complete_rc;

	cf_free(lri);

	as_namespace* ns = ssds->ns;

	cf_info(AS_DRV_SSD, "device %s: reading device to load record data",
			ssd->name);

	CF_ALLOC_SET_NS_ARENA_DIM(ns);

	ssd_cool_start_sweep(ssds, ssd);

	cf_info(AS_DRV_SSD, "device %s: read complete: added %lu expired %lu",
			ssd->name, ssd->record_add_unique_counter,
			ssd->record_add_expired_counter);

	if (cf_rc_release(complete_rc) == 0) {
		// All drives are done reading.

		ns->loading_records = false;

		void* _t = NULL;

		cf_queue_push(complete_q, &_t);
		cf_rc_free(complete_rc);
	}

	return NULL;
}


//==========================================================
// Durable delete: tombstones are binless records.
//

int
as_storage_record_write_ssd(as_storage_rd* rd)
{
	// No-op for drops, caller will drop record.
	return rd->pickle != NULL || rd->n_bins != 0 || rd->r->tombstone == 1 ?
			ssd_write(rd) : 0;
}


//==========================================================
// Durable delete: tomb raider.
//

int
write_q_reduce_cb(void* buf, void* udata)
{
	ssd_write_buf* swb = *(ssd_write_buf**)buf;
	as_flat_record* flat = (as_flat_record*)swb->buf;

	*(uint64_t*)udata = flat->last_update_time;

	return -1; // stop reducing immediately - poor man's peek
}

static const uint64_t MARK_MIN_AGE_SAFETY_MARGIN = 60; // 1 minute should be enough

// Don't mark cenotaphs that might cover records waiting in the write queues.
// For now peek at the heads of queues to estimate minimum last-update-time.
// This isn't rigorous - possible for older records to be deeper in an swb or
// not at head of a queue - hence the safety margin.
uint64_t
lut_mark_threshold(drv_ssds* ssds)
{
	uint64_t min_last_update_time = cf_clepoch_milliseconds();

	for (int i = 0; i < ssds->n_ssds; i++) {
		cf_queue* write_q = ssds->ssds[i].swb_write_q;
		uint64_t last_update_time = min_last_update_time;

		cf_queue_reduce(write_q, write_q_reduce_cb, (void*)&last_update_time);

		if (last_update_time < min_last_update_time) {
			min_last_update_time = last_update_time;
		}
	}

	return min_last_update_time - (1000 * MARK_MIN_AGE_SAFETY_MARGIN);
}

typedef struct mark_reduce_cb_info_s {
	as_namespace* ns;
	uint64_t lut_threshold;
} mark_reduce_cb_info;

typedef struct mark_cenotaph_info_s {
	as_namespace* ns;
	cf_atomic32 pid;
	uint64_t lut_threshold;
} mark_cenotaph_info;

bool
mark_cenotaph_reduce_cb(as_index_ref* r_ref, void* udata)
{
	as_record* r = r_ref->r;
	mark_reduce_cb_info* p_cb_info = (mark_reduce_cb_info*)udata;

	if (is_durable_tombstone(r) &&
			r->last_update_time < p_cb_info->lut_threshold) {
		r->cenotaph = 1;
	}

	as_record_done(r_ref, p_cb_info->ns);

	return true;
}

void*
run_mark_cenotaphs(void* pv_data)
{
	mark_cenotaph_info* p_mark_info = (mark_cenotaph_info*)pv_data;
	as_namespace* ns = p_mark_info->ns;

	uint32_t pid;

	while ((pid = (uint32_t)
			cf_atomic32_incr(&p_mark_info->pid)) < AS_PARTITIONS) {
		as_partition_reservation rsv;
		as_partition_reserve(ns, pid, &rsv);

		mark_reduce_cb_info cb_info = { ns, p_mark_info->lut_threshold };

		as_index_reduce(rsv.tree, mark_cenotaph_reduce_cb, (void*)&cb_info);
		as_partition_release(&rsv);
	}

	return NULL;
}

typedef struct unmark_cenotaph_info_s {
	drv_ssds* ssds;
	cf_atomic32 ssd_index;
	uint32_t now;
	volatile int aborted;
} unmark_cenotaph_info;

void
unmark_cenotaph(as_namespace* ns, cf_digest* keyd)
{
	uint32_t pid = as_partition_getid(keyd);

	as_partition_reservation rsv;
	as_partition_reserve(ns, pid, &rsv);

	as_index_ref r_ref;

	if (as_record_get(rsv.tree, keyd, &r_ref) == 0) {
		if (is_durable_tombstone(r_ref.r)) {
			r_ref.r->cenotaph = 0;
		}

		as_record_done(&r_ref, ns);
	}

	as_partition_release(&rsv);
}

void*
run_unmark_cenotaphs(void* pv_data)
{
	unmark_cenotaph_info* p_unmark_info = (unmark_cenotaph_info*)pv_data;
	drv_ssds* ssds = (drv_ssds*)p_unmark_info->ssds;
	as_namespace* ns = ssds->ns;
	uint64_t now = (uint64_t)p_unmark_info->now;

	drv_ssd* ssd = &ssds->ssds[cf_atomic32_incr(&p_unmark_info->ssd_index)];

	cf_info(AS_DRV_SSD, "{%s} tomb raider reading %s ...", ns->name, ssd->name);

	int fd = ssd_fd_get(ssd);
	uint32_t buf_size = ssd->write_block_size; // TODO - config?
	uint8_t* read_buf = cf_valloc(buf_size);
	uint64_t end_offset = WBLOCK_ID_TO_OFFSET(ssd, ssd->n_wblocks);

	const int MAX_NEVER_WRITTEN = 10;
	int n_never_written = 0;

	bool prefetch = cf_arenax_want_prefetch(ssd->ns->arena);

	for (uint64_t file_offset = DRV_HEADER_SIZE;
			p_unmark_info->aborted == 0 &&
					n_never_written < MAX_NEVER_WRITTEN &&
					file_offset < end_offset;
			file_offset += buf_size) {
		uint64_t start_ns = ns->storage_benchmarks_enabled ? cf_getns() : 0;

		// Not worrying about calling pread() concurrently with pwrite().
		// Assumes using read buffer with "mixed" content turns out to be ok.
		if (! pread_all(fd, read_buf, buf_size, (off_t)file_offset)) {
			cf_warning(AS_DRV_SSD, "%s: read failed: errno %d (%s)", ssd->name,
					errno, cf_strerror(errno));
			p_unmark_info->aborted = 1;
			break;
		}

		if (start_ns != 0) {
			histogram_insert_data_point(ssd->hist_large_block_read, start_ns);
		}

		if (prefetch) {
			ssd_prefetch_wblock(ssd, file_offset, read_buf);
		}

		// Loop over records in this read buffer.

		uint32_t indent = 0; // byte offset within read buffer

		while (p_unmark_info->aborted == 0 && indent < buf_size) {
			as_flat_record* flat = (as_flat_record*)&read_buf[indent];

			if (! prefetch) {
				ssd_decrypt(ssd, file_offset + indent, flat);
			}

			if (flat->magic != AS_FLAT_MAGIC) {
				// First block must have magic.
				if (indent == 0) {
					n_never_written++;
					break;
				}

				// Later blocks may have no magic, just skip to next block.
				indent += RBLOCK_SIZE;
				continue;
			}

			uint32_t record_size = N_RBLOCKS_TO_SIZE(flat->n_rblocks);

			if (record_size < DRV_RECORD_MIN_SIZE) {
				cf_warning(AS_DRV_SSD, "%s: record too small: size %u",
						ssd->name, record_size);
				indent += RBLOCK_SIZE;
				continue; // try next rblock
			}

			uint64_t next_indent = (uint64_t)indent + record_size;

			if (next_indent > buf_size) {
				cf_warning(AS_DRV_SSD, "%s: record crosses wblock boundary: size %u",
						ssd->name, record_size);
				p_unmark_info->aborted = 1;
				break;
			}

			// Ignore tombstones and only un-mark if record hasn't expired.
			if (as_flat_record_is_live(flat) &&
					as_flat_record_not_expired(flat, now)) {
				unmark_cenotaph(ns, &flat->keyd);
			}

			indent = next_indent;
		}

		uint32_t sleep_us = ns->storage_tomb_raider_sleep;

		if (sleep_us != 0) {
			usleep(sleep_us);
		}

		ssd->n_tomb_raider_reads++;
	}

	cf_free(read_buf);
	ssd_fd_put(ssd, fd);

	cf_info(AS_DRV_SSD, "{%s} ... tomb raider %s - read %lu blocks on %s",
			ns->name, p_unmark_info->aborted == 0 ? "done" : "abort",
			ssd->n_tomb_raider_reads - (uint64_t)n_never_written, ssd->name);

	ssd->n_tomb_raider_reads = 0; // each raid has a fresh device ticker trail

	return NULL;
}

typedef struct drop_reduce_cb_info_s {
	as_namespace* ns;
	as_index_tree* tree;
	uint64_t lut_threshold;
	bool cancelled;
	int32_t n_dropped;
} drop_reduce_cb_info;

typedef struct drop_cenotaph_info_s {
	as_namespace* ns;
	cf_atomic32 pid;
	uint64_t lut_threshold;
	bool cancelled;
	cf_atomic32 n_dropped;
} drop_cenotaph_info;

bool
drop_cenotaph_reduce_cb(as_index_ref* r_ref, void* udata)
{
	as_record* r = r_ref->r;
	drop_reduce_cb_info* p_cb_info = (drop_reduce_cb_info*)udata;

	if (is_durable_tombstone(r) && r->cenotaph == 1) {
		r->cenotaph = 0;

		if (! p_cb_info->cancelled &&
				r->last_update_time < p_cb_info->lut_threshold) {
			p_cb_info->n_dropped++;
			// Note - tombstone will not be in set-index.
			as_index_delete(p_cb_info->tree, &r->keyd);
		}
	}

	as_record_done(r_ref, p_cb_info->ns);

	return true;
}

void*
run_drop_cenotaphs(void* pv_data)
{
	drop_cenotaph_info* p_drop_info = (drop_cenotaph_info*)pv_data;
	as_namespace* ns = p_drop_info->ns;

	int pid;

	while ((pid = (int)cf_atomic32_incr(&p_drop_info->pid)) < AS_PARTITIONS) {
		as_partition_reservation rsv;
		as_partition_reserve(ns, pid, &rsv);

		// Don't drop anything in this partition if any migrations remain.
		bool migrations = as_partition_pending_migrations(&ns->partitions[pid]);

		drop_reduce_cb_info cb_info = { ns, rsv.tree,
				p_drop_info->lut_threshold,
				p_drop_info->cancelled || migrations, 0 };

		as_index_reduce(rsv.tree, drop_cenotaph_reduce_cb, (void*)&cb_info);
		as_partition_release(&rsv);

		cf_atomic32_add(&p_drop_info->n_dropped, cb_info.n_dropped);
	}

	return NULL;
}

uint32_t
drop_cenotaphs(as_namespace* ns, int n_threads, bool cancelled)
{
	// Don't drop cenotaphs unless they're old enough.
	uint64_t lut_drop_threshold = cf_clepoch_milliseconds() -
			(1000 * ns->tomb_raider_eligible_age);

	// Don't drop cenotaphs if XDR has not shipped them yet.
	uint64_t xdr_ns_min_lst = as_dc_manager_ns_min_lst(ns);

	if (xdr_ns_min_lst < lut_drop_threshold) {
		lut_drop_threshold = xdr_ns_min_lst;
	}

	// Split this task across multiple threads.
	cf_tid tids[n_threads];
	drop_cenotaph_info drop_info = { ns, -1, lut_drop_threshold, cancelled, 0 };

	for (int n = 0; n < n_threads; n++) {
		tids[n] = cf_thread_create_joinable(run_drop_cenotaphs,
				(void*)&drop_info);
	}

	for (int n = 0; n < n_threads; n++) {
		cf_thread_join(tids[n]);
	}
	// Now we're single-threaded again.

	return drop_info.n_dropped;
}

// It's runtime, so tomb raider is more like a scan than a warm restart.
// TODO - config? single thread?
static const int NUM_TOMB_RAIDER_THREADS = 4;

void
tomb_raid(as_namespace* ns)
{
	// Reduce index to mark tombstones as potential cenotaphs.

	cf_info(AS_DRV_SSD, "{%s} tomb raider start - marking cenotaphs ...",
			ns->name);

	drv_ssds* ssds = (drv_ssds*)ns->storage_private;

	// Split this task across multiple threads.
	cf_tid mark_tids[NUM_TOMB_RAIDER_THREADS];
	mark_cenotaph_info mark_info = { ns, -1, lut_mark_threshold(ssds) };

	for (int n = 0; n < NUM_TOMB_RAIDER_THREADS; n++) {
		mark_tids[n] = cf_thread_create_joinable(run_mark_cenotaphs,
				(void*)&mark_info);
	}

	for (int n = 0; n < NUM_TOMB_RAIDER_THREADS; n++) {
		cf_thread_join(mark_tids[n]);
	}
	// Now we're single-threaded again.

	cf_info(AS_DRV_SSD, "{%s} tomb raider detecting cenotaphs ...", ns->name);

	// Scan all drives to un-mark remaining records' cenotaphs.

	uint32_t expire_at = as_record_void_time_get();

	// Split this task using one thread per device.
	cf_tid unmark_tids[ssds->n_ssds];
	unmark_cenotaph_info unmark_info = { ssds, -1, expire_at, 0 };

	for (int n = 0; n < ssds->n_ssds; n++) {
		unmark_tids[n] = cf_thread_create_joinable(run_unmark_cenotaphs,
				(void*)&unmark_info);
	}

	for (int n = 0; n < ssds->n_ssds; n++) {
		cf_thread_join(unmark_tids[n]);
	}
	// Now we're single-threaded again.

	cf_info(AS_DRV_SSD, "{%s} tomb raider removing cenotaphs ...", ns->name);

	// Reduce index to drop cenotaphs.
	uint32_t n_dropped = drop_cenotaphs(ns, NUM_TOMB_RAIDER_THREADS,
			unmark_info.aborted == 1);

	cf_info(AS_DRV_SSD, "{%s} ... tomb raider done - removed %u cenotaphs",
			ns->name, n_dropped);
}

void*
run_tomb_raider(void* arg)
{
	as_namespace* ns = (as_namespace*)arg;

	uint64_t last_time = cf_get_seconds();

	while (true) {
		sleep(1); // wake up every second to check

		uint64_t period = (uint64_t)ns->tomb_raider_period;
		uint64_t curr_time = cf_get_seconds();

		if (period == 0 || curr_time - last_time < period) {
			continue;
		}

		last_time = curr_time;

		if (ns->n_durable_tombstones != 0) {
			tomb_raid(ns);
		}
	}

	return NULL;
}

void*
run_serial_tomb_raider(void* arg)
{
	uint64_t init_time = cf_get_seconds();
	uint64_t last_times[g_config.n_namespaces];

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		last_times[ns_ix] = init_time;
	}

	while (true) {
		sleep(1); // wake up every second to check

		for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
			as_namespace *ns = g_config.namespaces[ns_ix];

			if (! ns->storage_serialize_tomb_raider) {
				continue;
			}

			uint64_t period = (uint64_t)ns->tomb_raider_period;
			uint64_t curr_time = cf_get_seconds();

			if (period == 0 || curr_time - last_times[ns_ix] < period) {
				continue;
			}

			last_times[ns_ix] = curr_time;

			if (ns->n_durable_tombstones != 0) {
				tomb_raid(ns);
			}
		}
	}

	return NULL;
}

static bool g_serial_tomb_raider_started = false;

void
start_serial_tomb_raider()
{
	if (g_serial_tomb_raider_started) {
		return;
	}

	g_serial_tomb_raider_started = true;
	cf_thread_create_detached(run_serial_tomb_raider, NULL);
}

void
ssd_cold_start_adjust_cenotaph(as_namespace* ns, const as_flat_record* flat,
		uint32_t block_void_time, as_record* r)
{
	if (r->cenotaph == 1 && as_flat_record_is_live(flat) &&
			! as_flat_record_expired_or_evicted(ns, block_void_time,
					as_index_get_set_id(r))) {
		r->cenotaph = 0;
	}
}

void
ssd_cold_start_transition_record(as_namespace* ns, const as_flat_record* flat,
		const as_flat_opt_meta* opt_meta, as_index_tree* tree,
		as_index_ref* r_ref, bool is_create)
{
	as_record* r = r_ref->r;

	index_metadata old_metadata = {
			// Note - other members irrelevant.
			.generation = is_create ? 0 : 1, // fake to transition set-index
			.tombstone = r->tombstone == 1,
			.xdr_tombstone = r->xdr_tombstone == 1,
			.xdr_bin_cemetery = r->xdr_bin_cemetery == 1
	};

	bool was_cenotaph = r->cenotaph == 1;
	bool is_bin_cemetery = opt_meta->extra_flags.xdr_bin_cemetery;
	bool is_tombstone = flat->has_bins == 0 || is_bin_cemetery;

	r->tombstone = is_tombstone ? 1 : 0;
	r->cenotaph = is_tombstone && (is_create || was_cenotaph) ? 1 : 0;
	r->xdr_tombstone = opt_meta->extra_flags.xdr_tombstone;
	r->xdr_nsup_tombstone = opt_meta->extra_flags.xdr_nsup_tombstone;
	r->xdr_bin_cemetery = is_bin_cemetery;

	as_record_transition_stats(r, ns, &old_metadata);
	as_record_transition_set_index(tree, r_ref, ns, opt_meta->n_bins,
			&old_metadata);
}

// TODO - not sure what's best here...
static const int NUM_COLD_START_DROP_THREADS = 24;

void
ssd_cold_start_drop_cenotaphs(as_namespace* ns)
{
	if (ns->n_durable_tombstones == 0) {
		return;
	}

	cf_info(AS_DRV_SSD, "{%s} cold start removing cenotaphs ...", ns->name);

	uint32_t n_dropped = drop_cenotaphs(ns, NUM_COLD_START_DROP_THREADS, false);

	cf_info(AS_DRV_SSD, "{%s} ... cold start removed %u cenotaphs", ns->name,
			n_dropped);
}

void
as_storage_start_tomb_raider_ssd(as_namespace* ns)
{
	cf_info(AS_DRV_SSD, "{%s} starting tomb raider thread", ns->name);

	if (ns->storage_serialize_tomb_raider) {
		start_serial_tomb_raider();
		return;
	}

	cf_thread_create_detached(run_tomb_raider, (void*)ns);
}


//==========================================================
// CP enterprise separation API.
//

void
ssd_adjust_versions(as_namespace* ns, drv_pmeta* pmeta)
{
	if (! ns->cp) {
		return;
	}

	cf_info(AS_DRV_SSD, "{%s} setting partition version 'e' flags", ns->name);

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition_version* version = &pmeta[pid].version;

		version->evade = 1;
		version->revived = 0;
	}
}

conflict_resolution_pol
ssd_cold_start_policy(const as_namespace *ns)
{
	return ns->cp ?
			AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_CP :
			AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_LAST_UPDATE_TIME;
}

void
ssd_cold_start_init_repl_state(as_namespace* ns, as_record* r)
{
	if (ns->cp) {
		r->repl_state = AS_REPL_STATE_UNREPLICATED;
		// Stat will be set after cold start.
	}
}

void
ssd_cold_start_set_unrepl_stat(as_namespace* ns)
{
	if (ns->cp) {
		// Everything starts as unreplicated on cold start.
		ns->n_unreplicated_records = ns->n_objects + ns->n_tombstones;
	}
}


//==========================================================
// XDR enterprise separation API.
//

void
ssd_cold_start_init_xdr_state(const as_flat_record* flat, as_record* r)
{
	r->xdr_write = flat->xdr_write;
}


//==========================================================
// Record encryption.
//

void
as_storage_cfg_init_ssd(as_namespace* ns)
{
	if (ns->storage_encryption_key_file != NULL) {
		drv_init_encryption_key(ns);
	}
}


#define MAX_XTS_LEN (1024 * 1024)

void
ssd_encrypt(drv_ssd *ssd, uint64_t off, as_flat_record *flat)
{
	if (ssd->ns->storage_encryption_key_file == NULL) {
		return;
	}

	uint32_t len = N_RBLOCKS_TO_SIZE(flat->n_rblocks);
	uint8_t* buf = (uint8_t*)flat;

	while (len != 0) {
		uint32_t enc_len = len > MAX_XTS_LEN ? MAX_XTS_LEN : len;

		drv_xts_encrypt(ssd->ns->storage_encryption, ssd->encryption_key, off,
				buf, enc_len, buf);

		off += enc_len;
		buf += enc_len;
		len -= enc_len;
	}
}


void
ssd_decrypt(drv_ssd *ssd, uint64_t off, as_flat_record *flat)
{
	if (ssd->ns->storage_encryption_key_file == NULL) {
		return;
	}

	uint64_t* block64 = (uint64_t*)flat;

	if (block64[0] == 0 && block64[1] == 0) {
		// We pad wblock ends with all zeros, and don't encrypt this padding.
		// Make sure we don't accidentally decrypt all zeros to good magic.
		return;
	}

	as_flat_record dec;

	drv_xts_decrypt(ssd->ns->storage_encryption, ssd->encryption_key, off,
			(uint8_t*)flat, 16, (uint8_t*)&dec);

	if (dec.magic != AS_FLAT_MAGIC) {
		flat->magic = 0; // ensure caller fails magic check
		return;
	}

	uint32_t len = N_RBLOCKS_TO_SIZE(dec.n_rblocks);
	uint8_t* buf = (uint8_t*)flat;

	while (len != 0) {
		uint32_t dec_len = len > MAX_XTS_LEN ? MAX_XTS_LEN : len;

		drv_xts_decrypt(ssd->ns->storage_encryption, ssd->encryption_key, off,
				buf, dec_len, buf);

		off += dec_len;
		buf += dec_len;
		len -= dec_len;
	}
}


void
ssd_decrypt_whole(drv_ssd *ssd, uint64_t off, uint32_t n_rblocks,
		as_flat_record *flat)
{
	if (ssd->ns->storage_encryption_key_file == NULL) {
		return;
	}

	uint32_t len = N_RBLOCKS_TO_SIZE(n_rblocks);
	uint8_t* buf = (uint8_t*)flat;

	while (len != 0) {
		uint32_t dec_len = len > MAX_XTS_LEN ? MAX_XTS_LEN : len;

		drv_xts_decrypt(ssd->ns->storage_encryption, ssd->encryption_key, off,
				buf, dec_len, buf);

		off += dec_len;
		buf += dec_len;
		len -= dec_len;
	}
}


//==========================================================
// Miscellaneous enterprise separation API.
//

static void
write_canary_and_key(const as_namespace* ns, drv_ssd* ssd, drv_header* header)
{
	// Write canary - assumes caller has zeroed the canary area.
	drv_xts_encrypt(ns->storage_encryption, ssd->encryption_key, 0,
			header->unique.canary, sizeof(header->unique.canary),
			header->unique.canary);

	// Write encrypted encryption key.
	drv_xts_encrypt(ns->storage_encryption, ns->storage_encryption_key, 0,
			ssd->encryption_key, sizeof(ssd->encryption_key),
			header->unique.encrypted_key);
}

// Called at startup, for any drive that is "fresh".
void
ssd_header_init_cfg(const as_namespace* ns, drv_ssd* ssd, drv_header* header)
{
	if (ns->single_bin) {
		header->generic.prefix.flags |= DRV_HEADER_FLAG_SINGLE_BIN;
	}

	if (ns->storage_encryption_key_file != NULL) {
		header->generic.prefix.flags |= DRV_HEADER_FLAG_ENCRYPTED;

		if (RAND_bytes(ssd->encryption_key,
				(int)sizeof(ssd->encryption_key)) < 1) {
			cf_crash(AS_DRV_SSD, "random key generation failed");
		}

		// The canary area has just been zeroed by caller.
		write_canary_and_key(ns, ssd, header);
	}

	if (ns->cp) {
		header->generic.prefix.flags |= DRV_HEADER_FLAG_CP;

		if (ns->storage_commit_to_device) {
			header->generic.prefix.flags |= DRV_HEADER_FLAG_COMMIT_TO_DEVICE;
		}
	}
}

static bool
extract_encryption_key(const as_namespace* ns, drv_ssd* ssd,
		const drv_header* header, const uint8_t* key)
{
	drv_xts_decrypt(ns->storage_encryption, key, 0,
			header->unique.encrypted_key, sizeof(header->unique.encrypted_key),
			ssd->encryption_key);

	uint64_t canary_zero[2]; // rely on sizeof(header->unique.canary) = 16

	drv_xts_decrypt(ns->storage_encryption, ssd->encryption_key, 0,
			header->unique.canary, sizeof(header->unique.canary),
			(uint8_t*)canary_zero);

	return canary_zero[0] == 0 && canary_zero[1] == 0;
}

// Called at startup, for any drive that is not "fresh".
void
ssd_header_validate_cfg(const as_namespace* ns, drv_ssd* ssd,
		drv_header* header)
{
	if ((header->generic.prefix.flags & DRV_HEADER_FLAG_SINGLE_BIN) != 0) {
		if (! ns->single_bin) {
			cf_crash(AS_DRV_SSD, "device has 'single-bin' data but 'single-bin' is not configured");
		}
	}
	else {
		if (ns->single_bin) {
			cf_crash(AS_DRV_SSD, "device has multi-bin data but 'single-bin' is configured");
		}
	}

	if ((header->generic.prefix.flags & DRV_HEADER_FLAG_ENCRYPTED) != 0) {
		if (ns->storage_encryption_key_file == NULL) {
			cf_crash(AS_DRV_SSD, "device encrypted but no encryption key file configured");
		}

		if (ns->storage_encryption_old_key_file == NULL) {
			if (! extract_encryption_key(ns, ssd, header,
					ns->storage_encryption_key)) {
				cf_crash(AS_DRV_SSD, "encryption key or algorithm mismatch");
			}
		}
		else {
			// Rotating keys - try old key.

			if (extract_encryption_key(ns, ssd, header,
					ns->storage_encryption_old_key)) {
				// Old key valid - write back to header using new key.
				cf_info(AS_DRV_SSD, "%s switching to new encryption key",
						ssd->name);

				// Zero the canary area.
				uint64_t* canary = (uint64_t*)header->unique.canary;

				canary[0] = 0;
				canary[1] = 0;

				write_canary_and_key(ns, ssd, header);
			}
			else {
				// Old key invalid - leftover config? - be nice, try new key.
				cf_warning(AS_DRV_SSD, "%s ignoring invalid old encryption key",
						ssd->name);

				if (! extract_encryption_key(ns, ssd, header,
						ns->storage_encryption_key)) {
					cf_crash(AS_DRV_SSD, "encryption key or algorithm mismatch");
				}
			}
		}
	}
	else { // header flag says not encrypted
		if (ns->storage_encryption_key_file != NULL) {
			cf_crash(AS_DRV_SSD, "device not encrypted but encryption key file %s is configured",
					ns->storage_encryption_key_file);
		}
	}

	if ((header->generic.prefix.flags & DRV_HEADER_FLAG_CP) != 0) {
		if (! ns->cp) {
			cf_crash(AS_DRV_SSD, "device has CP partition versions but 'strong-consistency' is not configured");
		}
	}
	else { // header flag says not CP
		if (ns->cp) {
			cf_crash(AS_DRV_SSD, "device has AP partition versions but 'strong-consistency' is configured");
		}
	}

	// Note - nothing to be done for DRV_HEADER_FLAG_COMMIT_TO_DEVICE -
	// changing either way is allowed.
}

// Called at startup once user keys are no longer needed.
void
ssd_clear_encryption_keys(as_namespace* ns)
{
	if (ns->storage_encryption_key_file != NULL) {
		dead_memset(ns->storage_encryption_key, 0,
				sizeof(ns->storage_encryption_key));
		dead_memset(ns->storage_encryption_old_key, 0,
				sizeof(ns->storage_encryption_old_key));
	}
}

// Called at startup, for items that must be flushed last.
void
ssd_flush_final_cfg(as_namespace* ns)
{
	if (! ns->cp) {
		return;
	}

	drv_ssds* ssds = (drv_ssds*)ns->storage_private;

	if (ns->storage_commit_to_device) {
		// Flush last, to be sure 'e' flags have already been committed.
		ssds->generic->prefix.flags |= DRV_HEADER_FLAG_COMMIT_TO_DEVICE;
	}
	else {
		ssds->generic->prefix.flags &= ~DRV_HEADER_FLAG_COMMIT_TO_DEVICE;
	}

	for (int i = 0; i < ssds->n_ssds; i++) {
		drv_ssd* ssd = &ssds->ssds[i];

		ssd_write_header(ssd, (uint8_t*)ssds->generic,
				(uint8_t*)&ssds->generic->prefix.flags,
				sizeof(ssds->generic->prefix.flags));
	}
}

void
ssd_prefetch_wblock(drv_ssd *ssd, uint64_t file_offset, uint8_t *read_buf)
{
	size_t indent = 0;

	while (indent < ssd->write_block_size) {
		as_flat_record *flat = (as_flat_record*)&read_buf[indent];

		ssd_decrypt(ssd, file_offset + indent, flat);

		if (flat->magic != AS_FLAT_MAGIC) {
			indent += RBLOCK_SIZE;
			continue;
		}

		uint32_t record_size = N_RBLOCKS_TO_SIZE(flat->n_rblocks);

		if (record_size < DRV_RECORD_MIN_SIZE) {
			indent += RBLOCK_SIZE;
			continue;
		}

		indent += record_size;

		if (indent > ssd->write_block_size) {
			break;
		}

		uint32_t pid = as_partition_getid(&flat->keyd);

		as_partition_reservation rsv;
		as_partition_reserve(ssd->ns, pid, &rsv);

		as_index_prefetch(rsv.tree, &flat->keyd);

		as_partition_release(&rsv);
	}
}


//==========================================================
// Durability - enterprise separation.
//

void
ssd_init_commit(drv_ssd *ssd)
{
	as_namespace *ns = ssd->ns;

	if (! ns->storage_commit_to_device) {
		return;
	}

	if (ns->storage_commit_min_size == 0) {
		ssd->commit_min_size = ssd->io_min_size;

		if (ssd->shadow_name != NULL) {
			ssd->shadow_commit_min_size = ssd->shadow_io_min_size;
		}
	}
	else {
		if (ns->storage_commit_min_size < ssd->io_min_size) {
			// TODO - something more gentle?
			cf_crash(AS_DRV_SSD, "{%s} commit-min-size %u < io-min-size %lu",
					ns->name, ns->storage_commit_min_size, ssd->io_min_size);
		}

		ssd->commit_min_size = ns->storage_commit_min_size;

		if (ssd->shadow_name != NULL) {
			if (ns->storage_commit_min_size < ssd->shadow_io_min_size) {
				// TODO - something more gentle?
				cf_crash(AS_DRV_SSD, "{%s} commit-min-size %u < shadow-io-min-size %lu",
						ns->name, ns->storage_commit_min_size,
						ssd->shadow_io_min_size);
			}

			ssd->shadow_commit_min_size = ns->storage_commit_min_size;
		}
	}

	ssd->commit_fd = ssd_fd_get(ssd);

	if (ssd->shadow_name) {
		ssd->shadow_commit_fd = ssd_shadow_fd_get(ssd);
	}
}

uint64_t
ssd_flush_max_us(const as_namespace *ns)
{
	// No need to flush current buffer if flushing every write.
	return ns->storage_commit_to_device ? 0 : ns->storage_flush_max_us;
}

// Round bytes down to a multiple of minimum commit size.
static inline uint64_t
BYTES_DOWN_TO_COMMIT_MIN(drv_ssd *ssd, uint64_t bytes) {
	return bytes & -ssd->commit_min_size;
}

// Round bytes up to a multiple of minimum commit size.
static inline uint64_t
BYTES_UP_TO_COMMIT_MIN(drv_ssd *ssd, uint64_t bytes) {
	return (bytes + (ssd->commit_min_size - 1)) & -ssd->commit_min_size;
}

// Round bytes down to a multiple of minimum shadow commit size.
static inline uint64_t
BYTES_DOWN_TO_SHADOW_COMMIT_MIN(drv_ssd *ssd, uint64_t bytes) {
	return bytes & -ssd->shadow_commit_min_size;
}

// Round bytes up to a multiple of minimum shadow commit size.
static inline uint64_t
BYTES_UP_TO_SHADOW_COMMIT_MIN(drv_ssd *ssd, uint64_t bytes) {
	return (bytes + (ssd->shadow_commit_min_size - 1)) &
			-ssd->shadow_commit_min_size;
}

void
ssd_commit_chunk(drv_ssd *ssd, const ssd_write_buf *swb, uint64_t offset,
		uint32_t size)
{
	uint64_t flush_offset = BYTES_DOWN_TO_COMMIT_MIN(ssd, offset);
	uint64_t flush_end_offset = BYTES_UP_TO_COMMIT_MIN(ssd, offset + size);

	uint8_t *flush = swb->buf + (swb->pos - (uint32_t)(offset - flush_offset));
	size_t flush_sz = flush_end_offset - flush_offset;

	uint64_t start_ns = ssd->ns->storage_benchmarks_enabled ? cf_getns() : 0;

	if (! pwrite_all(ssd->commit_fd, flush, flush_sz, (off_t)flush_offset)) {
		cf_crash(AS_DRV_SSD, "%s: DEVICE FAILED write: errno %d (%s)",
				ssd->name, errno, cf_strerror(errno));
	}

	if (start_ns != 0) {
		histogram_insert_data_point(ssd->hist_write, start_ns);
	}

	if (! ssd->shadow_name) {
		return;
	}
	// else - flush to shadow drive.

	flush_offset = BYTES_DOWN_TO_SHADOW_COMMIT_MIN(ssd, offset);
	flush_end_offset = BYTES_UP_TO_SHADOW_COMMIT_MIN(ssd, offset + size);

	flush = swb->buf + (swb->pos - (uint32_t)(offset - flush_offset));
	flush_sz = flush_end_offset - flush_offset;

	start_ns = ssd->ns->storage_benchmarks_enabled ? cf_getns() : 0;

	if (! pwrite_all(ssd->shadow_commit_fd, flush, flush_sz,
			(off_t)flush_offset)) {
		cf_crash(AS_DRV_SSD, "%s: DEVICE FAILED write: errno %d (%s)",
				ssd->shadow_name, errno, cf_strerror(errno));
	}

	if (start_ns != 0) {
		histogram_insert_data_point(ssd->hist_shadow_write, start_ns);
	}
}

int
ssd_commit_bins(as_storage_rd *rd)
{
	as_namespace *ns = rd->ns;
	as_record *r = rd->r;
	drv_ssd *ssd = rd->ssd;

	uint32_t flat_sz;
	uint32_t limit_sz;

	if (rd->pickle == NULL) {
		flat_sz = as_flat_record_size(rd);
		limit_sz = ns->max_record_size == 0 ?
				ssd->write_block_size : ns->max_record_size;
	}
	else {
		flat_sz = rd->orig_pickle_sz;
		limit_sz = ssd->write_block_size;
	}

	uint32_t flat_w_mark_sz = flat_sz + END_MARK_SZ;

	if (flat_w_mark_sz > limit_sz) {
		cf_detail(AS_DRV_SSD, "{%s} write: size %u - rejecting %pD", ns->name,
				flat_w_mark_sz, &r->keyd);
		return -AS_ERR_RECORD_TOO_BIG;
	}

	as_flat_record *flat;

	if (rd->pickle == NULL) {
		flat = as_flat_compress_bins_and_pack_record(rd, ssd->write_block_size,
				false, true, &flat_w_mark_sz);
		flat_sz = flat_w_mark_sz - END_MARK_SZ;
	}
	else {
		flat = (as_flat_record *)rd->pickle;

		// Limit check used orig size, but from here on use compressed size.
		flat_sz = rd->pickle_sz;
		flat_w_mark_sz = flat_sz + END_MARK_SZ;

		// Tree IDs are node-local - can't use those sent from other nodes.
		flat->tree_id = r->tree_id;
	}

	// Note - this is the only place where rounding size (up to a  multiple of
	// RBLOCK_SIZE) is really necessary.
	uint32_t write_sz = SIZE_UP_TO_RBLOCK_SIZE(flat_w_mark_sz);

	current_swb *cur_swb = &ssd->current_swbs[rd->which_current_swb];

	cf_mutex_lock(&cur_swb->lock);

	ssd_write_buf *swb = cur_swb->swb;

	if (! swb) {
		swb = swb_get(ssd, false);
		cur_swb->swb = swb;

		if (! swb) {
			cf_ticker_warning(AS_DRV_SSD, "{%s} out of space", ns->name);
			cf_mutex_unlock(&cur_swb->lock);
			return -AS_ERR_OUT_OF_SPACE;
		}

		swb->use_post_write_q = write_uses_post_write_q(rd);

		memset(swb->buf, 0, ssd->write_block_size);
	}

	// Check if there's enough space in current buffer - if not, free and zero
	// any remaining unused space, enqueue it to post-write-queue, and grab a
	// new buffer.
	if (write_sz > ssd->write_block_size - swb->pos) {
		if (ssd->write_block_size != swb->pos) {
			// Flush the clean end of the buffer, to overwrite old records.
			uint64_t clean_offset =
					WBLOCK_ID_TO_OFFSET(ssd, swb->wblock_id) + swb->pos;
			uint32_t clean_size = ssd->write_block_size - swb->pos;

			ssd_commit_chunk(ssd, swb, clean_offset, clean_size);
		}

		// Pass full buffer to post-write-queue.
		ssd_post_write(ssd, swb);
		cur_swb->n_wblocks_written++;

		// Get the new buffer.
		swb = swb_get(ssd, false);
		cur_swb->swb = swb;

		if (! swb) {
			cf_ticker_warning(AS_DRV_SSD, "{%s} out of space", ns->name);
			cf_mutex_unlock(&cur_swb->lock);
			return -AS_ERR_OUT_OF_SPACE;
		}

		swb->use_post_write_q = write_uses_post_write_q(rd);

		memset(swb->buf, 0, ssd->write_block_size);
	}

	// There's enough space - flatten data into the block.

	uint32_t n_rblocks = ROUNDED_SIZE_TO_N_RBLOCKS(write_sz);

	if (rd->pickle != NULL) {
		flat->n_rblocks = n_rblocks;
	}

	as_flat_record *flat_in_swb = (as_flat_record*)&swb->buf[swb->pos];

	if (flat == NULL) {
		as_flat_pack_record(rd, n_rblocks, false, flat_in_swb);
	}
	else {
		memcpy(flat_in_swb, flat, flat_sz);
	}

	ssd_add_end_mark((uint8_t*)flat_in_swb + flat_sz, flat_in_swb);

	// Make a pickle if needed.
	if (rd->keep_pickle) {
		rd->pickle_sz = flat_sz;
		rd->pickle = cf_malloc(flat_sz);
		memcpy(rd->pickle, flat_in_swb, flat_sz);

		// FIXME - should this be only for compatibility with old nodes?
		if (write_sz - flat_sz >= RBLOCK_SIZE) {
			((as_flat_record*)rd->pickle)->n_rblocks--;
		}
	}

	uint64_t write_offset = WBLOCK_ID_TO_OFFSET(ssd, swb->wblock_id) + swb->pos;

	ssd_encrypt(ssd, write_offset, flat_in_swb);

	// Flush the record to device.
	ssd_commit_chunk(ssd, swb, write_offset, write_sz);

	swb->pos += write_sz;

	r->file_id = ssd->file_id;
	r->rblock_id = OFFSET_TO_RBLOCK_ID(write_offset);

	as_namespace_adjust_set_device_bytes(ns, as_index_get_set_id(r),
			DELTA_N_RBLOCKS_TO_SIZE(n_rblocks, r->n_rblocks));

	r->n_rblocks = n_rblocks;

	cf_atomic64_add(&ssd->inuse_size, (int64_t)write_sz);
	cf_atomic32_add(&ssd->wblock_state[swb->wblock_id].inuse_sz,
			(int32_t)write_sz);

	cf_mutex_unlock(&cur_swb->lock);

	if (ns->storage_benchmarks_enabled) {
		histogram_insert_raw(ns->device_write_size_hist, write_sz);
	}

	return 0;
}

int
ssd_write_bins(as_storage_rd *rd)
{
	return rd->ns->storage_commit_to_device ?
			ssd_commit_bins(rd) : ssd_buffer_bins(rd);
}
