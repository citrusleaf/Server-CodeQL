/*
 * drv_memory_ee.c
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "citrusleaf/cf_clock.h"

#include "cf_thread.h"
#include "log.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "base/proto.h"
#include "base/record_ee.h"
#include "fabric/partition.h"
#include "fabric/partition_balance.h"
#include "storage/flat.h"
#include "storage/storage.h"
#include "xdr/dc_manager.h"


int
as_storage_record_write_memory(as_storage_rd* rd)
{
	bool is_master = rd->pickle == NULL;

	// Make a pickle if needed. (No pickle needed for drop.)
	if ((rd->n_bins != 0 || rd->r->tombstone == 1) && rd->keep_pickle) {
		as_flat_pickle_record(rd);
	}

	as_namespace* ns = rd->ns;

	if (is_master && ns->max_record_size != 0) {
		uint32_t flat_sz = rd->pickle_sz == 0 ?
				as_flat_record_size(rd) : rd->pickle_sz;

		if (flat_sz > ns->max_record_size) {
			return -AS_ERR_RECORD_TOO_BIG;
		}
	}

	return 0;
}

void
as_storage_load_pmeta_memory(as_namespace *ns, as_partition *p)
{
	if (ns->cp) {
		p->version.evade = 1;
	}
}


//==========================================================
// Durable delete: tomb raider.
// TODO - isn't this absurd ???
//

typedef struct reduce_cb_info_s {
	as_namespace* ns;
	as_index_tree* tree;
	uint64_t lut_threshold;
	uint32_t* p_n_dropped;
} reduce_cb_info;

bool
drop_reduce_cb(as_index_ref* r_ref, void* udata)
{
	as_record* r = r_ref->r;
	reduce_cb_info* p_cb_info = (reduce_cb_info*)udata;

	if (is_durable_tombstone(r) &&
			r->last_update_time < p_cb_info->lut_threshold) {
		(*p_cb_info->p_n_dropped)++;
		// Note - tombstone will not be in set-index.
		as_index_delete(p_cb_info->tree, &r->keyd);
	}

	as_record_done(r_ref, p_cb_info->ns);

	return true;
}

void
mem_tomb_raid(as_namespace* ns)
{
	// Reduce index to drop tombstones that are old enough.

	cf_info(AS_STORAGE, "{%s} tomb raider start ...", ns->name);

	// Don't drop tombstones unless they're old enough.
	uint64_t lut_threshold = cf_clepoch_milliseconds() -
			(1000 * ns->tomb_raider_eligible_age);

	// Don't drop cenotaphs if XDR has not shipped them yet.
	uint64_t xdr_ns_min_lst = as_dc_manager_ns_min_lst(ns);

	if (xdr_ns_min_lst < lut_threshold) {
		lut_threshold = xdr_ns_min_lst;
	}

	uint32_t n_dropped = 0;

	for (int pid = 0; pid < AS_PARTITIONS; pid++) {
		// Don't drop anything in this partition if any migrations remain.
		if (as_partition_pending_migrations(&ns->partitions[pid])) {
			continue;
		}

		as_partition_reservation rsv;
		as_partition_reserve(ns, pid, &rsv);

		reduce_cb_info cb_info = { ns, rsv.tree, lut_threshold, &n_dropped };

		as_index_reduce(rsv.tree, drop_reduce_cb, (void*)&cb_info);
		as_partition_release(&rsv);
	}

	cf_info(AS_STORAGE, "{%s} ... tomb raider done - removed %u tombstones",
			ns->name, n_dropped);
}

// Same as 'device' version for now.
void*
run_mem_tomb_raider(void* arg)
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

		// Don't raid if this namespace doesn't do durable deletes.
		if (ns->n_durable_tombstones != 0) {
			mem_tomb_raid(ns);
		}
	}

	return NULL;
}

void
as_storage_start_tomb_raider_memory(as_namespace* ns)
{
	cf_info(AS_STORAGE, "{%s} starting tomb raider thread", ns->name);

	cf_thread_create_detached(run_mem_tomb_raider, (void*)ns);
}
