/*
 * drv_pmem_ee.c
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "storage/storage.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <unistd.h>
#include <xmmintrin.h>

#include "libpmem.h"

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_queue.h"
#include "citrusleaf/cf_random.h"

#include "arenax_ee.h"
#include "bits.h"
#include "cf_mutex.h"
#include "cf_thread.h"
#include "hist.h"
#include "log.h"
#include "os.h"
#include "vmapx.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "base/nsup.h"
#include "base/record_ee.h"
#include "base/set_index.h"
#include "base/set_index_ee.h"
#include "base/truncate.h"
#include "fabric/partition.h"
#include "fabric/partition_balance.h"
#include "storage/drv_common.h"
#include "storage/drv_common_ee.h"
#include "storage/flat.h"
#include "storage/flat_ee.h"
#include "transaction/re_replicate_ee.h"
#include "transaction/rw_utils.h"
#include "xdr/dc_manager.h"


//==========================================================
// Typedefs & constants.
//

#define PMEM_WRITE_BLOCK_SIZE (8 * 1024 * 1024UL)
#define PMEM_IO_SIZE 512
#define PMEM_CIPHER_BLOCK_SIZE 16

// A defragged wblock waiting to be freed.
typedef struct vacated_wblock_s {
	uint32_t file_id;
	uint32_t wblock_id;
} vacated_wblock;

struct drv_pmem_s;

// Where records accumulate until flushed to device.
typedef struct pmem_write_block_s {
	cf_atomic32			n_writers;	// number of concurrent writers
	bool				dirty;		// written to since last flushed
	uint32_t			n_vacated;
	uint32_t			vacated_capacity;
	vacated_wblock*		vacated_wblocks;
	struct drv_pmem_s*	pmem;
	uint32_t			wblock_id;
	uint8_t*			base_addr;
	uint32_t			first_dirty_pos;
	uint32_t			pos;
} pmem_write_block;

// Per-wblock information.
typedef struct pmem_wblock_state_s {
	cf_atomic32			inuse_sz;	// number of bytes currently used in the wblock
	cf_mutex			LOCK;		// transactions, write_worker, and defrag all are interested in wblock_state
	pmem_write_block*	pwb;		// pending writes for the wblock, also treated as a cache for reads
	uint32_t			state;		// for now just a defrag flag
	cf_atomic32			n_vac_dests; // number of wblocks into which this wblock defragged
} pmem_wblock_state;

// Per current write buffer information.
typedef struct current_pwb_s {
	cf_mutex		lock;				// lock protects writes to pwb
	pmem_write_block* pwb;				// pwb currently being filled by writes
	uint64_t		n_wblocks_written;	// total number of pwbs added to the pwb_write_q by writes
} current_pwb;

// Per-device information.
typedef struct drv_pmem_s {
	struct as_namespace_s* ns;

	const char*		name;				// this device's name
	const char*		shadow_name;		// this device's shadow's name, if any

	uint32_t		running;

	current_pwb		current_pwbs[N_CURRENT_SWBS];

	int				shadow_commit_fd;	// relevant for enterprise edition only

	cf_mutex		defrag_lock;		// lock protects writes to defrag pwb
	pmem_write_block* defrag_pwb;		// pwb currently being filled by defrag

	cf_queue*		shadow_fd_q;		// queue of open fds on shadow, if any

	uint8_t*		pmem_base_addr;	// base address of pmem-mapped file

	cf_queue*		free_wblock_q;		// IDs of free wblocks
	cf_queue*		defrag_wblock_q;	// IDs of wblocks to defrag

	cf_queue*		pwb_write_q;		// pointers to pwbs ready to write
	cf_queue*		pwb_shadow_q;		// pointers to pwbs ready to write to shadow, if any
	cf_queue*		pwb_free_q;			// pointers to pwbs free and waiting

	uint8_t			encryption_key[64];		// relevant for enterprise edition only

	cf_atomic64		n_defrag_wblock_reads;	// total number of wblocks added to the defrag_wblock_q
	cf_atomic64		n_defrag_wblock_writes;	// total number of pwbs added to the pwb_write_q by defrag

	cf_atomic64		n_wblock_defrag_io_skips;	// total number of wblocks empty on defrag_wblock_q pop
	cf_atomic64		n_wblock_direct_frees;		// total number of wblocks freed by other than defrag

	volatile uint64_t n_tomb_raider_reads;	// relevant for enterprise edition only

	cf_atomic32		defrag_sweep;		// defrag sweep flag

	uint64_t		file_size;
	int				file_id;

	uint32_t		open_flag;

	cf_atomic64		inuse_size;			// number of bytes in actual use on this device

	uint32_t		first_wblock_id;	// wblock-id of first non-header wblock

	uint32_t		pristine_wblock_id;	// minimum wblock-id of "pristine" region

	uint32_t		n_wblocks;			// number of wblocks on this device
	pmem_wblock_state* wblock_state;	// array of info per wblock on this device

	uint32_t		sweep_wblock_id;				// wblocks read at startup
	uint64_t		record_add_older_counter;		// records not inserted due to better existing one
	uint64_t		record_add_expired_counter;		// records not inserted due to expiration
	uint64_t		record_add_evicted_counter;		// records not inserted due to eviction
	uint64_t		record_add_replace_counter;		// records reinserted
	uint64_t		record_add_unique_counter;		// records inserted

	cf_tid			write_tid;
	cf_tid			shadow_tid;

	histogram*		hist_shadow_write;
} drv_pmem;

// Per-namespace storage information.
typedef struct drv_pmems_s {
	as_namespace* ns;
	drv_generic* generic;

	// Not a great place for this - used only at startup to determine whether to
	// load a record.
	bool get_state_from_storage[AS_PARTITIONS];

	// Indexed by previous device-id to get new device-id. -1 means device is
	// "fresh" or absent. Used only at startup to fix index elements' file-id.
	int8_t device_translation[AS_STORAGE_MAX_DEVICES];

	// Used only at startup, set true if all devices are fresh.
	bool all_fresh;

	cf_mutex flush_lock;

	int n_pmems;
	drv_pmem pmems[];
} drv_pmems;

typedef struct pmem_load_records_info_s {
	drv_pmems* pmems;
	drv_pmem* pmem;
	cf_queue* complete_q;
	void* complete_rc;
} pmem_load_records_info;

#define DEFRAG_PEN_INIT_CAPACITY (8 * 1024)

typedef struct defrag_pen_s {
	uint32_t n_ids;
	uint32_t capacity;
	uint32_t* ids;
	uint32_t stack_ids[DEFRAG_PEN_INIT_CAPACITY];
} defrag_pen;

// TODO - not sure what's best here...
static const int NUM_COLD_START_DROP_THREADS = 24;

#define MAX_XTS_LEN (1024 * 1024)

typedef struct overall_info_s {
	cf_atomic32		n_threads_done;
	cf_atomic32		i_cpu;
	cf_atomic32		stage_id;
	uint32_t		now;
	drv_pmems*		pmems;
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

typedef struct per_cpu_info_s {
	uint32_t		stage_id;
	uint32_t		now;
	drv_pmems*		pmems;
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
	uint64_t		used_size_per_pmem[AS_STORAGE_MAX_DEVICES];
} per_cpu_info;

#define PROGRESS_RESOLUTION 10000

#define WARM_START_TICKER_INTERVAL 5 // seconds
#define WARM_START_TICKER_SLEEP_US (1000 * 10)
#define WARM_START_TICKER_EVERY_N \
	((WARM_START_TICKER_INTERVAL * 1000000) / WARM_START_TICKER_SLEEP_US)

#define LOG_STATS_INTERVAL_sec 20

// All in microseconds since we're using usleep().
#define MAX_INTERVAL		(1000 * 1000)
#define LOG_STATS_INTERVAL	(1000 * 1000 * LOG_STATS_INTERVAL_sec)
#define FREE_SWBS_INTERVAL	(1000 * 1000 * 20)

// It's runtime, so tomb raider is more like a scan than a warm restart.
// TODO - config? single thread?
static const int NUM_TOMB_RAIDER_THREADS = 4;

typedef struct mark_cenotaph_info_s {
	as_namespace* ns;
	cf_atomic32 pid;
	uint64_t lut_threshold;
} mark_cenotaph_info;

typedef struct unmark_cenotaph_info_s {
	drv_pmems* pmems;
	cf_atomic32 pmem_index;
	uint32_t now;
	volatile int aborted;
} unmark_cenotaph_info;

static const uint64_t MARK_MIN_AGE_SAFETY_MARGIN = 60;

typedef struct mark_reduce_cb_info_s {
	as_namespace* ns;
	uint64_t lut_threshold;
} mark_reduce_cb_info;

typedef struct drop_cenotaph_info_s {
	as_namespace* ns;
	cf_atomic32 pid;
	uint64_t lut_threshold;
	bool cancelled;
	cf_atomic32 n_dropped;
} drop_cenotaph_info;

typedef struct drop_reduce_cb_info_s {
	as_namespace* ns;
	as_index_tree* tree;
	uint64_t lut_threshold;
	bool cancelled;
	int32_t n_dropped;
} drop_reduce_cb_info;

#define VACATED_CAPACITY_STEP 128 // allocate in 1K chunks


//==========================================================
// Globals.
//

static bool g_serial_tomb_raider_started = false;


//==========================================================
// Forward declarations.
//

// Startup control.
static void init_files(as_namespace* ns, drv_pmems** pmems_p);
static uint64_t check_file_size(uint64_t file_size, const char* tag);
static void init_shadow_files(as_namespace* ns, drv_pmems* pmems);
static void wblock_init(drv_pmem* pmem);
static void init_commit(drv_pmem* pmem);
static void init_synchronous(drv_pmems* pmems);
static drv_header* read_header(drv_pmem* pmem);
static void header_validate_cfg(const as_namespace* ns, drv_pmem* pmem, drv_header* header);
static bool extract_encryption_key(const as_namespace* ns, drv_pmem* pmem, const drv_header* header, const uint8_t* key);
static void write_canary_and_key(const as_namespace* ns, drv_pmem* pmem, drv_header* header);
static drv_header* init_header(as_namespace* ns, drv_pmem* pmem);
static void header_init_cfg(const as_namespace* ns, drv_pmem* pmem, drv_header* header);
static void clear_encryption_keys(as_namespace* ns);
static void adjust_versions(const as_namespace* ns, drv_pmeta* pmeta);
static void flush_header(drv_pmems* pmems, drv_header** headers);
static void init_pristine_wblock_id(drv_pmem* pmem, uint64_t offset);
static void flush_final_cfg(as_namespace* ns);
static void start_loading_records(drv_pmems* pmems, cf_queue* complete_q);
static void load_wblock_queues(drv_pmems* pmems);
static void* run_load_queues(void* pv_data);
static void defrag_pen_init(defrag_pen* pen);
static void defrag_pen_destroy(defrag_pen* pen);
static void defrag_pen_add(defrag_pen* pen, uint32_t wblock_id);
static void defrag_pen_transfer(defrag_pen* pen, drv_pmem* pmem);
static void defrag_pens_dump(defrag_pen pens[], uint32_t n_pens, const char* pmem_name);
static void start_maintenance_threads(drv_pmems* pmems);
static void start_write_threads(drv_pmems* pmems);
static void start_defrag_threads(drv_pmems* pmems);

// Cold start.
static void* run_pmem_cold_start(void* udata);
static void cold_start_sweep(drv_pmems* pmems, drv_pmem* pmem);
static void cold_start_add_record(drv_pmems* pmems, drv_pmem* pmem, const as_flat_record* flat, uint64_t rblock_id, uint32_t record_size);
static bool prefer_existing_record(const as_namespace* ns, const as_flat_record* flat, uint32_t block_void_time, const as_index* r);
static conflict_resolution_pol cold_start_policy(const as_namespace* ns);
static void cold_start_adjust_cenotaph(const as_namespace* ns, const as_flat_record* flat, uint32_t block_void_time, as_record* r);
static void cold_start_init_repl_state(const as_namespace* ns, as_record* r);
static void cold_start_set_unrepl_stat(as_namespace* ns);
static void cold_start_init_xdr_state(const as_flat_record* flat, as_record* r);
static void cold_start_transition_record(as_namespace* ns, const as_flat_record* flat, const as_flat_opt_meta* opt_meta, as_index_tree* tree, as_index_ref* r_ref, bool is_create);
static void cold_start_drop_cenotaphs(as_namespace* ns);

// Warm restart.
static void resume_devices(drv_pmems* pmems);
static void* run_scan_stages(void* pv_data);
static cf_arenax_element_result resume_element_cb(void* pv_element, cf_arenax_handle h, void* udata);
static void discover_pristine_wblock_ids(drv_pmems* pmems);

// Shutdown.
static void set_pristine_offset(drv_pmems* pmems);
static void set_trusted(drv_pmems* pmems);

// Read record.
static int read_record(as_storage_rd* rd, bool pickle_only);

// Write record.
static int write_record(as_storage_rd* rd);
static int write_bins(as_storage_rd* rd);
static int buffer_bins(as_storage_rd* rd);
static int commit_bins(as_storage_rd* rd);
static void prepare_for_first_commit(pmem_write_block* pwb, bool encrypt);
static void shadow_commit(const drv_pmem* pmem, const pmem_write_block* pwb, off_t offset, size_t size);

// Write and recycle wblocks.
static void* run_write(void* arg);
static void flush_final_pwb(pmem_write_block* pwb, bool encrypt);
static void* run_shadow(void* arg);
static void write_sanity_checks(drv_pmem* pmem, pmem_write_block* pwb);
static void block_free(drv_pmem* pmem, uint64_t rblock_id, uint32_t n_rblocks, char* msg);
static void push_wblock_to_defrag_q(drv_pmem* pmem, uint32_t wblock_id);
static void push_wblock_to_free_q(drv_pmem* pmem, uint32_t wblock_id);

// Write to header.
static void write_header(drv_pmem* pmem, const uint8_t* header, const uint8_t* from, size_t size);
static void write_header_atomic(drv_pmem* pmem, const uint8_t* header, const uint8_t* from, size_t size);
static void aligned_write_to_shadow(drv_pmem* pmem, const uint8_t* header, const uint8_t* from, size_t size);
static void atomic_write(drv_pmem* pmem, const uint8_t* header, const uint8_t* from, size_t size);
static void flush_flags(drv_pmems* pmems);

// Defrag.
static void* run_defrag(void* pv_data);
static int defrag_wblock(drv_pmem* pmem, uint32_t wblock_id);
static int record_defrag(drv_pmem* pmem, uint32_t wblock_id, const as_flat_record* flat, uint64_t rblock_id);
static void defrag_move_record(drv_pmem* src_pmem, uint32_t src_wblock_id, const as_flat_record* flat, as_index* r);
static void release_vacated_wblock(drv_pmem* pmem, uint32_t wblock_id, pmem_wblock_state* p_wblock_state);

// Maintenance.
static void* run_pmem_maintenance(void* udata);
static void log_stats(drv_pmem* pmem, uint64_t* p_prev_n_total_writes, uint64_t* p_prev_n_defrag_reads, uint64_t* p_prev_n_defrag_writes, uint64_t* p_prev_n_defrag_io_skips, uint64_t* p_prev_n_direct_frees, uint64_t* p_prev_n_tomb_raider_reads);
static uint64_t next_time(uint64_t now, uint64_t job_interval, uint64_t next);
static void free_pwbs(drv_pmem* pmem);
static void flush_current_pwb(drv_pmem* pmem, uint8_t which, uint64_t* p_prev_n_writes);
static void flush_defrag_pwb(drv_pmem* pmem, uint64_t* p_prev_n_defrag_writes);
static void flush_partial_pwb(pmem_write_block* pwb, bool encrypt);
static void defrag_sweep(drv_pmem* pmem);

// Tomb raider.
static void start_serial_tomb_raider();
static void* run_serial_tomb_raider(void* arg);
static void* run_tomb_raider(void* arg);
static void tomb_raid(as_namespace* ns);
static uint64_t lut_mark_threshold(drv_pmems* pmems);
static int write_q_reduce_cb(void* buf, void* udata);
static void* run_mark_cenotaphs(void* pv_data);
static bool mark_cenotaph_reduce_cb(as_index_ref* r_ref, void* udata);
static void* run_unmark_cenotaphs(void* pv_data);
static void unmark_cenotaph(as_namespace* ns, const cf_digest* keyd);
static uint32_t drop_cenotaphs(as_namespace* ns, int n_threads, bool cancelled);
static void* run_drop_cenotaphs(void* pv_data);
static bool drop_cenotaph_reduce_cb(as_index_ref* r_ref, void* udata);

// pwb class.
static pmem_write_block* pwb_create(drv_pmem* pmem);
static void pwb_destroy(pmem_write_block* pwb);
static void pwb_reset(pmem_write_block* pwb);
static void pwb_release(drv_pmem* pmem, uint32_t wblock_id, pmem_write_block* pwb);
static pmem_write_block* pwb_get(drv_pmem* pmem, bool use_reserve);
static bool pop_pristine_wblock_id(drv_pmem* pmem, uint32_t* wblock_id);
static bool pwb_add_unique_vacated_wblock(pmem_write_block* pwb, uint32_t src_file_id, uint32_t src_wblock_id);
static void pwb_release_all_vacated_wblocks(pmem_write_block* pwb);

// Persistence utilities.
static void pmem_mprotect(void *addr, size_t len, int prot);
static void prepare_for_first_write(pmem_write_block* pwb, bool encrypt);
static size_t mark_flat_dirty(const drv_pmem* pmem, as_flat_record* flat_pmem, bool encrypt);
static void persist_and_mark_clean(const drv_pmem* pmem, as_flat_record* flat_pmem, size_t flush_size, bool encrypt);
static void copy_flat(as_flat_record* out, const as_flat_record* in, size_t size, bool encrypted);

// Shadow utilities.
static int shadow_fd_get(drv_pmem* pmem);
static void shadow_fd_put(drv_pmem* pmem, int fd);
static void shadow_flush_pwb(drv_pmem* pmem, pmem_write_block* pwb);

// Encryption utilities.
static as_flat_record* decrypt_sized_flat(const drv_pmem* pmem, uint64_t off, size_t len, uint8_t* buf_in);
static const as_flat_record* decrypt_flat(const drv_pmem* pmem, uint64_t off, const uint8_t* buf_in);
static void encrypt_flat(const drv_pmem* pmem, uint64_t off, const as_flat_record* flat, uint8_t* buf_out);
static void encrypt_data(const drv_pmem* pmem, uint64_t off, size_t len, const uint8_t* buf, uint8_t* buf_out);
static void* get_scratch_thread_buffer(size_t write_sz);


//==========================================================
// Inlines & macros.
//

// Convert byte offset to wblock_id.
static inline uint32_t
OFFSET_TO_WBLOCK_ID(uint64_t offset)
{
	return (uint32_t)(offset / PMEM_WRITE_BLOCK_SIZE);
}

// Convert wblock_id to byte offset.
static inline uint64_t
WBLOCK_ID_TO_OFFSET(uint32_t wblock_id)
{
	return (uint64_t)wblock_id * (uint64_t)PMEM_WRITE_BLOCK_SIZE;
}

// Convert rblock_id to wblock_id.
static inline uint32_t
RBLOCK_ID_TO_WBLOCK_ID(uint64_t rblock_id)
{
	return (uint32_t)((rblock_id << LOG_2_RBLOCK_SIZE) / PMEM_WRITE_BLOCK_SIZE);
}

// Round bytes down to a multiple of shadow's minimum IO operation size.
static inline uint64_t
BYTES_DOWN_TO_IO_MIN(uint64_t bytes)
{
	return bytes & -PMEM_IO_SIZE;
}

// Round bytes up to a multiple of shadow's minimum IO operation size.
static inline uint64_t
BYTES_UP_TO_IO_MIN(uint64_t bytes)
{
	return (bytes + (PMEM_IO_SIZE - 1)) & -PMEM_IO_SIZE;
}

// Decide which device a record belongs on.
static inline uint32_t
pmem_get_file_id(const drv_pmems* pmems, const cf_digest* keyd)
{
	return *(uint32_t*)&keyd->digest[DIGEST_STORAGE_BASE_BYTE] % pmems->n_pmems;
}

static inline void
pmem_wait_writers_done(pmem_write_block* pwb)
{
	while (cf_atomic32_get(pwb->n_writers) != 0) {
		_mm_pause();
	}
}

static inline uint32_t
num_pristine_wblocks(const drv_pmem* pmem)
{
	return pmem->n_wblocks - pmem->pristine_wblock_id;
}

static inline uint32_t
num_free_wblocks(const drv_pmem* pmem)
{
	return cf_queue_sz(pmem->free_wblock_q) + num_pristine_wblocks(pmem);
}

static inline void
push_wblock_to_write_q(drv_pmem* pmem, const pmem_write_block* pwb)
{
	cf_atomic32_incr(&pmem->ns->n_wblocks_to_flush);
	cf_queue_push(pmem->pwb_write_q, &pwb);
}

// Available contiguous size.
static inline uint64_t
available_size(const drv_pmem* pmem)
{
	// Note - returns 100% available during cold start, to make it irrelevant in
	// cold start eviction threshold check.

	return pmem->free_wblock_q != NULL ?
			(uint64_t)num_free_wblocks(pmem) * PMEM_WRITE_BLOCK_SIZE :
			pmem->file_size;
}

// We can often avoid all writes to an index element, meaning we won't write
// back to its cache line. This makes a measurable difference.
#define set_if_needed(x, y) \
	if (x != y) { \
		x = y; \
	}


//==========================================================
// Public API.
//

void
as_storage_cfg_init_pmem(as_namespace* ns)
{
	if (ns->storage_encryption_key_file != NULL) {
		drv_init_encryption_key(ns);
	}
}

void
as_storage_init_pmem(as_namespace* ns)
{
	drv_pmems* pmems;

	init_files(ns, &pmems);
	init_shadow_files(ns, pmems);

	g_unique_data_size += ns->drive_size / (2 * ns->cfg_replication_factor);

	cf_mutex_init(&pmems->flush_lock);

	// The queue limit is more efficient to work with.
	ns->storage_max_write_q = (uint32_t)
			(pmems->n_pmems * ns->storage_max_write_cache /
					PMEM_WRITE_BLOCK_SIZE);

	// Minimize how often we recalculate this.
	ns->defrag_lwm_size =
			(PMEM_WRITE_BLOCK_SIZE * ns->storage_defrag_lwm_pct) / 100;

	ns->storage_private = (void*)pmems;

	char histname[HISTOGRAM_NAME_SIZE];

	snprintf(histname, sizeof(histname), "{%s}-device-read-size", ns->name);
	ns->device_read_size_hist = histogram_create(histname, HIST_SIZE);

	snprintf(histname, sizeof(histname), "{%s}-device-write-size", ns->name);
	ns->device_write_size_hist = histogram_create(histname, HIST_SIZE);

	uint32_t first_wblock_id = DRV_HEADER_SIZE / PMEM_WRITE_BLOCK_SIZE;

	// Finish initializing drv_pmem structures (non-zero-value members).
	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		pmem->ns = ns;
		pmem->file_id = i;

		for (uint8_t c = 0; c < N_CURRENT_SWBS; c++) {
			cf_mutex_init(&pmem->current_pwbs[c].lock);
		}

		cf_mutex_init(&pmem->defrag_lock);

		pmem->running = true;

		// Some (non-dynamic) config shortcuts:
		pmem->first_wblock_id = first_wblock_id;

		// Non-fresh devices will initialize this appropriately later.
		pmem->pristine_wblock_id = first_wblock_id;

		wblock_init(pmem);

		// Note: free_wblock_q, defrag_wblock_q created after loading devices.

		if (pmem->shadow_name) {
			pmem->shadow_fd_q = cf_queue_create(sizeof(int), true);
		}

		pmem->pwb_write_q = cf_queue_create(sizeof(void*), true);

		if (pmem->shadow_name) {
			pmem->pwb_shadow_q = cf_queue_create(sizeof(void*), true);
		}

		pmem->pwb_free_q = cf_queue_create(sizeof(void*), true);

		if (pmem->shadow_name) {
			snprintf(histname, sizeof(histname), "{%s}-%s-shadow-write",
					ns->name, pmem->name);
			pmem->hist_shadow_write =
					histogram_create(histname, HIST_MILLISECONDS);
		}

		init_commit(pmem);
	}

	// Will load headers and, if warm restart, resume persisted index.
	init_synchronous(pmems);
}

void
as_storage_load_pmem(as_namespace* ns, cf_queue* complete_q)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	// If devices have data, and it's cold start, scan devices.
	if (! pmems->all_fresh && ns->cold_start) {
		// Fire off threads to scan devices to build index and/or load record
		// data into memory - will signal completion when threads are all done.
		start_loading_records(pmems, complete_q);
		return;
	}
	// else - fresh devices or warm restart, this namespace is ready to roll.

	void* _t = NULL;

	cf_queue_push(complete_q, &_t);
}

void
as_storage_load_ticker_pmem(const as_namespace* ns)
{
	char buf[1024];
	int pos = 0;
	const drv_pmems* pmems = (const drv_pmems*)ns->storage_private;

	for (int i = 0; i < pmems->n_pmems; i++) {
		const drv_pmem* pmem = &pmems->pmems[i];
		uint32_t pct = (uint32_t)((pmem->sweep_wblock_id * 100UL) /
				(pmem->file_size / PMEM_WRITE_BLOCK_SIZE));

		pos += sprintf(buf + pos, "%u,", pct);
	}

	if (pos != 0) {
		buf[pos - 1] = '\0'; // chomp last comma
	}

	if (ns->n_tombstones == 0) {
		cf_info(AS_DRV_PMEM, "{%s} loaded: objects %lu device-pcts (%s)",
				ns->name, ns->n_objects, buf);
	}
	else {
		cf_info(AS_DRV_PMEM, "{%s} loaded: objects %lu tombstones %lu device-pcts (%s)",
				ns->name, ns->n_objects, ns->n_tombstones, buf);
	}
}

void
as_storage_activate_pmem(as_namespace* ns)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	load_wblock_queues(pmems);

	start_maintenance_threads(pmems);
	start_write_threads(pmems);

	if (ns->storage_defrag_startup_minimum != 0) {
		// Allow defrag to go full speed during startup - restore configured
		// setting when startup is done.
		ns->saved_defrag_sleep = ns->storage_defrag_sleep;
		ns->storage_defrag_sleep = 0;
	}

	start_defrag_threads(pmems);
}

bool
as_storage_wait_for_defrag_pmem(as_namespace* ns)
{
	if (ns->storage_defrag_startup_minimum == 0) {
		return false; // nothing to do - don't wait
	}

	int avail_pct;

	as_storage_stats_pmem(ns, &avail_pct, NULL);

	if (avail_pct >= (int)ns->storage_defrag_startup_minimum) {
		// Restore configured defrag throttling values.
		ns->storage_defrag_sleep = ns->saved_defrag_sleep;
		return false; // done - don't wait
	}
	// else - not done - wait.

	cf_info(AS_DRV_PMEM, "{%s} wait-for-defrag: avail-pct %d wait-for %u ...",
			ns->name, avail_pct, ns->storage_defrag_startup_minimum);

	return true;
}

void
as_storage_start_tomb_raider_pmem(as_namespace* ns)
{
	cf_info(AS_DRV_PMEM, "{%s} starting tomb raider thread", ns->name);

	if (ns->storage_serialize_tomb_raider) {
		start_serial_tomb_raider();
		return;
	}

	cf_thread_create_detached(run_tomb_raider, (void*)ns);
}

void
as_storage_shutdown_pmem(struct as_namespace_s* ns)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		for (uint8_t c = 0; c < N_CURRENT_SWBS; c++) {
			current_pwb* cur_pwb = &pmem->current_pwbs[c];

			// Stop the maintenance thread from (also) flushing the pwbs.
			cf_mutex_lock(&cur_pwb->lock);

			pmem_write_block* pwb = cur_pwb->pwb;

			// Flush current pwb by pushing it to write-q.
			if (pwb != NULL) {
				if (! ns->storage_commit_to_device) {
					push_wblock_to_write_q(pmem, pwb);
				}

				cur_pwb->pwb = NULL;
			}
		}

		// Stop the maintenance thread from (also) flushing the defrag pwb.
		cf_mutex_lock(&pmem->defrag_lock);

		// Flush defrag pwb by pushing it to write-q.
		if (pmem->defrag_pwb) {
			push_wblock_to_write_q(pmem, pmem->defrag_pwb);
			pmem->defrag_pwb = NULL;
		}
	}

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		while (cf_queue_sz(pmem->pwb_write_q) != 0) {
			usleep(1000);
		}

		if (pmem->shadow_name) {
			while (cf_queue_sz(pmem->pwb_shadow_q) != 0) {
				usleep(1000);
			}
		}

		pmem->running = false;
	}

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		cf_thread_join(pmem->write_tid);

		if (pmem->shadow_name) {
			cf_thread_join(pmem->shadow_tid);
		}
	}

	set_pristine_offset(pmems);
	set_trusted(pmems);
}

// Note that this is *NOT* the counterpart to as_storage_record_create_pmem()!
// That would be as_storage_record_close_pmem(). This is what gets called when a
// record is destroyed, to dereference storage.
void
as_storage_destroy_record_pmem(as_namespace* ns, as_record* r)
{
	if (STORAGE_RBLOCK_IS_VALID(r->rblock_id) && r->n_rblocks != 0) {
		drv_pmems* pmems = (drv_pmems*)ns->storage_private;
		drv_pmem* pmem = &pmems->pmems[r->file_id];

		block_free(pmem, r->rblock_id, r->n_rblocks, "destroy");

		as_namespace_adjust_set_device_bytes(ns, as_index_get_set_id(r),
				-(int64_t)N_RBLOCKS_TO_SIZE(r->n_rblocks));

		r->rblock_id = 0;
		r->n_rblocks = 0;
	}
}

void
as_storage_record_create_pmem(as_storage_rd* rd)
{
	rd->flat = NULL;
	rd->flat_end = NULL;
	rd->flat_bins = NULL;
	rd->flat_n_bins = 0;
	rd->read_buf = NULL;
	rd->pmem = NULL;

	cf_assert(rd->r->rblock_id == 0, AS_DRV_PMEM, "unexpected - uninitialized rblock-id");
}

void
as_storage_record_open_pmem(as_storage_rd* rd)
{
	drv_pmems* pmems = (drv_pmems*)rd->ns->storage_private;

	rd->flat = NULL;
	rd->flat_end = NULL;
	rd->flat_bins = NULL;
	rd->flat_n_bins = 0;
	rd->read_buf = NULL;
	rd->pmem = &pmems->pmems[rd->r->file_id];
}

void
as_storage_record_close_pmem(as_storage_rd* rd)
{
	if (rd->read_buf) {
		cf_free(rd->read_buf);
		rd->read_buf = NULL;
	}

	rd->flat = NULL;
	rd->flat_end = NULL;
	rd->flat_bins = NULL;
	rd->flat_n_bins = 0;
	rd->pmem = NULL;
}

int
as_storage_record_load_bins_pmem(as_storage_rd* rd)
{
	if (as_record_is_binless(rd->r)) {
		rd->n_bins = 0;
		return 0; // no need to read device
	}

	// If record hasn't been read, read it - sets rd->block_bins and
	// rd->block_n_bins.
	if (! rd->flat && read_record(rd, false) != 0) {
		cf_warning(AS_DRV_PMEM, "load_bins: failed pmem_read_record()");
		return -AS_ERR_UNKNOWN;
	}

	int result = as_flat_unpack_bins(rd->ns, rd->flat_bins, rd->flat_end,
			rd->flat_n_bins, rd->bins);

	if (result == AS_OK) {
		rd->n_bins = rd->flat_n_bins;
	}

	return result;
}

bool
as_storage_record_load_key_pmem(as_storage_rd* rd)
{
	// If record hasn't been read, read it - sets rd->key_size and rd->key.
	if (! rd->flat && read_record(rd, false) != 0) {
		cf_warning(AS_DRV_PMEM, "get_key: failed pmem_read_record()");
		return false;
	}

	return true;
}

bool
as_storage_record_load_pickle_pmem(as_storage_rd* rd)
{
	if (read_record(rd, true) != 0) {
		return false;
	}

	size_t sz = rd->flat_end - (const uint8_t*)rd->flat;

	rd->pickle = cf_malloc(sz);
	rd->pickle_sz = (uint32_t)sz;

	if (rd->flat->magic == AS_FLAT_MAGIC_DIRTY) {
		as_flat_record* flat_in_pickle = (as_flat_record*)rd->pickle;

		flat_in_pickle->magic = AS_FLAT_MAGIC;
		as_flat_copy_wo_magic(flat_in_pickle, rd->flat, sz);
	}
	else {
		memcpy(rd->pickle, rd->flat, sz);
	}

	return true;
}

int
as_storage_record_write_pmem(as_storage_rd* rd)
{
	// No-op for drops, caller will drop record.
	return rd->pickle != NULL || rd->n_bins != 0 || rd->r->tombstone == 1 ?
			write_record(rd) : 0;
}

bool
as_storage_overloaded_pmem(const as_namespace* ns, uint32_t margin,
		const char* tag)
{
	uint32_t limit = ns->storage_max_write_q + margin;

	if (ns->n_wblocks_to_flush > limit) {
		cf_ticker_warning(AS_DRV_PMEM, "{%s} %s fail: queue too deep: exceeds max %u",
				ns->name, tag, limit);
		return true;
	}

	return false;
}

void
as_storage_defrag_sweep_pmem(as_namespace* ns)
{
	cf_info(AS_DRV_PMEM, "{%s} sweeping all devices for wblocks to defrag ...",
			ns->name);

	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	for (int i = 0; i < pmems->n_pmems; i++) {
		cf_atomic32_incr(&pmems->pmems[i].defrag_sweep);
	}
}

void
as_storage_load_regime_pmem(as_namespace* ns)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	ns->eventual_regime = pmems->generic->prefix.eventual_regime;
	ns->rebalance_regime = ns->eventual_regime;
}

void
as_storage_save_regime_pmem(as_namespace* ns)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	cf_mutex_lock(&pmems->flush_lock);

	pmems->generic->prefix.eventual_regime = ns->eventual_regime;

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		write_header(pmem, (uint8_t*)pmems->generic,
				(uint8_t*)&pmems->generic->prefix.eventual_regime,
				sizeof(pmems->generic->prefix.eventual_regime));
	}

	cf_mutex_unlock(&pmems->flush_lock);
}

void
as_storage_load_roster_generation_pmem(as_namespace* ns)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	ns->roster_generation = pmems->generic->prefix.roster_generation;
}

void
as_storage_save_roster_generation_pmem(as_namespace* ns)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	// Normal for this to not change, cleaner to check here versus outside.
	if (ns->roster_generation == pmems->generic->prefix.roster_generation) {
		return;
	}

	cf_mutex_lock(&pmems->flush_lock);

	pmems->generic->prefix.roster_generation = ns->roster_generation;

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		write_header(pmem, (uint8_t*)pmems->generic,
				(uint8_t*)&pmems->generic->prefix.roster_generation,
				sizeof(pmems->generic->prefix.roster_generation));
	}

	cf_mutex_unlock(&pmems->flush_lock);
}

void
as_storage_load_pmeta_pmem(as_namespace* ns, as_partition* p)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;
	drv_pmeta* pmeta = &pmems->generic->pmeta[p->id];

	p->version = pmeta->version;
}

void
as_storage_save_pmeta_pmem(as_namespace* ns, const as_partition* p)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;
	drv_pmeta* pmeta = &pmems->generic->pmeta[p->id];

	cf_mutex_lock(&pmems->flush_lock);

	pmeta->version = p->version;
	pmeta->tree_id = p->tree_id;

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		write_header_atomic(pmem, (uint8_t*)pmems->generic,
				(uint8_t*)pmeta, sizeof(*pmeta));
	}

	cf_mutex_unlock(&pmems->flush_lock);
}

void
as_storage_cache_pmeta_pmem(as_namespace* ns, const as_partition* p)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;
	drv_pmeta* pmeta = &pmems->generic->pmeta[p->id];

	pmeta->version = p->version;
	pmeta->tree_id = p->tree_id;
}

void
as_storage_flush_pmeta_pmem(as_namespace* ns, uint32_t start_pid,
		uint32_t n_partitions)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;
	drv_pmeta* pmeta = &pmems->generic->pmeta[start_pid];

	cf_mutex_lock(&pmems->flush_lock);

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		write_header_atomic(pmem, (uint8_t*)pmems->generic,
				(uint8_t*)pmeta, sizeof(drv_pmeta) * n_partitions);
	}

	cf_mutex_unlock(&pmems->flush_lock);
}

void
as_storage_stats_pmem(as_namespace* ns, int* available_pct,
		uint64_t* used_bytes)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	if (available_pct) {
		*available_pct = 100;

		// Find the device with the lowest available percent.
		for (int i = 0; i < pmems->n_pmems; i++) {
			drv_pmem* pmem = &pmems->pmems[i];
			uint64_t pct = (available_size(pmem) * 100) / pmem->file_size;

			if (pct < (uint64_t)*available_pct) {
				*available_pct = pct;
			}
		}
	}

	if (used_bytes) {
		uint64_t sz = 0;

		for (int i = 0; i < pmems->n_pmems; i++) {
			sz += pmems->pmems[i].inuse_size;
		}

		*used_bytes = sz;
	}
}

void
as_storage_device_stats_pmem(const as_namespace* ns, uint32_t device_ix,
		storage_device_stats* stats)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;
	drv_pmem* pmem = &pmems->pmems[device_ix];

	stats->used_sz = pmem->inuse_size;
	stats->n_free_wblocks = num_free_wblocks(pmem);

	stats->write_q_sz = cf_queue_sz(pmem->pwb_write_q);
	stats->n_writes = 0;

	for (uint8_t c = 0; c < N_CURRENT_SWBS; c++) {
		stats->n_writes += pmem->current_pwbs[c].n_wblocks_written;
	}

	stats->defrag_q_sz = cf_queue_sz(pmem->defrag_wblock_q);
	stats->n_defrag_reads = pmem->n_defrag_wblock_reads;
	stats->n_defrag_writes = pmem->n_defrag_wblock_writes;

	stats->shadow_write_q_sz = pmem->pwb_shadow_q ?
			cf_queue_sz(pmem->pwb_shadow_q) : 0;
}

void
as_storage_ticker_stats_pmem(as_namespace* ns)
{
	histogram_dump(ns->device_read_size_hist);
	histogram_dump(ns->device_write_size_hist);

	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		if (pmem->hist_shadow_write) {
			histogram_dump(pmem->hist_shadow_write);
		}
	}
}

void
as_storage_dump_wb_summary_pmem(const as_namespace* ns)
{
	drv_pmems* pmems = ns->storage_private;
	uint32_t total_num_defraggable = 0;
	uint32_t total_num_above_wm = 0;
	uint64_t defraggable_sz = 0;
	uint64_t non_defraggable_sz = 0;

	// Note: This is a sparse array that could be more efficiently stored.
	// (In addition, ranges of block sizes could be binned together to
	// compress the histogram, rather than using one bin per block size.)
	uint32_t* wb_hist = cf_calloc(1, sizeof(uint32_t) * MAX_WRITE_BLOCK_SIZE);

	for (uint32_t d = 0; d < pmems->n_pmems; d++) {
		drv_pmem* pmem = &pmems->pmems[d];
		uint32_t num_free_blocks = 0;
		uint32_t num_full_pwb = 0;
		uint32_t num_full_blocks = 0;
		uint32_t lwm_size = ns->defrag_lwm_size;
		uint32_t num_defraggable = 0;
		uint32_t num_above_wm = 0;

		for (uint32_t i = 0; i < pmem->n_wblocks; i++) {
			pmem_wblock_state* wblock_state = &pmem->wblock_state[i];
			uint32_t inuse_sz = cf_atomic32_get(wblock_state->inuse_sz);

			if (inuse_sz > PMEM_WRITE_BLOCK_SIZE) {
				cf_warning(AS_DRV_PMEM, "wblock size (%u > %lu) too large ~~ not counting in histogram",
						inuse_sz, PMEM_WRITE_BLOCK_SIZE);
			}
			else {
				wb_hist[inuse_sz]++;
			}

			if (inuse_sz == 0) {
				num_free_blocks++;
			}
			else if (inuse_sz == PMEM_WRITE_BLOCK_SIZE) {
				if (wblock_state->pwb != NULL) {
					num_full_pwb++;
				}
				else {
					num_full_blocks++;
				}
			}
			else if (inuse_sz < lwm_size) {
				defraggable_sz += inuse_sz;
				num_defraggable++;
			}
			else {
				non_defraggable_sz += inuse_sz;
				num_above_wm++;
			}
		}

		total_num_defraggable += num_defraggable;
		total_num_above_wm += num_above_wm;

		cf_info(AS_DRV_PMEM, "device %s free %u full %u fullpwb %u pfull %u defrag %u freeq %u",
				pmem->name, num_free_blocks, num_full_blocks, num_full_pwb,
				num_above_wm, num_defraggable,
				cf_queue_sz(pmem->free_wblock_q));
	}

	cf_info(AS_DRV_PMEM, "WBH: Storage histogram for namespace \"%s\":",
			ns->name);
	cf_info(AS_DRV_PMEM, "WBH: Average wblock size of: defraggable blocks: %lu bytes; nondefraggable blocks: %lu bytes; all blocks: %lu bytes",
			defraggable_sz / MAX(1, total_num_defraggable),
			non_defraggable_sz / MAX(1, total_num_above_wm),
			(defraggable_sz + non_defraggable_sz) /
					MAX(1, (total_num_defraggable + total_num_above_wm)));

	for (uint32_t i = 0; i < MAX_WRITE_BLOCK_SIZE; i++) {
		if (wb_hist[i] > 0) {
			cf_info(AS_DRV_PMEM, "WBH: %u block%s of size %u bytes",
					wb_hist[i], (wb_hist[i] != 1 ? "s" : ""), i);
		}
	}

	cf_free(wb_hist);
}

void
as_storage_histogram_clear_pmem(as_namespace* ns)
{
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		if (pmem->hist_shadow_write) {
			histogram_clear(pmem->hist_shadow_write);
		}
	}
}

uint32_t
as_storage_record_device_size_pmem(const as_record* r)
{
	return N_RBLOCKS_TO_SIZE(r->n_rblocks);
}


//==========================================================
// Local helpers - startup control.
//

static void
init_files(as_namespace* ns, drv_pmems** pmems_p)
{
	size_t pmems_size = sizeof(drv_pmems) +
			(ns->n_storage_files * sizeof(drv_pmem));
	drv_pmems* pmems = cf_malloc(pmems_size);

	memset(pmems, 0, pmems_size);
	pmems->n_pmems = (int)ns->n_storage_files;
	pmems->ns = ns;

	// File-specific initialization of drv_pmem structures.
	for (uint32_t i = 0; i < ns->n_storage_files; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		pmem->name = ns->storage_devices[i];

		// Note - can't configure commit-to-device and disable-odsync.
		uint32_t direct_flags =
				O_DIRECT | (ns->storage_disable_odsync ? 0 : O_DSYNC);

		pmem->open_flag = O_RDWR |
				(ns->storage_commit_to_device || ns->storage_direct_files ?
						direct_flags : 0);

		pmem->file_size = check_file_size(ns->storage_filesize, "file");

		int is_pmem;
		size_t mapped_sz;

		pmem->pmem_base_addr = pmem_map_file(pmem->name, pmem->file_size,
				PMEM_FILE_CREATE, S_IRUSR | S_IWUSR, &mapped_sz, &is_pmem);

		if (pmem->pmem_base_addr == NULL) {
			cf_crash(AS_DRV_PMEM, "unable to map file %s: %d (%s)", pmem->name,
					errno, cf_strerror(errno));
		}

		cf_detail(AS_DRV_PMEM, "pmem - mapped %zu bytes at %p", mapped_sz,
				pmem->pmem_base_addr);

		cf_assert(mapped_sz == pmem->file_size, AS_DRV_PMEM,
				"pmem - mapped size %zu != file size %lu", mapped_sz,
				pmem->file_size);

		// Remap the data area as RO, keeping the header RW.
		pmem_mprotect(pmem->pmem_base_addr + DRV_HEADER_SIZE,
				mapped_sz - DRV_HEADER_SIZE, PROT_READ);

		ns->drive_size += pmem->file_size; // increment total storage size

		cf_info(AS_DRV_PMEM, "opened file %s: usable size %lu", pmem->name,
				pmem->file_size);
	}

	*pmems_p = pmems;
}

static uint64_t
check_file_size(uint64_t file_size, const char* tag)
{
	cf_assert(sizeof(off_t) > 4, AS_DRV_PMEM, "this OS supports only 32-bit (4g) files - compile with 64 bit offsets");

	if (file_size > DRV_HEADER_SIZE) {
		off_t unusable_size =
				(file_size - DRV_HEADER_SIZE) % PMEM_WRITE_BLOCK_SIZE;

		if (unusable_size != 0) {
			cf_info(AS_DRV_PMEM, "%s size must be header size %u + multiple of %lu, rounding down",
					tag, DRV_HEADER_SIZE, PMEM_WRITE_BLOCK_SIZE);
			file_size -= unusable_size;
		}

		if (file_size > AS_STORAGE_MAX_DEVICE_SIZE) {
			cf_warning(AS_DRV_PMEM, "%s size must be <= %ld, trimming original size %ld",
					tag, AS_STORAGE_MAX_DEVICE_SIZE, file_size);
			file_size = AS_STORAGE_MAX_DEVICE_SIZE;
		}
	}

	if (file_size <= DRV_HEADER_SIZE) {
		cf_crash(AS_DRV_PMEM, "%s size %ld must be greater than header size %d",
				tag, file_size, DRV_HEADER_SIZE);
	}

	return file_size;
}

static void
init_shadow_files(as_namespace* ns, drv_pmems* pmems)
{
	if (ns->n_storage_shadows == 0) {
		// No shadows - a normal deployment.
		return;
	}

	// Check shadow files.
	for (uint32_t i = 0; i < ns->n_storage_shadows; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		pmem->shadow_name = ns->storage_shadows[i];

		// Validate that file can be opened, create it if it doesn't exist.
		int fd = open(pmem->shadow_name, pmem->open_flag | O_CREAT,
				cf_os_base_perms());

		if (fd == -1) {
			cf_crash(AS_DRV_PMEM, "unable to open shadow file %s: %s",
					pmem->shadow_name, cf_strerror(errno));
		}

		// Truncate will grow or shrink the file to the correct size.
		if (ftruncate(fd, (off_t)pmem->file_size) != 0) {
			cf_crash(AS_DRV_PMEM, "unable to truncate file: errno %d", errno);
		}

		close(fd);

		cf_info(AS_DRV_PMEM, "shadow file %s is initialized",
				pmem->shadow_name);
	}
}

static void
wblock_init(drv_pmem* pmem)
{
	uint32_t n_wblocks = (uint32_t)(pmem->file_size / PMEM_WRITE_BLOCK_SIZE);

	cf_info(AS_DRV_PMEM, "%s has %u wblocks of size %lu", pmem->name, n_wblocks,
			PMEM_WRITE_BLOCK_SIZE);

	pmem->n_wblocks = n_wblocks;
	pmem->wblock_state = cf_malloc(n_wblocks * sizeof(pmem_wblock_state));

	// Device header wblocks' inuse_sz will (also) be 0 but that doesn't matter.
	for (uint32_t i = 0; i < n_wblocks; i++) {
		pmem_wblock_state* p_wblock_state = &pmem->wblock_state[i];

		cf_atomic32_set(&p_wblock_state->inuse_sz, 0);
		cf_mutex_init(&p_wblock_state->LOCK);
		p_wblock_state->pwb = NULL;
		p_wblock_state->state = WBLOCK_STATE_NONE;
		p_wblock_state->n_vac_dests = 0;
	}
}

static void
init_commit(drv_pmem* pmem)
{
	as_namespace* ns = pmem->ns;

	if (! ns->storage_commit_to_device) {
		return;
	}

	if (pmem->shadow_name) {
		pmem->shadow_commit_fd = shadow_fd_get(pmem);
	}
}

static void
init_synchronous(drv_pmems* pmems)
{
	uint64_t random = 0;

	while (random == 0) {
		random = cf_get_rand64();
	}

	int n_pmems = pmems->n_pmems;
	as_namespace* ns = pmems->ns;

	drv_header* headers[n_pmems];
	int first_used = -1;

	// Check all the headers. Pick one as the representative.
	for (int i = 0; i < n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		headers[i] = read_header(pmem);

		if (! headers[i]) {
			headers[i] = init_header(ns, pmem);
		}
		else if (first_used < 0) {
			first_used = i;
		}
	}

	clear_encryption_keys(ns);

	if (first_used < 0) {
		// Shouldn't find all fresh headers here during warm restart.
		if (! ns->cold_start) {
			// There's no going back to cold start now - do so the harsh way.
			cf_crash(AS_DRV_PMEM, "{%s} found all %d devices fresh during warm restart",
					ns->name, n_pmems);
		}

		cf_info(AS_DRV_PMEM, "{%s} found all %d devices fresh, initializing to random %lu",
				ns->name, n_pmems, random);

		pmems->generic = cf_valloc(ROUND_UP_GENERIC);
		memcpy(pmems->generic, &headers[0]->generic, ROUND_UP_GENERIC);

		pmems->generic->prefix.n_devices = n_pmems;
		pmems->generic->prefix.random = random;

		for (int i = 0; i < n_pmems; i++) {
			headers[i]->unique.device_id = (uint32_t)i;
		}

		adjust_versions(ns, pmems->generic->pmeta);

		flush_header(pmems, headers);

		for (int i = 0; i < n_pmems; i++) {
			cf_free(headers[i]);
		}

		as_truncate_list_cenotaphs(ns); // all will show as cenotaph
		as_truncate_done_startup(ns);

		pmems->all_fresh = true; // won't need to scan devices

		return;
	}

	// At least one device is not fresh. Check that all non-fresh devices match.

	bool fresh_drive = false;
	bool non_commit_drive = false;
	drv_prefix* prefix_first = &headers[first_used]->generic.prefix;

	memset(pmems->device_translation, -1, sizeof(pmems->device_translation));

	for (int i = 0; i < n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];
		drv_prefix* prefix_i = &headers[i]->generic.prefix;
		uint32_t old_device_id = headers[i]->unique.device_id;

		headers[i]->unique.device_id = (uint32_t)i;

		// Skip fresh devices.
		if (prefix_i->random == 0) {
			cf_info(AS_DRV_PMEM, "{%s} device %s is empty", ns->name,
					pmem->name);
			fresh_drive = true;
			continue;
		}

		init_pristine_wblock_id(pmem, headers[i]->unique.pristine_offset);

		pmems->device_translation[old_device_id] = (int8_t)i;

		if (prefix_first->random != prefix_i->random) {
			cf_crash(AS_DRV_PMEM, "{%s} drive set with unmatched headers - devices %s & %s have different signatures",
					ns->name, pmems->pmems[first_used].name, pmem->name);
		}

		if (prefix_first->n_devices != prefix_i->n_devices) {
			cf_crash(AS_DRV_PMEM, "{%s} drive set with unmatched headers - devices %s & %s have different device counts",
					ns->name, pmems->pmems[first_used].name, pmem->name);
		}

		// These should all be 0, unless upgrading from pre-4.5.1.
		if (prefix_first->last_evict_void_time !=
				prefix_i->last_evict_void_time) {
			cf_warning(AS_DRV_PMEM, "{%s} devices have inconsistent evict-void-times - ignoring",
					ns->name);
			prefix_first->last_evict_void_time = 0;
		}

		if ((prefix_i->flags & DRV_HEADER_FLAG_TRUSTED) == 0) {
			cf_info(AS_DRV_PMEM, "{%s} device %s prior shutdown not clean",
					ns->name, pmem->name);
			ns->dirty_restart = true;
		}

		if ((prefix_i->flags & DRV_HEADER_FLAG_COMMIT_TO_DEVICE) == 0) {
			non_commit_drive = true;
		}
	}

	// Handle devices' evict threshold - may be upgrading from pre-4.5.1.
	if (prefix_first->last_evict_void_time != 0) {
		if (ns->smd_evict_void_time == 0) {
			ns->smd_evict_void_time = prefix_first->last_evict_void_time;
			ns->evict_void_time = ns->smd_evict_void_time;
			// Leave header threshold in case we don't commit SMD threshold.
		}
		else {
			// Use SMD threshold, may now erase header threshold.
			prefix_first->last_evict_void_time = 0;
		}
	}

	// Drive set OK - fix up header set.
	pmems->generic = cf_valloc(ROUND_UP_GENERIC);
	memcpy(pmems->generic, &headers[first_used]->generic, ROUND_UP_GENERIC);

	pmems->generic->prefix.n_devices = n_pmems; // may have added fresh drives
	pmems->generic->prefix.random = random;
	pmems->generic->prefix.flags &= ~DRV_HEADER_FLAG_TRUSTED;

	flush_flags(pmems);

	if (fresh_drive || (ns->dirty_restart && non_commit_drive)) {
		adjust_versions(ns, pmems->generic->pmeta);
	}

	flush_header(pmems, headers);
	flush_final_cfg(ns);

	for (int i = 0; i < n_pmems; i++) {
		cf_free(headers[i]);
	}

	uint32_t now = as_record_void_time_get();

	// Sanity check void-times during startup.
	ns->startup_max_void_time = now + MAX_ALLOWED_TTL;

	// Cache booleans indicating whether partitions are owned or not. Also
	// restore tree-ids - note that absent partitions do have tree-ids.
	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		drv_pmeta* pmeta = &pmems->generic->pmeta[pid];

		pmems->get_state_from_storage[pid] =
				as_partition_version_has_data(&pmeta->version);
		ns->partitions[pid].tree_id = pmeta->tree_id;
	}

	// Warm restart.
	if (! ns->cold_start) {
		as_truncate_done_startup(ns); // set truncate last-update-times in sets' vmap
		resume_devices(pmems);

		return; // warm restart is done
	}

	// Cold start - we can now create our partition trees.
	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		if (pmems->get_state_from_storage[pid]) {
			as_partition* p = &ns->partitions[pid];

			p->tree = as_index_tree_create(&ns->tree_shared, p->tree_id,
					as_partition_tree_done, (void*)p);

			as_set_index_create_all(ns, p->tree);
		}
	}

	// Initialize the cold start expiration and eviction machinery.
	cf_mutex_init(&ns->cold_start_evict_lock);
	ns->cold_start_now = now;
}

static drv_header*
read_header(drv_pmem* pmem)
{
	as_namespace* ns = pmem->ns;

	bool use_shadow = ns->cold_start && pmem->shadow_name;

	const char* drv_name;
	size_t read_size = BYTES_UP_TO_IO_MIN(sizeof(drv_header));
	drv_header* header = cf_valloc(read_size);

	if (use_shadow) {
		int fd = shadow_fd_get(pmem);

		drv_name = pmem->shadow_name;

		if (! pread_all(fd, (void*)header, read_size, 0)) {
			cf_crash(AS_DRV_PMEM, "%s: read failed: errno %d (%s)", drv_name,
					errno, cf_strerror(errno));
		}

		shadow_fd_put(pmem, fd);
	}
	else {
		drv_name = pmem->name;

		memcpy(header, pmem->pmem_base_addr, sizeof(drv_header));
	}

	drv_prefix* prefix = &header->generic.prefix;

	// Normal path for a fresh drive.
	if (prefix->magic != DRV_HEADER_MAGIC) {
		if (! cf_memeq(header, 0, read_size)) {
			cf_crash(AS_DRV_PMEM, "%s: not an Aerospike device but not erased - check config or erase device",
					drv_name);
		}

		cf_detail(AS_DRV_PMEM, "%s: zero magic - fresh device", drv_name);
		cf_free(header);
		return NULL;
	}

	if (prefix->version != DRV_VERSION) {
		if (prefix->version == 3) { // pmem never had 2 or 1
			cf_crash(AS_DRV_PMEM, "%s: Aerospike device has old format - must erase device to upgrade",
					drv_name);
		}

		cf_crash(AS_DRV_PMEM, "%s: unknown version %u", drv_name,
				prefix->version);
	}

	if (strcmp(prefix->namespace, ns->name) != 0) {
		cf_crash(AS_DRV_PMEM, "%s: previous namespace %s now %s - check config or erase device",
				drv_name, prefix->namespace, ns->name);
	}

	if (prefix->n_devices > AS_STORAGE_MAX_DEVICES) {
		cf_crash(AS_DRV_PMEM, "%s: bad n-devices %u", drv_name,
				prefix->n_devices);
	}

	if (prefix->random == 0) {
		cf_crash(AS_DRV_PMEM, "%s: random signature is 0", drv_name);
	}

	if (prefix->write_block_size == 0 ||
			PMEM_WRITE_BLOCK_SIZE % prefix->write_block_size != 0) {
		cf_crash(AS_DRV_PMEM, "%s: can't change write-block-size from %u to %lu",
				drv_name, prefix->write_block_size,
				PMEM_WRITE_BLOCK_SIZE);
	}

	if (header->unique.device_id >= AS_STORAGE_MAX_DEVICES) {
		cf_crash(AS_DRV_PMEM, "%s: bad device-id %u", drv_name,
				header->unique.device_id);
	}

	header_validate_cfg(ns, pmem, header);

	if (header->unique.pristine_offset != 0 && // always 0 before 4.6
			(header->unique.pristine_offset < DRV_HEADER_SIZE ||
					header->unique.pristine_offset > pmem->file_size)) {
		cf_crash(AS_DRV_PMEM, "%s: bad pristine offset %lu", drv_name,
				header->unique.pristine_offset);
	}

	prefix->write_block_size = PMEM_WRITE_BLOCK_SIZE;

	drv_atomic* atomic = &header->atomic;

	if (atomic->size != 0) {
		memcpy((uint8_t*)header + atomic->offset, atomic->data, atomic->size);
		atomic->size = 0;
	}

	return header;
}

static void
header_validate_cfg(const as_namespace* ns, drv_pmem* pmem, drv_header* header)
{
	if ((header->generic.prefix.flags & DRV_HEADER_FLAG_SINGLE_BIN) != 0) {
		if (! ns->single_bin) {
			cf_crash(AS_DRV_PMEM, "device has 'single-bin' data but 'single-bin' is not configured");
		}
	}
	else {
		if (ns->single_bin) {
			cf_crash(AS_DRV_PMEM, "device has multi-bin data but 'single-bin' is configured");
		}
	}

	if ((header->generic.prefix.flags & DRV_HEADER_FLAG_ENCRYPTED) != 0) {
		if (ns->storage_encryption_key_file == NULL) {
			cf_crash(AS_DRV_PMEM, "device encrypted but no encryption key file configured");
		}

		if (ns->storage_encryption_old_key_file == NULL) {
			if (! extract_encryption_key(ns, pmem, header,
					ns->storage_encryption_key)) {
				cf_crash(AS_DRV_PMEM, "encryption key or algorithm mismatch");
			}
		}
		else {
			// Rotating keys - try old key.

			if (extract_encryption_key(ns, pmem, header,
					ns->storage_encryption_old_key)) {
				// Old key valid - write back to header using new key.
				cf_info(AS_DRV_PMEM, "%s switching to new encryption key",
						pmem->name);

				// Zero the canary area.
				uint64_t* canary = (uint64_t*)header->unique.canary;

				canary[0] = 0;
				canary[1] = 0;

				write_canary_and_key(ns, pmem, header);
			}
			else {
				// Old key invalid - leftover config? - be nice, try new key.
				cf_warning(AS_DRV_PMEM, "%s ignoring invalid old encryption key",
						pmem->name);

				if (! extract_encryption_key(ns, pmem, header,
						ns->storage_encryption_key)) {
					cf_crash(AS_DRV_PMEM, "encryption key or algorithm mismatch");
				}
			}
		}
	}
	else { // header flag says not encrypted
		if (ns->storage_encryption_key_file != NULL) {
			cf_crash(AS_DRV_PMEM, "device not encrypted but encryption key file %s is configured",
					ns->storage_encryption_key_file);
		}
	}

	if ((header->generic.prefix.flags & DRV_HEADER_FLAG_CP) != 0) {
		if (! ns->cp) {
			cf_crash(AS_DRV_PMEM, "device has CP partition versions but 'strong-consistency' is not configured");
		}
	}
	else { // header flag says not CP
		if (ns->cp) {
			cf_crash(AS_DRV_PMEM, "device has AP partition versions but 'strong-consistency' is configured");
		}
	}

	// Note - nothing to be done for DRV_HEADER_FLAG_COMMIT_TO_DEVICE -
	// changing either way is allowed.
}

static bool
extract_encryption_key(const as_namespace* ns, drv_pmem* pmem,
		const drv_header* header, const uint8_t* key)
{
	drv_xts_decrypt(ns->storage_encryption, key, 0,
			header->unique.encrypted_key, sizeof(header->unique.encrypted_key),
			pmem->encryption_key);

	uint64_t canary_zero[2]; // rely on sizeof(header->unique.canary) = 16

	drv_xts_decrypt(ns->storage_encryption, pmem->encryption_key, 0,
			header->unique.canary, sizeof(header->unique.canary),
			(uint8_t*)canary_zero);

	// If the canary doesn't properly decrypt, try the pre-4.5.0 format, which
	// only supported AES-128 with a 32-byte header->unique.encrypted_key.
	// TODO - get rid of this legacy support on next storage format change.

	if ((canary_zero[0] != 0 || canary_zero[1] != 0) &&
			ns->storage_encryption == AS_ENCRYPTION_AES_128) {
		const uint8_t *canary = header->unique.encrypted_key + 32;

		// Bytes 32 .. 63 of header->unique.encrypted_key were decrypted to
		// garbage in bytes 32 .. 63 of ssd->encryption_key. That's fine,
		// because AES-128 only uses the first 32 bytes.
		drv_xts_decrypt(AS_ENCRYPTION_AES_128, pmem->encryption_key, 0, canary,
				sizeof(header->unique.canary), (uint8_t*)canary_zero);
	}

	return canary_zero[0] == 0 && canary_zero[1] == 0;
}

static void
write_canary_and_key(const as_namespace* ns, drv_pmem* pmem, drv_header* header)
{
	// Write canary - assumes caller has zeroed the canary area.
	drv_xts_encrypt(ns->storage_encryption, pmem->encryption_key, 0,
			header->unique.canary, sizeof(header->unique.canary),
			header->unique.canary);

	// Write encrypted encryption key.
	drv_xts_encrypt(ns->storage_encryption, ns->storage_encryption_key, 0,
			pmem->encryption_key, sizeof(pmem->encryption_key),
			header->unique.encrypted_key);
}

static drv_header*
init_header(as_namespace *ns, drv_pmem *pmem)
{
	drv_header* header = cf_malloc(sizeof(drv_header));

	memset(header, 0, sizeof(drv_header));

	drv_prefix* prefix = &header->generic.prefix;

	// Set non-zero common fields.
	prefix->magic = DRV_HEADER_MAGIC;
	prefix->version = DRV_VERSION;
	strcpy(prefix->namespace, ns->name);
	prefix->write_block_size = PMEM_WRITE_BLOCK_SIZE;

	header_init_cfg(ns, pmem, header);

	return header;
}

static void
header_init_cfg(const as_namespace* ns, drv_pmem* pmem, drv_header* header)
{
	if (ns->single_bin) {
		header->generic.prefix.flags |= DRV_HEADER_FLAG_SINGLE_BIN;
	}

	if (ns->storage_encryption_key_file != NULL) {
		header->generic.prefix.flags |= DRV_HEADER_FLAG_ENCRYPTED;

		if (RAND_bytes(pmem->encryption_key,
				(int)sizeof(pmem->encryption_key)) < 1) {
			cf_crash(AS_DRV_PMEM, "random key generation failed");
		}

		// This canary area has just been zeroed by caller.
		drv_xts_encrypt(ns->storage_encryption, pmem->encryption_key, 0,
				header->unique.canary, sizeof(header->unique.canary),
				header->unique.canary);

		drv_xts_encrypt(ns->storage_encryption, ns->storage_encryption_key, 0,
				pmem->encryption_key, sizeof(pmem->encryption_key),
				header->unique.encrypted_key);
	}

	if (ns->cp) {
		header->generic.prefix.flags |= DRV_HEADER_FLAG_CP;

		if (ns->storage_commit_to_device) {
			header->generic.prefix.flags |= DRV_HEADER_FLAG_COMMIT_TO_DEVICE;
		}
	}
}

static void
clear_encryption_keys(as_namespace* ns)
{
	if (ns->storage_encryption_key_file != NULL) {
		dead_memset(ns->storage_encryption_key, 0,
				sizeof(ns->storage_encryption_key));
		dead_memset(ns->storage_encryption_old_key, 0,
				sizeof(ns->storage_encryption_old_key));
	}
}

static void
adjust_versions(const as_namespace* ns, drv_pmeta* pmeta)
{
	if (! ns->cp) {
		return;
	}

	cf_info(AS_DRV_PMEM, "{%s} setting partition version 'e' flags", ns->name);

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition_version* version = &pmeta[pid].version;

		version->evade = 1;
		version->revived = 0;
	}
}

static void
flush_header(drv_pmems* pmems, drv_header** headers)
{
	uint8_t* buf = cf_valloc(DRV_HEADER_SIZE);

	memset(buf, 0, DRV_HEADER_SIZE);
	memcpy(buf, pmems->generic, sizeof(drv_generic));

	for (int i = 0; i < pmems->n_pmems; i++) {
		memcpy(buf + DRV_OFFSET_UNIQUE, &headers[i]->unique,
				sizeof(drv_unique));

		write_header(&pmems->pmems[i], buf, buf, DRV_HEADER_SIZE);
	}

	cf_free(buf);
}

// Not called for fresh devices, but called in all (warm/cold) starts.
static void
init_pristine_wblock_id(drv_pmem* pmem, uint64_t offset)
{
	if (offset == 0) {
		// Legacy device with data - flag to scan and find id on warm restart.
		pmem->pristine_wblock_id = 0;
		return;
	}

	// Round up, in case write-block-size was increased.
	pmem->pristine_wblock_id =
			(offset + (PMEM_WRITE_BLOCK_SIZE - 1)) / PMEM_WRITE_BLOCK_SIZE;
}

// Called at startup, for items that must be flushed last.
static void
flush_final_cfg(as_namespace* ns)
{
	if (! ns->cp) {
		return;
	}

	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	if (ns->storage_commit_to_device) {
		// Flush last, to be sure 'e' flags have already been committed.
		pmems->generic->prefix.flags |= DRV_HEADER_FLAG_COMMIT_TO_DEVICE;
	}
	else {
		pmems->generic->prefix.flags &= ~DRV_HEADER_FLAG_COMMIT_TO_DEVICE;
	}

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		write_header(pmem, (uint8_t*)pmems->generic,
				(uint8_t*)&pmems->generic->prefix.flags,
				sizeof(pmems->generic->prefix.flags));
	}
}

static void
start_loading_records(drv_pmems* pmems, cf_queue* complete_q)
{
	as_namespace* ns = pmems->ns;

	ns->loading_records = true;

	void* p = cf_rc_alloc(1);

	for (int i = 1; i < pmems->n_pmems; i++) {
		cf_rc_reserve(p);
	}

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];
		pmem_load_records_info* lri = cf_malloc(sizeof(pmem_load_records_info));

		lri->pmems = pmems;
		lri->pmem = pmem;
		lri->complete_q = complete_q;
		lri->complete_rc = p;

		cf_thread_create_transient(run_pmem_cold_start, (void*)lri);
	}
}

static void
load_wblock_queues(drv_pmems* pmems)
{
	cf_info(AS_DRV_PMEM, "{%s} loading free & defrag queues", pmems->ns->name);

	// Split this task across multiple threads.
	cf_tid tids[pmems->n_pmems];

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		tids[i] = cf_thread_create_joinable(run_load_queues, (void*)pmem);
	}

	for (int i = 0; i < pmems->n_pmems; i++) {
		cf_thread_join(tids[i]);
	}
	// Now we're single-threaded again.

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		cf_info(AS_DRV_PMEM, "%s init wblocks: pristine-id %u pristine %u free-q %u, defrag-q %u",
				pmem->name,
				pmem->pristine_wblock_id, num_pristine_wblocks(pmem),
				cf_queue_sz(pmem->free_wblock_q),
				cf_queue_sz(pmem->defrag_wblock_q));
	}
}

// Thread "run" function to create and load a device's (wblock) free & defrag
// queues at startup. Sorts defrag-eligible wblocks so the most depleted ones
// are at the head of the defrag queue.
static void*
run_load_queues(void* pv_data)
{
	drv_pmem* pmem = (drv_pmem*)pv_data;

	pmem->free_wblock_q = cf_queue_create(sizeof(uint32_t), true);
	pmem->defrag_wblock_q = cf_queue_create(sizeof(uint32_t), true);

	as_namespace* ns = pmem->ns;
	uint32_t lwm_pct = ns->storage_defrag_lwm_pct;
	uint32_t lwm_size = ns->defrag_lwm_size;
	defrag_pen pens[lwm_pct];

	for (uint32_t n = 0; n < lwm_pct; n++) {
		defrag_pen_init(&pens[n]);
	}

	uint32_t first_id = pmem->first_wblock_id;
	uint32_t end_id = pmem->pristine_wblock_id;

	// TODO - paranoia - remove eventually.
	cf_assert(end_id >= first_id && end_id <= pmem->n_wblocks, AS_DRV_PMEM,
			"%s bad pristine-wblock-id %u", pmem->name, end_id);

	for (uint32_t wblock_id = first_id; wblock_id < end_id; wblock_id++) {
		uint32_t inuse_sz = pmem->wblock_state[wblock_id].inuse_sz;

		if (inuse_sz == 0) {
			// Faster than using push_wblock_to_free_q() here...
			cf_queue_push(pmem->free_wblock_q, &wblock_id);
		}
		else if (inuse_sz < lwm_size) {
			defrag_pen_add(&pens[(inuse_sz * lwm_pct) / lwm_size], wblock_id);
		}
	}

	defrag_pens_dump(pens, lwm_pct, pmem->name);

	for (uint32_t n = 0; n < lwm_pct; n++) {
		defrag_pen_transfer(&pens[n], pmem);
		defrag_pen_destroy(&pens[n]);
	}

	pmem->n_defrag_wblock_reads = (uint64_t)cf_queue_sz(pmem->defrag_wblock_q);

	return NULL;
}

static void
defrag_pen_init(defrag_pen* pen)
{
	pen->n_ids = 0;
	pen->capacity = DEFRAG_PEN_INIT_CAPACITY;
	pen->ids = pen->stack_ids;
}

static void
defrag_pen_destroy(defrag_pen* pen)
{
	if (pen->ids != pen->stack_ids) {
		cf_free(pen->ids);
	}
}

static void
defrag_pen_add(defrag_pen* pen, uint32_t wblock_id)
{
	if (pen->n_ids == pen->capacity) {
		if (pen->capacity == DEFRAG_PEN_INIT_CAPACITY) {
			pen->capacity <<= 2;
			pen->ids = cf_malloc(pen->capacity * sizeof(uint32_t));
			memcpy(pen->ids, pen->stack_ids, sizeof(pen->stack_ids));
		}
		else {
			pen->capacity <<= 1;
			pen->ids = cf_realloc(pen->ids, pen->capacity * sizeof(uint32_t));
		}
	}

	pen->ids[pen->n_ids++] = wblock_id;
}

static void
defrag_pen_transfer(defrag_pen* pen, drv_pmem* pmem)
{
	// For speed, "customize" instead of using push_wblock_to_defrag_q()...
	for (uint32_t i = 0; i < pen->n_ids; i++) {
		uint32_t wblock_id = pen->ids[i];

		pmem->wblock_state[wblock_id].state = WBLOCK_STATE_DEFRAG;
		cf_queue_push(pmem->defrag_wblock_q, &wblock_id);
	}
}

static void
defrag_pens_dump(defrag_pen pens[], uint32_t n_pens, const char* pmem_name)
{
	char buf[2048];
	uint32_t n = 0;
	int pos = sprintf(buf, "%u", pens[n++].n_ids);

	while (n < n_pens) {
		pos += sprintf(buf + pos, ",%u", pens[n++].n_ids);
	}

	cf_info(AS_DRV_PMEM, "%s init defrag profile: %s", pmem_name, buf);
}

static void
start_maintenance_threads(drv_pmems* pmems)
{
	cf_info(AS_DRV_PMEM, "{%s} starting device maintenance threads",
			pmems->ns->name);

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		cf_thread_create_detached(run_pmem_maintenance, (void*)pmem);
	}
}

static void
start_write_threads(drv_pmems* pmems)
{
	cf_info(AS_DRV_PMEM, "{%s} starting write threads", pmems->ns->name);

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		pmem->write_tid = cf_thread_create_joinable(run_write, (void*)pmem);

		if (pmem->shadow_name) {
			pmem->shadow_tid =
					cf_thread_create_joinable(run_shadow, (void*)pmem);
		}
	}
}

static void
start_defrag_threads(drv_pmems* pmems)
{
	cf_info(AS_DRV_PMEM, "{%s} starting defrag threads", pmems->ns->name);

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		cf_thread_create_detached(run_defrag, (void*)pmem);
	}
}


//==========================================================
// Local helpers - cold start.
//

static void*
run_pmem_cold_start(void* udata)
{
	pmem_load_records_info* lri = (pmem_load_records_info*)udata;
	drv_pmem* pmem = lri->pmem;
	drv_pmems* pmems = lri->pmems;
	cf_queue* complete_q = lri->complete_q;
	void* complete_rc = lri->complete_rc;

	cf_free(lri);

	as_namespace* ns = pmems->ns;

	cf_info(AS_DRV_PMEM, "device %s: reading device to load index", pmem->name);

	cold_start_sweep(pmems, pmem);

	cf_info(AS_DRV_PMEM, "device %s: read complete: UNIQUE %lu (REPLACED %lu) (OLDER %lu) (EXPIRED %lu) (EVICTED %lu) records",
			pmem->name, pmem->record_add_unique_counter,
			pmem->record_add_replace_counter, pmem->record_add_older_counter,
			pmem->record_add_expired_counter, pmem->record_add_evicted_counter);

	if (cf_rc_release(complete_rc) == 0) {
		// All drives are done reading.

		ns->loading_records = false;
		cold_start_drop_cenotaphs(ns);

		cf_mutex_destroy(&ns->cold_start_evict_lock);

		as_truncate_list_cenotaphs(ns);
		as_truncate_done_startup(ns); // set truncate last-update-times in sets' vmap

		cold_start_set_unrepl_stat(ns);

		void* _t = NULL;

		cf_queue_push(complete_q, &_t);
		cf_rc_free(complete_rc);
	}

	return NULL;
}

static void
cold_start_sweep(drv_pmems* pmems, drv_pmem* pmem)
{
	bool read_shadow = pmem->shadow_name;
	const char* read_pmem_name = read_shadow ? pmem->shadow_name : pmem->name;
	int fd = read_shadow ? shadow_fd_get(pmem) : -1;
	uint8_t* read_buf = read_shadow ? cf_valloc(PMEM_WRITE_BLOCK_SIZE) : NULL;

	// Loop over all wblocks, unless we encounter 10 contiguous unused wblocks.

	pmem->sweep_wblock_id = pmem->first_wblock_id;

	uint64_t file_offset = DRV_HEADER_SIZE;
	uint32_t n_unused_wblocks = 0;

	while (file_offset < pmem->file_size && n_unused_wblocks < 10) {
		if (read_shadow) {
			if (! pread_all(fd, read_buf, PMEM_WRITE_BLOCK_SIZE,
					(off_t)file_offset)) {
				cf_crash(AS_DRV_PMEM, "%s: read failed: errno %d (%s)",
						 read_pmem_name, errno, cf_strerror(errno));
			}

			pmem_mprotect(pmem->pmem_base_addr + file_offset,
					PMEM_WRITE_BLOCK_SIZE, PROT_READ | PROT_WRITE);
			pmem_memcpy(pmem->pmem_base_addr + file_offset, read_buf,
					PMEM_WRITE_BLOCK_SIZE, 0);
			pmem_mprotect(pmem->pmem_base_addr + file_offset,
					PMEM_WRITE_BLOCK_SIZE, PROT_READ);
		}

		const uint8_t* buf = pmem->pmem_base_addr + file_offset;
		size_t indent = 0; // current offset within wblock, in bytes

		while (indent < PMEM_WRITE_BLOCK_SIZE) {
			const as_flat_record* flat = decrypt_flat(pmem,
					file_offset + indent, &buf[indent]);

			// Look for record magic.
			if (flat->magic != AS_FLAT_MAGIC) {
				// Should always find a record at beginning of used wblock. if
				// not, we've likely encountered the unused part of the device.
				if (flat->magic != AS_FLAT_MAGIC_DIRTY && indent == 0) {
					n_unused_wblocks++;
					break; // try next wblock
				}
				// else - nothing more in this wblock, but keep looking for
				// magic - necessary if we want to be able to increase
				// write-block-size across restarts.
				if (! pmem->ns->storage_commit_to_device) {
					break;
				}

				indent += RBLOCK_SIZE;
				continue; // try next rblock
			}

			if (n_unused_wblocks != 0) {
				cf_warning(AS_DRV_PMEM, "%s: found used wblock after skipping %u unused",
						pmem->name, n_unused_wblocks);

				n_unused_wblocks = 0; // restart contiguous count
			}

			uint32_t record_size = N_RBLOCKS_TO_SIZE(flat->n_rblocks);

			if (record_size < DRV_RECORD_MIN_SIZE) {
				cf_warning(AS_DRV_PMEM, "%s: record too small: size %u",
						pmem->name, record_size);
				indent += RBLOCK_SIZE;
				continue; // try next rblock
			}

			size_t next_indent = indent + record_size;

			// Sanity-check for wblock overruns.
			if (next_indent > PMEM_WRITE_BLOCK_SIZE) {
				cf_warning(AS_DRV_PMEM, "%s: record crosses wblock boundary: size %u",
						pmem->name, record_size);
				break; // skip this record, try next wblock
			}

			// Found a record - try to add it to the index.
			cold_start_add_record(pmems, pmem, flat,
					OFFSET_TO_RBLOCK_ID(file_offset + indent), record_size);

			indent = next_indent;
		}

		file_offset += PMEM_WRITE_BLOCK_SIZE;
		pmem->sweep_wblock_id++;
	}

	pmem->pristine_wblock_id = pmem->sweep_wblock_id - n_unused_wblocks;

	pmem->sweep_wblock_id = (uint32_t)(pmem->file_size / PMEM_WRITE_BLOCK_SIZE);

	if (read_shadow) {
		shadow_fd_put(pmem, fd);
		cf_free(read_buf);
	}
}

static void
cold_start_add_record(drv_pmems* pmems, drv_pmem* pmem,
		const as_flat_record* flat, uint64_t rblock_id, uint32_t record_size)
{
	uint32_t pid = as_partition_getid(&flat->keyd);

	// If this isn't a partition we're interested in, skip this record.
	if (! pmems->get_state_from_storage[pid]) {
		return;
	}

	as_namespace* ns = pmems->ns;
	as_partition* p_partition = &ns->partitions[pid];

	const uint8_t* end = (const uint8_t*)flat + record_size;
	as_flat_opt_meta opt_meta = { { 0 } };

	const uint8_t* p_read = as_flat_unpack_record_meta(flat, end, &opt_meta,
			ns->single_bin);

	if (! p_read) {
		cf_warning(AS_DRV_PMEM, "bad metadata for %pD", &flat->keyd);
		return;
	}

	if (opt_meta.void_time > ns->startup_max_void_time) {
		cf_warning(AS_DRV_PMEM, "bad void-time for %pD", &flat->keyd);
		return;
	}

	if (! as_flat_decompress_buffer(&opt_meta.cm, PMEM_WRITE_BLOCK_SIZE,
			&p_read, &end, NULL)) {
		cf_warning(AS_DRV_PMEM, "bad compressed data for %pD", &flat->keyd);
		return;
	}

	if (as_flat_check_packed_bins(p_read, end, opt_meta.n_bins,
			ns->single_bin) == NULL) {
		cf_warning(AS_DRV_PMEM, "bad flat record %pD", &flat->keyd);
		return;
	}

	// Ignore record if it was in a dropped tree.
	if (flat->tree_id != p_partition->tree_id) {
		return;
	}

	// Ignore records that were truncated.
	if (as_truncate_lut_is_truncated(flat->last_update_time, ns,
			opt_meta.set_name, opt_meta.set_name_len)) {
		return;
	}

	// If eviction is necessary, evict previously added records closest to
	// expiration. (If evicting, this call will block for a long time.) This
	// call may also update the cold start threshold void-time.
	if (! as_cold_start_evict_if_needed(ns)) {
		cf_crash(AS_DRV_PMEM, "hit stop-writes limit before drive scan completed");
	}

	// Get/create the record from/in the appropriate index tree.
	as_index_ref r_ref;
	int rv = as_record_get_create(p_partition->tree, &flat->keyd, &r_ref, ns);

	if (rv < 0) {
		cf_crash(AS_DRV_PMEM, "{%s} can't add record to index", ns->name);
	}

	bool is_create = rv == 1;

	as_index* r = r_ref.r;

	if (! is_create) {
		// Record already existed. Ignore this one if existing record is newer.
		if (prefer_existing_record(ns, flat, opt_meta.void_time, r)) {
			cold_start_adjust_cenotaph(ns, flat, opt_meta.void_time, r);
			as_record_done(&r_ref, ns);
			pmem->record_add_older_counter++;
			return;
		}
	}
	// The record we're now reading is the latest version (so far) ...

	// Skip records that have expired.
	if (opt_meta.void_time != 0 && ns->cold_start_now > opt_meta.void_time) {
		if (! is_create) {
			as_set_index_delete_live(ns, p_partition->tree, r, r_ref.r_h);
		}

		as_index_delete(p_partition->tree, &flat->keyd);
		as_record_done(&r_ref, ns);
		pmem->record_add_expired_counter++;
		return;
	}

	// Skip records that were evicted.
	if (opt_meta.void_time != 0 && ns->evict_void_time > opt_meta.void_time &&
			drv_is_set_evictable(ns, &opt_meta)) {
		if (! is_create) {
			as_set_index_delete_live(ns, p_partition->tree, r, r_ref.r_h);
		}

		as_index_delete(p_partition->tree, &flat->keyd);
		as_record_done(&r_ref, ns);
		pmem->record_add_evicted_counter++;
		return;
	}

	// We'll keep the record we're now reading ...

	cold_start_init_repl_state(ns, r);

	// Set/reset the record's last-update-time generation, and void-time.
	r->last_update_time = flat->last_update_time;
	r->generation = flat->generation;
	r->void_time = opt_meta.void_time;

	// Set/reset the records's XDR-write status.
	cold_start_init_xdr_state(flat, r);

	// Update maximum void-time.
	cf_atomic32_setmax(&p_partition->max_void_time, (int32_t)r->void_time);

	drv_apply_opt_meta(r, ns, &opt_meta);

	if (is_create) {
		pmem->record_add_unique_counter++;
	}
	else if (STORAGE_RBLOCK_IS_VALID(r->rblock_id)) {
		// Replacing an existing record, undo its previous storage accounting.
		block_free(&pmems->pmems[r->file_id], r->rblock_id, r->n_rblocks,
				"record-add");
		pmem->record_add_replace_counter++;
	}
	else {
		cf_warning(AS_DRV_PMEM, "replacing record with invalid rblock-id");
	}

	cold_start_transition_record(ns, flat, &opt_meta, p_partition->tree, &r_ref,
			is_create);

	uint32_t wblock_id = RBLOCK_ID_TO_WBLOCK_ID(rblock_id);

	pmem->inuse_size += record_size;
	pmem->wblock_state[wblock_id].inuse_sz += record_size;

	// Set/reset the record's storage information.
	r->file_id = pmem->file_id;
	r->rblock_id = rblock_id;

	as_namespace_adjust_set_device_bytes(ns, as_index_get_set_id(r),
			DELTA_N_RBLOCKS_TO_SIZE(flat->n_rblocks, r->n_rblocks));

	r->n_rblocks = flat->n_rblocks;

	as_record_done(&r_ref, ns);
}

static bool
prefer_existing_record(const as_namespace* ns, const as_flat_record* flat,
		uint32_t block_void_time, const as_index* r)
{
	int result = as_record_resolve_conflict(cold_start_policy(ns),
			r->generation, r->last_update_time,
			flat->generation, flat->last_update_time);

	if (result != 0) {
		return result == -1; // -1 means block record < existing record
	}

	// Finally, compare void-times. Note that defragged records will generate
	// identical copies on drive, so they'll get here and return true.
	return r->void_time == 0 ||
			(block_void_time != 0 && block_void_time <= r->void_time);
}

static conflict_resolution_pol
cold_start_policy(const as_namespace* ns)
{
	return ns->cp ?
			AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_CP :
			AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_LAST_UPDATE_TIME;
}

static void
cold_start_adjust_cenotaph(const as_namespace* ns, const as_flat_record* flat,
		uint32_t block_void_time, as_record* r)
{
	if (r->cenotaph == 1 && as_flat_record_is_live(flat) &&
			! as_flat_record_expired_or_evicted(ns, block_void_time,
					as_index_get_set_id(r))) {
		r->cenotaph = 0;
	}
}

static void
cold_start_init_repl_state(const as_namespace* ns, as_record* r)
{
	if (ns->cp) {
		r->repl_state = AS_REPL_STATE_UNREPLICATED;
		// Stat will be set after cold start.
	}
}

static void
cold_start_set_unrepl_stat(as_namespace* ns)
{
	if (ns->cp) {
		// Everything starts as unreplicated on cold start.
		ns->n_unreplicated_records = ns->n_objects + ns->n_tombstones;
	}
}

static void
cold_start_init_xdr_state(const as_flat_record* flat, as_record* r)
{
	r->xdr_write = flat->xdr_write;
}

static void
cold_start_transition_record(as_namespace* ns, const as_flat_record* flat,
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

static void
cold_start_drop_cenotaphs(as_namespace* ns)
{
	if (ns->n_durable_tombstones == 0) {
		return;
	}

	cf_info(AS_DRV_PMEM, "{%s} cold start removing cenotaphs ...", ns->name);

	uint32_t n_dropped = drop_cenotaphs(ns, NUM_COLD_START_DROP_THREADS, false);

	cf_info(AS_DRV_PMEM, "{%s} ... cold start removed %u cenotaphs", ns->name,
			n_dropped);
}


//==========================================================
// Local helpers - warm restart.
//

static void
resume_devices(drv_pmems* pmems)
{
	as_namespace* ns = pmems->ns;

	// Sanity check that treex agrees with stored partition versions. Also set
	// restored tree-ids on the tree structs.
	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition* p = &ns->partitions[pid];

		bool owned = pmems->get_state_from_storage[pid];
		bool has_tree = p->tree != NULL;

		cf_assert(owned == has_tree, AS_DRV_PMEM, "{%s} pid %u %s but %s",
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
	cf_info(AS_DRV_PMEM, "{%s} scanning arena stages for %lu index elements ...",
			ns->name, total_n_elements);

	// Split this task across multiple threads.
	overall_info overall = {
			.n_threads_done = 0,
			.i_cpu = -1,
			.stage_id = -1,
			.now = as_record_void_time_get(),
			.pmems = pmems,
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

			cf_info(AS_DRV_PMEM, "{%s} ... scanned %lu index elements [%.1f%%]",
					ns->name, n_elements, pct);
		}
	}

	// Now we're single-threaded again.
	cf_info(AS_DRV_PMEM, "{%s} ... scanned %lu index elements [100.0%%]",
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
		cf_info(AS_DRV_PMEM, "{%s} freed %lu elements in dropped trees",
				ns->name, overall.n_dropped);
	}

	if (overall.n_erased != 0) {
		cf_warning(AS_DRV_PMEM, "{%s} deleted %lu records on wiped and/or missing devices",
				ns->name, overall.n_erased);
	}

	if (overall.n_expired != 0) {
		cf_info(AS_DRV_PMEM, "{%s} deleted %lu expired records", ns->name,
				overall.n_expired);
	}

	if (overall.n_evicted != 0) {
		cf_info(AS_DRV_PMEM, "{%s} deleted %lu evicted records", ns->name,
				overall.n_evicted);
	}

	if (overall.n_truncated != 0) {
		cf_info(AS_DRV_PMEM, "{%s} deleted %lu truncated records", ns->name,
				overall.n_truncated);
	}

	// Finished rebuilding stats and storage state. The wblock free and defrag
	// queues will be created and loaded later.
	cf_info(AS_DRV_PMEM, "{%s} scanned: objects %lu tombstones %lu free %lu",
			ns->name, ns->n_objects, ns->n_tombstones,
			total_n_elements - (ns->n_objects + ns->n_tombstones));

	// If upgrading from < 4.6, device headers won't contain pristine-wblock-id.
	// Must scan devices to discover these ids. (Done after rebuilding wblock
	// used-size stats so scan starting points are optimized.)
	discover_pristine_wblock_ids(pmems);
}

static void*
run_scan_stages(void* pv_data)
{
	overall_info* overall = (overall_info*)pv_data;
	as_namespace* ns = overall->pmems->ns;

	cf_topo_pin_to_cpu(
			(cf_topo_cpu_index)cf_atomic32_incr(&overall->i_cpu));

	per_cpu_info per_cpu = {
			.stage_id = 0, // reset for every stage
			.now = overall->now,
			.pmems = overall->pmems,
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
			.used_size_per_pmem = { 0 }
	};

	while (true) {
		uint32_t stage_id = (uint32_t)cf_atomic32_incr(&overall->stage_id);

		per_cpu.stage_id = stage_id;

		if (! cf_arenax_resume_stage(ns->arena, stage_id, resume_element_cb,
				&per_cpu)) {
			break;
		}

		cf_debug(AS_DRV_PMEM, "... scanned arena stage %u", stage_id);
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
			cf_crash(AS_DRV_PMEM, "can't get set index %u from vmap", set_ix);
		}

		cf_atomic64_add(&p_set->n_objects,
				(int64_t)per_cpu.n_objects_per_set[set_ix]);
		cf_atomic64_add(&p_set->n_tombstones,
				(int64_t)per_cpu.n_tombstones_per_set[set_ix]);
		cf_atomic64_add(&p_set->n_bytes_device,
				(int64_t)per_cpu.used_size_per_set[set_ix]);
	}

	for (int pmem_ix = 0; pmem_ix < overall->pmems->n_pmems; pmem_ix++) {
		drv_pmem* pmem = &overall->pmems->pmems[pmem_ix];

		cf_atomic64_add(&pmem->inuse_size,
				(int64_t)per_cpu.used_size_per_pmem[pmem_ix]);
	}

	cf_atomic32_incr(&overall->n_threads_done);

	return NULL;
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
	drv_pmems* pmems = per_cpu->pmems;

	as_namespace* ns = pmems->ns;
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
			cf_crash(AS_DRV_PMEM, "generation 0");
		}

		// Record was deleted and removed from tree while ref-counted.
		result.free_it = true; // causes element to be freed
		return result;
	}

	// Sanity-check storage info.
	uint16_t file_id = r->file_id;
	uint64_t rblock_id = r->rblock_id;
	uint32_t n_rblocks = r->n_rblocks;

	// Happens when drives are removed, or a subset of drives was dd'd.
	if (pmems->device_translation[file_id] < 0) {
		per_cpu->n_erased++;
		drv_delete_element(tree, r);
		result.free_it = true; // causes element to be freed
		return result;
	}

	set_if_needed(r->file_id, pmems->device_translation[file_id]);

	drv_pmem* pmem = &pmems->pmems[r->file_id];

	uint32_t wblock_id = RBLOCK_ID_TO_WBLOCK_ID(rblock_id);
	uint32_t record_size = N_RBLOCKS_TO_SIZE(n_rblocks);

	if (wblock_id >= pmem->n_wblocks || wblock_id < pmem->first_wblock_id) {
		cf_crash(AS_DRV_PMEM, "bad wblock-id %u", wblock_id);
	}

	if (record_size > PMEM_WRITE_BLOCK_SIZE ||
			record_size < DRV_RECORD_MIN_SIZE) {
		cf_crash(AS_DRV_PMEM, "bad size %u", record_size);
	}

	if (r->void_time > ns->startup_max_void_time) {
		cf_crash(AS_DRV_PMEM, "bad void-time %u", r->void_time);
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
		cf_crash(AS_DRV_PMEM, "bad set-id %u", set_id);
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

	// Increment the record's set's element counters if relevant.
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
	per_cpu->used_size_per_pmem[r->file_id] += record_size;
	cf_atomic32_add(&pmem->wblock_state[wblock_id].inuse_sz,
			(int32_t)record_size);

	as_index_locked_puddle locked_puddle =
			as_index_puddle_for_element(tree, &r->keyd);

	result.puddle = locked_puddle.puddle;
	result.lock = locked_puddle.lock;

	return result;
}

static void
discover_pristine_wblock_ids(drv_pmems* pmems)
{
	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		if (pmem->pristine_wblock_id != 0) {
			continue; // normal - already set from device header
		}
		// else - legacy device with data - scan to find pristine-wblock-id.

		uint32_t last_id = pmem->n_wblocks - 1;
		uint32_t first_id = pmem->first_wblock_id;
		uint32_t last_used_id;

		for (last_used_id = last_id; last_used_id >= first_id; last_used_id--) {
			if (pmem->wblock_state[last_used_id].inuse_sz != 0) {
				break;
			}
		}

		uint32_t id;

		for (id = last_used_id + 1; id < pmem->n_wblocks; id++) {
			uint64_t offset = (uint64_t)id * PMEM_WRITE_BLOCK_SIZE;
			const uint32_t* magic = (uint32_t*)&pmem->pmem_base_addr[offset];

			if (*magic != AS_FLAT_MAGIC) {
				break; // unused wblock is pristine
			}
		}

		pmem->pristine_wblock_id = id;

		cf_info(AS_DRV_PMEM, "%s: legacy device - found pristine-wblock-id %u",
				pmem->name, id);
	}
}


//==========================================================
// Local helpers - shutdown.
//

static void
set_pristine_offset(drv_pmems* pmems)
{
	cf_mutex_lock(&pmems->flush_lock);

	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];
		drv_header* header = (drv_header*)&pmem->pmem_base_addr[0];

		header->unique.pristine_offset =
				(uint64_t)pmem->pristine_wblock_id * PMEM_WRITE_BLOCK_SIZE;

		pmem_persist(&header->unique.pristine_offset,
				sizeof(header->unique.pristine_offset));

		// Skip shadow - persisted offset never used at cold start.
	}

	cf_mutex_unlock(&pmems->flush_lock);
}

static void
set_trusted(drv_pmems* pmems)
{
	cf_mutex_lock(&pmems->flush_lock);

	pmems->generic->prefix.flags |= DRV_HEADER_FLAG_TRUSTED;
	flush_flags(pmems);

	cf_mutex_unlock(&pmems->flush_lock);
}


//==========================================================
// Local helpers - read record.
//

static int
read_record(as_storage_rd* rd, bool pickle_only)
{
	as_namespace* ns = rd->ns;
	as_record* r = rd->r;
	drv_pmem* pmem = rd->pmem;

	if (STORAGE_RBLOCK_IS_INVALID(r->rblock_id)) {
		cf_warning(AS_DRV_PMEM, "{%s} read_pmem: invalid rblock_id digest %pD",
				ns->name, &r->keyd);
		return -1;
	}

	uint64_t record_offset = RBLOCK_ID_TO_OFFSET(r->rblock_id);
	uint32_t record_size = N_RBLOCKS_TO_SIZE(r->n_rblocks);
	uint64_t record_end_offset = record_offset + record_size;

	uint32_t wblock_id = OFFSET_TO_WBLOCK_ID(record_offset);

	if (wblock_id >= pmem->n_wblocks) {
		cf_warning(AS_DRV_PMEM, "{%s} read_pmem: bad offset %lu digest %pD",
				ns->name, record_offset, &r->keyd);
		return -1;
	}

	if (record_size < DRV_RECORD_MIN_SIZE) {
		cf_warning(AS_DRV_PMEM, "{%s} read_pmem: bad record size %u digest %pD",
				ns->name, record_size, &r->keyd);
		return -1;
	}

	if (record_end_offset > WBLOCK_ID_TO_OFFSET(wblock_id + 1)) {
		cf_warning(AS_DRV_PMEM, "{%s} read_pmem: record size %u crosses wblock boundary digest %pD",
				ns->name, record_size, &r->keyd);
		return -1;
	}

	const as_flat_record* flat = decrypt_sized_flat(pmem, record_offset,
			record_size, pmem->pmem_base_addr + record_offset);

	rd->flat = flat;

	cf_atomic32_incr(&ns->n_reads_from_device);

	if (flat->magic != AS_FLAT_MAGIC && flat->magic != AS_FLAT_MAGIC_DIRTY) {
		cf_warning(AS_DRV_PMEM, "read: bad block magic offset %lu",
				record_offset);
		return -1;
	}

	if (flat->n_rblocks != r->n_rblocks) {
		cf_warning(AS_DRV_PMEM, "read: bad n-rblocks %u %u", flat->n_rblocks,
				r->n_rblocks);
		return -1;
	}

	if (cf_digest_compare(&flat->keyd, &r->keyd) != 0) {
		cf_warning(AS_DRV_PMEM, "read: read wrong key: expecting %lx got %lx",
				*(uint64_t*)&r->keyd, *(uint64_t*)&flat->keyd);
		return -1;
	}

	as_flat_opt_meta opt_meta = { { 0 } };

	rd->flat_end = (const uint8_t*)flat + record_size;
	rd->flat_bins = as_flat_unpack_record_meta(flat, rd->flat_end, &opt_meta,
			ns->single_bin);

	if (! rd->flat_bins) {
		cf_warning(AS_DRV_PMEM, "read: bad record metadata");
		return -1;
	}

	// After unpacking meta so there's a bit of sanity checking.
	if (pickle_only) {
		return 0;
	}

	if (! as_flat_decompress_bins(&opt_meta.cm, rd)) {
		cf_warning(AS_DRV_PMEM, "{%s} read: bad compressed data (%s:%lu) digest %pD",
				ns->name, pmem->name, record_offset, &r->keyd);
		return -1;
	}

	if (opt_meta.key) {
		rd->key_size = opt_meta.key_size;
		rd->key = opt_meta.key;
	}
	// else - if updating record without key, leave rd (msg) key to be stored.

	rd->flat_n_bins = (uint16_t)opt_meta.n_bins;

	return 0;
}


//==========================================================
// Local helpers - write record.
//

static int
write_record(as_storage_rd* rd)
{
	as_record* r = rd->r;

	drv_pmem* old_pmem = NULL;
	uint64_t old_rblock_id = 0;
	uint32_t old_n_rblocks = 0;

	if (STORAGE_RBLOCK_IS_VALID(r->rblock_id)) {
		// Replacing an old record.
		old_pmem = rd->pmem;
		old_rblock_id = r->rblock_id;
		old_n_rblocks = r->n_rblocks;
	}

	drv_pmems* pmems = (drv_pmems*)rd->ns->storage_private;

	// Figure out which device to write to. When replacing an old record, it's
	// possible this is different from the old device (e.g. if we've added a
	// fresh device), so derive it from the digest each time.
	rd->pmem = &pmems->pmems[pmem_get_file_id(pmems, &r->keyd)];

	cf_assert(rd->pmem, AS_DRV_PMEM, "{%s} null pmem", rd->ns->name);

	int rv = write_bins(rd);

	if (rv == 0 && old_pmem) {
		block_free(old_pmem, old_rblock_id, old_n_rblocks, "pmem-write");
	}

	return rv;
}

static int
write_bins(as_storage_rd* rd)
{
	return rd->ns->storage_commit_to_device ?
			commit_bins(rd) : buffer_bins(rd);
}

static int
buffer_bins(as_storage_rd* rd)
{
	as_namespace* ns = rd->ns;
	as_record* r = rd->r;
	drv_pmem* pmem = rd->pmem;

	uint32_t flat_sz;
	uint32_t limit_sz;

	if (rd->pickle == NULL) {
		flat_sz = as_flat_record_size(rd);
		limit_sz = ns->max_record_size == 0 ?
				PMEM_WRITE_BLOCK_SIZE : ns->max_record_size;
	}
	else {
		flat_sz = rd->orig_pickle_sz;
		limit_sz = PMEM_WRITE_BLOCK_SIZE;
	}

	if (flat_sz > limit_sz) {
		cf_detail(AS_DRV_PMEM, "{%s} write: size %u - rejecting %pD", ns->name,
				flat_sz, &r->keyd);
		return -AS_ERR_RECORD_TOO_BIG;
	}

	as_flat_record* flat;

	if (rd->pickle == NULL) {
		flat = as_flat_compress_bins_and_pack_record(rd, PMEM_WRITE_BLOCK_SIZE,
				false, false, &flat_sz);
	}
	else {
		flat = (as_flat_record*)rd->pickle;
		flat_sz = rd->pickle_sz;

		// Tree IDs are node-local - can't use those sent from other nodes.
		flat->tree_id = r->tree_id;
	}

	// Note - this is the only place where rounding size (up to a  multiple of
	// RBLOCK_SIZE) is really necessary.
	uint32_t write_sz = SIZE_UP_TO_RBLOCK_SIZE(flat_sz);

	// Reserve the portion of the current pwb where this record will be written.

	current_pwb* cur_pwb = &pmem->current_pwbs[rd->which_current_swb];
	bool encrypt = ns->storage_encryption_key_file != NULL;

	cf_mutex_lock(&cur_pwb->lock);

	pmem_write_block* pwb = cur_pwb->pwb;

	if (! pwb) {
		pwb = pwb_get(pmem, false);
		cur_pwb->pwb = pwb;

		if (! pwb) {
			cf_ticker_warning(AS_DRV_PMEM, "{%s} out of space", ns->name);
			cf_mutex_unlock(&cur_pwb->lock);
			return -AS_ERR_OUT_OF_SPACE;
		}

		prepare_for_first_write(pwb, encrypt);
	}

	// Check if there's enough space in current buffer - if not, enqueue it to
	// be flushed to device, and grab a new buffer.
	if (write_sz > PMEM_WRITE_BLOCK_SIZE - pwb->pos) {
		// Enqueue the buffer, to be flushed to device.
		push_wblock_to_write_q(pmem, pwb);
		cur_pwb->n_wblocks_written++;

		// Get the new buffer.
		pwb = pwb_get(pmem, false);
		cur_pwb->pwb = pwb;

		if (! pwb) {
			cf_ticker_warning(AS_DRV_PMEM, "{%s} out of space", ns->name);
			cf_mutex_unlock(&cur_pwb->lock);
			return -AS_ERR_OUT_OF_SPACE;
		}

		prepare_for_first_write(pwb, encrypt);
	}

	// There's enough space - save the position where this record will be
	// written, and advance pwb->pos for the next writer.

	uint32_t n_rblocks = ROUNDED_SIZE_TO_N_RBLOCKS(write_sz);
	uint32_t pwb_pos = pwb->pos;
	bool keep_dirty = ! pwb->dirty;

	pwb->pos += write_sz;

	cf_atomic32_incr(&pwb->n_writers);
	pwb->dirty = true;

	cf_mutex_unlock(&cur_pwb->lock);
	// May now write this record concurrently with others in this pwb.

	// Flatten data into the block.

	uint8_t* flat_buf_pmem = &pwb->base_addr[pwb_pos];
	as_flat_record* plaintext_flat = encrypt ?
			get_scratch_thread_buffer(write_sz) :
			(as_flat_record*)flat_buf_pmem;

	if (flat == NULL) {
		as_flat_pack_record(rd, n_rblocks, keep_dirty, plaintext_flat);
	}
	else if (keep_dirty) {
		plaintext_flat->magic = AS_FLAT_MAGIC_DIRTY;
		as_flat_copy_wo_magic(plaintext_flat, flat, flat_sz);
	}
	else {
		copy_flat(plaintext_flat, flat, flat_sz, encrypt);
	}

	// Make a pickle if needed.
	if (rd->keep_pickle) {
		rd->pickle_sz = flat_sz;
		rd->pickle = cf_malloc(flat_sz);

		as_flat_record* flat_in_pickle = (as_flat_record*)rd->pickle;

		if (keep_dirty) {
			flat_in_pickle->magic = AS_FLAT_MAGIC;
			as_flat_copy_wo_magic(flat_in_pickle, plaintext_flat, flat_sz);
		}
		else {
			memcpy(flat_in_pickle, plaintext_flat, flat_sz);
		}
	}

	uint64_t write_offset = WBLOCK_ID_TO_OFFSET(pwb->wblock_id) + pwb_pos;

	if (encrypt) {
		encrypt_flat(pmem, write_offset, plaintext_flat, flat_buf_pmem);
	}

	r->file_id = pmem->file_id;
	r->rblock_id = OFFSET_TO_RBLOCK_ID(write_offset);

	as_namespace_adjust_set_device_bytes(ns, as_index_get_set_id(r),
			DELTA_N_RBLOCKS_TO_SIZE(n_rblocks, r->n_rblocks));

	r->n_rblocks = n_rblocks;

	cf_atomic64_add(&pmem->inuse_size, (int64_t)write_sz);
	cf_atomic32_add(&pmem->wblock_state[pwb->wblock_id].inuse_sz,
			(int32_t)write_sz);

	// We are finished writing to the buffer.
	cf_atomic32_decr(&pwb->n_writers);

	if (ns->storage_benchmarks_enabled) {
		histogram_insert_raw(ns->device_write_size_hist, write_sz);
	}

	return 0;
}

static int
commit_bins(as_storage_rd* rd)
{
	as_namespace* ns = rd->ns;
	as_record* r = rd->r;
	drv_pmem* pmem = rd->pmem;

	uint32_t flat_sz;
	uint32_t limit_sz;

	if (rd->pickle == NULL) {
		flat_sz = as_flat_record_size(rd);
		limit_sz = ns->max_record_size == 0 ?
				PMEM_WRITE_BLOCK_SIZE : ns->max_record_size;
	}
	else {
		flat_sz = rd->orig_pickle_sz;
		limit_sz = PMEM_WRITE_BLOCK_SIZE;
	}

	if (flat_sz > limit_sz) {
		cf_detail(AS_DRV_PMEM, "{%s} write: size %u - rejecting %pD", ns->name,
				flat_sz, &r->keyd);
		return -AS_ERR_RECORD_TOO_BIG;
	}

	as_flat_record* flat;

	if (rd->pickle == NULL) {
		flat = as_flat_compress_bins_and_pack_record(rd, PMEM_WRITE_BLOCK_SIZE,
				false, false, &flat_sz);
	}
	else {
		flat = (as_flat_record*)rd->pickle;
		flat_sz = rd->pickle_sz;

		// Tree IDs are node-local - can't use those sent from other nodes.
		flat->tree_id = r->tree_id;
	}

	// Note - this is the only place where rounding size (up to a  multiple of
	// RBLOCK_SIZE) is really necessary.
	uint32_t write_sz = SIZE_UP_TO_RBLOCK_SIZE(flat_sz);

	current_pwb* cur_pwb = &pmem->current_pwbs[rd->which_current_swb];
	bool encrypt = ns->storage_encryption_key_file != NULL;

	cf_mutex_lock(&cur_pwb->lock);

	pmem_write_block* pwb = cur_pwb->pwb;

	if (! pwb) {
		pwb = pwb_get(pmem, false);
		cur_pwb->pwb = pwb;

		if (! pwb) {
			cf_ticker_warning(AS_DRV_PMEM, "{%s} out of space", ns->name);
			cf_mutex_unlock(&cur_pwb->lock);
			return -AS_ERR_OUT_OF_SPACE;
		}

		prepare_for_first_commit(pwb, encrypt);
	}

	// Check if there's enough space in current buffer - if not, zero
	// any remaining shadow unused space, free, and grab a new buffer.
	if (write_sz > PMEM_WRITE_BLOCK_SIZE - pwb->pos) {
		if (pmem->shadow_name != NULL) {
			if (PMEM_WRITE_BLOCK_SIZE != pwb->pos) {
				// Flush the end of the buffer to shadow.
				off_t clean_offset =
						WBLOCK_ID_TO_OFFSET(pwb->wblock_id) + pwb->pos;
				size_t clean_size = PMEM_WRITE_BLOCK_SIZE - pwb->pos;

				shadow_commit(pmem, pwb, clean_offset, clean_size);
			}
		}
		else {
			pmem_wait_writers_done(pwb);
		}

		pmem_mprotect(pwb->base_addr, PMEM_WRITE_BLOCK_SIZE, PROT_READ);

		pwb_release(pmem, pwb->wblock_id, pwb);
		cur_pwb->n_wblocks_written++;

		// Get the new buffer.
		pwb = pwb_get(pmem, false);
		cur_pwb->pwb = pwb;

		if (! pwb) {
			cf_ticker_warning(AS_DRV_PMEM, "{%s} out of space", ns->name);
			cf_mutex_unlock(&cur_pwb->lock);
			return -AS_ERR_OUT_OF_SPACE;
		}

		prepare_for_first_commit(pwb, encrypt);
	}

	// There's enough space - flatten data into the block.

	uint32_t pwb_pos = pwb->pos;

	if (pmem->shadow_name == NULL) {
		pwb->pos += write_sz;
		cf_atomic32_incr(&pwb->n_writers);
		cf_mutex_unlock(&cur_pwb->lock);
	}

	uint32_t n_rblocks = ROUNDED_SIZE_TO_N_RBLOCKS(write_sz);

	as_flat_record* flat_pmem = (as_flat_record*)&pwb->base_addr[pwb_pos];
	as_flat_record* plaintext_flat = encrypt ?
			get_scratch_thread_buffer(write_sz) : flat_pmem;

	if (pwb_pos > 0) {
		mark_flat_dirty(pmem, flat_pmem, encrypt);
	}

	if (flat == NULL) {
		as_flat_pack_record(rd, n_rblocks, true, plaintext_flat);
	}
	else {
		if (encrypt) {
			// prepare_for_first_commit() and pmem_mark_flat_dirty() place a
			// dirty magic number in pmem only. Put one into RAM as well.
			plaintext_flat->magic = AS_FLAT_MAGIC_DIRTY;
		}

		as_flat_copy_wo_magic(plaintext_flat, flat, flat_sz);
	}

	// Make a pickle if needed.
	if (rd->keep_pickle) {
		rd->pickle_sz = flat_sz;
		rd->pickle = cf_malloc(flat_sz);

		as_flat_record* flat_in_pickle = (as_flat_record*)rd->pickle;

		flat_in_pickle->magic = AS_FLAT_MAGIC;
		as_flat_copy_wo_magic(flat_in_pickle, plaintext_flat, flat_sz);
	}

	uint64_t write_offset = WBLOCK_ID_TO_OFFSET(pwb->wblock_id) + pwb_pos;

	if (encrypt) {
		encrypt_flat(pmem, write_offset, plaintext_flat, (uint8_t*)flat_pmem);
	}

	persist_and_mark_clean(pmem, flat_pmem, write_sz, encrypt);

	if (pmem->shadow_name != NULL) {
		shadow_commit(pmem, pwb, write_offset, write_sz);
		pwb->pos += write_sz;
	}

	r->file_id = pmem->file_id;
	r->rblock_id = OFFSET_TO_RBLOCK_ID(write_offset);

	as_namespace_adjust_set_device_bytes(ns, as_index_get_set_id(r),
			DELTA_N_RBLOCKS_TO_SIZE(n_rblocks, r->n_rblocks));

	r->n_rblocks = n_rblocks;

	cf_atomic64_add(&pmem->inuse_size, (int64_t)write_sz);
	cf_atomic32_add(&pmem->wblock_state[pwb->wblock_id].inuse_sz,
			(int32_t)write_sz);

	if (pmem->shadow_name == NULL) {
		cf_atomic32_decr(&pwb->n_writers);
	}
	else {
		cf_mutex_unlock(&cur_pwb->lock);
	}

	if (ns->storage_benchmarks_enabled) {
		histogram_insert_raw(ns->device_write_size_hist, write_sz);
	}

	return 0;
}

static void
prepare_for_first_commit(pmem_write_block* pwb, bool encrypt)
{
	// Ensure a non-zero magic number at the beginning of the wblock - cold
	// start considers wblocks that start with zeroes unused and skips them. A
	// second record can commit to a wblock before the first record had a chance
	// to overwrite the zeros. This second record would be lost on cold start.

	as_flat_record* first = (as_flat_record*)pwb->base_addr;
	size_t len = mark_flat_dirty(pwb->pmem, first, encrypt);

	pmem_memset(pwb->base_addr + len, 0, PMEM_WRITE_BLOCK_SIZE - len,
			PMEM_F_MEM_NONTEMPORAL);
}

static void
shadow_commit(const drv_pmem* pmem, const pmem_write_block* pwb, off_t offset,
		size_t size)
{
	off_t flush_offset = BYTES_DOWN_TO_IO_MIN(offset);
	off_t flush_end_offset = BYTES_UP_TO_IO_MIN(offset + size);

	const uint8_t* flush = pwb->base_addr +
			(pwb->pos - (uint32_t)(offset - flush_offset));
	size_t flush_sz = flush_end_offset - flush_offset;

	if (! pwrite_all(pmem->shadow_commit_fd, flush, flush_sz, flush_offset)) {
		cf_crash(AS_DRV_PMEM, "%s: DEVICE FAILED write: errno %d (%s)",
				pmem->shadow_name, errno, cf_strerror(errno));
	}
}


//==========================================================
// Local helpers - write and recycle wblocks.
//

static void*
run_write(void* arg)
{
	drv_pmem* pmem = (drv_pmem*)arg;
	bool encrypt = pmem->ns->storage_encryption_key_file != NULL;

	while (pmem->running) {
		pmem_write_block* pwb;

		if (CF_QUEUE_OK != cf_queue_pop(pmem->pwb_write_q, &pwb, 100)) {
			continue;
		}

		// Sanity checks (optional).
		write_sanity_checks(pmem, pwb);

		// Flush to the device.
		flush_final_pwb(pwb, encrypt);

		if (pmem->shadow_name) {
			// Queue for shadow device write.
			cf_queue_push(pmem->pwb_shadow_q, &pwb);
		}
		else {
			// If this pwb was a defrag destination, release the sources.
			pwb_release_all_vacated_wblocks(pwb);

			pwb_release(pmem, pwb->wblock_id, pwb);
			cf_atomic32_decr(&pmem->ns->n_wblocks_to_flush);
		}
	} // infinite event loop waiting for block to write

	return NULL;
}

static void
flush_final_pwb(pmem_write_block* pwb, bool encrypt)
{
	pmem_wait_writers_done(pwb);

	as_flat_record* flat_pmem = (as_flat_record*)&pwb->base_addr[pwb->pos];
	size_t flush_size = pwb->pos - pwb->first_dirty_pos;

	pmem_memset(flat_pmem, 0, PMEM_WRITE_BLOCK_SIZE - pwb->pos,
			PMEM_F_MEM_NONTEMPORAL);

	if (flush_size != 0) {
		as_flat_record* flat_dirty_pmem = (as_flat_record*)
					&pwb->base_addr[pwb->first_dirty_pos];

		// Remove the dirty magic after cleaning the tail for crash safety
		persist_and_mark_clean(pwb->pmem, flat_dirty_pmem, flush_size,
				encrypt);
	}

	pmem_mprotect(pwb->base_addr, PMEM_WRITE_BLOCK_SIZE, PROT_READ);
}

static void*
run_shadow(void* arg)
{
	drv_pmem* pmem = (drv_pmem*)arg;

	while (pmem->running) {
		pmem_write_block* pwb;

		if (CF_QUEUE_OK != cf_queue_pop(pmem->pwb_shadow_q, &pwb, 100)) {
			continue;
		}

		// Sanity checks (optional).
		write_sanity_checks(pmem, pwb);

		// Flush to the shadow device.
		shadow_flush_pwb(pmem, pwb);

		// If this pwb was a defrag destination, release the sources.
		pwb_release_all_vacated_wblocks(pwb);

		pwb_release(pmem, pwb->wblock_id, pwb);
		cf_atomic32_decr(&pmem->ns->n_wblocks_to_flush);
	}

	return NULL;
}

static void
write_sanity_checks(drv_pmem* pmem, pmem_write_block* pwb)
{
	pmem_wblock_state* p_wblock_state = &pmem->wblock_state[pwb->wblock_id];

	cf_assert(p_wblock_state->pwb == pwb, AS_DRV_PMEM,
			"device %s: wblock-id %u pwb not consistent while writing",
			pmem->name, pwb->wblock_id);

	cf_assert(p_wblock_state->state != WBLOCK_STATE_DEFRAG, AS_DRV_PMEM,
			"device %s: wblock-id %u state DEFRAG while writing", pmem->name,
			pwb->wblock_id);
}

// Reduce wblock's used size, if result is 0 put it in the "free" pool, if it's
// below the defrag threshold put it in the defrag queue.
static void
block_free(drv_pmem* pmem, uint64_t rblock_id, uint32_t n_rblocks, char* msg)
{
	// Determine which wblock we're reducing used size in.
	uint64_t start_offset = RBLOCK_ID_TO_OFFSET(rblock_id);
	uint32_t size = N_RBLOCKS_TO_SIZE(n_rblocks);
	uint32_t wblock_id = OFFSET_TO_WBLOCK_ID(start_offset);
	uint32_t end_wblock_id = OFFSET_TO_WBLOCK_ID(start_offset + size - 1);

	cf_assert(size >= DRV_RECORD_MIN_SIZE, AS_DRV_PMEM,
			"%s: %s: freeing bad size %u rblock_id %lu", pmem->name, msg, size,
			rblock_id);

	cf_assert(start_offset >= DRV_HEADER_SIZE &&
			wblock_id < pmem->n_wblocks && wblock_id == end_wblock_id,
			AS_DRV_PMEM, "%s: %s: freeing bad range rblock_id %lu n_rblocks %u",
			pmem->name, msg, rblock_id, n_rblocks);

	cf_atomic64_sub(&pmem->inuse_size, (int64_t)size);

	pmem_wblock_state* p_wblock_state = &pmem->wblock_state[wblock_id];

	cf_mutex_lock(&p_wblock_state->LOCK);

	int64_t resulting_inuse_sz = cf_atomic32_sub(&p_wblock_state->inuse_sz,
			(int32_t)size);

	cf_assert(resulting_inuse_sz >= 0 &&
			resulting_inuse_sz < (int64_t)PMEM_WRITE_BLOCK_SIZE, AS_DRV_PMEM,
			"%s: %s: wblock %d %s, subtracted %d now %ld", pmem->name, msg,
			wblock_id, resulting_inuse_sz < 0 ? "over-freed" : "bad inuse_sz",
			(int32_t)size, resulting_inuse_sz);

	if (p_wblock_state->pwb == NULL &&
			p_wblock_state->state != WBLOCK_STATE_DEFRAG) {
		// Free wblock if all three gating conditions hold.
		if (resulting_inuse_sz == 0) {
			cf_atomic64_incr(&pmem->n_wblock_direct_frees);
			push_wblock_to_free_q(pmem, wblock_id);
		}
		// Queue wblock for defrag if appropriate.
		else if (resulting_inuse_sz < pmem->ns->defrag_lwm_size) {
			push_wblock_to_defrag_q(pmem, wblock_id);
		}
	}

	cf_mutex_unlock(&p_wblock_state->LOCK);
}

static void
push_wblock_to_defrag_q(drv_pmem* pmem, uint32_t wblock_id)
{
	if (pmem->defrag_wblock_q) { // null until devices are loaded at startup
		pmem->wblock_state[wblock_id].state = WBLOCK_STATE_DEFRAG;
		cf_queue_push(pmem->defrag_wblock_q, &wblock_id);
		cf_atomic64_incr(&pmem->n_defrag_wblock_reads);
	}
}

static void
push_wblock_to_free_q(drv_pmem* pmem, uint32_t wblock_id)
{
	// Can get here before queue created, e.g. cold start replacing records.
	if (pmem->free_wblock_q == NULL) {
		return;
	}

	cf_assert(wblock_id < pmem->n_wblocks, AS_DRV_PMEM,
			"pushing bad wblock_id %d to free_wblock_q", (int32_t)wblock_id);

	cf_queue_push(pmem->free_wblock_q, &wblock_id);
}


//==========================================================
// Local helpers - write to header.
//

static void
write_header(drv_pmem* pmem, const uint8_t* header, const uint8_t* from,
		size_t size)
{
	pmem_memcpy(&pmem->pmem_base_addr[from - header], from, size,
			PMEM_F_MEM_NONTEMPORAL);

	if (pmem->shadow_name != NULL) {
		aligned_write_to_shadow(pmem, header, from, size);
	}
}

static void
write_header_atomic(drv_pmem* pmem, const uint8_t* header, const uint8_t* from,
		size_t size)
{
	atomic_write(pmem, header, from, size);

	if (pmem->shadow_name != NULL) {
		aligned_write_to_shadow(pmem, header, from, size);
	}
}

static void
aligned_write_to_shadow(drv_pmem* pmem, const uint8_t* header,
		const uint8_t* from, size_t size)
{
	off_t offset = from - header;

	off_t flush_offset = BYTES_DOWN_TO_IO_MIN(offset);
	off_t flush_end_offset = BYTES_UP_TO_IO_MIN(offset + size);

	const uint8_t* flush = header + flush_offset;
	size_t flush_sz = flush_end_offset - flush_offset;

	int fd = shadow_fd_get(pmem);

	if (! pwrite_all(fd, flush, flush_sz, flush_offset)) {
		cf_crash(AS_DRV_PMEM, "%s: DEVICE FAILED write: errno %d (%s)",
				pmem->shadow_name, errno, cf_strerror(errno));
	}

	shadow_fd_put(pmem, fd);
}

static void
atomic_write(drv_pmem* pmem, const uint8_t* header, const uint8_t* from,
		size_t size)
{
	off_t offset = from - header;
	drv_header* pmem_header = (drv_header*)&pmem->pmem_base_addr[0];
	drv_atomic* staged_write = &pmem_header->atomic;

	cf_assert(staged_write->size == 0, AS_DRV_PMEM, "staged write size != 0");

	staged_write->offset = offset;
	pmem_memcpy(staged_write->data, from, size, PMEM_F_MEM_NONTEMPORAL);
	pmem_persist(&staged_write->offset, sizeof(staged_write->offset));

	staged_write->size = size;
	pmem_persist(&staged_write->size, sizeof(staged_write->size));

	pmem_memcpy(&pmem->pmem_base_addr[offset], from, size,
			PMEM_F_MEM_NONTEMPORAL);

	staged_write->size = 0;
	pmem_persist(&staged_write->size, sizeof(staged_write->size));
}

static void
flush_flags(drv_pmems* pmems)
{
	for (int i = 0; i < pmems->n_pmems; i++) {
		drv_pmem* pmem = &pmems->pmems[i];

		write_header(pmem, (uint8_t*)pmems->generic,
				(uint8_t*)&pmems->generic->prefix.flags,
				sizeof(pmems->generic->prefix.flags));
	}
}


//==========================================================
// Local helpers - defrag.
//

static void*
run_defrag(void* pv_data)
{
	drv_pmem* pmem = (drv_pmem*)pv_data;
	as_namespace* ns = pmem->ns;
	uint32_t wblock_id;

	while (true) {
		uint32_t q_min = as_load_uint32(&ns->storage_defrag_queue_min);

		if (q_min == 0) {
			cf_queue_pop(pmem->defrag_wblock_q, &wblock_id, CF_QUEUE_FOREVER);
		}
		else {
			if (cf_queue_sz(pmem->defrag_wblock_q) <= q_min) {
				usleep(1000 * 50);
				continue;
			}

			cf_queue_pop(pmem->defrag_wblock_q, &wblock_id, CF_QUEUE_NOWAIT);
		}

		defrag_wblock(pmem, wblock_id);

		uint32_t sleep_us = ns->storage_defrag_sleep;

		if (sleep_us != 0) {
			usleep(sleep_us);
		}

		while (ns->n_wblocks_to_flush > ns->storage_max_write_q + 100) {
			usleep(1000);
		}
	}

	return NULL;
}

static int
defrag_wblock(drv_pmem* pmem, uint32_t wblock_id)
{
	int record_count = 0;

	pmem_wblock_state* p_wblock_state = &pmem->wblock_state[wblock_id];

	cf_assert(p_wblock_state->n_vac_dests == 0, AS_DRV_PMEM,
			"n-vacations not 0 beginning defrag wblock");

	// Make sure this can't decrement to 0 while defragging this wblock.
	cf_atomic32_set(&p_wblock_state->n_vac_dests, 1);

	if (cf_atomic32_get(p_wblock_state->inuse_sz) == 0) {
		cf_atomic64_incr(&pmem->n_wblock_defrag_io_skips);
		goto Finished;
	}

	uint64_t file_offset = WBLOCK_ID_TO_OFFSET(wblock_id);
	const uint8_t* pmem_buf = pmem->pmem_base_addr + file_offset;

	size_t indent = 0; // current offset within the wblock, in bytes

	while (indent < PMEM_WRITE_BLOCK_SIZE &&
			cf_atomic32_get(p_wblock_state->inuse_sz) != 0) {
		const as_flat_record* flat = decrypt_flat(pmem,
				file_offset + indent, &pmem_buf[indent]);

		if (flat->magic != AS_FLAT_MAGIC) {
			// The first record must have magic.
			if (flat->magic != AS_FLAT_MAGIC_DIRTY && indent == 0) {
				cf_warning(AS_DRV_PMEM, "%s: no magic at beginning of used wblock %d",
						pmem->name, wblock_id);
				break;
			}

			// Later records may have no magic.
			if (! pmem->ns->storage_commit_to_device) {
				break;
			}

			indent += RBLOCK_SIZE;
			continue;
		}

		uint32_t record_size = N_RBLOCKS_TO_SIZE(flat->n_rblocks);

		if (record_size < DRV_RECORD_MIN_SIZE) {
			cf_warning(AS_DRV_PMEM, "%s: record too small: size %u", pmem->name,
					record_size);
			indent += RBLOCK_SIZE;
			continue; // try next rblock
		}

		size_t next_indent = indent + record_size;

		if (next_indent > PMEM_WRITE_BLOCK_SIZE) {
			cf_warning(AS_DRV_PMEM, "%s: record crosses wblock boundary: n-rblocks %u",
					pmem->name, flat->n_rblocks);
			break;
		}

		// Found a good record, move it if it's current.
		int rv = record_defrag(pmem, wblock_id, flat,
				OFFSET_TO_RBLOCK_ID(file_offset + indent));

		if (rv == 0) {
			record_count++;
		}

		indent = next_indent;
	}

Finished:

	// Note - usually wblock's inuse_sz is 0 here, but may legitimately be non-0
	// e.g. if a dropped partition's tree is not done purging. In this case, we
	// may have found deleted records in the wblock whose used-size contribution
	// has not yet been subtracted.

	release_vacated_wblock(pmem, wblock_id, p_wblock_state);

	return record_count;
}

static int
record_defrag(drv_pmem* pmem, uint32_t wblock_id, const as_flat_record* flat,
		uint64_t rblock_id)
{
	as_namespace* ns = pmem->ns;
	as_partition_reservation rsv;
	uint32_t pid = as_partition_getid(&flat->keyd);

	as_partition_reserve(ns, pid, &rsv);

	int rv;
	as_index_ref r_ref;
	bool found = 0 == as_record_get(rsv.tree, &flat->keyd, &r_ref);

	if (found) {
		as_index* r = r_ref.r;

		if (r->file_id == pmem->file_id && r->rblock_id == rblock_id) {
			if (r->generation != flat->generation) {
				cf_warning(AS_DRV_PMEM, "device %s defrag: rblock_id %lu generation mismatch (%u:%u) %pD",
						pmem->name, rblock_id, r->generation, flat->generation,
						&r->keyd);
			}

			if (r->n_rblocks != flat->n_rblocks) {
				cf_warning(AS_DRV_PMEM, "device %s defrag: rblock_id %lu n_blocks mismatch (%u:%u) %pD",
						pmem->name, rblock_id, r->n_rblocks, flat->n_rblocks,
						&r->keyd);
			}

			defrag_move_record(pmem, wblock_id, flat, r);

			rv = 0; // record was in index tree and current - moved it
		}
		else {
			rv = -1; // record was in index tree - presumably was overwritten
		}

		as_record_done(&r_ref, ns);
	}
	else {
		rv = -2; // record was not in index tree - presumably was deleted
	}

	as_partition_release(&rsv);

	return rv;
}

// FIXME - what really to do if n_rblocks on drive doesn't match index?
static void
defrag_move_record(drv_pmem* src_pmem, uint32_t src_wblock_id,
		const as_flat_record* flat, as_index* r)
{
	uint64_t old_rblock_id = r->rblock_id;
	uint32_t old_n_rblocks = r->n_rblocks;

	as_namespace* ns = src_pmem->ns;
	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	// Figure out which device to write to. When replacing an old record, it's
	// possible this is different from the old device (e.g. if we've added a
	// fresh device), so derive it from the digest each time.
	drv_pmem* pmem = &pmems->pmems[pmem_get_file_id(pmems, &flat->keyd)];

	cf_assert(pmem, AS_DRV_PMEM, "{%s} null pmem", ns->name);

	uint32_t pmem_n_rblocks = flat->n_rblocks;
	uint32_t write_size = N_RBLOCKS_TO_SIZE(pmem_n_rblocks);

	cf_mutex_lock(&pmem->defrag_lock);

	pmem_write_block* pwb = pmem->defrag_pwb;
	bool encrypt = ns->storage_encryption_key_file != NULL;

	if (! pwb) {
		pwb = pwb_get(pmem, true);
		pmem->defrag_pwb = pwb;

		if (! pwb) {
			cf_warning(AS_DRV_PMEM, "defrag_move_record: couldn't get pwb");
			cf_mutex_unlock(&pmem->defrag_lock);
			return;
		}

		prepare_for_first_write(pwb, encrypt);
	}

	// Check if there's enough space in defrag buffer - if not, enqueue it to be
	// flushed to device, and grab a new buffer.
	if (write_size > PMEM_WRITE_BLOCK_SIZE - pwb->pos) {
		// Enqueue the buffer, to be flushed to device.
		push_wblock_to_write_q(pmem, pwb);
		cf_atomic64_incr(&pmem->n_defrag_wblock_writes);

		// Get the new buffer.
		while ((pwb = pwb_get(pmem, true)) == NULL) {
			// If we got here, we used all our reserve wblocks, but the wblocks
			// we defragged must still have non-zero inuse_sz. Must wait for
			// those to become free.
			cf_ticker_warning(AS_DRV_PMEM, "{%s} defrag: drive %s totally full - waiting for vacated wblocks to be freed",
					pmem->ns->name, pmem->name);

			usleep(10 * 1000);
		}

		pmem->defrag_pwb = pwb;

		prepare_for_first_write(pwb, encrypt);
	}

	uint8_t* flat_buf_pmem = &pwb->base_addr[pwb->pos];
	as_flat_record* plaintext_flat = encrypt ?
			get_scratch_thread_buffer(write_size) :
			(as_flat_record*)flat_buf_pmem;

	if (pwb->n_vacated == 0) {
		plaintext_flat->magic = AS_FLAT_MAGIC_DIRTY;
		as_flat_copy_wo_magic(plaintext_flat, flat, write_size);
	}
	else {
		copy_flat(plaintext_flat, flat, write_size, encrypt);
	}

	uint64_t write_offset = WBLOCK_ID_TO_OFFSET(pwb->wblock_id) + pwb->pos;

	if (encrypt) {
		encrypt_flat(pmem, write_offset, plaintext_flat, flat_buf_pmem);
	}

	r->file_id = pmem->file_id;
	r->rblock_id = OFFSET_TO_RBLOCK_ID(write_offset);
	r->n_rblocks = pmem_n_rblocks;

	pwb->pos += write_size;

	cf_atomic64_add(&pmem->inuse_size, (int64_t)write_size);
	cf_atomic32_add(&pmem->wblock_state[pwb->wblock_id].inuse_sz,
			(int32_t)write_size);

	// If we just defragged into a new destination pwb, count it.
	if (pwb_add_unique_vacated_wblock(pwb, src_pmem->file_id, src_wblock_id)) {
		pmem_wblock_state* p_wblock_state =
				&src_pmem->wblock_state[src_wblock_id];

		cf_atomic32_incr(&p_wblock_state->n_vac_dests);
	}

	cf_mutex_unlock(&pmem->defrag_lock);

	block_free(src_pmem, old_rblock_id, old_n_rblocks, "defrag-write");
}

static void
release_vacated_wblock(drv_pmem* pmem, uint32_t wblock_id,
		pmem_wblock_state* p_wblock_state)
{
	cf_assert(p_wblock_state->pwb == NULL, AS_DRV_PMEM,
			"device %s: wblock-id %u pwb not null while defragging",
			pmem->name, wblock_id);

	cf_assert(p_wblock_state->state == WBLOCK_STATE_DEFRAG, AS_DRV_PMEM,
			"device %s: wblock-id %u state not DEFRAG while defragging",
			pmem->name, wblock_id);

	int32_t n_vac_dests = cf_atomic32_decr(&p_wblock_state->n_vac_dests);

	if (n_vac_dests > 0) {
		return;
	}
	// else - all wblocks we defragged into have been flushed.

	cf_assert(n_vac_dests == 0, AS_DRV_PMEM,
			"device %s: wblock-id %u vacation destinations underflow",
			pmem->name, wblock_id);

	cf_mutex_lock(&p_wblock_state->LOCK);

	p_wblock_state->state = WBLOCK_STATE_NONE;

	// Free the wblock if it's empty.
	if (cf_atomic32_get(p_wblock_state->inuse_sz) == 0 &&
			// TODO - given assertions above, this condition is superfluous:
			p_wblock_state->pwb == NULL) {
		push_wblock_to_free_q(pmem, wblock_id);
	}

	cf_mutex_unlock(&p_wblock_state->LOCK);
}


//==========================================================
// Local helpers - maintenance.
//

static void*
run_pmem_maintenance(void* udata)
{
	drv_pmem* pmem = (drv_pmem*)udata;
	as_namespace* ns = pmem->ns;

	uint64_t prev_n_total_writes = 0;
	uint64_t prev_n_defrag_reads = 0;
	uint64_t prev_n_defrag_writes = 0;
	uint64_t prev_n_defrag_io_skips = 0;
	uint64_t prev_n_direct_frees = 0;
	uint64_t prev_n_tomb_raider_reads = 0;

	uint64_t prev_n_writes_flush[N_CURRENT_SWBS] = { 0 };

	uint64_t prev_n_defrag_writes_flush = 0;

	uint64_t now = cf_getus();
	uint64_t next = now + MAX_INTERVAL;

	uint64_t prev_log_stats = now;
	uint64_t prev_free_pwbs = now;
	uint64_t prev_flush[N_CURRENT_SWBS];
	uint64_t prev_defrag_flush = now;

	for (uint8_t c = 0; c < N_CURRENT_SWBS; c++) {
		prev_flush[c] = now;
	}

	// If any job's (initial) interval is less than MAX_INTERVAL and we want it
	// done on its interval the first time through, add a next_time() call for
	// that job here to adjust 'next'. (No such jobs for now.)

	uint64_t sleep_us = next - now;

	while (true) {
		usleep((uint32_t)sleep_us);

		now = cf_getus();
		next = now + MAX_INTERVAL;

		if (now >= prev_log_stats + LOG_STATS_INTERVAL) {
			log_stats(pmem, &prev_n_total_writes, &prev_n_defrag_reads,
					&prev_n_defrag_writes, &prev_n_defrag_io_skips,
					&prev_n_direct_frees, &prev_n_tomb_raider_reads);
			prev_log_stats = now;
			next = next_time(now, LOG_STATS_INTERVAL, next);
		}

		if (now >= prev_free_pwbs + FREE_SWBS_INTERVAL) {
			free_pwbs(pmem);
			prev_free_pwbs = now;
			next = next_time(now, FREE_SWBS_INTERVAL, next);
		}

		uint64_t flush_max_us = ns->storage_commit_to_device ?
				0 : ns->storage_flush_max_us;

		for (uint8_t c = 0; c < N_CURRENT_SWBS; c++) {
			if (flush_max_us != 0 && now >= prev_flush[c] + flush_max_us) {
				flush_current_pwb(pmem, c, &prev_n_writes_flush[c]);
				prev_flush[c] = now;
				next = next_time(now, flush_max_us, next);
			}
		}

		static const uint64_t DEFRAG_FLUSH_MAX_US = 3UL * 1000 * 1000; // 3 sec

		if (now >= prev_defrag_flush + DEFRAG_FLUSH_MAX_US) {
			flush_defrag_pwb(pmem, &prev_n_defrag_writes_flush);
			prev_defrag_flush = now;
			next = next_time(now, DEFRAG_FLUSH_MAX_US, next);
		}

		if (cf_atomic32_get(pmem->defrag_sweep) != 0) {
			// May take long enough to mess up other jobs' schedules, but it's a
			// very rare manually-triggered intervention.
			defrag_sweep(pmem);
			cf_atomic32_decr(&pmem->defrag_sweep);
		}

		now = cf_getus(); // refresh in case jobs took significant time
		sleep_us = next > now ? next - now : 1;
	}

	return NULL;
}

static void
log_stats(drv_pmem* pmem, uint64_t* p_prev_n_total_writes,
		uint64_t* p_prev_n_defrag_reads, uint64_t* p_prev_n_defrag_writes,
		uint64_t* p_prev_n_defrag_io_skips, uint64_t* p_prev_n_direct_frees,
		uint64_t* p_prev_n_tomb_raider_reads)
{
	uint64_t n_defrag_reads = cf_atomic64_get(pmem->n_defrag_wblock_reads);
	uint64_t n_defrag_writes = cf_atomic64_get(pmem->n_defrag_wblock_writes);

	uint64_t n_total_writes = n_defrag_writes;

	for (uint8_t c = 0; c < N_CURRENT_SWBS; c++) {
		n_total_writes += pmem->current_pwbs[c].n_wblocks_written;
	}

	uint64_t n_defrag_io_skips = cf_atomic64_get(pmem->n_wblock_defrag_io_skips);
	uint64_t n_direct_frees = cf_atomic64_get(pmem->n_wblock_direct_frees);

	float total_write_rate = (float)(n_total_writes - *p_prev_n_total_writes) /
			(float)LOG_STATS_INTERVAL_sec;
	float defrag_read_rate = (float)(n_defrag_reads - *p_prev_n_defrag_reads) /
			(float)LOG_STATS_INTERVAL_sec;
	float defrag_write_rate =
			(float)(n_defrag_writes - *p_prev_n_defrag_writes) /
			(float)LOG_STATS_INTERVAL_sec;

	float defrag_io_skip_rate =
			(float)(n_defrag_io_skips - *p_prev_n_defrag_io_skips) /
			(float)LOG_STATS_INTERVAL_sec;
	float direct_free_rate = (float)(n_direct_frees - *p_prev_n_direct_frees) /
			(float)LOG_STATS_INTERVAL_sec;

	uint64_t n_tomb_raider_reads = pmem->n_tomb_raider_reads;
	char tomb_raider_str[64];

	*tomb_raider_str = 0;

	if (n_tomb_raider_reads != 0) {
		if (*p_prev_n_tomb_raider_reads > n_tomb_raider_reads) {
			*p_prev_n_tomb_raider_reads = 0;
		}

		float tomb_raider_read_rate =
				(float)(n_tomb_raider_reads - *p_prev_n_tomb_raider_reads) /
				(float)LOG_STATS_INTERVAL_sec;

		sprintf(tomb_raider_str, " tomb-raider-read (%lu,%.1f)",
				n_tomb_raider_reads, tomb_raider_read_rate);
	}

	char shadow_str[64];

	*shadow_str = 0;

	if (pmem->shadow_name) {
		sprintf(shadow_str, " shadow-write-q %u",
				cf_queue_sz(pmem->pwb_shadow_q));
	}

	uint32_t free_wblock_q_sz = cf_queue_sz(pmem->free_wblock_q);
	uint32_t n_pristine_wblocks = num_pristine_wblocks(pmem);
	uint32_t n_free_wblocks = free_wblock_q_sz + n_pristine_wblocks;

	cf_info(AS_DRV_PMEM, "{%s} %s: used-bytes %lu free-wblocks %u write-q %u write (%lu,%.1f) defrag-q %u defrag-read (%lu,%.1f) defrag-write (%lu,%.1f)%s%s",
			pmem->ns->name, pmem->name,
			pmem->inuse_size, n_free_wblocks,
			cf_queue_sz(pmem->pwb_write_q),
			n_total_writes, total_write_rate,
			cf_queue_sz(pmem->defrag_wblock_q), n_defrag_reads,
					defrag_read_rate,
			n_defrag_writes, defrag_write_rate,
			shadow_str, tomb_raider_str);

	cf_detail(AS_DRV_PMEM, "{%s} %s: free-wblocks (%u,%u) defrag-io-skips (%lu,%.1f) direct-frees (%lu,%.1f)",
			pmem->ns->name, pmem->name,
			free_wblock_q_sz, n_pristine_wblocks,
			n_defrag_io_skips, defrag_io_skip_rate,
			n_direct_frees, direct_free_rate);

	*p_prev_n_total_writes = n_total_writes;
	*p_prev_n_defrag_reads = n_defrag_reads;
	*p_prev_n_defrag_writes = n_defrag_writes;
	*p_prev_n_defrag_io_skips = n_defrag_io_skips;
	*p_prev_n_direct_frees = n_direct_frees;
	*p_prev_n_tomb_raider_reads = n_tomb_raider_reads;

	if (n_free_wblocks == 0) {
		cf_warning(AS_DRV_PMEM, "device %s: out of storage space", pmem->name);
	}
}

static uint64_t
next_time(uint64_t now, uint64_t job_interval, uint64_t next)
{
	uint64_t next_job = now + job_interval;

	return next_job < next ? next_job : next;
}

static void
free_pwbs(drv_pmem* pmem)
{
	// Try to recover pwbs, 16 at a time, down to 16.
	for (uint32_t i = 0; i < 16 && cf_queue_sz(pmem->pwb_free_q) > 16; i++) {
		pmem_write_block* pwb;

		if (CF_QUEUE_OK !=
				cf_queue_pop(pmem->pwb_free_q, &pwb, CF_QUEUE_NOWAIT)) {
			break;
		}

		pwb_destroy(pwb);
	}
}

static void
flush_current_pwb(drv_pmem* pmem, uint8_t which, uint64_t* p_prev_n_writes)
{
	current_pwb* cur_pwb = &pmem->current_pwbs[which];
	uint64_t n_writes = as_load_uint64(&cur_pwb->n_wblocks_written);

	// If there's an active write load, we don't need to flush.
	if (n_writes != *p_prev_n_writes) {
		*p_prev_n_writes = n_writes;
		return;
	}

	cf_mutex_lock(&cur_pwb->lock);

	n_writes = as_load_uint64(&cur_pwb->n_wblocks_written);

	// Must check under the lock, could be racing a current pwb just queued.
	if (n_writes != *p_prev_n_writes) {

		cf_mutex_unlock(&cur_pwb->lock);

		*p_prev_n_writes = n_writes;
		return;
	}

	// Flush the current pwb if it isn't empty, and has been written to since
	// last flushed.

	pmem_write_block* pwb = cur_pwb->pwb;

	if (pwb && pwb->dirty) {
		pwb->dirty = false;

		bool encrypt = pmem->ns->storage_encryption_key_file != NULL;

		// Flush it.
		flush_partial_pwb(pwb, encrypt);

		if (pmem->shadow_name) {
			shadow_flush_pwb(pmem, pwb);
		}
	}

	cf_mutex_unlock(&cur_pwb->lock);
}

static void
flush_defrag_pwb(drv_pmem* pmem, uint64_t* p_prev_n_defrag_writes)
{
	uint64_t n_defrag_writes = cf_atomic64_get(pmem->n_defrag_wblock_writes);

	// If there's an active defrag load, we don't need to flush.
	if (n_defrag_writes != *p_prev_n_defrag_writes) {
		*p_prev_n_defrag_writes = n_defrag_writes;
		return;
	}

	cf_mutex_lock(&pmem->defrag_lock);

	n_defrag_writes = cf_atomic64_get(pmem->n_defrag_wblock_writes);

	// Must check under the lock, could be racing a current pwb just queued.
	if (n_defrag_writes != *p_prev_n_defrag_writes) {

		cf_mutex_unlock(&pmem->defrag_lock);

		*p_prev_n_defrag_writes = n_defrag_writes;
		return;
	}

	// Flush the defrag pwb if it isn't empty, and has been written to since
	// last flushed.

	pmem_write_block* pwb = pmem->defrag_pwb;

	if (pwb && pwb->n_vacated != 0) {
		bool encrypt = pmem->ns->storage_encryption_key_file != NULL;

		flush_partial_pwb(pwb, encrypt);

		if (pmem->shadow_name) {
			shadow_flush_pwb(pmem, pwb);
		}

		// The whole point - free source wblocks.
		pwb_release_all_vacated_wblocks(pwb);
	}

	cf_mutex_unlock(&pmem->defrag_lock);
}

static void
flush_partial_pwb(pmem_write_block* pwb, bool encrypt)
{
	pmem_wait_writers_done(pwb);

	size_t flush_size = pwb->pos - pwb->first_dirty_pos;

	if (pwb->pos != PMEM_WRITE_BLOCK_SIZE) { // >= 16 bytes left at the end
		as_flat_record* flat_pmem = (as_flat_record*)&pwb->base_addr[pwb->pos];

		if (encrypt) {
			as_flat_record flat = { .magic = AS_FLAT_MAGIC_DIRTY };
			uint64_t offset = (uint8_t*)flat_pmem - pwb->pmem->pmem_base_addr;

			encrypt_data(pwb->pmem, offset, PMEM_CIPHER_BLOCK_SIZE,
					(const uint8_t*)&flat, (uint8_t*)flat_pmem);
			// Don't touch flush_size - magic already flushed to pmem.
		}
		else {
			flat_pmem->magic = AS_FLAT_MAGIC_DIRTY;
			flush_size += sizeof(flat_pmem->magic);
		}
	}

	as_flat_record* flat_dirty_pmem = (as_flat_record*)
			&pwb->base_addr[pwb->first_dirty_pos];

	persist_and_mark_clean(pwb->pmem, flat_dirty_pmem, flush_size, encrypt);
	pwb->first_dirty_pos = pwb->pos;
}

// Check all wblocks to load a device's defrag queue at runtime. Triggered only
// when defrag-lwm-pct is increased by manual intervention.
static void
defrag_sweep(drv_pmem* pmem)
{
	uint32_t first_id = pmem->first_wblock_id;
	uint32_t end_id = pmem->n_wblocks;
	uint32_t n_queued = 0;

	for (uint32_t wblock_id = first_id; wblock_id < end_id; wblock_id++) {
		pmem_wblock_state* p_wblock_state = &pmem->wblock_state[wblock_id];

		cf_mutex_lock(&p_wblock_state->LOCK);

		uint32_t inuse_sz = cf_atomic32_get(p_wblock_state->inuse_sz);

		if (p_wblock_state->pwb == NULL &&
				p_wblock_state->state != WBLOCK_STATE_DEFRAG &&
					inuse_sz != 0 &&
						inuse_sz < pmem->ns->defrag_lwm_size) {
			push_wblock_to_defrag_q(pmem, wblock_id);
			n_queued++;
		}

		cf_mutex_unlock(&p_wblock_state->LOCK);
	}

	cf_info(AS_DRV_PMEM, "... %s sweep queued %u wblocks for defrag",
			pmem->name, n_queued);
}


//==========================================================
// Local helpers - tomb raider.
//

static void
start_serial_tomb_raider()
{
	if (g_serial_tomb_raider_started) {
		return;
	}

	g_serial_tomb_raider_started = true;
	cf_thread_create_detached(run_serial_tomb_raider, NULL);
}

static void*
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
			as_namespace* ns = g_config.namespaces[ns_ix];

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

static void*
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

static void
tomb_raid(as_namespace* ns)
{
	// Reduce index to mark tombstones as potential cenotaphs.

	cf_info(AS_DRV_PMEM, "{%s} tomb raider start - marking cenotaphs ...",
			ns->name);

	drv_pmems* pmems = (drv_pmems*)ns->storage_private;

	// Split this task across multiple threads.
	cf_tid mark_tids[NUM_TOMB_RAIDER_THREADS];
	mark_cenotaph_info mark_info = { ns, -1, lut_mark_threshold(pmems) };

	for (int n = 0; n < NUM_TOMB_RAIDER_THREADS; n++) {
		mark_tids[n] = cf_thread_create_joinable(run_mark_cenotaphs,
				(void*)&mark_info);
	}

	for (int n = 0; n < NUM_TOMB_RAIDER_THREADS; n++) {
		cf_thread_join(mark_tids[n]);
	}
	// Now we're single-threaded again.

	cf_info(AS_DRV_PMEM, "{%s} tomb raider detecting cenotaphs ...", ns->name);

	// Scan all drives to un-mark remaining records' cenotaphs.

	uint32_t expire_at = as_record_void_time_get();

	// Split this task using one thread per device.
	cf_tid unmark_tids[pmems->n_pmems];
	unmark_cenotaph_info unmark_info = { pmems, -1, expire_at, 0 };

	for (int n = 0; n < pmems->n_pmems; n++) {
		unmark_tids[n] = cf_thread_create_joinable(run_unmark_cenotaphs,
				(void*)&unmark_info);
	}

	for (int n = 0; n < pmems->n_pmems; n++) {
		cf_thread_join(unmark_tids[n]);
	}
	// Now we're single-threaded again.

	cf_info(AS_DRV_PMEM, "{%s} tomb raider removing cenotaphs ...", ns->name);

	// Reduce index to drop cenotaphs.
	uint32_t n_dropped = drop_cenotaphs(ns, NUM_TOMB_RAIDER_THREADS,
			unmark_info.aborted == 1);

	cf_info(AS_DRV_PMEM, "{%s} ... tomb raider done - removed %u cenotaphs",
			ns->name, n_dropped);
}

// Don't mark cenotaphs that might cover records waiting in the write queues.
// For now peek at the heads of queues to estimate minimum last-update-time.
// This isn't rigorous - possible for older records to be deeper in an pwb or
// not at head of a queue - hence the safety margin.
static uint64_t
lut_mark_threshold(drv_pmems* pmems)
{
	uint64_t min_last_update_time = cf_clepoch_milliseconds();

	for (int i = 0; i < pmems->n_pmems; i++) {
		cf_queue* write_q = pmems->pmems[i].pwb_write_q;
		uint64_t last_update_time = min_last_update_time;

		cf_queue_reduce(write_q, write_q_reduce_cb, (void*)&last_update_time);

		if (last_update_time < min_last_update_time) {
			min_last_update_time = last_update_time;
		}
	}

	return min_last_update_time - (1000 * MARK_MIN_AGE_SAFETY_MARGIN);
}

static int
write_q_reduce_cb(void* buf, void* udata)
{
	pmem_write_block* pwb = *(pmem_write_block**)buf;
	as_flat_record* flat = (as_flat_record*)pwb->base_addr;

	*(uint64_t*)udata = flat->last_update_time;

	return -1; // stop reducing immediately - poor man's peek
}

static void*
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

static bool
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

static void*
run_unmark_cenotaphs(void* pv_data)
{
	unmark_cenotaph_info* p_unmark_info = (unmark_cenotaph_info*)pv_data;
	drv_pmems* pmems = (drv_pmems*)p_unmark_info->pmems;
	as_namespace* ns = pmems->ns;
	uint64_t now = (uint64_t)p_unmark_info->now;

	drv_pmem* pmem =
			&pmems->pmems[cf_atomic32_incr(&p_unmark_info->pmem_index)];

	cf_info(AS_DRV_PMEM, "{%s} tomb raider reading %s ...", ns->name,
			pmem->name);

	uint64_t end_offset = WBLOCK_ID_TO_OFFSET(pmem->n_wblocks);

	const int MAX_NEVER_WRITTEN = 10;
	int n_never_written = 0;

	for (uint64_t file_offset = DRV_HEADER_SIZE;
			p_unmark_info->aborted == 0 &&
					n_never_written < MAX_NEVER_WRITTEN &&
					file_offset < end_offset;
			file_offset += PMEM_WRITE_BLOCK_SIZE) {
		const uint8_t* buf = pmem->pmem_base_addr + file_offset;

		// Loop over records in this read buffer.

		uint32_t indent = 0; // byte offset within read buffer

		while (p_unmark_info->aborted == 0 && indent < PMEM_WRITE_BLOCK_SIZE) {
			const as_flat_record* flat = decrypt_flat(pmem,
					file_offset + indent, &buf[indent]);

			if (flat->magic != AS_FLAT_MAGIC) {
				// First block must have magic.
				if (flat->magic != AS_FLAT_MAGIC_DIRTY && indent == 0) {
					n_never_written++;
					break;
				}

				// Later blocks may have no magic.
				if (! pmem->ns->storage_commit_to_device) {
					break;
				}

				indent += RBLOCK_SIZE;
				continue;
			}

			uint32_t record_size = N_RBLOCKS_TO_SIZE(flat->n_rblocks);

			if (record_size < DRV_RECORD_MIN_SIZE) {
				cf_warning(AS_DRV_PMEM, "%s: record too small: size %u",
						pmem->name, record_size);
				indent += RBLOCK_SIZE;
				continue; // try next rblock
			}

			uint64_t next_indent = (uint64_t)indent + record_size;

			if (next_indent > PMEM_WRITE_BLOCK_SIZE) {
				cf_warning(AS_DRV_PMEM, "%s: record crosses wblock boundary: size %u",
						pmem->name, record_size);
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

		pmem->n_tomb_raider_reads++;
	}

	cf_info(AS_DRV_PMEM, "{%s} ... tomb raider %s - read %lu blocks on %s",
			ns->name, p_unmark_info->aborted == 0 ? "done" : "abort",
			pmem->n_tomb_raider_reads - (uint64_t)n_never_written, pmem->name);

	pmem->n_tomb_raider_reads = 0; // each raid has a fresh device ticker trail

	return NULL;
}

static void
unmark_cenotaph(as_namespace* ns, const cf_digest* keyd)
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

static uint32_t
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

static void*
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

static bool
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


//==========================================================
// Local helpers - pwb class.
//

static pmem_write_block*
pwb_create(drv_pmem* pmem)
{
	pmem_write_block* pwb =
			(pmem_write_block*)cf_malloc(sizeof(pmem_write_block));

	pwb->n_vacated = 0;
	pwb->vacated_capacity = VACATED_CAPACITY_STEP;
	pwb->vacated_wblocks =
			cf_malloc(sizeof(vacated_wblock) * pwb->vacated_capacity);

	return pwb;
}

static void
pwb_destroy(pmem_write_block* pwb)
{
	cf_free(pwb->vacated_wblocks);
	cf_free(pwb);
}

static void
pwb_reset(pmem_write_block* pwb)
{
	pwb->dirty = false;
	pwb->wblock_id = STORAGE_INVALID_WBLOCK;
	pwb->pos = 0;
}

static void
pwb_release(drv_pmem* pmem, uint32_t wblock_id, pmem_write_block* pwb)
{
	pmem_wblock_state* wblock_state = &pmem->wblock_state[wblock_id];

	cf_mutex_lock(&wblock_state->LOCK);

	cf_assert(pwb == wblock_state->pwb, AS_DRV_PMEM,
			"releasing wrong pwb! %p (%d) != %p (%d), thread %d",
			pwb, (int32_t)pwb->wblock_id, wblock_state->pwb,
			(int32_t)wblock_state->pwb->wblock_id, cf_thread_sys_tid());

	pwb_reset(wblock_state->pwb);
	cf_queue_push(pwb->pmem->pwb_free_q, &pwb);

	wblock_state->pwb = NULL;

	cf_assert(wblock_state->state != WBLOCK_STATE_DEFRAG, AS_DRV_PMEM,
			"device %s: wblock-id %u state is DEFRAG on pwb release",
			pmem->name, wblock_id);

	uint32_t inuse_sz = cf_atomic32_get(wblock_state->inuse_sz);

	// Free wblock if all three gating conditions hold.
	if (inuse_sz == 0) {
		cf_atomic64_incr(&pmem->n_wblock_direct_frees);
		push_wblock_to_free_q(pmem, wblock_id);
	}
	// Queue wblock for defrag if applicable.
	else if (inuse_sz < pmem->ns->defrag_lwm_size) {
		push_wblock_to_defrag_q(pmem, wblock_id);
	}

	cf_mutex_unlock(&wblock_state->LOCK);
}

static pmem_write_block*
pwb_get(drv_pmem* pmem, bool use_reserve)
{
	if (! use_reserve && num_free_wblocks(pmem) <= DRV_DEFRAG_RESERVE) {
		return NULL;
	}

	pmem_write_block* pwb;

	if (CF_QUEUE_OK != cf_queue_pop(pmem->pwb_free_q, &pwb, CF_QUEUE_NOWAIT)) {
		pwb = pwb_create(pmem);
		pwb->n_writers = 0;
		pwb->dirty = false;
		pwb->pmem = pmem;
		pwb->wblock_id = STORAGE_INVALID_WBLOCK;
		pwb->pos = 0;
	}

	// Find a device block to write to.
	if (cf_queue_pop(pmem->free_wblock_q, &pwb->wblock_id, CF_QUEUE_NOWAIT) !=
			CF_QUEUE_OK && ! pop_pristine_wblock_id(pmem, &pwb->wblock_id)) {
		cf_queue_push(pmem->pwb_free_q, &pwb);
		return NULL;
	}

	pwb->base_addr = pmem->pmem_base_addr +
			(uint64_t)pwb->wblock_id * PMEM_WRITE_BLOCK_SIZE;

	pmem_mprotect(pwb->base_addr, PMEM_WRITE_BLOCK_SIZE,
			PROT_READ | PROT_WRITE);

	pmem_wblock_state* p_wblock_state = &pmem->wblock_state[pwb->wblock_id];

	uint32_t inuse_sz = cf_atomic32_get(p_wblock_state->inuse_sz);

	cf_assert(inuse_sz == 0, AS_DRV_PMEM,
			"device %s: wblock-id %u inuse-size %u off free-q", pmem->name,
			pwb->wblock_id, inuse_sz);

	cf_assert(p_wblock_state->pwb == NULL, AS_DRV_PMEM,
			"device %s: wblock-id %u pwb not null off free-q", pmem->name,
			pwb->wblock_id);

	cf_assert(p_wblock_state->state != WBLOCK_STATE_DEFRAG, AS_DRV_PMEM,
			"device %s: wblock-id %u state DEFRAG off free-q", pmem->name,
			pwb->wblock_id);

	cf_mutex_lock(&p_wblock_state->LOCK);
	p_wblock_state->pwb = pwb;
	cf_mutex_unlock(&p_wblock_state->LOCK);

	return pwb;
}

static bool
pop_pristine_wblock_id(drv_pmem* pmem, uint32_t* wblock_id)
{
	uint32_t id;

	while ((id = as_load_uint32(&pmem->pristine_wblock_id)) < pmem->n_wblocks) {
		if (as_cas_uint32(&pmem->pristine_wblock_id, id, id + 1)) {
			*wblock_id = id;
			return true;
		}
	}

	return false; // out of space
}

static bool
pwb_add_unique_vacated_wblock(pmem_write_block* pwb, uint32_t src_file_id,
		uint32_t src_wblock_id)
{
	for (uint32_t i = 0; i < pwb->n_vacated; i++) {
		vacated_wblock* vw = &pwb->vacated_wblocks[i];

		if (vw->wblock_id == src_wblock_id && vw->file_id == src_file_id) {
			return false; // already present
		}
	}

	if (pwb->n_vacated == pwb->vacated_capacity) {
		pwb->vacated_capacity += VACATED_CAPACITY_STEP;
		pwb->vacated_wblocks = cf_realloc(pwb->vacated_wblocks,
				sizeof(vacated_wblock) * pwb->vacated_capacity);
	}

	pwb->vacated_wblocks[pwb->n_vacated].file_id = src_file_id;
	pwb->vacated_wblocks[pwb->n_vacated].wblock_id = src_wblock_id;
	pwb->n_vacated++;

	return true; // added to list
}

static void
pwb_release_all_vacated_wblocks(pmem_write_block* pwb)
{
	drv_pmems* pmems = (drv_pmems*)pwb->pmem->ns->storage_private;

	for (uint32_t i = 0; i < pwb->n_vacated; i++) {
		vacated_wblock* vw = &pwb->vacated_wblocks[i];

		drv_pmem* src_pmem = &pmems->pmems[vw->file_id];
		pmem_wblock_state* wblock_state =
				&src_pmem->wblock_state[vw->wblock_id];

		release_vacated_wblock(src_pmem, vw->wblock_id, wblock_state);
	}

	pwb->n_vacated = 0;
}


//==========================================================
// Local helpers - persistence utilities.
//

static void
pmem_mprotect(void* addr, size_t len, int prot)
{
	if (mprotect(addr, len, prot) < 0) {
		cf_crash(AS_DRV_PMEM, "mprotect(%p, %zu, %d) failed: %d (%s)", addr,
				len, prot, errno, cf_strerror(errno));
	}
}

static void
prepare_for_first_write(pmem_write_block* pwb, bool encrypt)
{
	as_flat_record* first = (as_flat_record*)pwb->base_addr;

	mark_flat_dirty(pwb->pmem, first, encrypt);
	pwb->first_dirty_pos = 0;
}

static size_t
mark_flat_dirty(const drv_pmem* pmem, as_flat_record* flat_pmem, bool encrypt)
{
	if (encrypt) {
		as_flat_record flat = { .magic = AS_FLAT_MAGIC_DIRTY };
		uint64_t offset = (uint8_t*)flat_pmem - pmem->pmem_base_addr;

		encrypt_data(pmem, offset, PMEM_CIPHER_BLOCK_SIZE,
				(const uint8_t*)&flat, (uint8_t*)flat_pmem);
		// No need to flush cache - encryption uses non-temporal memcpy().

		return PMEM_CIPHER_BLOCK_SIZE;
	}

	flat_pmem->magic = AS_FLAT_MAGIC_DIRTY;
	pmem_persist(&flat_pmem->magic, sizeof(flat_pmem->magic));

	return sizeof(flat_pmem->magic);
}

static void
persist_and_mark_clean(const drv_pmem* pmem, as_flat_record* flat_pmem,
		size_t flush_size, bool encrypt)
{
	pmem_persist(flat_pmem, flush_size);

	if (encrypt) {
		uint64_t offset = (uint8_t*)flat_pmem - pmem->pmem_base_addr;

		as_flat_record* flat = decrypt_sized_flat(pmem, offset,
				PMEM_CIPHER_BLOCK_SIZE, (uint8_t*)flat_pmem);

		flat->magic = AS_FLAT_MAGIC;

		// XTS mode allows us to replace the first 16 bytes of the encrypted
		// data. (Unlike, for example, CBC mode.)
		encrypt_data(pmem, offset, PMEM_CIPHER_BLOCK_SIZE, (const uint8_t*)flat,
				(uint8_t*)flat_pmem);
		// No need to flush cache - encryption uses non-temporal memcpy().
	}
	else {
		flat_pmem->magic = AS_FLAT_MAGIC;
		pmem_persist(&flat_pmem->magic, sizeof(flat_pmem->magic));
	}
}

static void
copy_flat(as_flat_record* out, const as_flat_record* in, size_t size,
		bool encrypted)
{
	if (encrypted) {
		memcpy(out, in, size);
	}
	else {
		pmem_memcpy(out, in, size, PMEM_F_MEM_NONTEMPORAL);
	}
}


//==========================================================
// Local helpers - shadow utilities.
//

int
shadow_fd_get(drv_pmem* pmem)
{
	int fd = -1;
	int rv = cf_queue_pop(pmem->shadow_fd_q, (void*)&fd, CF_QUEUE_NOWAIT);

	if (rv != CF_QUEUE_OK) {
		fd = open(pmem->shadow_name, pmem->open_flag, cf_os_base_perms());

		if (-1 == fd) {
			cf_crash(AS_DRV_PMEM, "%s: DEVICE FAILED open: errno %d (%s)",
					pmem->shadow_name, errno, cf_strerror(errno));
		}
	}

	return fd;
}

static void
shadow_fd_put(drv_pmem* pmem, int fd)
{
	cf_queue_push(pmem->shadow_fd_q, (void*)&fd);
}

static void
shadow_flush_pwb(drv_pmem* pmem, pmem_write_block* pwb)
{
	int fd = shadow_fd_get(pmem);
	off_t write_offset = (off_t)WBLOCK_ID_TO_OFFSET(pwb->wblock_id);

	uint64_t start_ns = pmem->ns->storage_benchmarks_enabled ? cf_getns() : 0;

	if (! pwrite_all(fd, pwb->base_addr, PMEM_WRITE_BLOCK_SIZE,
			write_offset)) {
		cf_crash(AS_DRV_PMEM, "%s: DEVICE FAILED write: errno %d (%s)",
				pmem->shadow_name, errno, cf_strerror(errno));
	}

	if (start_ns != 0) {
		histogram_insert_data_point(pmem->hist_shadow_write, start_ns);
	}

	shadow_fd_put(pmem, fd);
}


//==========================================================
// Local helpers - encryption utilities.
//

static as_flat_record*
decrypt_sized_flat(const drv_pmem* pmem, uint64_t off, size_t len,
		uint8_t* buf_in)
{
	if (pmem->ns->storage_encryption_key_file == NULL) {
		return (as_flat_record*)buf_in;
	}

	as_flat_record* flat = get_scratch_thread_buffer(len);
	uint8_t* buf_out = (uint8_t*)flat;

	while (len != 0) {
		size_t dec_len = len > MAX_XTS_LEN ? MAX_XTS_LEN : len;

		drv_xts_decrypt(pmem->ns->storage_encryption, pmem->encryption_key, off,
				buf_in, dec_len, buf_out);

		off += dec_len;
		buf_in += dec_len;
		buf_out += dec_len;
		len -= dec_len;
	}

	return flat;
}

static const as_flat_record*
decrypt_flat(const drv_pmem* pmem, uint64_t off, const uint8_t* buf_in)
{
	if (pmem->ns->storage_encryption_key_file == NULL) {
		return (const as_flat_record*)buf_in;
	}

	// Ensure caller fails magic check.
	static const as_flat_record invalid_flat = { .magic = 0 };
	uint64_t* block64 = (uint64_t*)buf_in;

	if (block64[0] == 0 && block64[1] == 0) {
		// We pad wblock ends with all zeros, and don't encrypt this padding.
		// Make sure we don't accidentally decrypt all zeros to good magic.
		return &invalid_flat;
	}

	as_flat_record dec;

	drv_xts_decrypt(pmem->ns->storage_encryption, pmem->encryption_key, off,
			buf_in, 16, (uint8_t*)&dec);

	if (dec.magic != AS_FLAT_MAGIC && dec.magic != AS_FLAT_MAGIC_DIRTY) {
		return &invalid_flat;
	}

	size_t len = N_RBLOCKS_TO_SIZE(dec.n_rblocks);
	as_flat_record* flat = get_scratch_thread_buffer(len);
	uint8_t* buf_out = (uint8_t*)flat;

	while (len != 0) {
		size_t dec_len = len > MAX_XTS_LEN ? MAX_XTS_LEN : len;

		drv_xts_decrypt(pmem->ns->storage_encryption, pmem->encryption_key, off,
				buf_in, dec_len, buf_out);

		off += dec_len;
		buf_in += dec_len;
		buf_out += dec_len;
		len -= dec_len;
	}

	return flat;
}

static void
encrypt_flat(const drv_pmem* pmem, uint64_t off, const as_flat_record* flat,
		uint8_t* buf_out)
{
	encrypt_data(pmem, off, N_RBLOCKS_TO_SIZE(flat->n_rblocks),
			(const uint8_t*)flat, buf_out);
}

static void
encrypt_data(const drv_pmem* pmem, uint64_t off, size_t len, const uint8_t* buf,
		uint8_t* buf_out)
{
	uint8_t block[MAX_XTS_LEN];

	while (len != 0) {
		size_t enc_len = len > MAX_XTS_LEN ? MAX_XTS_LEN : len;

		drv_xts_encrypt(pmem->ns->storage_encryption, pmem->encryption_key, off,
				buf, enc_len, block);

		pmem_memcpy(buf_out, block, enc_len, PMEM_F_MEM_NONTEMPORAL);

		off += enc_len;
		buf += enc_len;
		buf_out += enc_len;
		len -= enc_len;
	}
}

static void*
get_scratch_thread_buffer(size_t write_sz)
{
	// Not unified with compression buffer - overlapping lifetimes.
	// Not unified with decompression buffer - can't decompress in place.

	static __thread size_t buffer_sz = 0;
	static __thread void* buffer = NULL;

	if (write_sz > buffer_sz) {
		buffer_sz = write_sz;
		cf_thread_realloc(&buffer, &buffer_sz);
	}

	return buffer;
}
