/*
 * dc.c
 *
 * Copyright (C) 2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "xdr/dc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aerospike/as_atomic.h"
#include "aerospike/as_password.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_queue.h"

#include "cf_mutex.h"
#include "cf_thread.h"
#include "dynbuf.h"
#include "fetch.h"
#include "log.h"
#include "msg.h"
#include "node.h"
#include "vector.h"
#include "vmapx.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/exp.h"
#include "base/features_ee.h"
#include "base/index.h"
#include "base/smd.h"
#include "base/xdr.h"
#include "fabric/fabric.h"
#include "fabric/partition.h"
#include "fabric/partition_balance.h"
#include "fabric/partition_ee.h"
#include "xdr/cluster.h"
#include "xdr/dc_manager.h"
#include "xdr/reader.h"
#include "xdr/ship.h"
#include "xdr/xdr_ee.h"

//#include "warnings.h" // generates warnings we're living with for now


//==========================================================
// Typedefs & constants.
//

#define LST_PUBLISH_PERIOD_MS (2 * 1000)
#define LST_SAFETY_MS (3 * 1000) // 3 seconds - TODO - what about clock skew?

#define LST_PERSIST_PERIOD_MS (30 * 1000)

#define DC_INACTIVE_PERIOD_US (1000 * 1000)

#define LAP_RECS_QUOTA_SPLIT 4 // total/recovery

// Per-partition.
#define MAX_IN_PROGRESS 50
#define MAX_RECOVERY_IN_PROGRESS 1000
#define N_WINDOWS 8
#define RETRY_THROTTLE_THRESHOLD N_WINDOWS // each window may have only one req
#define RETRY_SPEEDUP_THRESHOLD 3
#define RETRY_INTERVAL_MAX 10

#define DEAD_STATS_IX 0

typedef struct dc_q_ele_s {
	cf_digest keyd;
	uint64_t lut: 40;
} __attribute__ ((__packed__)) dc_q_ele;

typedef struct window_s {
	uint64_t lst;
	uint32_t n_in_progress;
} window;

typedef enum {
	TRANSACTION,
	STARTUP,
	PRE_RECOVERY,
	RECOVERY,
	POST_RECOVERY_JOB,
	RECOVERY_DRAIN,
	RECOVERY_INCOMPLETE
} partition_state;

static const char state_as_char [] = {
	'T', // TRANSACTION
	'S', // STARTUP
	'B', // PRE_RECOVERY
	'R', // RECOVERY
	'A', // POST_RECOVERY_JOB
	'D', // RECOVERY_DRAIN
	'I'  // RECOVERY_INCOMPLETE
};

typedef struct dc_partition_s {
	uint64_t safe_lst; // includes safety margin
	uint64_t first_trans_lut;

	uint64_t last_published;
	bool lst_update_pending;

	char role;
	partition_state state;
	bool recovery_aborted;
	bool recovery_job_done;

	bool trans_q_used;
	bool retry_q_used;

	cf_mutex trans_q_lock;
	cf_mutex retry_q_lock;

	cf_queue* trans_q;
	cf_queue* retry_q;

	uint32_t retry_interval;

	uint32_t at_window;
	uint32_t n_windows;
	window windows[N_WINDOWS];
} dc_partition;

typedef struct partition_aggr_s {
	uint64_t min_safe_lst;
	uint64_t trans_q_total;
	uint32_t n_in_progress;
} partition_aggr;

typedef struct dcn_stats_s {
	partition_aggr pa;
	uint32_t n_recoveries;
	uint32_t n_recoveries_pending;
	uint64_t n_hot_keys;
	uint32_t throughput; // updated only in ticker
	uint64_t prev_n_success; // not a stat - used to derive throughput
} dcn_stats;

typedef struct dc_namespace_s {
	bool enabled;
	bool disabling;
	bool is_self_hub;
	bool need_recovery_quota;
	uint64_t last_persisted;
	uint64_t last_persisted_lst;
	uint32_t base_pid;
	uint32_t max_lap_recs;
	uint32_t n_recs_left;
	uint32_t n_recovery_recs_left;
	uint64_t n_ships;
	uint64_t n_prev_ships;
	cf_mutex filter_lock;
	xdr_filter* filter;
	dc_partition dcps[AS_PARTITIONS];
	dcn_stats stats;
} dc_namespace;

// We rely on no padding to delete by value from recovery queue.
typedef struct recovery_job_s {
	uint32_t ns_ix;
	uint32_t pid;
	bool resume;
	cf_digest last_keyd;
} recovery_job;

typedef struct find_recovery_job_s {
	uint32_t ns_ix;
	uint32_t pid;
	bool found;
} find_recovery_job;

typedef struct recovery_info_s {
	as_dc* dc;
	as_namespace* ns;
	dc_partition* dcp;
	bool* resume;
	cf_digest* last_keyd;
} recovery_info;

typedef struct find_ele_s {
	const cf_digest* keyd;
	uint64_t lut;
	uint64_t lut_limit;
	bool found;
} find_ele;


//==========================================================
// Globals.
//

static __thread tl_dc_stats* g_tl_dc_stats[AS_XDR_MAX_DCS] = { NULL };


//==========================================================
// Forward declarations.
//

static bool should_submit(const as_dc* dc, const as_namespace* ns, const as_xdr_submit_info* info);
static bool already_in_trans_q(cf_queue* q, const dc_q_ele* ele, uint32_t hot_key_ms);
static int hot_key_cb(void* buf, void* udata);

static void* run_dc(void* udata);
static void handle_hub_change(const as_namespace* ns, dc_namespace* dcn);
static void persist_lst(as_dc* dc, const as_namespace* ns);
static void update_max_lap_recs(dc_namespace* dcn, uint32_t max_throughput, uint32_t period);
static void update_lap_quotas(dc_namespace* dcn);
static void process_master(as_dc* dc, uint32_t ns_ix, uint32_t pid, bool is_immigrating, partition_aggr* pa);
static void process_prole(as_dc* dc, uint32_t ns_ix, uint32_t pid);
static void process_none(as_dc* dc, uint32_t ns_ix, uint32_t pid);
static void process_disabled(as_dc* dc, uint32_t ns_ix);

static void process_trans_q(as_dc* dc, as_namespace* ns, dc_partition* dcp);
static bool process_retry_q(as_dc* dc, const as_namespace* ns, dc_partition* dcp);
static void advance_safe_lst_idle(dc_partition* dcp);
static void advance_safe_lst(dc_partition* dcp);
static void publish_safe_lst(as_dc* dc, uint32_t ns_ix, uint32_t pid);
static void enqueue_recovery_job(as_dc* dc, dc_partition* dcp, uint32_t ns_ix, uint32_t pid);

static bool abort_recovery_job(as_dc* dc, dc_partition* dcp, uint32_t ns_ix, uint32_t pid);
static int abort_recovery_cb(void* buf, void* udata);

static void trim_trans_q(as_dc* dc, dc_partition* dcp);
static void empty_trans_q(dc_partition* dcp);
static bool empty_trans_q_on_overflow(dc_partition* dcp, uint32_t limit);
static void empty_retry_q(dc_partition* dcp);

static void* run_recovery(void* udata);
static bool recovery_reduce_cb(as_index_ref* r_ref, void* udata);

static void complete_ship_request(ship_request* req, int32_t result);
static void requeue_ship_request(const ship_request* req, int32_t result);
static void abandon_ship_request(ship_request* req, int32_t result, bool warn);

static void init_config(as_xdr_dc_cfg* cfg, const char* name);
static void init_ns_config(as_xdr_dc_ns_cfg* cfg);
static void destroy_config(as_xdr_dc_cfg* cfg);
static bool remote_namespace_is_valid(const as_xdr_dc_cfg* dc_cfg, const char* ns_name);

static void dc_update_throughput(as_dc* dc, uint64_t delta_time);
static void dc_aggregate_dcn_stats(const as_dc* dc, dcn_stats* na);
static void dc_aggregate_tl_dc_stats(as_dc* dc);
static void dc_aggregate_tl_ns_stats(as_dc* dc, tl_ns_stats* ta);
static void ns_aggregate_tl_ns_stats(as_dc* dc, uint32_t ns_ix, tl_ns_stats* ta);
static void add_tl_ns_stats(const tl_ns_stats* stats, tl_ns_stats* ta);
static void add_tl_ns_averages(const tl_ns_stats* stats, tl_ns_stats* ta);
static void append_ns_stats(const dcn_stats* n, const tl_ns_stats* ta, cf_dyn_buf* db);
static void invalidate_stats(as_dc* dc);


//==========================================================
// Inlines & macros.
//

static inline bool
is_hot_key(const as_xdr_submit_info* info, uint32_t hot_key_ms)
{
	return info->lut - info->prev_lut < (uint64_t)hot_key_ms;
}

// TODO - consolidate with other moving average utils?
static inline void
update_avg_latency(double* avg, uint64_t val)
{
	*avg = (*avg * 0.999) + ((double)val * 0.001); // thread local
}

static inline uint32_t
total_in_progress(const dc_partition* dcp)
{
	uint32_t total = 0;

	for (uint32_t w_ix = 0; w_ix < N_WINDOWS; w_ix++) {
		total += dcp->windows[w_ix].n_in_progress;
	}

	return total;
}

static inline uint64_t
calculate_lag(uint64_t min_safe_lst)
{
	int64_t lag = 0;
	uint64_t now = cf_clepoch_milliseconds();

	// Note - there may not be any masters - that's ok.
	if (min_safe_lst != UINT64_MAX) {
		lag = (int64_t) (now - (min_safe_lst + LST_SAFETY_MS)) / 1000;
	}

	return lag > 0 ? (uint64_t)lag : 0;
}

static inline const char*
state_string(partition_state state)
{
	switch (state) {
	case TRANSACTION:
		return "TRANSACTION";
	case STARTUP:
		return "STARTUP";
	case PRE_RECOVERY:
		return "PRE_RECOVERY";
	case RECOVERY:
		return "RECOVERY";
	case POST_RECOVERY_JOB:
		return "POST_RECOVERY_JOB";
	case RECOVERY_DRAIN:
		return "RECOVERY_DRAIN";
	case RECOVERY_INCOMPLETE:
		return "RECOVERY_INCOMPLETE";
	default:
		cf_crash(AS_XDR, "invalid state %d", (int)state);
		return NULL;
	}
}


//==========================================================
// Public API - enterprise only - DC lifecycle.
// Called only at startup or under set-config info lock.
//

as_dc*
as_dc_create(const char* name, uint32_t dc_ix)
{
	as_dc* dc = cf_calloc(1, sizeof(as_dc));

	dc->ix = dc_ix;
	dc->state = DC_DISCONNECTED;

	as_xdr_dc_cfg* cfg = &dc->cfg;

	init_config(cfg, name);

	cf_mutex_init(&cfg->seed_lock);
	cf_vector_init(&cfg->seed_nodes, sizeof(seed_node_cfg), 8, 0);

	cf_info(AS_XDR, "DC %s created", name);
	cf_detail(AS_XDR, "DC %s using slot %u", name, dc->ix);

	return dc;
}

as_xdr_dc_ns_cfg*
as_dc_create_ns_cfg(const char* ns_name)
{
	as_xdr_dc_ns_cfg* cfg = cf_calloc(1, sizeof(as_xdr_dc_ns_cfg));

	cfg->ns_name = cf_strdup(ns_name);

	init_ns_config(cfg);

	return cfg;
}

void
as_dc_cfg_post_process(as_dc* dc)
{
	as_xdr_dc_cfg* dc_cfg = &dc->cfg;

	if (dc_cfg->connector && dc_cfg->auth_mode != XDR_AUTH_NONE) {
		cf_crash_nostack(AS_XDR, "DC %s can't set 'auth-mode' if 'connector' is 'true'",
				dc_cfg->name);
	}

	if (dc_cfg->auth_user != NULL && dc_cfg->auth_password_file == NULL) {
		cf_crash_nostack(AS_XDR, "DC %s has 'auth-user' but no 'auth-password-file'",
				dc_cfg->name);
	}

	if (dc_cfg->auth_user == NULL && dc_cfg->auth_password_file != NULL) {
		cf_crash_nostack(AS_XDR, "DC %s has 'auth-password-file' but no 'auth-user'",
				dc_cfg->name);
	}

	// Courtesy - 5.7 requires 'auth-mode' be explicitly set to 'internal'.
	if (dc_cfg->auth_user != NULL && dc_cfg->auth_mode == XDR_AUTH_NONE) {
		cf_crash_nostack(AS_XDR, "DC %s has 'auth-user' but 'auth-mode' is 'none'",
				dc_cfg->name);
	}

	if (dc_cfg->auth_user != NULL && dc_cfg->auth_mode == XDR_AUTH_INTERNAL &&
			! cf_fetch_validate_string(dc_cfg->auth_password_file)) {
		cf_crash_nostack(AS_XDR, "DC %s can't read password", dc_cfg->name);
	}

	if (dc_cfg->connector && ! as_features_change_notification()) {
		cf_crash_nostack(AS_XDR, "DC %s 'connector' not allowed by feature key",
				dc_cfg->name);
	}

	cf_vector* nv = &dc_cfg->seed_nodes;
	uint32_t n_seeds = cf_vector_size(nv);

	for (uint32_t i = 0; i < n_seeds; i++) {
		seed_node_cfg node_cfg;

		cf_vector_get(nv, i, &node_cfg);

		if (dc_cfg->tls_our_name != NULL && node_cfg.tls_name == NULL) {
			cf_crash_nostack(AS_XDR, "DC %s missing TLS name for node %s:%s",
					dc_cfg->name, node_cfg.host, node_cfg.port);
		}

		if (dc_cfg->tls_our_name == NULL && node_cfg.tls_name != NULL) {
			cf_crash_nostack(AS_XDR, "DC %s unexpected TLS name for node %s:%s:%s",
					dc_cfg->name, node_cfg.host, node_cfg.port,
					node_cfg.tls_name);
		}
	}

	cf_vector* nsv = dc_cfg->ns_cfg_v;
	uint32_t n_ns_cfgs = cf_vector_size(nsv);

	for (uint32_t i = 0; i < n_ns_cfgs; i++) {
		as_xdr_dc_ns_cfg* dc_ns_cfg = cf_vector_get_ptr(nsv, i);
		as_namespace* ns = as_namespace_get_byname(dc_ns_cfg->ns_name);

		if (ns == NULL) {
			cf_crash_nostack(AS_XDR, "DC %s has invalid namespace '%s'",
					dc_cfg->name, dc_ns_cfg->ns_name);
		}

		if (dc_cfg->ns_cfgs[ns->ix] != NULL) {
			cf_crash_nostack(AS_XDR, "DC %s has multiple instances of namespace '%s'",
					dc_cfg->name, dc_ns_cfg->ns_name);
		}

		if (dc_ns_cfg->delay_ms > dc_ns_cfg->hot_key_ms) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s 'hot-key-ms' %u must be >= 'delay-ms' %u",
					dc_ns_cfg->ns_name, dc_cfg->name,
					dc_ns_cfg->hot_key_ms, dc_ns_cfg->delay_ms);
		}

		if (dc_ns_cfg->remote_namespace != NULL &&
				! remote_namespace_is_valid(dc_cfg,
						dc_ns_cfg->remote_namespace)) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s has invalid 'remote-namespace'",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		if (dc_cfg->connector && dc_ns_cfg->ship_bin_luts) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s can't set 'ship-bin-luts' to 'true' if 'connector' is 'true'",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		if (! dc_cfg->connector &&
				dc_ns_cfg->bin_policy == XDR_BIN_POLICY_NO_BINS) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s can't set 'bin-policy' to 'no-bins' unless 'connector' is 'true'",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		uint32_t n_ignored_bins = cf_vector_size(dc_ns_cfg->ignored_bins);
		uint32_t n_shipped_bins = cf_vector_size(dc_ns_cfg->shipped_bins);

		if (ns->single_bin &&
				(dc_ns_cfg->bin_policy != XDR_BIN_POLICY_ALL ||
						n_ignored_bins != 0 || n_shipped_bins != 0)) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s configuring bins in single-bin namespace",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		if (dc_ns_cfg->bin_policy == XDR_BIN_POLICY_ALL &&
				dc_ns_cfg->ship_bin_luts) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s can't set 'ship-bin-luts' to 'true' if 'bin-policy' is 'all'",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		if (dc_ns_cfg->bin_policy != XDR_BIN_POLICY_ALL &&
				dc_ns_cfg->write_policy == XDR_WRITE_POLICY_REPLACE) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s can't set 'write-policy' to 'replace' if 'bin-policy' is not 'all'",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		if (dc_ns_cfg->ship_bin_luts && g_config.xdr_cfg.src_id == 0) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s can't set 'ship-bin-luts' to 'true' if xdr context 'src-id' is 0",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		if (n_ignored_bins != 0 &&
				ships_specified_bins(dc_ns_cfg->bin_policy)) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s can't ignore bins if 'bin-policy' ships specified bins",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		if (n_shipped_bins != 0 &&
				! ships_specified_bins(dc_ns_cfg->bin_policy)){
			cf_crash_nostack(AS_XDR, "{%s} DC %s can't specify bins unless 'bin-policy' ships specified bins",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		if (n_ignored_bins > MAX_BIN_NAMES || n_shipped_bins > MAX_BIN_NAMES) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s has too many bins in namespace",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		if (cf_vector_size(dc_ns_cfg->ignored_sets) +
				cf_vector_size(dc_ns_cfg->shipped_sets) > AS_SET_MAX_COUNT) {
			cf_crash_nostack(AS_XDR, "{%s} DC %s has too many sets in namespace",
					dc_ns_cfg->ns_name, dc_cfg->name);
		}

		// Transfer ownership from startup-only vector to quick-access array.
		dc_cfg->ns_cfgs[ns->ix] = dc_ns_cfg;
	}
}

void
as_dc_link_tls(as_dc* dc)
{
	as_xdr_dc_cfg* cfg = &dc->cfg;

	if (cfg->tls_our_name != NULL &&
			(cfg->tls_spec = cfg_link_tls("xdr", &cfg->tls_our_name)) == NULL) {
		cf_crash_nostack(AS_XDR, "DC %s failed to set up tls", cfg->name);
	}

	if (cfg->auth_mode == XDR_AUTH_EXTERNAL && cfg->tls_spec == NULL) {
		cf_crash_nostack(AS_XDR, "DC %s external auth-mode requires tls",
				cfg->name);
	}

	if (cfg->auth_mode == XDR_AUTH_PKI && cfg->tls_spec == NULL) {
		cf_crash_nostack(AS_XDR, "DC %s pki auth-mode requires tls", cfg->name);
	}
}

void
as_dc_run(as_dc* dc)
{
	cf_queue_init(&dc->recovery_q, sizeof(recovery_job), 8, true);

	cf_mutex_init(&dc->stats_lock);
	cf_vector_init(&dc->stats, sizeof(tl_dc_stats*), 32, 0);

	// Dead thread stats is always first element in vector.
	cf_vector_append_ptr(&dc->stats, cf_calloc(1, sizeof(tl_dc_stats)));

	as_cluster_create(dc->ix, &dc->cfg);

	cf_thread_create_detached(run_dc, dc);
	cf_thread_create_detached(run_recovery, dc);
}

bool
as_dc_connect(as_dc* dc)
{
	if (dc->state == DC_CONNECTED) {
		cf_detail(AS_XDR, "DC %s already connected", dc->cfg.name);
		return true;
	}

	if (cf_vector_size(&dc->cfg.seed_nodes) == 0) {
		cf_warning(AS_XDR, "DC %s has no seeds", dc->cfg.name);
		return false;
	}

	if (! as_cluster_connect(dc->ix)) {
		cf_warning(AS_XDR, "DC %s connect failed", dc->cfg.name);
		return false;
	}

	dc->state = DC_CONNECTED;

	cf_info(AS_XDR, "DC %s connected", dc->cfg.name);

	return true;
}

void
as_dc_disconnect(as_dc* dc)
{
	if (dc->state == DC_DISCONNECTED) {
		cf_detail(AS_XDR, "DC %s already disconnected", dc->cfg.name);
		return;
	}

	cf_info(AS_XDR, "DC %s disconnecting ...", dc->cfg.name);

	as_cluster_disconnect(dc->ix);

	dc->state = DC_DISCONNECTED;
}

bool
as_dc_reuse(as_dc* dc, const char* name)
{
	if (! as_cluster_reusable(dc->ix)) {
		cf_detail(AS_XDR, "DC slot %u (%s) not reusable", dc->ix, dc->cfg.name);
		return false;
	}

	cf_detail(AS_XDR, "DC %s reusing slot %u", name, dc->ix);

	as_xdr_dc_cfg* dc_cfg = &dc->cfg;

	// Perform cleanup skipped by as_dc_destroy() - tend thread gone now.
	destroy_config(dc_cfg);
	invalidate_stats(dc);

	// Set the new stuff.
	init_config(dc_cfg, name);

	// Cleanup and set new stuff at namespace level.
	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_xdr_dc_ns_cfg* dc_ns_cfg = dc_cfg->ns_cfgs[ns_ix];
		char* ns_name = dc_ns_cfg->ns_name;

		if (dc_ns_cfg->remote_namespace != NULL) {
			cf_free(dc_ns_cfg->remote_namespace);
		}

		memset(dc_ns_cfg, 0, sizeof(as_xdr_dc_ns_cfg));

		dc_ns_cfg->ns_name = ns_name;
		init_ns_config(dc_ns_cfg);
	}

	dc->state = DC_DISCONNECTED;

	cf_info(AS_XDR, "DC %s created", name);

	return true;
}

bool
as_dc_delete(as_dc* dc)
{
	if (! as_cluster_delete(dc->ix)) {
		cf_warning(AS_XDR, "DC %s delete failed", dc->cfg.name);
		return false;
	}

	cf_info(AS_XDR, "DC %s deleting ...", dc->cfg.name);

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_dc_remove_ns(dc, g_config.namespaces[ns_ix]);
	}

	dc->state = DC_UNUSED;

	// Skip config cleanup - still in use by tend thread.

	return true;
}

void
as_dc_cluster_changed_cb(as_dc* dc)
{
	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		dc_namespace* dcn = dc->dcns[ns_ix];

		if (! dcn->enabled) {
			continue;
		}

		for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
			dcn->dcps[pid].last_published = 0;
		}
	}
}


//==========================================================
// Public API - enterprise only - namespace lifecycle.
//

void
as_dc_init_ns(as_dc* dc, const as_namespace* ns)
{
	dc_namespace* dcn = cf_calloc(1, sizeof(dc_namespace));

	cf_mutex_init(&dcn->filter_lock);

	dcn->stats.pa = (partition_aggr){ .min_safe_lst = UINT64_MAX };

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		dc_partition* dcp = &dcn->dcps[pid];

		cf_mutex_init(&dcp->trans_q_lock);
		cf_mutex_init(&dcp->retry_q_lock);

		dcp->trans_q = cf_queue_create(sizeof(dc_q_ele), false);
		dcp->retry_q = cf_queue_create(sizeof(ship_request*), false);

		dcp->role = 'U';
		dcp->state = STARTUP;
	}

	dc->dcns[ns->ix] = dcn;
}

void
as_dc_add_ns(as_dc* dc, const as_namespace* ns, uint64_t lst)
{
	dc_namespace* dcn = dc->dcns[ns->ix];

	if (dcn->enabled) {
		return;
	}

	// Make sure previous remove got to its final state.
	if (dcn->disabling) {
		usleep(1000);
	}

	dcn->last_persisted = 0;
	dcn->last_persisted_lst = lst;

	// Make placeholder less than lst (now) to avoid multiple recoveries.
	uint64_t now = cf_clepoch_milliseconds();
	uint64_t placeholder = now - 100;

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		dc_partition* dcp = &dcn->dcps[pid];

		dcp->first_trans_lut = placeholder; // until submit updates it
		dcp->safe_lst = lst;
		dcp->trans_q_used = false;
		dcp->retry_interval = 0;
	}

	dcn->enabled = true;
}

void
as_dc_remove_ns(as_dc* dc, const as_namespace* ns)
{
	dc_namespace* dcn = dc->dcns[ns->ix];

	dcn->disabling = true; // limit processing to one lap
	dcn->enabled = false;

	// dcn->is_self_hub - must be set false in run_dc thread.
	dcn->need_recovery_quota = false;
	// dcn->last_persisted - handled when adding namespace.
	// dcn->last_persisted_lst - handled when adding namespace.
	dcn->base_pid = 0;
	// dcn->max_lap_recs - will be set as needed during run_dc().
	// dcn->n_recs_left - will be set as needed during run_dc().
	// dcn->n_recovery_recs_left - will be set as needed during run_dc().
	dcn->n_ships = 0;
	dcn->n_prev_ships = 0;
	// dcn->dc_partitions - stay active.
	// dcn->stats.pa - will be reset by process_disabled().
	// dcn->stats.n_recoveries - leave history.
	// dcn->stats.n_recoveries_pending - stay active.
	// dcn->stats.n_hot_keys - leave history.
	// dcn->stats.throughput - stay active.
	// dcn->stats.prev_n_success - leave history.
}

bool
as_dc_has_ns(const as_dc* dc, const as_namespace* ns)
{
	return dc->dcns[ns->ix]->enabled;
}

bool
as_dc_has_any_ns(const as_dc* dc)
{
	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		if (dc->dcns[ns_ix]->enabled) {
			return true;
		}
	}

	return false;
}

bool
as_dc_update_ns_remote_namespace(as_dc* dc, const as_namespace* ns,
		const char* ns_name)
{
	if (strlen(ns_name) >= AS_ID_NAMESPACE_SZ) {
		cf_warning(AS_XDR, "remote namespace '%s' too long", ns_name);
		return false;
	}

	as_xdr_dc_cfg* dc_cfg = &dc->cfg;
	char* name = NULL;

	if (strcmp(ns_name, "null") != 0) { // remote-namespace "null" unmaps
		if (! remote_namespace_is_valid(dc_cfg, ns_name)) {
			return false;
		}

		name = cf_strdup(ns_name);
	}

	as_xdr_dc_ns_cfg* dc_ns_cfg = dc_cfg->ns_cfgs[ns->ix];

	if (dc_ns_cfg->remote_namespace != NULL) {
		cf_free(dc_ns_cfg->remote_namespace);
	}

	dc_ns_cfg->remote_namespace = name;

	return true;
}


//==========================================================
// Public API - enterprise only - setup namespace filters.
//

void
as_dc_setup_ns_bins(as_dc* dc, as_namespace* ns)
{
	as_xdr_dc_ns_cfg* cfg = dc->cfg.ns_cfgs[ns->ix];

	cf_vector* binv = cfg->ignored_bins;

	if (binv == NULL) {
		return; // namespace not configured in file for this DC
	}

	uint32_t sz = cf_vector_size(binv);

	for (uint32_t i = 0; i < sz; i++) {
		char* bin_name = cf_vector_get_ptr(binv, i);
		uint16_t bin_id;

		if (! as_bin_get_or_assign_id_w_len(ns, bin_name, strlen(bin_name),
				&bin_id)) {
			cf_crash(AS_XDR, "{%s} failed to create bin", ns->name);
		}

		cfg->bins[bin_id] = SHIPPING_DISABLED;
	}

	binv = cfg->shipped_bins;
	sz = cf_vector_size(binv);

	for (uint32_t i = 0; i < sz; i++) {
		char* bin_name = cf_vector_get_ptr(binv, i);
		uint16_t bin_id;

		if (! as_bin_get_or_assign_id_w_len(ns, bin_name, strlen(bin_name),
				&bin_id)) {
			cf_crash(AS_XDR, "{%s} failed to create bin", ns->name);
		}

		cfg->bins[bin_id] = SHIPPING_ENABLED;
	}

	cf_vector_destroy(cfg->ignored_bins);
	cf_vector_destroy(cfg->shipped_bins);
}

void
as_dc_setup_ns_sets(as_dc* dc, as_namespace* ns)
{
	as_xdr_dc_ns_cfg* cfg = dc->cfg.ns_cfgs[ns->ix];

	cf_vector* setv = cfg->ignored_sets;

	if (setv == NULL) {
		return; // namespace not configured in file for this DC
	}

	uint32_t sz = cf_vector_size(setv);

	for (uint32_t i = 0; i < sz; i++) {
		char* set_name = cf_vector_get_ptr(setv, i);
		uint16_t set_id = as_namespace_get_create_set_id(ns, set_name);

		if (set_id == INVALID_SET_ID) {
			cf_crash(AS_XDR, "{%s} failed to create set", ns->name);
		}

		cfg->sets[set_id] = SHIPPING_DISABLED;
	}

	setv = cfg->shipped_sets;
	sz = cf_vector_size(setv);

	for (uint32_t i = 0; i < sz; i++) {
		char* set_name = cf_vector_get_ptr(setv, i);
		uint16_t set_id = as_namespace_get_create_set_id(ns, set_name);

		if (set_id == INVALID_SET_ID) {
			cf_crash(AS_XDR, "{%s} failed to create set", ns->name);
		}

		cfg->sets[set_id] = SHIPPING_ENABLED;
	}

	cf_vector_destroy(cfg->ignored_sets);
	cf_vector_destroy(cfg->shipped_sets);
}

bool
as_dc_update_ns_bins(as_dc* dc, as_namespace* ns, const char* bin_name,
		bool enabled)
{
	uint16_t bin_id;

	// Users may want to define behavior of a bin before writing the records.
	if (! as_bin_get_or_assign_id_w_len(ns, bin_name, strlen(bin_name),
			&bin_id)) {
		return false;
	}

	as_xdr_dc_ns_cfg* cfg = dc->cfg.ns_cfgs[ns->ix];

	cfg->bins[bin_id] = enabled ? SHIPPING_ENABLED : SHIPPING_DISABLED;

	return true;
}

bool
as_dc_update_ns_sets(as_dc* dc, as_namespace* ns, const char* set_name,
		bool enabled)
{
	// Users may want to define behavior of a set before writing the records.
	uint16_t set_id = as_namespace_get_create_set_id(ns, set_name);

	if (set_id == INVALID_SET_ID) {
		return false;
	}

	as_xdr_dc_ns_cfg* cfg = dc->cfg.ns_cfgs[ns->ix];

	cfg->sets[set_id] = enabled ? SHIPPING_ENABLED : SHIPPING_DISABLED;

	return true;
}

void
as_dc_set_ns_filter(as_dc* dc, const struct as_namespace_s* ns, const char* b64)
{
	as_exp* exp = NULL;

	if (b64 != NULL &&
			(exp = as_exp_filter_build_base64(b64, strlen(b64))) == NULL) {
		cf_warning(AS_XDR, "can't build filter");
		return;
	}

	dc_namespace* dcn = dc->dcns[ns->ix];

	cf_mutex_lock(&dcn->filter_lock);

	if (dcn->filter != NULL) {
		xdr_filter_release(dcn->filter);
		dcn->filter = NULL;
	}

	if (exp != NULL) {
		dcn->filter = cf_rc_alloc(sizeof(xdr_filter));
		dcn->filter->exp = exp;
		dcn->filter->b64 = cf_strdup(b64);
	}

	cf_mutex_unlock(&dcn->filter_lock);
}

xdr_filter*
as_dc_get_ns_filter(const as_dc* dc, const as_namespace* ns)
{
	dc_namespace* dcn = dc->dcns[ns->ix];

	if (dcn->filter == NULL) {
		return NULL;
	}

	cf_mutex_lock(&dcn->filter_lock);

	if (dcn->filter == NULL) {
		cf_mutex_unlock(&dcn->filter_lock);
		return NULL;
	}

	cf_rc_reserve(dcn->filter);

	xdr_filter* filter = dcn->filter;

	cf_mutex_unlock(&dcn->filter_lock);

	return filter;
}


//==========================================================
// Public API - enterprise only - per-record.
//

void
as_dc_submit(as_dc* dc, const as_namespace* ns, const as_xdr_submit_info* info)
{
	dc_namespace* dcn = dc->dcns[ns->ix];

	if (! dcn->enabled) {
		return;
	}

	if (! should_submit(dc, ns, info)) {
		return;
	}

	uint32_t hot_key_ms = dc->cfg.ns_cfgs[ns->ix]->hot_key_ms;

	const cf_digest* keyd = &info->keyd;
	uint64_t lut = info->lut;

	dc_partition* dcp = &dcn->dcps[as_partition_getid(keyd)];
	dc_q_ele ele = { .keyd = *keyd, .lut = lut };

	cf_mutex_lock(&dcp->trans_q_lock);

	if (is_hot_key(info, hot_key_ms) &&
			already_in_trans_q(dcp->trans_q, &ele, hot_key_ms)) {
		dcn->stats.n_hot_keys++;
		as_xdr_trace(dc, keyd, lut, "hot-key");
		cf_mutex_unlock(&dcp->trans_q_lock);
		return;
	}

	if (! dcp->trans_q_used) {
		dcp->trans_q_used = true;
		dcp->first_trans_lut = lut;
	}

	as_xdr_trace(dc, keyd, lut, "submit");

	cf_queue_push(dcp->trans_q, &ele);

	cf_mutex_unlock(&dcp->trans_q_lock);
}

bool
as_dc_should_submit(const as_dc* dc, const as_namespace* ns, const as_record* r)
{
	as_xdr_dc_ns_cfg* cfg = dc->cfg.ns_cfgs[ns->ix];
	as_xdr_submit_info submit_info;

	as_xdr_get_submit_info(r, 0, &submit_info);

	if (ships_changed_bins(cfg->bin_policy)) {
		submit_info.xdr_write = false; // may have earlier locally written bins
	}

	return should_submit(dc, ns, &submit_info);
}

void
as_dc_ship_attempt_cb(as_dc* dc, const as_namespace* ns)
{
	as_incr_uint64(&dc->dcns[ns->ix]->n_ships);
}

void
as_dc_client_cb(int32_t result, void* udata)
{
	ship_request* req = (ship_request*)udata;
	as_dc* dc = req->dc;
	uint32_t ns_ix = req->ns->ix;
	tl_dc_stats* dc_stats = as_dc_get_tl_dc_stats(dc);
	tl_ns_stats* ns_stats = &dc_stats->ns_stats[ns_ix];

	switch (result) {
	case LOCAL_ERR_REC_READ:
	case LOCAL_ERR_REC_ABANDONED:
		// No stats for now - n_abandoned is for remote errors.
		abandon_ship_request(req, result, false);
		return;
	case LOCAL_ERR_REC_NOT_FOUND:
		ns_stats->n_not_found++;
		complete_ship_request(req, result);
		return;
	case LOCAL_ERR_REC_FILTERED_OUT:
		ns_stats->n_filtered_out++;
		complete_ship_request(req, result);
		return;
	case LOCAL_ERR_REC_UNREPLICATED:
		// Re-replication will submit with new lut_cutoff, but when shipping
		// changed bins, requeue to cover bin LUTs >= this request's lut_cutoff.
		// No stats for now - normal and not interesting enough.
		if (ships_changed_bins(dc->cfg.ns_cfgs[ns_ix]->bin_policy)) {
			requeue_ship_request(req, result);
		}
		else {
			abandon_ship_request(req, result, false);
		}
		return;
	case LOCAL_ERR_REC_REPLICATING:
	case LOCAL_ERR_CONN_BUSY:
		// No stats for now - normal and not interesting enough.
		requeue_ship_request(req, result);
		return;
	case LOCAL_ERR_NO_NODE:
		ns_stats->n_retry_no_node++;
		requeue_ship_request(req, result);
		return;
	case LOCAL_ERR_CONN_RESET:
		ns_stats->n_retry_conn_reset++;
		requeue_ship_request(req, result);
		return;
	case AS_OK:
	case AS_ERR_NOT_FOUND: // ok when shipping a delete
	case AS_ERR_LOST_CONFLICT: // ok - remote record not touched
		update_avg_latency(&dc_stats->latency_ns, cf_getns() - req->ship_time);
		ns_stats->n_success++;
		complete_ship_request(req, result);
		return;
	case AS_ERR_OUT_OF_SPACE:
	case AS_ERR_TIMEOUT:
	case AS_ERR_UNAVAILABLE:
	case AS_ERR_KEY_BUSY:
	case AS_ERR_DEVICE_OVERLOAD:
	case AS_SEC_ERR_NOT_AUTHENTICATED:
		ns_stats->n_retry_dest++;
		requeue_ship_request(req, result);
		return;
	default:
		ns_stats->n_abandoned++;
		abandon_ship_request(req, result, true);
		return;
	}
}


//==========================================================
// Public API - enterprise only - LST.
//

void
as_dc_init_safe_lsts(as_dc* dc, const as_namespace* ns, uint64_t lst)
{
	// Accept lst even when dcn is disabled.
	dc_namespace* dcn = dc->dcns[ns->ix];

	cf_info(AS_XDR, "{%s} DC %s init-lst %lu", ns->name, dc->cfg.name, lst);

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		dcn->dcps[pid].safe_lst = lst;
	}
}

void
as_dc_accept_safe_lst(as_dc* dc, const as_namespace* ns, uint32_t pid,
		uint64_t lst)
{
	// Accept lst even when dcn is disabled.
	dc_namespace* dcn = dc->dcns[ns->ix];
	dc_partition* dcp = &dcn->dcps[pid];

	// safe_lst should never go back. Maybe this was sent from an old master.
	if (lst < dcp->safe_lst) {
		return;
	}

	dcp->safe_lst = lst;
	dcp->lst_update_pending = false;

//	cf_debug(AS_XDR, "{%s:%u} DC %s safe_lst %lu first_trans_lut %lu", ns->name,
//			pid, dc->cfg.name, lst, dcp->first_trans_lut);
}

void
as_dc_update_ns_persisted_lst(as_dc* dc, const as_namespace* ns, uint64_t lst)
{
	dc_namespace* dcn = dc->dcns[ns->ix];

	if (dcn->enabled && lst > dcn->last_persisted_lst) {
		dcn->last_persisted_lst = lst;
	}
}

uint64_t
as_dc_ns_min_lst(const as_dc* dc, const as_namespace* ns)
{
	dc_namespace* dcn = dc->dcns[ns->ix];

	return dcn->enabled ? dcn->last_persisted_lst : UINT64_MAX;
}


//==========================================================
// Public API - enterprise only - info & stats.
//

void
as_dc_get_config(as_dc* dc, cf_dyn_buf* db)
{
	as_xdr_dc_cfg* cfg = &dc->cfg;

	as_xdr_auth_mode m = cfg->auth_mode;

	info_append_string(db, "auth-mode",
		m == XDR_AUTH_NONE ? "none" :
			(m == XDR_AUTH_INTERNAL ? "internal" :
				(m == XDR_AUTH_EXTERNAL ? "external" :
					(m == XDR_AUTH_EXTERNAL_INSECURE ? "external-insecure" :
						"illegal"))));

	info_append_string_safe(db, "auth-password-file", cfg->auth_password_file);
	info_append_string_safe(db, "auth-user", cfg->auth_user);
	info_append_bool(db, "connector", cfg->connector);
	info_append_uint32(db, "max-recoveries-interleaved",
			cfg->max_recoveries_interleaved);
	info_append_uint32(db, "max-used-service-threads",
			cfg->max_used_service_threads);

	cf_dyn_buf_append_string(db, "node-address-port=");

	cf_mutex_lock(&cfg->seed_lock);

	cf_vector* nv = &cfg->seed_nodes;
	seed_node_cfg node_cfg;

	uint32_t sz = cf_vector_size(nv);

	for (uint32_t i = 0; i < sz; i++) {
		cf_vector_get(nv, i, &node_cfg);
		cf_dyn_buf_append_string(db, node_cfg.host);
		cf_dyn_buf_append_char(db, ':');
		cf_dyn_buf_append_string(db, node_cfg.port);

		if (node_cfg.tls_name != NULL) {
			cf_dyn_buf_append_char(db, ':');
			cf_dyn_buf_append_string(db, node_cfg.tls_name);
		}

		cf_dyn_buf_append_char(db, ',');
	}

	cf_mutex_unlock(&cfg->seed_lock);

	cf_dyn_buf_chomp_char(db, ',');
	cf_dyn_buf_append_char(db, ';');

	info_append_uint32(db, "period-ms", cfg->period_us / 1000);
	info_append_string_safe(db, "tls-name", cfg->tls_our_name);
	info_append_bool(db, "use-alternate-access-address",
			cfg->use_alternate_access_address);

	cf_dyn_buf_append_string(db, "namespaces=");

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		dc_namespace* dcn = dc->dcns[ns_ix];

		if (! dcn->enabled) {
			continue;
		}

		cf_dyn_buf_append_string(db, g_config.namespaces[ns_ix]->name);
		cf_dyn_buf_append_char(db, ',');
	}

	cf_dyn_buf_chomp_char(db, ',');
	cf_dyn_buf_append_char(db, ';');
}

void
as_dc_get_ns_config(const as_dc* dc, const as_namespace* ns, cf_dyn_buf* db)
{
	as_xdr_dc_ns_cfg* cfg = dc->cfg.ns_cfgs[ns->ix];

	uint16_t n_sets = (uint16_t)cf_vmapx_count(ns->p_sets_vmap);
	uint16_t n_bins = (uint16_t)
			(ns->single_bin ? 0 : cf_vmapx_count(ns->p_bin_name_vmap));

	info_append_bool(db, "enabled", dc->dcns[ns->ix]->enabled);

	as_xdr_bin_policy b = cfg->bin_policy;

	info_append_string(db, "bin-policy",
		 b == XDR_BIN_POLICY_ALL ? "all" :
		(b == XDR_BIN_POLICY_NO_BINS ? "no-bins" :
		(b == XDR_BIN_POLICY_ONLY_CHANGED ? "only-changed" :
		(b == XDR_BIN_POLICY_CHANGED_AND_SPECIFIED ? "changed-and-specified" :
		(b == XDR_BIN_POLICY_CHANGED_OR_SPECIFIED ? "changed-or-specified" :
			"illegal")))));

	info_append_uint32(db, "compression-level", cfg->compression_level);
	info_append_uint32(db, "compression-threshold", cfg->compression_threshold);
	info_append_uint32(db, "delay-ms", cfg->delay_ms);
	info_append_bool(db, "enable-compression", cfg->compression_enabled);
	info_append_bool(db, "forward", cfg->forward);
	info_append_uint32(db, "hot-key-ms", cfg->hot_key_ms);

	cf_dyn_buf_append_string(db, "ignored-bins=");

	for (uint16_t bin_id = 0; bin_id < n_bins; bin_id++) {
		if (cfg->bins[bin_id] == SHIPPING_DISABLED) {
			cf_dyn_buf_append_string(db, as_bin_get_name_from_id(ns, bin_id));
			cf_dyn_buf_append_char(db, ',');
		}
	}

	cf_dyn_buf_chomp_char(db, ',');
	cf_dyn_buf_append_char(db, ';');

	info_append_bool(db, "ignore-expunges", cfg->ignore_expunges);

	cf_dyn_buf_append_string(db, "ignored-sets=");

	for (uint16_t set_ix = 0; set_ix < n_sets; set_ix++) {
		uint16_t set_id = set_ix + 1;

		if (cfg->sets[set_id] == SHIPPING_DISABLED) {
			cf_dyn_buf_append_string(db, as_namespace_get_set_name(ns, set_id));
			cf_dyn_buf_append_char(db, ',');
		}
	}

	cf_dyn_buf_chomp_char(db, ',');
	cf_dyn_buf_append_char(db, ';');

	info_append_uint32(db, "max-throughput", cfg->max_throughput);
	info_append_string_safe(db, "remote-namespace", cfg->remote_namespace);
	info_append_uint32(db, "sc-replication-wait-ms",
			cfg->sc_replication_wait_ms);

	cf_dyn_buf_append_string(db, "shipped-bins=");

	for (uint16_t bin_id = 0; bin_id < n_bins; bin_id++) {
		if (cfg->bins[bin_id] == SHIPPING_ENABLED) {
			cf_dyn_buf_append_string(db, as_bin_get_name_from_id(ns, bin_id));
			cf_dyn_buf_append_char(db, ',');
		}
	}

	cf_dyn_buf_chomp_char(db, ',');
	cf_dyn_buf_append_char(db, ';');

	info_append_bool(db, "ship-bin-luts", cfg->ship_bin_luts);
	info_append_bool(db, "ship-nsup-deletes", cfg->ship_nsup_deletes);
	info_append_bool(db, "ship-only-specified-sets",
			cfg->ship_only_specified_sets);

	cf_dyn_buf_append_string(db, "shipped-sets=");

	for (uint16_t set_ix = 0; set_ix < n_sets; set_ix++) {
		uint16_t set_id = set_ix + 1;

		if (cfg->sets[set_id] == SHIPPING_ENABLED) {
			cf_dyn_buf_append_string(db, as_namespace_get_set_name(ns, set_id));
			cf_dyn_buf_append_char(db, ',');
		}
	}

	cf_dyn_buf_chomp_char(db, ',');
	cf_dyn_buf_append_char(db, ';');

	info_append_uint32(db, "transaction-queue-limit",
			cfg->transaction_queue_limit);

	as_xdr_write_policy w = cfg->write_policy;

	info_append_string(db, "write-policy",
		w == XDR_WRITE_POLICY_AUTO ? "auto" :
			(w == XDR_WRITE_POLICY_UPDATE ? "update" :
				(w == XDR_WRITE_POLICY_REPLACE ? "replace" :
					"illegal")));
}

void
as_dc_get_stats(as_dc* dc, cf_dyn_buf* db)
{
	dcn_stats na = { { 0 } };
	tl_ns_stats ta = { 0 };

	dc_aggregate_dcn_stats(dc, &na);
	// No need yet to call dc_aggregate_tl_dc_stats().
	dc_aggregate_tl_ns_stats(dc, &ta);

	append_ns_stats(&na, &ta, db);

	cluster_info cinfo;

	as_cluster_info(dc->ix, &cinfo);

	// Updated only in ticker - not fresh.
	info_append_uint32(db, "nodes", cinfo.n_nodes);

	info_append_uint32(db, "throughput", dc->throughput);
	info_append_uint32(db, "latency_ms", dc->latency_ms);

	info_append_uint32(db, "lap_us", dc->lap_us); // not in ticker

	cf_dyn_buf_chomp_char(db, ';');
}

void
as_dc_get_ns_stats(as_dc* dc, const as_namespace* ns, cf_dyn_buf* db)
{
	dcn_stats* n = &dc->dcns[ns->ix]->stats;
	tl_ns_stats ta = { 0 };

	ns_aggregate_tl_ns_stats(dc, ns->ix, &ta);

	append_ns_stats(n, &ta, db);

	// Updated only in ticker - not fresh.
	info_append_uint32(db, "throughput", n->throughput);

	cf_dyn_buf_chomp_char(db, ';');
}

bool
as_dc_get_state(const as_dc* dc, const as_namespace* ns, cf_dyn_buf* db,
		bool add_header)
{
	dc_namespace* dcn = dc->dcns[ns->ix];

	if (! dcn->enabled) {
		return false;
	}

	if (add_header) {
		cf_dyn_buf_append_string(db,
				"namespace:"
				"partition:"
				"role:"
				"state:"
				"safe_lst:"
				"first_trans_lut:"
				"trans_q:"
				"retry_q:"
				"windows:"
				"in_progress;"
				);
	}

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		dc_partition* dcp = &dcn->dcps[pid];

		cf_dyn_buf_append_format(db,
				"%s:%4u:%c:%c:%s:%s:%7u:%5u:%1u:%5u;",
				ns->name,
				pid,
				dcp->role,
				state_as_char[dcp->state],
				as_xdr_pretty_ms(dcp->safe_lst),
				as_xdr_pretty_ms(dcp->first_trans_lut),
				cf_queue_sz(dcp->trans_q),
				cf_queue_sz(dcp->retry_q),
				dcp->n_windows,
				total_in_progress(dcp)
				);
	}

	return true;
}

void
as_dc_get_ns_display_filter(const as_dc* dc, const as_namespace* ns, bool b64,
		cf_dyn_buf* db)
{
	dc_namespace* dcn = dc->dcns[ns->ix];

	cf_dyn_buf_append_format(db, "namespace=%s:exp=", ns->name);

	cf_mutex_lock(&dcn->filter_lock);

	if (dcn->filter == NULL) {
		cf_dyn_buf_append_string(db, "null");
	}
	else if (b64) {
		cf_dyn_buf_append_string(db, dcn->filter->b64);
	}
	else {
		as_exp_display(dcn->filter->exp, db);
	}

	cf_mutex_unlock(&dcn->filter_lock);

	cf_dyn_buf_append_char(db, ';');
}

void
as_dc_ticker(as_dc* dc, uint64_t delta_time)
{
	dc_update_throughput(dc, delta_time);

	cluster_info cinfo;

	as_cluster_info(dc->ix, &cinfo);
	dc_aggregate_tl_dc_stats(dc);

	cf_info(AS_INFO, "xdr-dc %s: nodes %u latency-ms %u",
			dc->cfg.name,
			cinfo.n_nodes,
			dc->latency_ms
			);

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		dcn_stats* n = &dc->dcns[ns_ix]->stats;
		tl_ns_stats ta = { 0 };

		ns_aggregate_tl_ns_stats(dc, ns_ix, &ta);

		cf_info(AS_INFO, "{%s} xdr-dc %s: lag %lu throughput %u in-queue %lu in-progress %u complete (%lu,%lu,%lu,%lu) retries (%lu,%lu,%lu) recoveries (%u,%u) hot-keys %lu",
				g_config.namespaces[ns_ix]->name,
				dc->cfg.name,
				calculate_lag(n->pa.min_safe_lst),
				n->throughput,
				n->pa.trans_q_total,
				n->pa.n_in_progress,
				ta.n_success, ta.n_abandoned, ta.n_not_found, ta.n_filtered_out,
				ta.n_retry_no_node, ta.n_retry_conn_reset, ta.n_retry_dest,
				n->n_recoveries, n->n_recoveries_pending,
				n->n_hot_keys
				);
	}
}

tl_dc_stats*
as_dc_get_tl_dc_stats(as_dc* dc)
{
	uint32_t dc_ix = dc->ix;
	tl_dc_stats* stats = g_tl_dc_stats[dc_ix];

	if (stats != NULL) {
		if (stats->pending_reset) {
			memset(stats, 0, sizeof(tl_dc_stats));
		}

		return stats;
	}

	stats = cf_calloc(1, sizeof(tl_dc_stats));
	g_tl_dc_stats[dc_ix] = stats;

	cf_mutex_lock(&dc->stats_lock);
	cf_vector_append_ptr(&dc->stats, stats);
	cf_mutex_unlock(&dc->stats_lock);

	return stats;
}

void
as_dc_cleanup_tl_stats(as_dc* dc)
{
	tl_dc_stats* stats = g_tl_dc_stats[dc->ix];

	if (stats == NULL) {
		return;
	}

	cf_mutex_lock(&dc->stats_lock);

	tl_dc_stats* dead = cf_vector_get_ptr(&dc->stats, DEAD_STATS_IX);

	for (uint32_t i = 1; i < cf_vector_size(&dc->stats); i++) {
		tl_dc_stats* ele = cf_vector_get_ptr(&dc->stats, i);

		if (ele != stats) {
			continue;
		}

		// Consolidate dead thread's stats. For now, no DC-level dead stats.
		for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
			add_tl_ns_stats(&stats->ns_stats[ns_ix], &dead->ns_stats[ns_ix]);
		}

		cf_vector_delete(&dc->stats, i);
		g_tl_dc_stats[dc->ix] = NULL; // needed for pooled cf_threads

		cf_mutex_unlock(&dc->stats_lock);
		return;
	}

	cf_crash(AS_XDR, "DC %s - cleanup didn't find stats object", dc->cfg.name);
}


//==========================================================
// Local helpers - submit to dc.
//

static bool
should_submit(const as_dc* dc, const as_namespace* ns,
		const as_xdr_submit_info* info)
{
	as_xdr_dc_ns_cfg* cfg = dc->cfg.ns_cfgs[ns->ix];

	if (info->xdr_write && ! cfg->forward) {
		return false;
	}

	if (info->xdr_tombstone && ! info->xdr_nsup_tombstone &&
			cfg->ignore_expunges) {
		return false;
	}

	if (info->xdr_nsup_tombstone && ! cfg->ship_nsup_deletes) {
		return false;
	}

	if (cfg->ship_only_specified_sets &&
			cfg->sets[info->set_id] == SHIPPING_UNSPECIFIED) {
		return false;
	}

	if (cfg->sets[info->set_id] == SHIPPING_DISABLED) {
		return false;
	}

	return true;
}

static bool
already_in_trans_q(cf_queue* q, const dc_q_ele* ele, uint32_t hot_key_ms)
{
	find_ele fele = {
			.keyd = &ele->keyd,
			.lut = ele->lut,
			.lut_limit = ele->lut - hot_key_ms
	};

	cf_queue_reduce_reverse(q, hot_key_cb, (void*)&fele);

	return fele.found;
}

static int
hot_key_cb(void* buf, void* udata)
{
	dc_q_ele* ele = (dc_q_ele*)buf;
	find_ele* fele = (find_ele*)udata;

	if (ele->lut < fele->lut_limit) {
		return -1; // not found - stop looking
	}

	// TODO - use ele->lut > fele->prev_lut to avoid digest compare - worth it?

	if (cf_digest_compare(&ele->keyd, fele->keyd) == 0) {
		fele->found = true;

		if (fele->lut < ele->lut) {
			ele->lut = fele->lut; // out of order - replace with oldest
		}

		return -1; // found - stop looking
	}

	return 0; // not found - keep looking
}


//==========================================================
// Local helpers - DC loop.
//

static void*
run_dc(void* udata)
{
	as_dc* dc = (as_dc*)udata;

	while (! as_partition_balance_is_init_resolved()) {
		usleep(10 * 1000);
	}

	uint32_t period = dc->cfg.period_us;

	while (true) {
		uint64_t start = cf_getus();
		bool any_active = false;

		dc->lap++;

		for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
			dc_namespace* dcn = dc->dcns[ns_ix];

			if (! dcn->enabled) {
				process_disabled(dc, ns_ix);
				continue;
			}

			any_active = true;

			as_namespace* ns = g_config.namespaces[ns_ix];
			as_xdr_dc_ns_cfg* dc_ns_cfg = dc->cfg.ns_cfgs[ns_ix];

			handle_hub_change(ns, dcn);
			persist_lst(dc, ns);
			update_max_lap_recs(dcn, dc_ns_cfg->max_throughput, period);
			update_lap_quotas(dcn);

			uint32_t base_pid = dcn->base_pid;
			bool base_pid_moved = false;

			partition_aggr pa = { .min_safe_lst = UINT64_MAX };

			for (uint32_t i = 0; i < AS_PARTITIONS; i++) {
				uint32_t pid = (base_pid + i) % AS_PARTITIONS;

				if (dcn->n_recs_left == 0 && ! base_pid_moved) {
					dcn->base_pid = pid;
					base_pid_moved = true;
				}

				partition_xdr_state state = as_partition_xdr_state(ns, pid);

				if (state.role == XDR_ROLE_MASTER) {
					process_master(dc, ns_ix, pid, state.is_immigrating, &pa);
				}
				else if (state.role == XDR_ROLE_PROLE) {
					process_prole(dc, ns_ix, pid);
				}
				else { // XDR_ROLE_NONE
					process_none(dc, ns_ix, pid);
				}
			}

			dcn->stats.pa = pa;
			as_add_uint32(&dcn->n_recovery_recs_left, dcn->n_recs_left);
		}

		dc->lap_us = (uint32_t)(cf_getus() - start);

		period = any_active ? dc->cfg.period_us : DC_INACTIVE_PERIOD_US;

		if (dc->lap_us < period) {
			usleep(period - dc->lap_us);
		}
		else {
			period = dc->lap_us;
		}
	}

	return NULL;
}

static void
handle_hub_change(const as_namespace* ns, dc_namespace* dcn)
{
	if (dcn->is_self_hub && ns->hub != g_config.self_node) {
		dcn->is_self_hub = false;
		return;
	}

	if (! dcn->is_self_hub && ns->hub == g_config.self_node) {
		dcn->is_self_hub = true;

		for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
			dcn->dcps[pid].lst_update_pending = true;
		}
	}
}

static void
persist_lst(as_dc* dc, const as_namespace* ns)
{
	dc_namespace* dcn = dc->dcns[ns->ix];

	if (! dcn->is_self_hub) {
		return;
	}

	uint64_t now = cf_clepoch_milliseconds();

	if (now < dcn->last_persisted + LST_PERSIST_PERIOD_MS) {
		return;
	}

	uint64_t min_lst = UINT64_MAX;

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		dc_partition* dcp = &dcn->dcps[pid];

		if (dcp->lst_update_pending) {
			return;
		}

		if (dcp->safe_lst < min_lst) {
			min_lst = dcp->safe_lst;
		}
	}

	dcn->last_persisted = now;
	dcn->last_persisted_lst = min_lst;

	char smd_key[strlen(dc->cfg.name) + 1 + AS_ID_NAMESPACE_SZ];
	char smd_value[20 + 1];

	sprintf(smd_key, "%s|%s", dc->cfg.name, ns->name);
	sprintf(smd_value, "%lu", min_lst);

	as_smd_set_and_forget(AS_SMD_MODULE_XDR, smd_key, smd_value);
}

static void
update_max_lap_recs(dc_namespace* dcn, uint32_t max_throughput, uint32_t period)
{
	uint64_t ship_rate = (dcn->n_ships - dcn->n_prev_ships) * 1000000 / period;
	uint64_t prev_max = (uint64_t)dcn->max_lap_recs;

	dcn->n_prev_ships = dcn->n_ships;

	dcn->max_lap_recs = (uint32_t)(ship_rate != 0 && prev_max != 0 ?
			prev_max * max_throughput / ship_rate :
			(uint64_t)max_throughput * period / 1000000);

//	cf_debug(AS_XDR, "base-pid %u ship-rate %lu max-lap-recs %u period %u",
//			dcn->base_pid, ship_rate, dcn->max_lap_recs, period);
}

static void
update_lap_quotas(dc_namespace* dcn)
{
	uint32_t n_recovery_recs = 0;

	if (dcn->need_recovery_quota) {
		n_recovery_recs = dcn->max_lap_recs / LAP_RECS_QUOTA_SPLIT;
		dcn->need_recovery_quota = false;
	}

	dcn->n_recs_left = dcn->max_lap_recs - n_recovery_recs;

	// Don't set to 0 - may underflow in recovery_reduce_cb().
	as_store_uint32(&dcn->n_recovery_recs_left,
			n_recovery_recs != 0 ? n_recovery_recs : 1);
}

static void
process_master(as_dc* dc, uint32_t ns_ix, uint32_t pid, bool is_immigrating,
		partition_aggr* pa)
{
	dc_namespace* dcn = dc->dcns[ns_ix];
	dc_partition* dcp = &dcn->dcps[pid];
	as_namespace* ns = g_config.namespaces[ns_ix];

	char old_role = dcp->role;
	partition_state old_state = dcp->state;

	dcp->role = 'M';

	bool healthy = process_retry_q(dc, ns, dcp);

	uint32_t limit = dc->cfg.ns_cfgs[ns_ix]->transaction_queue_limit;
	bool emptied = empty_trans_q_on_overflow(dcp, limit);

	switch (dcp->state) {
	case TRANSACTION:
		if (emptied) {
			dcp->state = PRE_RECOVERY;
		}
		else {
			advance_safe_lst_idle(dcp);
			advance_safe_lst(dcp);

			if (healthy) {
				process_trans_q(dc, ns, dcp);
			}
		}
		break;
	case STARTUP:
		if (! is_immigrating) { // immigrations may bring old records
			enqueue_recovery_job(dc, dcp, ns_ix, pid);
			dcn->stats.n_recoveries_pending++;
			dcn->need_recovery_quota = true;
			dcp->state = RECOVERY;
		}
		break;
	case PRE_RECOVERY:
		if (total_in_progress(dcp) == 0) {
			// Don't call advance_safe_lst() - can't trust window->lst when
			// coming from previous incomplete recovery.
			dcp->n_windows = 0;

			// A re-enabled namespace always goes through PRE_RECOVERY.
			if (dcp->trans_q_used && dcp->safe_lst > dcp->first_trans_lut) {
				trim_trans_q(dc, dcp);
				dcp->state = TRANSACTION;
			}
			else if (! is_immigrating) { // immigrations may bring old records
				enqueue_recovery_job(dc, dcp, ns_ix, pid);
				dcn->stats.n_recoveries_pending++;
				dcn->need_recovery_quota = true;
				dcp->state = RECOVERY;
			}
		}
		break;
	case RECOVERY:
		if (dcp->recovery_job_done) {
			dcp->state = POST_RECOVERY_JOB;
		}
		else {
			dcn->need_recovery_quota = true;
		}
		break;
	case POST_RECOVERY_JOB:
		if (total_in_progress(dcp) == 0) {
			advance_safe_lst(dcp);
			dcn->stats.n_recoveries++; // for now - excludes aborted rounds

			// Ok to use placeholder lut after a round of recovery.
			if (dcp->safe_lst > dcp->first_trans_lut) {
				trim_trans_q(dc, dcp);
				dcn->stats.n_recoveries_pending--;
				dcp->state = TRANSACTION;
			}
			else {
				enqueue_recovery_job(dc, dcp, ns_ix, pid);
				// dcn->stats.n_recoveries_pending unchanged - already pending.
				dcn->need_recovery_quota = true;
				dcp->state = RECOVERY;
			}
		}
		break;
	case RECOVERY_DRAIN:
		if (dcp->recovery_job_done) {
			dcp->state = PRE_RECOVERY;
		}
		break;
	case RECOVERY_INCOMPLETE:
		// To handle master->prole/none (recovery aborted)->master transition
		// or startup->prole->master.
		dcp->state = PRE_RECOVERY;
		break;
	}

	if (dcp->role != old_role || dcp->state != old_state) {
		cf_detail(AS_XDR, "{%s:%u} DC %s role %c -> %c, state %s -> %s",
				ns->name, pid, dc->cfg.name,
				old_role, dcp->role,
				state_string(old_state), state_string(dcp->state));
	}

	publish_safe_lst(dc, ns_ix, pid);

	if (dcp->safe_lst < pa->min_safe_lst) {
		pa->min_safe_lst = dcp->safe_lst;
	}

	pa->trans_q_total += (uint64_t)cf_queue_sz(dcp->trans_q);
	pa->n_in_progress += total_in_progress(dcp);
}

static void
process_prole(as_dc* dc, uint32_t ns_ix, uint32_t pid)
{
	dc_namespace* dcn = dc->dcns[ns_ix];
	dc_partition* dcp = &dcn->dcps[pid];

	char old_role = dcp->role;
	partition_state old_state = dcp->state;

	dcp->role = 'P';

	// Do not process retry queue but keep it around.

	uint32_t limit = dc->cfg.ns_cfgs[ns_ix]->transaction_queue_limit;
	bool emptied = empty_trans_q_on_overflow(dcp, limit);

	switch (dcp->state) {
	case TRANSACTION:
		if (emptied) {
			dcp->state = RECOVERY_INCOMPLETE;
		}
		else if (dcp->trans_q_used && dcp->safe_lst > dcp->first_trans_lut) {
			trim_trans_q(dc, dcp);
		}
		break;
	case STARTUP:
		dcp->state = RECOVERY_INCOMPLETE;
		break;
	case PRE_RECOVERY:
		dcp->state = RECOVERY_INCOMPLETE;
		break;
	case RECOVERY:
		dcn->stats.n_recoveries_pending--;
		if (abort_recovery_job(dc, dcp, ns_ix, pid)) {
			// The job was in queue. No need to wait for recovery reduce.
			dcp->state = RECOVERY_INCOMPLETE;
		}
		else {
			dcp->state = RECOVERY_DRAIN;
		}
		break;
	case POST_RECOVERY_JOB:
		dcn->stats.n_recoveries_pending--;
		dcp->state = RECOVERY_INCOMPLETE;
		break;
	case RECOVERY_DRAIN:
		if (dcp->recovery_job_done) {
			dcp->state = RECOVERY_INCOMPLETE;
		}
		break;
	case RECOVERY_INCOMPLETE:
		if (dcp->trans_q_used && dcp->safe_lst > dcp->first_trans_lut) {
			dcp->state = TRANSACTION;
		}
		break;
	}

	if (dcp->role != old_role || dcp->state != old_state) {
		cf_detail(AS_XDR, "{%s:%u} DC %s role %c -> %c, state %s -> %s",
				g_config.namespaces[ns_ix]->name, pid, dc->cfg.name,
				old_role, dcp->role,
				state_string(old_state), state_string(dcp->state));
	}
}

static void
process_none(as_dc* dc, uint32_t ns_ix, uint32_t pid)
{
	dc_namespace* dcn = dc->dcns[ns_ix];
	dc_partition* dcp = &dcn->dcps[pid];

	char old_role = dcp->role;
	partition_state old_state = dcp->state;

	dcp->role = 'X';

	// Do not process retry queue but keep it around.

	empty_trans_q(dcp);

	switch (dcp->state) {
	case TRANSACTION:
		dcp->state = RECOVERY_INCOMPLETE;
		break;
	case STARTUP:
		dcp->state = RECOVERY_INCOMPLETE;
		break;
	case PRE_RECOVERY:
		dcp->state = RECOVERY_INCOMPLETE;
		break;
	case RECOVERY:
		dcn->stats.n_recoveries_pending--;
		if (abort_recovery_job(dc, dcp, ns_ix, pid)) {
			// The job was in queue. No need to wait for recovery reduce.
			dcp->state = RECOVERY_INCOMPLETE;
		}
		else {
			dcp->state = RECOVERY_DRAIN;
		}
		break;
	case POST_RECOVERY_JOB:
		dcn->stats.n_recoveries_pending--;
		dcp->state = RECOVERY_INCOMPLETE;
		break;
	case RECOVERY_DRAIN:
		if (dcp->recovery_job_done) {
			dcp->state = RECOVERY_INCOMPLETE;
		}
		break;
	case RECOVERY_INCOMPLETE:
		// Not strictly necessary - keep safe_lst relatively current in case
		// this node becomes master (e.g. becomes single node cluster).
		if (! dcn->is_self_hub && dcn->last_persisted_lst > dcp->safe_lst) {
			dcp->safe_lst = dcn->last_persisted_lst;
		}
		break;
	}

	if (dcp->role != old_role || dcp->state != old_state) {
		cf_detail(AS_XDR, "{%s:%u} DC %s role %c -> %c, state %s -> %s",
				g_config.namespaces[ns_ix]->name, pid, dc->cfg.name,
				old_role, dcp->role,
				state_string(old_state), state_string(dcp->state));
	}
}

static void
process_disabled(as_dc* dc, uint32_t ns_ix)
{
	dc_namespace* dcn = dc->dcns[ns_ix];

	if (! dcn->disabling) {
		return;
	}

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		dc_partition* dcp = &dcn->dcps[pid];

		empty_retry_q(dcp);
		process_none(dc, ns_ix, pid);
	}

	dcn->stats.pa = (partition_aggr){ .min_safe_lst = UINT64_MAX };

	// Wait for everbody's published LST when re-enabled.
	dcn->is_self_hub = false;

	dcn->disabling = false; // process for only one lap
}


//==========================================================
// Local helpers - master processing.
//

static void
process_trans_q(as_dc* dc, as_namespace* ns, dc_partition* dcp)
{
	if (dcp->n_windows == N_WINDOWS) {
		return; // windows are full - wait until next lap
	}

	dc_namespace* dcn = dc->dcns[ns->ix];

	if (dcn->n_recs_left == 0) {
		return;
	}

	uint32_t max_eles = MAX_IN_PROGRESS - total_in_progress(dcp);

	if (max_eles > dcn->n_recs_left) {
		max_eles = dcn->n_recs_left;
	}

	dc_q_ele eles[max_eles];
	uint32_t n_eles;
	uint64_t max_lut = 0;

	as_xdr_dc_ns_cfg* cfg = dc->cfg.ns_cfgs[ns->ix];
	uint32_t delay_ms = as_load_uint32(&cfg->delay_ms);
	uint64_t now = ns->cp || delay_ms != 0 ? cf_clepoch_milliseconds() : 0;

	cf_mutex_lock(&dcp->trans_q_lock);

	for (n_eles = 0; n_eles < max_eles; n_eles++) {
		dc_q_ele* ele = &eles[n_eles];

		if (cf_queue_pop(dcp->trans_q, ele, CF_QUEUE_NOWAIT) != CF_QUEUE_OK) {
			break;
		}

		if (now != 0) {
			if (ele->lut + delay_ms > now) {
				cf_queue_push_head(dcp->trans_q, ele);
				break;
			}

			if (ns->cp && ele->lut + cfg->sc_replication_wait_ms > now) {
				cf_queue_push_head(dcp->trans_q, ele);
				break;
			}
		}

		if (ele->lut > max_lut) {
			max_lut = ele->lut;
		}
	}

	cf_mutex_unlock(&dcp->trans_q_lock);

	if (n_eles == 0) {
		return;
	}

	window* w = &dcp->windows[dcp->at_window];

	w->lst = max_lut;
	w->n_in_progress = n_eles;

	for (uint32_t i = 0; i < n_eles; i++) {
		ship_request* req = cf_malloc(sizeof(ship_request));
		dc_q_ele* ele = &eles[i];

		as_xdr_trace(dc, &ele->keyd, ele->lut, "process");

		req->dc = dc;
		req->ns = ns;
		req->keyd = ele->keyd;
		req->is_retry = false;
		req->lut = ele->lut;
		req->lut_cutoff = ele->lut;
		req->w_ix = dcp->at_window;
		req->dcp = dcp;

		as_reader_enqueue(req);
	}

	dcp->at_window = (dcp->at_window + 1) % N_WINDOWS;
	dcp->n_windows++;

	dcn->n_recs_left -= n_eles;
}

static bool
process_retry_q(as_dc* dc, const as_namespace* ns, dc_partition* dcp)
{
	uint32_t q_sz = cf_queue_sz(dcp->retry_q);

	if (q_sz == 0) {
		dcp->retry_interval = 0;
		return true;
	}

	dc_namespace* dcn = dc->dcns[ns->ix];

	if (dcn->n_recs_left == 0) {
		return true;
	}

	cf_mutex_lock(&dcp->retry_q_lock);

	q_sz = cf_queue_sz(dcp->retry_q);

	uint32_t n_eles = q_sz;

	if (q_sz > dcn->n_recs_left) {
		n_eles = dcn->n_recs_left;
	}

	if (q_sz >= RETRY_THROTTLE_THRESHOLD && dcp->retry_interval == 0) {
		dcp->retry_interval = 1;
	}

	if (dcp->retry_interval != 0) {
		if (dc->lap % dcp->retry_interval == 0) {
			n_eles = 1;

			if (dcp->retry_interval < RETRY_INTERVAL_MAX) {
				dcp->retry_interval++;
			}
		}
		else {
			if (q_sz <= RETRY_SPEEDUP_THRESHOLD) {
				dcp->retry_interval--;
			}

			cf_mutex_unlock(&dcp->retry_q_lock);

			return false;
		}
	}

	ship_request* eles[n_eles];

	for (uint32_t i = 0; i < n_eles; i++) {
		cf_queue_pop(dcp->retry_q, &eles[i], CF_QUEUE_NOWAIT);
	}

	cf_mutex_unlock(&dcp->retry_q_lock);

	for (uint32_t i = 0; i < n_eles; i++) {
		ship_request* req = eles[i];
		window* w = &dcp->windows[req->w_ix];

		uint64_t safe_lst = as_load_uint64(&dcp->safe_lst);

		as_xdr_trace(req->dc, &req->keyd, req->lut, "retry? lst %s",
				as_xdr_pretty_ms(safe_lst));

		if (req->lut < safe_lst) {
			// Skip this record - likely from prior cycle as master.

			as_xdr_trace(req->dc, &req->keyd, req->lut, "no-retry");

			as_decr_uint32(&w->n_in_progress);
			cf_free(req);
			continue;
		}

		req->is_retry = true;

		as_reader_enqueue(req);
	}

	dcn->n_recs_left -= n_eles;

	return dcp->retry_interval == 0;
}

static void
advance_safe_lst_idle(dc_partition* dcp)
{
	// No ongoig or incoming work.
	if (dcp->n_windows == 0 && cf_queue_sz(dcp->trans_q) == 0) {
		dcp->safe_lst = cf_clepoch_milliseconds() - LST_SAFETY_MS;
	}
}

static void
advance_safe_lst(dc_partition* dcp)
{
	uint32_t n_windows = dcp->n_windows;
	uint32_t start_ix = (dcp->at_window + N_WINDOWS - n_windows) % N_WINDOWS;
	uint64_t apply_lst = 0;

	for (uint32_t i = 0; i < n_windows; i++) {
		uint32_t w_ix = (start_ix + i) % N_WINDOWS;
		window* w = &dcp->windows[w_ix];

		if (w->n_in_progress != 0) {
			break;
		}

		if (w->lst > apply_lst) {
			apply_lst = w->lst;
		}

		dcp->n_windows--;
	}

	// LST_SAFETY_MS is on the RHS because apply_lst can be 0.
	if (apply_lst > dcp->safe_lst + LST_SAFETY_MS) {
		dcp->safe_lst = apply_lst - LST_SAFETY_MS;
	}
}

static void
publish_safe_lst(as_dc* dc, uint32_t ns_ix, uint32_t pid)
{
	dc_namespace* dcn = dc->dcns[ns_ix];
	dc_partition* dcp = &dcn->dcps[pid];
	as_namespace* ns = g_config.namespaces[ns_ix];
	uint64_t now = cf_clepoch_milliseconds();

	if (now < dcp->last_published + LST_PUBLISH_PERIOD_MS) {
		return;
	}

	dcp->last_published = now;
	dcp->lst_update_pending = false; // will not send lst to self (may be hub)

	msg* m = as_fabric_msg_get(M_TYPE_XDR);

	msg_set_buf(m, XDR_FIELD_DC_NAME, (uint8_t*)dc->cfg.name,
			strlen(dc->cfg.name), MSG_SET_COPY);
	msg_set_buf(m, XDR_FIELD_NAMESPACE, (uint8_t*)ns->name, strlen(ns->name),
			MSG_SET_COPY);
	msg_set_uint32(m, XDR_FIELD_PID, pid);
	msg_set_uint64(m, XDR_FIELD_LST, dcp->safe_lst);

	cf_node repl_nodes[AS_CLUSTER_SZ];
	uint32_t n_repl = as_partition_get_other_replicas(&ns->partitions[pid],
			repl_nodes);

	for (uint32_t i = 0; i < n_repl; i++) {
		if (repl_nodes[i] == ns->hub) {
			continue;
		}

		msg_incr_ref(m);

		if (as_fabric_send(repl_nodes[i], m, AS_FABRIC_CHANNEL_META) !=
				AS_FABRIC_SUCCESS) {
			as_fabric_msg_put(m);
		}
	}

	// The extra reference is used to send to the hub (if not self).
	if (ns->hub == g_config.self_node ||
			as_fabric_send(ns->hub, m, AS_FABRIC_CHANNEL_META) !=
					AS_FABRIC_SUCCESS) {
		as_fabric_msg_put(m);
	}
}

static void
enqueue_recovery_job(as_dc* dc, dc_partition* dcp, uint32_t ns_ix, uint32_t pid)
{
	dcp->recovery_aborted = false;
	dcp->recovery_job_done = false;

	recovery_job job = { .ns_ix = ns_ix, .pid = pid };

	cf_queue_push(&dc->recovery_q, &job);
}


//==========================================================
// Local helpers - prole & none processing.
//

static bool
abort_recovery_job(as_dc* dc, dc_partition* dcp, uint32_t ns_ix, uint32_t pid)
{
	dcp->recovery_aborted = true;

	find_recovery_job fjob = { .ns_ix = ns_ix, .pid = pid };

	// Can't use cf_queue_delete() - must exclude resume & keyd when comparing.
	cf_queue_reduce(&dc->recovery_q, abort_recovery_cb, (void*)&fjob);

	return fjob.found;
}

static int
abort_recovery_cb(void* buf, void* udata)
{
	recovery_job* job = (recovery_job*)buf;
	find_recovery_job* fjob = (find_recovery_job*)udata;

	if (job->pid == fjob->pid && job->ns_ix == fjob->ns_ix) {
		fjob->found = true;
		return -2; // found - delete and stop looking
	}

	return 0; // not found - keep looking
}


//==========================================================
// Local helpers - queue utilities.
//

static void
trim_trans_q(as_dc* dc, dc_partition* dcp)
{
	cf_mutex_lock(&dcp->trans_q_lock);

	dc_q_ele ele;

	while (cf_queue_pop(dcp->trans_q, &ele, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
		if (ele.lut > dcp->safe_lst) {
			cf_queue_push_head(dcp->trans_q, &ele);
			break;
		}

		as_xdr_trace(dc, &ele.keyd, ele.lut, "trim");
	}

	cf_mutex_unlock(&dcp->trans_q_lock);
}

static void
empty_trans_q(dc_partition* dcp)
{
	// Not necessary to check this under lock.
	if (! dcp->trans_q_used) {
		return;
	}

	cf_mutex_lock(&dcp->trans_q_lock);

	cf_queue_destroy(dcp->trans_q);
	dcp->trans_q = cf_queue_create(sizeof(dc_q_ele), false);

	dcp->trans_q_used = false;
	// Placeholder until submit updates it.
	dcp->first_trans_lut = cf_clepoch_milliseconds();

	cf_mutex_unlock(&dcp->trans_q_lock);
}

static bool
empty_trans_q_on_overflow(dc_partition* dcp, uint32_t limit)
{
	if (cf_queue_sz(dcp->trans_q) >= limit) {
		empty_trans_q(dcp);
		return true;
	}

	return false;
}

static void
empty_retry_q(dc_partition* dcp)
{
	if (! dcp->retry_q_used) {
		return;
	}

	cf_mutex_lock(&dcp->retry_q_lock);

	ship_request* req;

	while (cf_queue_pop(dcp->retry_q, &req, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
		as_dc_client_cb(LOCAL_ERR_REC_ABANDONED, req);
	}

	cf_queue_destroy(dcp->retry_q);
	dcp->retry_q = cf_queue_create(sizeof(ship_request*), false);
	dcp->retry_q_used = false;

	cf_mutex_unlock(&dcp->retry_q_lock);
}


//==========================================================
// Local helpers - perform recovery.
//

static void*
run_recovery(void* udata)
{
	as_dc* dc = (as_dc*)udata;

	while (true) {
		recovery_job job;

		cf_queue_pop(&dc->recovery_q, &job, CF_QUEUE_FOREVER);

		as_namespace* ns = g_config.namespaces[job.ns_ix];
		dc_namespace* dcn = dc->dcns[job.ns_ix];
		dc_partition* dcp = &dcn->dcps[job.pid];

		cf_digest* last_keyd;

		if (job.resume) {
			last_keyd = &job.last_keyd;
		}
		else {
			last_keyd = NULL;

			// Recovery will use 0th window and no other window will be active.
			// There will be no in-progress records at this point.
			dcp->at_window = 1;
			dcp->n_windows = 1;
			dcp->windows[0].lst = cf_clepoch_milliseconds();
		}

		recovery_info ri = {
				.dc = dc,
				.ns = ns,
				.dcp = dcp,
				.resume = &job.resume,
				.last_keyd = &job.last_keyd
		};

		as_partition_reservation rsv;
		as_partition_reserve(ns, job.pid, &rsv);

		bool done = as_index_reduce_from(rsv.tree, last_keyd,
				recovery_reduce_cb, &ri);

		as_partition_release(&rsv);

		if (done || dcp->recovery_aborted) {
			dcp->recovery_job_done = true;
		}
		else {
			// If a record was processed, resume is true & last_keyd is valid.

			uint32_t mri = as_load_uint32(&dc->cfg.max_recoveries_interleaved);

			if (mri == 0) {
				cf_queue_push(&dc->recovery_q, &job);
			}
			else {
				cf_queue_push_index(&dc->recovery_q, &job, mri - 1);
			}
		}
	}

	return NULL;
}

static bool
recovery_reduce_cb(as_index_ref* r_ref, void* udata)
{
	recovery_info* ri = (recovery_info*)udata;
	as_dc* dc = ri->dc;
	as_namespace* ns = ri->ns;
	dc_partition* dcp = ri->dcp;

	if (dcp->recovery_aborted) {
		as_record_done(r_ref, ns);
		return false;
	}

	as_xdr_dc_ns_cfg* cfg = dc->cfg.ns_cfgs[ns->ix];

	window* w = &dcp->windows[0];
	dc_namespace* dcn = dc->dcns[ns->ix];

	if (w->n_in_progress >= MAX_RECOVERY_IN_PROGRESS ||
			dcn->n_recovery_recs_left == 0 || cfg->max_throughput == 0) {
		as_record_done(r_ref, ns);
		usleep(5 * 1000); // save CPU
		return false;
	}

	as_record* r = r_ref->r;

	*ri->resume = true;
	*ri->last_keyd = r->keyd;

	uint64_t lut = r->last_update_time;
	uint64_t safe_lst = as_load_uint64(&dcp->safe_lst);

	as_xdr_trace(dc, &r->keyd, lut, "recover? lst %s",
			as_xdr_pretty_ms(safe_lst));

	if (lut < safe_lst) {
		as_record_done(r_ref, ns);
		return true;
	}

	if (! as_dc_should_submit(dc, ns, r)) {
		as_record_done(r_ref, ns);
		return true;
	}

	ship_request* req = cf_malloc(sizeof(ship_request));

	req->dc = dc;
	req->ns = ns;
	req->keyd = r->keyd;
	req->is_retry = false;
	req->lut = lut;
	req->lut_cutoff = safe_lst;
	req->w_ix = 0;
	req->dcp = dcp;

	as_record_done(r_ref, ns);

	as_incr_uint32(&w->n_in_progress);
	as_decr_uint32(&dcn->n_recovery_recs_left);

	as_reader_enqueue(req);

	return true;
}


//==========================================================
// Local helpers - ship request callback.
//

static void
complete_ship_request(ship_request* req, int32_t result)
{
	as_dc* dc = req->dc;
	dc_partition* dcp = req->dcp;
	window* w = &dcp->windows[req->w_ix];

	cf_ticker_detail(AS_XDR, "{%s} DC %s complete result %d", req->ns->name,
			dc->cfg.name, result);
	as_xdr_trace(dc, &req->keyd, req->lut, "complete %d", result);

	as_decr_uint32(&w->n_in_progress);

	cf_free(req);
}

static void
requeue_ship_request(const ship_request* req, int32_t result)
{
	as_dc* dc = req->dc;
	dc_partition* dcp = req->dcp;

	cf_ticker_detail(AS_XDR, "{%s} DC %s requeue result %d", req->ns->name,
			dc->cfg.name, result);
	as_xdr_trace(dc, &req->keyd, req->lut, "requeue %d", result);

	cf_mutex_lock(&dcp->retry_q_lock);

	cf_queue_push(dcp->retry_q, &req);
	dcp->retry_q_used = true;

	cf_mutex_unlock(&dcp->retry_q_lock);
}

static void
abandon_ship_request(ship_request* req, int32_t result, bool warn)
{
	as_dc* dc = req->dc;
	dc_partition* dcp = req->dcp;
	window* w = &dcp->windows[req->w_ix];

	if (warn) {
		cf_ticker_warning(AS_XDR, "{%s} DC %s abandon result %d", req->ns->name,
				dc->cfg.name, result);
	}
	else {
		cf_ticker_detail(AS_XDR, "{%s} DC %s abandon result %d", req->ns->name,
				dc->cfg.name, result);
	}

	as_xdr_trace(dc, &req->keyd, req->lut, "abandon %d", result);

	as_decr_uint32(&w->n_in_progress);

	cf_free(req);
}


//==========================================================
// Local helpers - config.
//

static void
init_config(as_xdr_dc_cfg* cfg, const char* name)
{
	cfg->name = cf_strdup(name);

	cfg->auth_mode = XDR_AUTH_NONE;
	cfg->connector = false;
	cfg->max_recoveries_interleaved = 0;
	cfg->max_used_service_threads = 0;
	cfg->period_us = 100 * 1000;
	cfg->use_alternate_access_address = false;
}

static void
init_ns_config(as_xdr_dc_ns_cfg* cfg)
{
	cfg->bin_policy = XDR_BIN_POLICY_ALL;
	cfg->compression_level = 1;
	cfg->compression_threshold = AS_XDR_MIN_COMPRESSION_THRESHOLD;
	cfg->hot_key_ms = 100;
	cfg->max_throughput = 100000;
	cfg->sc_replication_wait_ms = 100;
	cfg->transaction_queue_limit = 16 * 1024;
	cfg->write_policy = XDR_WRITE_POLICY_AUTO;
}

static void
destroy_config(as_xdr_dc_cfg* cfg)
{
	cf_free(cfg->name);
	cfg->name = NULL;

	cf_vector* nv = &cfg->seed_nodes;
	uint32_t sz = cf_vector_size(nv);

	for (uint32_t i = 0; i < sz; i++) {
		seed_node_cfg node_cfg;

		cf_vector_get(nv, i, &node_cfg);
		seed_node_cfg_cleanup(&node_cfg);
	}

	cf_vector_clear(nv);
	// TODO - cf_vector_compact() is broken - fix/remove ?

	if (cfg->auth_password_file != NULL) {
		cf_free(cfg->auth_password_file);
		cfg->auth_password_file = NULL;
	}

	if (cfg->auth_user != NULL) {
		cf_free(cfg->auth_user);
		cfg->auth_user = NULL;
	}

	if (cfg->tls_our_name != NULL) {
		cf_free(cfg->tls_our_name);
		cfg->tls_our_name = NULL;
		cfg->tls_spec = NULL;
	}
}

static bool
remote_namespace_is_valid(const as_xdr_dc_cfg* dc_cfg, const char* ns_name)
{
	 // Cannot be a local namespace name.
	as_namespace* ns = as_namespace_get_byname(ns_name);

	if (ns != NULL) {
		cf_warning(AS_XDR, "remote namespace '%s' exists locally", ns_name);
		return false;
	}

	// Cannot be in use by any other dc-namespace config.
	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_xdr_dc_ns_cfg* dc_ns_cfg = dc_cfg->ns_cfgs[ns_ix];

		if (dc_ns_cfg == NULL) { // can be null at startup
			continue;
		}

		if (dc_ns_cfg->remote_namespace != NULL &&
				strcmp(dc_ns_cfg->remote_namespace, ns_name) == 0) {
			cf_warning(AS_XDR, "remote namespace '%s' already mapped", ns_name);
			return false;
		}
	}

	return true;
}


//==========================================================
// Local helpers - stats.
//

static void
dc_update_throughput(as_dc* dc, uint64_t delta_time)
{
	uint32_t throughput = 0;

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		dc_namespace* dcn = dc->dcns[ns_ix];
		uint64_t n_success = 0;

		cf_mutex_lock(&dc->stats_lock);

		for (uint32_t i = 0; i < cf_vector_size(&dc->stats); i++) {
			tl_dc_stats* dc_stats = cf_vector_get_ptr(&dc->stats, i);

			if (dc_stats->pending_reset) {
				continue;
			}

			tl_ns_stats* ns_stats = &dc_stats->ns_stats[ns_ix];

			n_success += ns_stats->n_success;
		}

		cf_mutex_unlock(&dc->stats_lock);

		dcn->stats.throughput = (uint32_t)(1000000000 *
				(n_success - dcn->stats.prev_n_success) / delta_time);

		dcn->stats.prev_n_success = n_success;
		throughput += dcn->stats.throughput;
	}

	dc->throughput = throughput;
}

static void
dc_aggregate_dcn_stats(const as_dc *dc, dcn_stats* na)
{
	na->pa.min_safe_lst = UINT64_MAX;

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		dc_namespace* dcn = dc->dcns[ns_ix];

		if (dcn->stats.pa.min_safe_lst < na->pa.min_safe_lst) {
			na->pa.min_safe_lst = dcn->stats.pa.min_safe_lst;
		}

		na->pa.trans_q_total += dcn->stats.pa.trans_q_total;
		na->pa.n_in_progress += dcn->stats.pa.n_in_progress;

		na->n_recoveries += dcn->stats.n_recoveries;
		na->n_recoveries_pending += dcn->stats.n_recoveries_pending;

		na->n_hot_keys += dcn->stats.n_hot_keys;
	}
}

static void
dc_aggregate_tl_dc_stats(as_dc* dc)
{
	double latency_ns_sum = 0;
	uint32_t n_avg = 0;

	cf_mutex_lock(&dc->stats_lock);

	for (uint32_t i = 0; i < cf_vector_size(&dc->stats); i++) {
		tl_dc_stats* dc_stats = cf_vector_get_ptr(&dc->stats, i);

		if (dc_stats->pending_reset) {
			continue;
		}

		if (i != DEAD_STATS_IX) {
			latency_ns_sum += dc_stats->latency_ns;
			n_avg++;
		}
	}

	cf_mutex_unlock(&dc->stats_lock);

	if (n_avg != 0) {
		dc->latency_ms = (uint32_t)
				((uint64_t)latency_ns_sum / (1000000 * n_avg));
	}
}

static void
dc_aggregate_tl_ns_stats(as_dc* dc, tl_ns_stats* ta)
{
	uint32_t n_avg = 0;

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		dc_namespace* dcn = dc->dcns[ns_ix];

		cf_mutex_lock(&dc->stats_lock);

		for (uint32_t i = 0; i < cf_vector_size(&dc->stats); i++) {
			tl_dc_stats* dc_stats = cf_vector_get_ptr(&dc->stats, i);

			if (dc_stats->pending_reset) {
				continue;
			}

			tl_ns_stats* ns_stats = &dc_stats->ns_stats[ns_ix];

			add_tl_ns_stats(ns_stats, ta);

			if (dcn->enabled && i != DEAD_STATS_IX) {
				add_tl_ns_averages(ns_stats, ta);
				n_avg++;
			}
		}

		cf_mutex_unlock(&dc->stats_lock);
	}

	if (n_avg != 0) {
		ta->compression.uncomp_pct /= n_avg;
		ta->compression.avg_orig_sz /= n_avg;
		ta->compression.avg_comp_sz /= n_avg;
	}
}

static void
ns_aggregate_tl_ns_stats(as_dc* dc, uint32_t ns_ix, tl_ns_stats* ta)
{
	uint32_t n_avg = 0;

	cf_mutex_lock(&dc->stats_lock);

	for (uint32_t i = 0; i < cf_vector_size(&dc->stats); i++) {
		tl_dc_stats* dc_stats = cf_vector_get_ptr(&dc->stats, i);

		if (dc_stats->pending_reset) {
			continue;
		}

		tl_ns_stats* ns_stats = &dc_stats->ns_stats[ns_ix];

		add_tl_ns_stats(ns_stats, ta);

		if (dc->dcns[ns_ix]->enabled && i != DEAD_STATS_IX) {
			add_tl_ns_averages(ns_stats, ta);
			n_avg++;
		}
	}

	cf_mutex_unlock(&dc->stats_lock);

	if (n_avg != 0) {
		ta->compression.uncomp_pct /= n_avg;
		ta->compression.avg_orig_sz /= n_avg;
		ta->compression.avg_comp_sz /= n_avg;
	}
}

static void
add_tl_ns_stats(const tl_ns_stats* stats, tl_ns_stats* ta)
{
	ta->n_success += stats->n_success;
	ta->n_abandoned += stats->n_abandoned;
	ta->n_not_found += stats->n_not_found;
	ta->n_filtered_out += stats->n_filtered_out;

	ta->n_retry_no_node += stats->n_retry_no_node;
	ta->n_retry_conn_reset += stats->n_retry_conn_reset;
	ta->n_retry_dest += stats->n_retry_dest;
}

static void
add_tl_ns_averages(const tl_ns_stats* stats, tl_ns_stats* ta)
{
	ta->compression.uncomp_pct += stats->compression.uncomp_pct;
	ta->compression.avg_orig_sz += stats->compression.avg_orig_sz;
	ta->compression.avg_comp_sz += stats->compression.avg_comp_sz;
}

static void
append_ns_stats(const dcn_stats* n, const tl_ns_stats* ta, cf_dyn_buf* db)
{
	info_append_uint64(db, "lag", calculate_lag(n->pa.min_safe_lst));
	info_append_uint64(db, "in_queue", n->pa.trans_q_total);
	info_append_uint32(db, "in_progress", n->pa.n_in_progress);

	info_append_uint64(db, "success", ta->n_success);
	info_append_uint64(db, "abandoned", ta->n_abandoned);
	info_append_uint64(db, "not_found", ta->n_not_found);
	info_append_uint64(db, "filtered_out", ta->n_filtered_out);

	info_append_uint64(db, "retry_no_node", ta->n_retry_no_node);
	info_append_uint64(db, "retry_conn_reset", ta->n_retry_conn_reset);
	info_append_uint64(db, "retry_dest", ta->n_retry_dest);

	info_append_uint64(db, "recoveries", n->n_recoveries);
	info_append_uint32(db, "recoveries_pending", n->n_recoveries_pending);

	info_append_uint64(db, "hot_keys", n->n_hot_keys);

	// Everything below is not in ticker...

	double uncomp_pct = ta->compression.uncomp_pct;
	double orig_sz = ta->compression.avg_orig_sz;
	double comp_sz = ta->compression.avg_comp_sz;
	double ratio = orig_sz > 0.0 ? comp_sz / orig_sz : 1.0;

	info_append_format(db, "uncompressed_pct", "%.3f", uncomp_pct);
	info_append_format(db, "compression_ratio", "%.3f", ratio);
}

static void
invalidate_stats(as_dc* dc)
{
	cf_mutex_lock(&dc->stats_lock);

	tl_dc_stats* dead = cf_vector_get_ptr(&dc->stats, DEAD_STATS_IX);

	memset(dead, 0, sizeof(tl_dc_stats));

	for (uint32_t i = 1; i < cf_vector_size(&dc->stats); i++) {
		tl_dc_stats* stats = cf_vector_get_ptr(&dc->stats, i);

		stats->pending_reset = true;
	}

	cf_mutex_unlock(&dc->stats_lock);
}
