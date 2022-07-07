/*
 * dc.h
 *
 * Copyright (C) 2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#pragma once

//==========================================================
// Includes.
//

#include <stdbool.h>
#include <stdint.h>

#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_queue.h"

#include "cf_mutex.h"
#include "dynbuf.h"

#include "base/cfg.h"
#include "base/proto.h"
#include "base/xdr.h"
#include "fabric/partition.h"


//==========================================================
// Forward declarations.
//

struct as_index_s;
struct as_namespace_s;
struct as_xdr_dc_cfg_s;
struct dc_namespace_s;
struct xdr_filter_s;


//==========================================================
// Typedefs & constants.
//

typedef enum {
	DC_UNUSED,
	DC_DISCONNECTED,
	DC_CONNECTED
} dc_state;

typedef struct as_dc_s {
	uint32_t ix;
	dc_state state;
	as_xdr_dc_cfg cfg;

	cf_queue recovery_q;
	struct dc_namespace_s* dcns[AS_NAMESPACE_SZ];
	uint32_t lap_us;
	uint32_t lap;

	uint32_t throughput; // updated only in ticker
	uint32_t latency_ms;

	cf_mutex stats_lock;
	cf_vector stats; // per-thread
} as_dc;

typedef struct ship_request_s {
	as_dc* dc;
	struct as_namespace_s* ns;
	cf_digest keyd;
	bool is_retry;
	uint64_t lut;
	uint64_t lut_cutoff;
	uint64_t ship_time;

	// Opaque outside DC.
	uint32_t w_ix;
	void* dcp;
} ship_request;

typedef struct tl_ns_stats_s {
	uint64_t n_success;
	uint64_t n_abandoned;
	uint64_t n_not_found;
	uint64_t n_filtered_out;

	uint64_t n_retry_no_node;
	uint64_t n_retry_conn_reset;
	uint64_t n_retry_dest;

	as_proto_comp_stat compression;
} tl_ns_stats;

typedef struct tl_dc_stats_s {
	bool pending_reset;

	double latency_ns;
	tl_ns_stats ns_stats[AS_NAMESPACE_SZ];
} tl_dc_stats;

// Local errors negative to not conflict with proto errors from destination.
#define LOCAL_ERR_REC_READ -1
#define LOCAL_ERR_REC_NOT_FOUND -2
#define LOCAL_ERR_REC_FILTERED_OUT -3
#define LOCAL_ERR_REC_UNREPLICATED -4
#define LOCAL_ERR_REC_REPLICATING -5
#define LOCAL_ERR_REC_ABANDONED -6
#define LOCAL_ERR_NO_NODE -7
#define LOCAL_ERR_CONN_BUSY -8
#define LOCAL_ERR_CONN_RESET -9

// For set and bin "projection" filters.
#define SHIPPING_UNSPECIFIED 0
#define SHIPPING_ENABLED 1
#define SHIPPING_DISABLED 2


//==========================================================
// Public API.
//

as_dc* as_dc_create(const char* name, uint32_t dc_ix);
as_xdr_dc_ns_cfg* as_dc_create_ns_cfg(const char* ns_name);
void as_dc_cfg_post_process(as_dc* dc);
void as_dc_link_tls(as_dc* dc);
void as_dc_run(as_dc* dc);
bool as_dc_connect(as_dc* dc);
void as_dc_disconnect(as_dc* dc);
bool as_dc_reuse(as_dc* dc, const char* name);
bool as_dc_delete(as_dc* dc);
void as_dc_cluster_changed_cb(as_dc* dc);

void as_dc_init_ns(as_dc* dc, const struct as_namespace_s* ns);
void as_dc_add_ns(as_dc* dc, const struct as_namespace_s* ns, uint64_t lst);
void as_dc_remove_ns(as_dc* dc, const struct as_namespace_s* ns);
bool as_dc_has_ns(const as_dc* dc, const struct as_namespace_s* ns);
bool as_dc_has_any_ns(const as_dc* dc);
bool as_dc_update_ns_remote_namespace(as_dc* dc, const struct as_namespace_s* ns, const char* ns_name);

void as_dc_setup_ns_bins(as_dc* dc, struct as_namespace_s* ns);
void as_dc_setup_ns_sets(as_dc* dc, struct as_namespace_s* ns);
bool as_dc_update_ns_bins(as_dc* dc, struct as_namespace_s* ns, const char* bin_name, bool enabled);
bool as_dc_update_ns_sets(as_dc* dc, struct as_namespace_s* ns, const char* set_name, bool enabled);
void as_dc_set_ns_filter(as_dc* dc, const struct as_namespace_s* ns, const char* b64);
struct xdr_filter_s* as_dc_get_ns_filter(const as_dc* dc, const struct as_namespace_s* ns);

void as_dc_submit(as_dc* dc, const struct as_namespace_s* ns, const as_xdr_submit_info* info);
bool as_dc_should_submit(const as_dc* dc, const struct as_namespace_s* ns, const struct as_index_s* r);
void as_dc_ship_attempt_cb(as_dc* dc, const struct as_namespace_s* ns);
void as_dc_client_cb(int32_t result, void* udata);

void as_dc_init_safe_lsts(as_dc* dc, const struct as_namespace_s* ns, uint64_t lst);
void as_dc_accept_safe_lst(as_dc* dc, const struct as_namespace_s* ns, uint32_t pid, uint64_t lst);
void as_dc_update_ns_persisted_lst(as_dc* dc, const struct as_namespace_s* ns, uint64_t lst);
uint64_t as_dc_ns_min_lst(const as_dc* dc, const struct as_namespace_s* ns);

void as_dc_get_config(as_dc* dc, cf_dyn_buf* db);
void as_dc_get_ns_config(const as_dc* dc, const struct as_namespace_s* ns, cf_dyn_buf* db);
void as_dc_get_stats(as_dc* dc, cf_dyn_buf* db);
void as_dc_get_ns_stats(as_dc* dc, const struct as_namespace_s* ns, cf_dyn_buf* db);
bool as_dc_get_state(const as_dc* dc, const struct as_namespace_s* ns, cf_dyn_buf* db, bool add_header);
void as_dc_get_ns_display_filter(const as_dc* dc, const struct as_namespace_s* ns, bool b64, cf_dyn_buf* db);
void as_dc_ticker(as_dc* dc, uint64_t delta_time);
tl_dc_stats* as_dc_get_tl_dc_stats(as_dc* dc);
void as_dc_cleanup_tl_stats(as_dc* dc);
