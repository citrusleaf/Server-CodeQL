/*
 * reader.c
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

#include "xdr/reader.h"

#include <stddef.h>
#include <stdint.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"

#include "log.h"

#include "base/datamodel.h"
#include "base/exp.h"
#include "base/index.h"
#include "base/proto.h"
#include "base/service.h"
#include "base/transaction.h"
#include "fabric/partition.h"
#include "storage/storage.h"
#include "transaction/re_replicate_ee.h"
#include "xdr/dc.h"
#include "xdr/ship.h"
#include "xdr/xdr_ee.h"

#include "warnings.h"


//==========================================================
// Forward declarations.
//

static void read_done(as_storage_rd* rd, as_index_ref* r_ref, as_partition_reservation* rsv);
static bool meta_filter(as_dc* dc, as_namespace* ns, as_record* r, xdr_filter** filter);
static bool bin_filter(as_namespace* ns, as_storage_rd* rd, xdr_filter* filter);


//==========================================================
// Public API.
//

void
as_xdr_read(as_transaction* tr)
{
	ship_request* req = *(ship_request**)tr->msgp->proto.body;

	cf_free(tr->msgp);

	as_dc* dc = req->dc;
	as_namespace* ns = req->ns;
	cf_digest* keyd = &req->keyd;
	uint32_t pid = as_partition_getid(keyd);

	as_xdr_trace(dc, keyd, req->lut, "read");

	as_partition_reservation rsv;

	as_partition_reserve(ns, pid, &rsv);

	as_index_ref r_ref;

	if (as_record_get(rsv.tree, keyd, &r_ref) != 0) {
		read_done(NULL, NULL, &rsv);
		as_dc_client_cb(LOCAL_ERR_REC_NOT_FOUND, req);
		return;
	}

	as_record* r = r_ref.r;

	if (req->is_retry && ! as_dc_should_submit(dc, ns, r)) {
		read_done(NULL, &r_ref, &rsv);
		as_dc_client_cb(LOCAL_ERR_REC_FILTERED_OUT, req);
		return;
	}

	if (as_record_is_doomed(r, ns)) {
		read_done(NULL, &r_ref, &rsv);
		as_dc_client_cb(LOCAL_ERR_REC_NOT_FOUND, req);
		return;
	}

	if (ns->cp && r->repl_state != AS_REPL_STATE_REPLICATED) {
		if (r->repl_state == AS_REPL_STATE_UNREPLICATED) {
			as_re_replicate(ns, &r->keyd);
			as_set_repl_state(ns, r, AS_REPL_STATE_RE_REPLICATING);

			read_done(NULL, &r_ref, &rsv);
			as_dc_client_cb(LOCAL_ERR_REC_UNREPLICATED, req);
			return;
		}

		read_done(NULL, &r_ref, &rsv);
		as_dc_client_cb(LOCAL_ERR_REC_REPLICATING, req);
		return;
	}

	xdr_filter* filter = NULL;

	if (! meta_filter(dc, ns, r, &filter)) {
		read_done(NULL, &r_ref, &rsv);
		as_dc_client_cb(LOCAL_ERR_REC_FILTERED_OUT, req);
		return;
	}

	tl_dc_stats* dc_stats = as_dc_get_tl_dc_stats(dc);
	tl_ns_stats* ns_stats = &dc_stats->ns_stats[ns->ix];
	as_storage_rd rd;

	as_storage_record_open(ns, r, &rd);
	as_storage_record_get_set_name(&rd);
	as_storage_rd_load_key(&rd);

	as_bin stack_bins[ns->single_bin ? 1 : RECORD_MAX_BINS];

	as_xdr_dc_ns_cfg* dc_ns_cfg = dc->cfg.ns_cfgs[ns->ix];

	if (dc_ns_cfg->bin_policy != XDR_BIN_POLICY_NO_BINS || filter != NULL) {
		if (as_storage_rd_load_bins(&rd, stack_bins) != 0) {
			read_done(&rd, &r_ref, &rsv);
			as_dc_client_cb(LOCAL_ERR_REC_READ, req);
			return;
		}

		// Note - bin_filter() also handles stored key, if any.
		if (filter != NULL && ! bin_filter(ns, &rd, filter)) {
			read_done(&rd, &r_ref, &rsv);
			as_dc_client_cb(LOCAL_ERR_REC_FILTERED_OUT, req);
			return;
		}
	}

	as_xdr_trace(dc, keyd, req->lut, "%s (read lut %s)",
			r->tombstone == 0 || r->xdr_bin_cemetery == 1 ? "ship" : "delete",
			as_xdr_pretty_ms((uint64_t)r->last_update_time));

	req->ship_time = cf_getns();
	as_ship_send_record(dc->ix, &dc->cfg, &rd, req, ns_stats);
	as_dc_ship_attempt_cb(dc, ns);

	read_done(&rd, &r_ref, &rsv);
}


//==========================================================
// Public API - enterprise only.
//

void
as_reader_enqueue(ship_request* req)
{
	as_proto* proto = cf_malloc(sizeof(as_proto) + sizeof(ship_request*));

	proto->version = PROTO_VERSION;
	proto->type = PROTO_TYPE_INTERNAL_XDR;
	proto->sz = sizeof(ship_request*);
	*(ship_request**)proto->body = req;

	as_transaction tr;
	as_transaction_init_head(&tr, NULL, (cl_msg*)proto);

	as_service_enqueue_internal_raw(&tr, &req->keyd,
			req->dc->cfg.max_used_service_threads, true);
}


//==========================================================
// Local helpers.
//

static void
read_done(as_storage_rd* rd, as_index_ref* r_ref, as_partition_reservation* rsv)
{
	if (rd != NULL) {
		as_storage_record_close(rd);
	}

	if (r_ref != NULL) {
		as_record_done(r_ref, rsv->ns);
	}

	as_partition_release(rsv);
}

static bool
meta_filter(as_dc* dc, as_namespace* ns, as_record* r, xdr_filter** p_filter)
{
	xdr_filter* filter = as_dc_get_ns_filter(dc, ns);

	if (filter == NULL) {
		return true;
	}

	as_exp_ctx ctx = { .ns = ns, .r = r };
	as_exp_trilean tv = as_exp_matches_metadata(filter->exp, &ctx);

	if (tv == AS_EXP_UNK) {
		*p_filter = filter; // caller must apply later with bins
		return true;
	}
	// else - caller will not need to apply filter later.

	xdr_filter_release(filter);

	return tv == AS_EXP_TRUE;
}

static bool
bin_filter(as_namespace* ns, as_storage_rd* rd, xdr_filter* filter)
{
	as_exp_ctx ctx = { .ns = ns, .r = rd->r, .rd = rd };
	bool result = as_exp_matches_record(filter->exp, &ctx);

	xdr_filter_release(filter);

	return result;
}
