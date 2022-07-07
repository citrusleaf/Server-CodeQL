/*
 * re_replicate_ee.c
 *
 * Copyright (C) 2017-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "transaction/re_replicate.h"
#include "transaction/re_replicate_ee.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"

#include "cf_mutex.h"
#include "log.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "base/proto.h"
#include "base/service.h"
#include "base/transaction.h"
#include "fabric/partition.h"
#include "storage/storage.h"
#include "transaction/duplicate_resolve.h"
#include "transaction/replica_write.h"
#include "transaction/rw_request.h"
#include "transaction/rw_request_hash.h"
#include "transaction/rw_utils.h"


//==========================================================
// Forward declarations.
//

void rer_init(as_transaction* tr, as_namespace* ns, const cf_digest* keyd);

void start_rer_repl_write(rw_request* rw, as_transaction* tr);
void start_rer_dup_res(rw_request* rw, as_transaction* tr);
bool rer_dup_res_cb(rw_request* rw);
void rer_repl_write_after_dup_res(rw_request* rw, as_transaction* tr);
void rer_repl_write_cb(rw_request* rw);

void rer_abort_cb(as_transaction* tr);
void rer_done(as_transaction* tr, bool success);
void rer_done_stats(as_transaction* tr, bool success);
void rer_timeout_cb(rw_request* rw);
void rer_set_state(as_partition_reservation* rsv, cf_digest* keyd, bool success);

transaction_status touch_master(rw_request* rw, as_transaction* tr);
void touch_master_failed(as_namespace* ns, as_index_ref* r_ref, as_storage_rd* rd);


//==========================================================
// Inlines & macros.
//

static inline void
rer_update_stats(as_namespace* ns, uint8_t result_code)
{
	switch (result_code) {
	case AS_OK:
		cf_atomic64_incr(&ns->n_re_repl_success);
		break;
	case AS_ERR_TIMEOUT:
		cf_atomic64_incr(&ns->n_re_repl_timeout);
		break;
	default:
		cf_atomic64_incr(&ns->n_re_repl_error);
		break;
	}
}


//==========================================================
// Public API.
//

transaction_status
as_re_replicate_start(as_transaction* tr)
{
	// We think it's best to bypass the write queue backup check.

	// Create rw_request and add to hash.
	rw_request_hkey hkey = { tr->rsv.ns->ix, tr->keyd };
	rw_request* rw = rw_request_create(&tr->keyd);
	transaction_status status = rw_request_hash_insert(&hkey, rw, tr);

	// If rw_request wasn't inserted in hash, transaction is waiting.
	if (status != TRANS_IN_PROGRESS) {
		cf_assert(status == TRANS_WAITING, AS_RW, "re-repl not waiting");
		rw_request_release(rw);
		return TRANS_WAITING;
	}
	// else - rw_request is now in hash, continue...

	// If there are duplicates to resolve, start doing so.
	if (tr->rsv.n_dupl != 0) {
		start_rer_dup_res(rw, tr);

		// Started duplicate resolution.
		return TRANS_IN_PROGRESS;
	}
	// else - no duplicate resolution phase, apply operation to master.

	status = touch_master(rw, tr);

	if (status != TRANS_IN_PROGRESS) {
		rw_request_hash_delete(&hkey, rw);
		rer_done_stats(tr, status == TRANS_DONE_SUCCESS);
		return status;
	}

	if (rw->n_dest_nodes == 0) {
		rer_done(tr, true);
		rw_request_hash_delete(&hkey, rw);
		return TRANS_DONE_SUCCESS;
	}

	start_rer_repl_write(rw, tr);

	// Started replica write.
	return TRANS_IN_PROGRESS;
}


//==========================================================
// Public API - enterprise only.
//

void
as_re_replicate(as_namespace* ns, const cf_digest* keyd)
{
	as_transaction tr;

	rer_init(&tr, ns, keyd);
	as_service_enqueue_internal(&tr);
}


//==========================================================
// Local helpers - transaction trigger.
//

void
rer_init(as_transaction* tr, as_namespace* ns, const cf_digest* keyd)
{
	uint8_t info2 = AS_MSG_INFO2_WRITE | AS_MSG_INFO2_DURABLE_DELETE;

	// Note - digest is on transaction head before it's enqueued.
	as_transaction_init_head(tr, keyd,
			as_msg_create_internal(ns->name, 0, info2, 0, 0, 0, NULL, 0));

	as_transaction_set_msg_field_flag(tr, AS_MSG_FIELD_TYPE_NAMESPACE);

	tr->origin = FROM_RE_REPL;
	tr->from.re_repl_orig_cb = rer_abort_cb;

	// Do this last, to exclude the setup time in this function.
	tr->start_time = cf_getns();
}


//==========================================================
// Local helpers - transaction flow.
//

void
start_rer_dup_res(rw_request* rw, as_transaction* tr)
{
	// Finish initializing rw, construct and send dup-res message.

	dup_res_make_message(rw, tr);

	cf_mutex_lock(&rw->lock);

	dup_res_setup_rw(rw, tr, rer_dup_res_cb, rer_timeout_cb);
	send_rw_messages(rw);

	cf_mutex_unlock(&rw->lock);
}

void
start_rer_repl_write(rw_request* rw, as_transaction* tr)
{
	// Finish initializing rw, construct and send repl-write message.

	repl_write_make_message(rw, tr);

	cf_mutex_lock(&rw->lock);

	repl_write_setup_rw(rw, tr, rer_repl_write_cb, rer_timeout_cb);
	send_rw_messages(rw);

	cf_mutex_unlock(&rw->lock);
}

bool
rer_dup_res_cb(rw_request* rw)
{
	as_transaction tr;
	as_transaction_init_from_rw(&tr, rw);

	if (tr.result_code != AS_OK) {
		rer_done(&tr, false);
		return true;
	}

	transaction_status status = touch_master(rw, &tr);

	if (status != TRANS_IN_PROGRESS) {
		rer_done_stats(&tr, status == TRANS_DONE_SUCCESS);
		return true;
	}

	if (rw->n_dest_nodes == 0) {
		rer_done(&tr, true);
		return true;
	}

	rer_repl_write_after_dup_res(rw, &tr);

	// Started replica write - don't delete rw_request from hash.
	return false;
}

void
rer_repl_write_after_dup_res(rw_request* rw, as_transaction* tr)
{
	// Recycle rw_request that was just used for duplicate resolution to now do
	// replica writes. Note - we are under the rw_request lock here!

	repl_write_make_message(rw, tr);
	repl_write_reset_rw(rw, tr, rer_repl_write_cb);
	send_rw_messages(rw);
}

void
rer_repl_write_cb(rw_request* rw)
{
	as_transaction tr;
	as_transaction_init_from_rw(&tr, rw);

	// Only get here on success.
	rer_done(&tr, true);

	// Finished transaction - rw_request cleans up reservation and msgp!
}


//==========================================================
// Local helpers - transaction end.
//

// Can be called without a reservation or available namespace and digest -
// extract necessary information from original message.
void
rer_abort_cb(as_transaction* tr)
{
	as_msg* m = &tr->msgp->msg;

	// No checks - message is internal, didn't come off wire.
	as_msg_field* nf = as_msg_field_get(m, AS_MSG_FIELD_TYPE_NAMESPACE);
	as_namespace* ns = as_namespace_get_bymsgfield(nf);

	as_partition_reservation rsv;

	as_partition_reserve(ns, as_partition_getid(&tr->keyd), &rsv);
	rer_set_state(&rsv, &tr->keyd, false);
	as_partition_release(&rsv);

	// Can't use macro - tr may not have a reservation.
	ns->re_repl_hist_active = true;

	if (tr->result_code != AS_ERR_TIMEOUT) {
		histogram_insert_data_point(ns->re_repl_hist, tr->start_time);
	}

	rer_update_stats(ns, tr->result_code);
}

void
rer_done(as_transaction* tr, bool success)
{
	// Paranoia - shouldn't get here on losing race with timeout.
	if (! tr->from.any) {
		cf_warning(AS_RW, "transaction origin %u has null 'from'", tr->origin);
		return;
	}

	cf_assert(tr->origin == FROM_RE_REPL, AS_RW,
			"unexpected transaction origin %u", tr->origin);

	rer_set_state(&tr->rsv, &tr->keyd, success);

	HIST_ACTIVATE_INSERT_DATA_POINT(tr, re_repl_hist);
	rer_update_stats(tr->rsv.ns, success ? AS_OK : AS_ERR_UNKNOWN);

//	tr->from.any = NULL; // no respond-on-master-complete
}

// TODO - when paranoia subsides, call this from rer_done().
void
rer_done_stats(as_transaction* tr, bool success)
{
	// Paranoia - shouldn't get here on losing race with timeout.
	if (! tr->from.any) {
		cf_warning(AS_RW, "transaction origin %u has null 'from'", tr->origin);
		return;
	}

	cf_assert(tr->origin == FROM_RE_REPL, AS_RW,
			"unexpected transaction origin %u", tr->origin);

	HIST_ACTIVATE_INSERT_DATA_POINT(tr, re_repl_hist);
	rer_update_stats(tr->rsv.ns, success ? AS_OK : AS_ERR_UNKNOWN);

//	tr->from.any = NULL; // no respond-on-master-complete
}

void
rer_timeout_cb(rw_request* rw)
{
	if (! rw->from.any) {
		return; // lost race against dup-res or repl-write callback
	}

	cf_assert(rw->origin == FROM_RE_REPL, AS_RW,
			"unexpected transaction origin %u", rw->origin);

	rer_set_state(&rw->rsv, &rw->keyd, false);

	// Timeouts aren't included in histograms.
	rer_update_stats(rw->rsv.ns, AS_ERR_TIMEOUT);

	rw->from.any = NULL; // inform other callback it lost the race
}

void
rer_set_state(as_partition_reservation* rsv, cf_digest* keyd, bool success)
{
	as_namespace* ns = rsv->ns;
	as_index_ref r_ref;

	if (as_record_get(rsv->tree, keyd, &r_ref) != 0) {
		cf_warning(AS_RW, "{%s} drop while re-replicating", ns->name);
		return;
	}

	if (r_ref.r->repl_state != AS_REPL_STATE_REPLICATING &&
			r_ref.r->repl_state != AS_REPL_STATE_RE_REPLICATING) {
		cf_warning(AS_RW, "{%s} drop & create while re-replicating", ns->name);
		as_record_done(&r_ref, ns);
		return;
	}

	// TODO - may prefer never dropping while record is (re-) replicating, and
	// letting the drops issue the above warnings.

	as_set_repl_state(ns, r_ref.r,
			success ? AS_REPL_STATE_REPLICATED : AS_REPL_STATE_UNREPLICATED);

	as_record_done(&r_ref, ns);
}


//==========================================================
// Local helpers - touch master.
//

// Not like a regular touch op, since this doesn't change generation, and can
// touch tombstones.
transaction_status
touch_master(rw_request* rw, as_transaction* tr)
{
	as_namespace* ns = tr->rsv.ns;

	CF_ALLOC_SET_NS_ARENA_DIM(ns);

	as_index_tree* tree = tr->rsv.tree;

	as_index_ref r_ref;

	if (as_record_get(tree, &tr->keyd, &r_ref) != 0) {
		return TRANS_DONE_ERROR;
	}

	as_record* r = r_ref.r;

	// Might be saved by our own duplicate resolution. Or, record may have been
	// dropped and recreated. It's also possible this leaves us 'unreplicated'.
	if (r->repl_state == AS_REPL_STATE_REPLICATED) {
		as_record_done(&r_ref, ns);
		return TRANS_DONE_SUCCESS;
	}

	// TODO - temporary paranoia:
	cf_assert(r->repl_state == AS_REPL_STATE_RE_REPLICATING ||
			r->repl_state == AS_REPL_STATE_UNREPLICATED, AS_RW,
			"unexpected repl-state %d", r->repl_state);

	// Not earlier, since we need to adjust repl-state under lock.
	if (ns->clock_skew_stop_writes) {
		touch_master_failed(ns, &r_ref, NULL);
		return TRANS_DONE_ERROR;
	}

	as_storage_rd rd;

	as_storage_record_open(ns, r, &rd);

	// Set up the nodes to which we'll write replicas.
	if (! set_replica_destinations(tr, rw)) {
		touch_master_failed(ns, &r_ref, &rd);
		return TRANS_DONE_ERROR;
	}

	// Will we need a pickle?
	rd.keep_pickle = rw->n_dest_nodes != 0;

	// Stack space for resulting record's bins.
	as_bin stack_bins[ns->single_bin ? 1 : RECORD_MAX_BINS];

	int result = as_storage_rd_load_bins(&rd, stack_bins);

	if (result < 0) {
		touch_master_failed(ns, &r_ref, &rd);
		return TRANS_DONE_ERROR;
	}

	// Shortcut for set name storage.
	as_storage_record_get_set_name(&rd);

	// Deal with key storage as needed.
	if (r->key_stored == 1 && ! as_storage_rd_load_key(&rd)) {
		touch_master_failed(ns, &r_ref, &rd);
		return TRANS_DONE_ERROR;
	}

	uint64_t old_last_update_time = r->last_update_time;
	uint16_t old_generation = r->generation;
	bool old_cenotaph = r->cenotaph == 1;

	as_record_set_lut(r, tr->rsv.regime, cf_clepoch_milliseconds(), ns);
	r->cenotaph = 0;

	if (r->xdr_tombstone == 1) {
		tr->flags |= AS_TRANSACTION_FLAG_XDR_TOMBSTONE;
	}

	if ((result = as_storage_record_write(&rd)) < 0) {
		r->last_update_time = old_last_update_time;
		r->generation = old_generation;
		r->cenotaph = old_cenotaph ? 1 : 0;
		touch_master_failed(ns, &r_ref, &rd);
		return TRANS_DONE_ERROR;
	}

	pickle_all(&rd, rw);

	as_set_repl_state(ns, r, AS_REPL_STATE_REPLICATING);

	// Make sure these go in the replica write.
	tr->generation = r->generation;
	tr->void_time = r->void_time;
	tr->last_update_time = r->last_update_time;

	// Save for XDR submit outside record lock.
	as_xdr_submit_info submit_info;

	as_xdr_get_submit_info(r, old_last_update_time, &submit_info);

	as_storage_record_close(&rd);
	as_record_done(&r_ref, ns);

	// Note - not bothering to check ns->xdr_ships_drops.
	as_xdr_submit(ns, &submit_info);

	return TRANS_IN_PROGRESS;
}

void
touch_master_failed(as_namespace* ns, as_index_ref* r_ref, as_storage_rd* rd)
{
	if (rd) {
		as_storage_record_close(rd);
	}

	as_set_repl_state(ns, r_ref->r, AS_REPL_STATE_UNREPLICATED);

	as_record_done(r_ref, ns);
}
