/*
 * delete_ee.c
 *
 * Copyright (C) 2008-2021 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "transaction/delete.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"

#include "log.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/exp.h"
#include "base/index.h"
#include "base/proto.h"
#include "base/set_index.h"
#include "base/transaction.h"
#include "fabric/fabric.h"
#include "fabric/partition.h"
#include "sindex/secondary_index.h"
#include "storage/storage.h"
#include "transaction/re_replicate_ee.h"
#include "transaction/rw_request.h"
#include "transaction/rw_utils.h"


//==========================================================
// Forward declarations.
//

transaction_status tombstone_master(as_transaction* tr, as_index_ref* r_ref, rw_request* rw);
bool xdr_tombstone_local(as_namespace* ns, as_partition_reservation* rsv, as_index_ref* r_ref);


//==========================================================
// Private API - for enterprise separation only.
//

bool
delete_storage_overloaded(as_transaction* tr)
{
	as_namespace* ns = tr->rsv.ns;

	return as_transaction_is_durable_delete(tr) || ns->xdr_ships_drops ?
			as_storage_overloaded(ns, 32, "durable delete") : false;
}

transaction_status
delete_master(as_transaction* tr, rw_request* rw)
{
	as_namespace* ns = tr->rsv.ns;

	if (ns->clock_skew_stop_writes) {
		// TODO - new error code?
		tr->result_code = AS_ERR_FORBIDDEN;
		return TRANS_DONE_ERROR;
	}

	as_index_ref r_ref;

	if (as_record_get(tr->rsv.tree, &tr->keyd, &r_ref) != 0) {
		tr->result_code = AS_ERR_NOT_FOUND;
		return TRANS_DONE_ERROR;
	}

	as_record* r = r_ref.r;

	// Make sure the message set name (if it's there) is correct.
	if (! set_name_check(tr, r)) {
		as_record_done(&r_ref, ns);
		tr->result_code = AS_ERR_PARAMETER;
		return TRANS_DONE_ERROR;
	}

	// Don't bother to re-replicate before drops. (Note - it's possible to drop
	// a record that is currently re-replicating.)
	if (as_transaction_is_durable_delete(tr) && repl_state_check(r, tr) < 0) {
		as_record_done(&r_ref, ns);
		return TRANS_WAITING;
	}

	if (r->tombstone == 1) {
		as_record_done(&r_ref, ns);
		tr->result_code = AS_ERR_NOT_FOUND;
		return TRANS_DONE_ERROR;
	}
	// else - delete live record.

	// CP uses this to avoid confirming replication for drops, etc.
	tr->flags |= AS_TRANSACTION_FLAG_IS_DELETE;

	return as_transaction_is_durable_delete(tr) || ns->xdr_ships_drops ?
			tombstone_master(tr, &r_ref, rw) : drop_master(tr, &r_ref, rw);
}

bool
drop_local(as_namespace* ns, as_partition_reservation* rsv, as_index_ref* r_ref)
{
	as_record* r = r_ref->r;

	if (! ns->xdr_ships_nsup_drops) {
		if (ns->storage_data_in_memory) {
			remove_from_sindex(ns, r_ref);
		}

		as_set_index_delete(ns, rsv->tree, as_index_get_set_id(r), r_ref->r_h);
		as_index_delete(rsv->tree, &r->keyd);
		as_record_done(r_ref, ns);
		return true;
	}

	// Simplest to leave (extremely unlikely) active records alone.
	if (ns->cp && (r->repl_state == AS_REPL_STATE_REPLICATING ||
			r->repl_state == AS_REPL_STATE_RE_REPLICATING)) {
		as_record_done(r_ref, ns);
		return false;
	}

	return xdr_tombstone_local(ns, rsv, r_ref); // calls as_record_done()
}


//==========================================================
// Local helpers - master operations.
//

transaction_status
tombstone_master(as_transaction* tr, as_index_ref* r_ref, rw_request* rw)
{
	as_msg* m = &tr->msgp->msg;
	as_namespace* ns = tr->rsv.ns;
	as_record* r = r_ref->r;

	// TODO - bypassing stop-writes and storage space check - is this ok?

	// Check generation requirement, if any.
	if (! generation_check(r, m, ns)) {
		as_record_done(r_ref, ns);
		cf_atomic64_incr(&ns->n_fail_generation);
		tr->result_code = AS_ERR_GENERATION;
		return TRANS_DONE_ERROR;
	}

	// Apply predexp metadata filter if present.

	as_exp* filter_exp = NULL;
	int result = handle_meta_filter(tr, r, &filter_exp);

	if (result != 0) {
		as_record_done(r_ref, ns);
		tr->result_code = result;
		return TRANS_DONE_ERROR;
	}

	as_storage_rd rd;
	as_storage_record_open(ns, r, &rd);

	// Apply predexp record bins filter if present.
	if (filter_exp != NULL) {
		if ((result = read_and_filter_bins(&rd, filter_exp)) != 0) {
			destroy_filter_exp(tr, filter_exp);
			as_storage_record_close(&rd);
			as_record_done(r_ref, ns);
			tr->result_code = result;
			return TRANS_DONE_ERROR;
		}

		destroy_filter_exp(tr, filter_exp);
	}

	// Already checked that message set name (if any - it's optional) matches.
	as_storage_record_get_set_name(&rd);

	// Deal with key storage as needed.
	if ((result = handle_msg_key(tr, &rd)) != 0) {
		as_storage_record_close(&rd);
		as_record_done(r_ref, ns);
		tr->result_code = result;
		return TRANS_DONE_ERROR;
	}

	// Set up the nodes to which we'll write replicas.
	if (! set_replica_destinations(tr, rw)) {
		as_storage_record_close(&rd);
		as_record_done(r_ref, ns);
		tr->result_code = AS_ERR_UNAVAILABLE;
		return TRANS_DONE_ERROR;
	}

	// Fire and forget can overload the fabric send queues - check.
	if (respond_on_master_complete(tr) &&
			as_fabric_is_overloaded(rw->dest_nodes, rw->n_dest_nodes,
					AS_FABRIC_CHANNEL_RW, 8)) {
		tr->flags |= AS_TRANSACTION_FLAG_SWITCH_TO_COMMIT_ALL;
	}

	// Will we need a pickle?
	rd.keep_pickle = rw->n_dest_nodes != 0;

	// Get the live record's bins info.
	as_bin stack_bins[RECORD_MAX_BINS];
	bool update_si = r->in_sindex == 1 && set_has_sindex(r, ns);

	if (ns->storage_data_in_memory || update_si) {
		as_storage_rd_load_bins(&rd, stack_bins);
	}

	// For memory accounting, note current usage.
	uint32_t memory_bytes = as_storage_record_mem_size(ns, r);

	// Save the live record's bins info.
	uint32_t n_old_bins = (uint32_t)rd.n_bins;
	as_bin* old_bins = rd.bins;

	// The new record has no bins.
	rd.n_bins = 0;
	rd.bins = NULL;

	// Apply changes to metadata in as_index needed for response, pickling,
	// and writing.
	index_metadata old_metadata;

	stash_index_metadata(r, &old_metadata);

	// Tombstones don't expire.
	r->void_time = 0;

	// Advance record version like a regular write.
	as_record_set_lut(r, tr->rsv.regime, cf_clepoch_milliseconds(), ns);
	as_record_increment_generation(r, ns);

	// Set type of write.
	r->xdr_write = as_transaction_is_xdr(tr) ? 1 : 0;

	// Transition record-type metadata.
	r->tombstone = 1;
	r->cenotaph = 0;
	r->xdr_tombstone = as_transaction_is_durable_delete(tr) ? 0 : 1;
	r->xdr_nsup_tombstone = 0; // nsup deletes never get here

	if (r->xdr_tombstone == 1) {
		tr->flags |= AS_TRANSACTION_FLAG_XDR_TOMBSTONE;
	}

	// Write the tombstone to storage.
	if ((result = as_storage_record_write(&rd)) < 0) {
		unwind_index_metadata(&old_metadata, r);
		as_storage_record_close(&rd);
		as_record_done(r_ref, ns);
		tr->result_code = -result;
		return TRANS_DONE_ERROR;
	}

	as_record_transition_stats(r, ns, &old_metadata);
	pickle_all(&rd, rw);

	// Success - no unwinding after this point.

	if (update_si) {
		remove_from_sindex_bins(ns, r_ref, old_bins, n_old_bins);
	}
	else {
		// Sindex drop will leave in_sindex bit. Good opportunity to clear.
		as_index_clear_in_sindex(r);
	}

	if (ns->storage_data_in_memory) {
		as_bin_destroy_all(old_bins, n_old_bins);

		if (ns->single_bin) {
			// Note - for single-bin DIM as_storage_rd_load_bins() derives
			// rd->n_bins from bin (used) state - must clear deleted bin.
			as_bin_set_empty(old_bins);
		}
		else {
			as_record_free_bin_space(r);
		}
	}

	// Accommodate a new stored key - wasn't needed for pickling and writing.
	if (r->key_stored == 0 && rd.key) {
		if (ns->storage_data_in_memory) {
			as_record_allocate_key(r, rd.key, rd.key_size);
		}

		r->key_stored = 1;
	}

	as_storage_record_adjust_mem_stats(&rd, memory_bytes);

	// These will also go to the replicas, but not the origin.
	tr->generation = r->generation;
	tr->void_time = r->void_time;
	tr->last_update_time = r->last_update_time;

	as_set_index_delete(ns, tr->rsv.tree, as_index_get_set_id(r), r_ref->r_h);

	will_replicate(r, ns);

	// Save for XDR submit outside record lock.
	as_xdr_submit_info submit_info;

	as_xdr_get_submit_info(r, old_metadata.last_update_time, &submit_info);

	as_storage_record_close(&rd);
	as_record_done(r_ref, ns);

	as_xdr_submit(ns, &submit_info);

	return TRANS_IN_PROGRESS;
}

bool
xdr_tombstone_local(as_namespace* ns, as_partition_reservation* rsv,
		as_index_ref* r_ref)
{
	as_record* r = r_ref->r;

	as_storage_rd rd;
	as_storage_record_open(ns, r, &rd);

	// Load the set name and key, to be stored.
	as_storage_record_get_set_name(&rd);
	as_storage_rd_load_key(&rd);

	// Get the live record's bins info.
	as_bin stack_bins[RECORD_MAX_BINS];
	bool update_si = r->in_sindex == 1 && set_has_sindex(r, ns);

	if (ns->storage_data_in_memory || update_si) {
		as_storage_rd_load_bins(&rd, stack_bins);
	}

	// For memory accounting, note current usage.
	uint32_t memory_bytes = as_storage_record_mem_size(ns, r);

	// Save the live record's bins info.
	uint32_t n_old_bins = (uint32_t)rd.n_bins;
	as_bin* old_bins = rd.bins;

	// The new record has no bins.
	rd.n_bins = 0;
	rd.bins = NULL;

	// Apply changes to metadata in as_index needed for response, pickling,
	// and writing.
	index_metadata old_metadata;

	stash_index_metadata(r, &old_metadata);

	// Tombstones don't expire.
	r->void_time = 0;

	// FIXME - ok to use possible stale regime on non-master?
	// Advance record version like a regular write.
	as_record_set_lut(r, rsv->regime, cf_clepoch_milliseconds(), ns);
	as_record_increment_generation(r, ns);

	// Set type of write.
	r->xdr_write = 0;

	// Transition record-type metadata.
	r->tombstone = 1;
	r->cenotaph = 0;
	r->xdr_tombstone = 1;
	r->xdr_nsup_tombstone = 1; // only nsup deletes get here

	rd.which_current_swb = ! ns->storage_data_in_memory &&
			// Only masters with stored keys should go in the post-write-queue.
			r->key_stored == 1 && g_config.self_node == rsv->p->working_master ?
					SWB_MASTER : SWB_UNCACHED;

	// Write the xdr-tombstone to storage.
	if (as_storage_record_write(&rd) < 0) {
		unwind_index_metadata(&old_metadata, r);
		as_storage_record_close(&rd);
		as_record_done(r_ref, ns);
		return false;
	}

	as_record_transition_stats(r, ns, &old_metadata);

	// Success - no unwinding after this point.

	if (update_si) {
		remove_from_sindex_bins(ns, r_ref, old_bins, n_old_bins);
	}
	else {
		// Sindex drop will leave in_sindex bit. Good opportunity to clear.
		as_index_clear_in_sindex(r);
	}

	if (ns->storage_data_in_memory) {
		as_bin_destroy_all(old_bins, n_old_bins);

		if (ns->single_bin) {
			// Clear the bin embedded in the tombstone as_index struct.
			as_bin_set_empty(old_bins);
		}
		else {
			as_record_free_bin_space(r);
		}
	}

	as_storage_record_adjust_mem_stats(&rd, memory_bytes);

	as_set_index_delete(ns, rsv->tree, as_index_get_set_id(r), r_ref->r_h);

	// Ok to delete UNREPLICATED records.
	as_set_repl_state(ns, r, AS_REPL_STATE_REPLICATED);

	// Save for XDR submit outside record lock.
	as_xdr_submit_info submit_info;

	as_xdr_get_submit_info(r, old_metadata.last_update_time, &submit_info);

	as_storage_record_close(&rd);
	as_record_done(r_ref, ns);

	as_xdr_submit(ns, &submit_info);

	return true;
}
