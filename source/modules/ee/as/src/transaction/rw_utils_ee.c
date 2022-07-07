/*
 * rw_utils_ee.c
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

#include "transaction/rw_utils.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "aerospike/as_atomic.h"

#include "log.h"
#include "msg.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "base/proto.h"
#include "base/record_ee.h"
#include "base/service.h"
#include "base/transaction.h"
#include "fabric/fabric.h"
#include "fabric/partition.h"
#include "transaction/re_replicate_ee.h"
#include "transaction/rw_request_hash.h"


//==========================================================
// Inlines & macros.
//

// TODO - may be possible to directly queue original if it won't be looked at on
// the way out.
static inline void
retry_self(as_transaction* tr)
{
	as_transaction rtr;

	as_transaction_copy_head(&rtr, tr);
	tr->from.any = NULL;
	tr->msgp = NULL;

	rtr.from_flags |= FROM_FLAG_RESTART;
	as_service_enqueue_internal(&rtr);
}

static inline uint8_t
get_src_id(uint64_t msg_lut)
{
	return (uint8_t)(msg_lut >> 40);
}

static inline uint64_t
get_src_lut(uint64_t msg_lut)
{
	return msg_lut & 0xFFffffFFFF;
}

static inline bool
forbid_client_bin_write(const as_storage_rd* rd, const as_bin* b, bool use_lut)
{
	return (b->xdr_write == 1 || rd->ns->cp) && (use_lut ?
			rd->r->last_update_time : cf_clepoch_milliseconds()) <= b->lut;
}

#define IS_FULL_DROP(trw) (IS_DROP(trw) && \
		(trw->flags & AS_TRANSACTION_FLAG_XDR_TOMBSTONE) == 0)


//==========================================================
// Public API.
//

bool
convert_to_write(as_transaction* tr, cl_msg** p_msgp)
{
	as_namespace* ns = tr->rsv.ns;

	if (! ns->xdr_ships_bin_luts || ! as_transaction_is_durable_delete(tr)) {
		return false; // just do a normal record delete
	}

	uint64_t old_proto_sz = tr->msgp->proto.sz;
	uint64_t new_proto_sz = old_proto_sz + sizeof(as_msg_op);

	cl_msg* new_msgp = (cl_msg*)cf_malloc(sizeof(as_proto) + new_proto_sz);

	new_msgp->proto.version = PROTO_VERSION;
	new_msgp->proto.type = PROTO_TYPE_AS_MSG;
	new_msgp->proto.sz = new_proto_sz;

	memcpy(new_msgp->proto.body, tr->msgp->proto.body, old_proto_sz);

	as_msg* m = &new_msgp->msg;

	// TODO - sanitize any other info bits?
	m->info2 &= ~AS_MSG_INFO2_DELETE;
	m->n_ops = 1;

	as_msg_op* op = (as_msg_op*)(new_msgp->proto.body + old_proto_sz);

	*op = (as_msg_op){
			.op_sz = sizeof(as_msg_op) - sizeof(op->op_sz),
			.op = AS_MSG_OP_DELETE_ALL
	};

	cf_free(tr->msgp);
	tr->msgp = new_msgp;
	*p_msgp = new_msgp;

	return true;
}


int
validate_delete_durability(as_transaction* tr)
{
	as_namespace* ns = tr->rsv.ns;

	if (! ns->cp || ns->cp_allow_drops) {
		return AS_OK;
	}
	// else - drops are not allowed, so policy better be 'durable'.

	return as_transaction_is_durable_delete(tr) ? AS_OK : AS_ERR_FORBIDDEN;
}


// Returns:
//  0: record was ok - proceed with current transaction
//  1: record was replicating (reads only) - wait behind it at rw-request hash
// -1: record re-replicating, transaction re-queued - abort current transaction
// -2: record in the "future", transaction re-queued - abort current transaction
// -3: read can't fix unreplicated record - fail current transaction
int
repl_state_check(as_record* r, as_transaction* tr)
{
	as_namespace* ns = tr->rsv.ns;

	if (! ns->cp) {
		return 0;
	}

	bool is_write = (tr->msgp->msg.info2 & AS_MSG_INFO2_WRITE) != 0;

	if (is_write && as_record_write_lut_is_stale_cp(r, tr->rsv.regime)) {
		// E.g. master was just handed off, new master has replicated back here
		// from future regime, our reservation is stale. Retrying should proxy
		// to new master, may succeed.
		retry_self(tr);
		return -2;
	}

	switch (r->repl_state) {
	case AS_REPL_STATE_REPLICATED:
		// Ok, move along.
		return 0;
	case AS_REPL_STATE_REPLICATING:
		cf_assert(! is_write, AS_RW, "write found state 'replicating'");
		return 1;
	case AS_REPL_STATE_UNREPLICATED:
		// If it's a relaxed read on a prole, retry forcing proxy.
		// TODO - for replication factor > 2, may want a heuristic to retry
		// locally - without tight retry loop - while waiting for confirmation.
		if ((tr->flags & AS_TRANSACTION_FLAG_RSV_PROLE) != 0) {
			tr->from_flags |= FROM_FLAG_RESTART_STRICT;
			retry_self(tr);
			return -1;
		}
		// If it's an allow-unavailable read on unavailable partition, fail.
		if ((tr->flags & AS_TRANSACTION_FLAG_RSV_UNAVAILABLE) != 0) {
			return -3;
		}
		// Generate re-replication and retry self.
		as_re_replicate(ns, &r->keyd);
		as_set_repl_state(ns, r, AS_REPL_STATE_RE_REPLICATING);
		// No break.
	case AS_REPL_STATE_RE_REPLICATING:
		retry_self(tr);
		return -1;
	default:
		cf_crash(AS_RW, "unexpected repl-state %u", r->repl_state);
		return 0;
	}
}


void
will_replicate(as_record* r, as_namespace* ns)
{
	if (ns->cp) {
		as_set_repl_state(ns, r, AS_REPL_STATE_REPLICATING);
	}
}


bool
write_is_full_drop(const as_transaction* tr)
{
	return IS_FULL_DROP(tr);
}


bool
sufficient_replica_destinations(const as_namespace* ns, uint32_t n_dests)
{
	return ns->cp ? n_dests >= ns->cfg_replication_factor - 1 : true;
}


bool
set_replica_destinations(as_transaction* tr, rw_request* rw)
{
	as_namespace* ns = tr->rsv.ns;

	rw->n_dest_nodes = as_partition_get_other_replicas(tr->rsv.p,
			rw->dest_nodes);

	return ns->cp ? rw->n_dest_nodes >= ns->cfg_replication_factor - 1 : true;
}


void
finished_replicated(as_transaction* tr)
{
	as_namespace* ns = tr->rsv.ns;

	if (! ns->cp || IS_FULL_DROP(tr)) {
		return;
	}

	as_index_ref r_ref;

	if (as_record_get(tr->rsv.tree, &tr->keyd, &r_ref) != 0) {
		cf_warning(AS_RW, "{%s} drop while replicating", ns->name);
		return;
	}

	if (r_ref.r->repl_state != AS_REPL_STATE_REPLICATING) {
		cf_assert(r_ref.r->repl_state != AS_REPL_STATE_RE_REPLICATING, AS_RW,
				"{%s} found re-replicating state while replicating", ns->name);
		cf_warning(AS_RW, "{%s} drop & create while replicating", ns->name);
		as_record_done(&r_ref, ns);
		return;
	}

	// TODO - may prefer never dropping while record is (re-) replicating, and
	// letting the drops issue the above warnings.

	// FIXME - temporary paranoia, remove soon.
	cf_assert(tr->generation == r_ref.r->generation, AS_RW, "generation changed");
	cf_assert(tr->last_update_time == r_ref.r->last_update_time, AS_RW, "last_update_time changed");

	as_set_repl_state(ns, r_ref.r, AS_REPL_STATE_REPLICATED);
	as_record_done(&r_ref, ns);
}


void
finished_not_replicated(rw_request* rw)
{
	as_namespace* ns = rw->rsv.ns;

	if (! ns->cp || ! rw->repl_write_cb || IS_FULL_DROP(rw)) {
		return;
	}

	as_index_ref r_ref;

	if (as_record_get(rw->rsv.tree, &rw->keyd, &r_ref) != 0) {
		cf_warning(AS_RW, "{%s} drop while replicating", ns->name);
		return;
	}

	if (r_ref.r->repl_state != AS_REPL_STATE_REPLICATING) {
		cf_assert(r_ref.r->repl_state != AS_REPL_STATE_RE_REPLICATING, AS_RW,
				"{%s} found re-replicating state while replicating", ns->name);
		cf_warning(AS_RW, "{%s} drop & create while replicating", ns->name);
		as_record_done(&r_ref, ns);
		return;
	}

	// TODO - may prefer never dropping while record is (re-) replicating, and
	// letting the drops issue the above warnings.

	// FIXME - temporary paranoia, remove soon.
	cf_assert(rw->generation == r_ref.r->generation, AS_RW, "generation changed");
	cf_assert(rw->last_update_time == r_ref.r->last_update_time, AS_RW, "last_update_time changed");

	as_re_replicate(ns, &rw->keyd);
	as_set_repl_state(ns, r_ref.r, AS_REPL_STATE_RE_REPLICATING);
	as_record_done(&r_ref, ns);
}


bool
generation_check(const as_record* r, const as_msg* m, const as_namespace* ns)
{
	// Pretend tombstones are generation 0.
	uint32_t record_generation = r->tombstone == 1 ?
			0 : plain_generation(r->generation, ns);

	if ((m->info2 & AS_MSG_INFO2_GENERATION) != 0) {
		return m->generation == record_generation;
	}

	if ((m->info2 & AS_MSG_INFO2_GENERATION_GT) != 0) {
		return m->generation > record_generation;
	}

	return true; // no generation requirement
}


bool
forbid_replace(const as_namespace* ns)
{
	// TODO - Forbid replace if just shipping changed bins?
	return ns->conflict_resolve_writes;
}


void
prepare_bin_metadata(const as_transaction* tr, as_storage_rd* rd)
{
	as_namespace* ns = rd->ns;
	as_record* r = rd->r;

	bool conflict_resolve_writes = as_load_bool(&ns->conflict_resolve_writes);
	bool xdr_ships_changed_bins = as_load_bool(&ns->xdr_ships_changed_bins);

	rd->resolve_writes = conflict_resolve_writes;
	rd->xdr_bin_writes = xdr_ships_changed_bins || conflict_resolve_writes;
	rd->bin_luts = xdr_ships_changed_bins;

	if (rd->xdr_bin_writes) {
		uint64_t now = cf_clepoch_milliseconds();
		uint64_t ttl_ms = as_load_uint64(&ns->xdr_bin_tombstone_ttl_ms);
		uint64_t lut_cutoff = ttl_ms == 0 ? 0 : now - ttl_ms;

		for (uint32_t i = 0; i < rd->n_bins; i++) {
			as_bin* b = &rd->bins[i];

			// Preserve metadata shared with record in case bin is not written.
			if (b->lut == 0) {
				b->xdr_write = r->xdr_write; // should be 0 if resolving bins
				b->lut = r->last_update_time;

				// FIXME - paranoia - b->src_id better be 0 if resolving bins.
				cf_assert(b->src_id == 0, AS_RW, "unexpected src-id %u",
						(uint32_t)b->src_id);
			}

			// Tomb raid bins.
			if (as_bin_is_tombstone(b) && b->lut < lut_cutoff) {
				as_bin_remove(rd, i--);
			}
			// Remove source IDs if no longer needed.
			else if (! conflict_resolve_writes) {
				b->src_id = 0;
			}
		}

		// Forbid successive (SC) client writes with the same LUT. Shipping such
		// successive writes leaves a hole, if they swap order after shipping.
		if (ns->xdr_ships_bin_luts && ns->cp && ! r->xdr_write &&
				! as_transaction_is_xdr(tr) && now == r->last_update_time) {
			// TODO - could avoid a loop if we had microsecond clock.
			while (cf_clepoch_milliseconds() == r->last_update_time) {
				usleep(100);
			}
		}

		return;
	}

	if (rd->bin_luts) { // no usage with independent LUTs yet
		for (uint32_t i = 0; i < rd->n_bins; i++) {
			as_bin* b = &rd->bins[i];

			// Remove all tombstones ...
			if (as_bin_is_tombstone(b)) {
				as_bin_remove(rd, i--);
				continue;
			}

			// ... and other non-LUT metadata.
			b->xdr_write = 0;
			b->src_id = 0;

			// Preserve LUT shared with record in case bin is not written.
			if (b->lut == 0) {
				b->lut = r->last_update_time;
			}
		}

		return;
	}

	if (! ns->storage_data_in_memory || r->has_bin_meta) {
		// Remove all tombstones and all metadata.
		for (uint32_t i = 0; i < rd->n_bins; i++) {
			as_bin* b = &rd->bins[i];

			if (as_bin_is_tombstone(b)) {
				as_bin_remove(rd, i--);
			}
			else {
				b->xdr_write = 0;
				b->lut = 0;
				b->src_id = 0;
			}
		}
	}
}


void
stash_index_metadata(const as_record* r, index_metadata* old)
{
	old->void_time = r->void_time;
	old->last_update_time = r->last_update_time;
	old->generation = r->generation;

	old->has_bin_meta = r->has_bin_meta == 1;

	old->xdr_write = r->xdr_write == 1;

	old->tombstone = r->tombstone == 1;
	old->cenotaph = r->cenotaph == 1;
	old->xdr_tombstone = r->xdr_tombstone == 1;
	old->xdr_nsup_tombstone = r->xdr_nsup_tombstone == 1;
	old->xdr_bin_cemetery = r->xdr_bin_cemetery == 1;
}


void
unwind_index_metadata(const index_metadata* old, as_record* r)
{
	r->void_time = old->void_time;
	r->last_update_time = old->last_update_time;
	r->generation = old->generation;

	r->has_bin_meta = old->has_bin_meta ? 1 : 0;

	r->xdr_write = old->xdr_write ? 1 : 0;

	r->tombstone = old->tombstone ? 1 : 0;
	r->cenotaph = old->cenotaph ? 1 : 0;
	r->xdr_tombstone = old->xdr_tombstone ? 1 : 0;
	r->xdr_nsup_tombstone = old->xdr_nsup_tombstone ? 1 : 0;
	r->xdr_bin_cemetery = old->xdr_bin_cemetery ? 1 : 0;
}


void
set_xdr_write(const as_transaction* tr, as_record* r)
{
	r->xdr_write = as_transaction_is_xdr(tr) ? 1 : 0;
}


void
touch_bin_metadata(as_storage_rd* rd)
{
	if (rd->xdr_bin_writes) { // rd->bin_luts must be true also
		for (uint32_t i = 0; i < rd->n_bins; i++) {
			as_bin* b = &rd->bins[i];

			b->xdr_write = 0;
			b->lut = 0;
		}

		return;
	}

	if (rd->bin_luts) { // no usage with independent LUTs yet
		for (uint32_t i = 0; i < rd->n_bins; i++) {
			rd->bins[i].lut = 0;
		}
	}
}


void
transition_delete_metadata(as_transaction* tr, as_record* r, bool is_delete,
		bool is_bin_cemetery)
{
	bool is_dd = as_transaction_is_durable_delete(tr);

	r->tombstone = is_delete && (is_dd || tr->rsv.ns->xdr_ships_drops) ? 1 : 0;
	r->cenotaph = 0;
	r->xdr_tombstone = r->tombstone == 1 && ! is_dd ? 1 : 0;
	r->xdr_nsup_tombstone = 0; // nsup deletes never get here
	r->xdr_bin_cemetery = is_bin_cemetery ? 1 : 0; // subset of tombstone

	if (r->tombstone == 1) {
		r->void_time = 0;
	}

	if (r->xdr_tombstone == 1) {
		tr->flags |= AS_TRANSACTION_FLAG_XDR_TOMBSTONE;
	}
}


// Return value false means apply ops, true means don't.
bool
forbid_resolve(const as_transaction* tr, const as_storage_rd* rd,
		uint64_t msg_lut)
{
	if (! rd->resolve_writes || ! as_transaction_is_xdr(tr)) {
		return false;
	}

	if (get_src_lut(msg_lut) == 0) {
		cf_ticker_warning(AS_RW, "unexpected src-lut 0");
		return true;
	}

	uint8_t src_id = get_src_id(msg_lut);

	if (src_id == 0 || src_id == g_config.xdr_cfg.src_id) {
		cf_ticker_warning(AS_RW, "unexpected src-id %u", (uint32_t)src_id);
		return true;
	}

	return false;
}


// Return value true means apply op (result irrelevant), false means don't.
bool
resolve_bin(as_storage_rd* rd, const as_msg_op* op, uint64_t msg_lut,
		uint16_t n_ops, uint16_t* n_won, int* result)
{
	if (! rd->resolve_writes) {
		return true;
	}

	as_namespace* ns = rd->ns;

	// TODO - paranoia - for development only.
	cf_assert(! ns->single_bin, AS_RW, "single-bin resolving writes");

	if (msg_lut != 0) {
		// XDR write.
		if (op->op == AS_MSG_OP_WRITE) {
			uint64_t op_lut = as_msg_op_get_lut(op);

			if (op_lut == 0) {
				op_lut = get_src_lut(msg_lut);
			}

			as_bin* b = as_bin_get_w_len(rd, op->name, op->name_sz);

			if (b != NULL) {
				if (op_lut < b->lut) {
					if (*n_won == n_ops) { // at least one bin lost
						cf_atomic64_incr(&ns->n_fail_xdr_lost_conflict);
					}

					*result = --(*n_won) == 0 ? AS_ERR_LOST_CONFLICT : AS_OK;
					return false;
				}

				if (op_lut == b->lut) {
					uint8_t src_id = b->src_id == 0 ?
							g_config.xdr_cfg.src_id : b->src_id;

					// Note - allow second write from same DC in same ms.
					if (get_src_id(msg_lut) < src_id) {
						if (*n_won == n_ops) { // at least one bin lost
							cf_atomic64_incr(&ns->n_fail_xdr_lost_conflict);
						}

						*result = --(*n_won) == 0 ?
								AS_ERR_LOST_CONFLICT : AS_OK;
						return false;
					}
				}
			}
		}
		// else - should never happen - TODO fail? or just do op?
	}
	// Client write.
	else if (op->op == AS_MSG_OP_WRITE ||
			op->op == AS_MSG_OP_INCR ||
			op->op == AS_MSG_OP_APPEND ||
			op->op == AS_MSG_OP_PREPEND ||
			op->op == AS_MSG_OP_CDT_MODIFY ||
			op->op == AS_MSG_OP_BITS_MODIFY ||
			op->op == AS_MSG_OP_HLL_MODIFY) {
		as_bin* b = as_bin_get_w_len(rd, op->name, op->name_sz);

		if (b != NULL && forbid_client_bin_write(rd, b, true)) {
			cf_atomic64_incr(&ns->n_fail_client_lost_conflict);
			*result = AS_ERR_LOST_CONFLICT;
			return false;
		}
	}
	else if (op->op == AS_MSG_OP_TOUCH || op->op == AS_MSG_OP_DELETE_ALL) {
		for (uint16_t i = 0; i < rd->n_bins; i++) {
			as_bin* b = &rd->bins[i];

			if (forbid_client_bin_write(rd, b, true)) {
				cf_atomic64_incr(&ns->n_fail_client_lost_conflict);
				*result = AS_ERR_LOST_CONFLICT;
				return false;
			}
		}
	}

	return true; // won conflict, read op, or unexpected XDR op
}


// Return value true means apply op, false means lost conflict, don't apply op.
bool
udf_resolve_bin(as_storage_rd* rd, const char* name)
{
	if (! rd->resolve_writes) {
		return true;
	}

	as_bin* b = as_bin_get(rd, name);

	if (b != NULL &&
			// Can't use record LUT - it's not yet advanced.
			forbid_client_bin_write(rd, b, false)) {
		cf_atomic64_incr(&rd->ns->n_fail_client_lost_conflict);
		return false;
	}

	return true;
}


bool
delete_bin(as_storage_rd* rd, const as_msg_op* op, uint64_t msg_lut,
		as_bin* cleanup_bins, uint32_t* p_n_cleanup_bins, int* result)
{
	as_namespace* ns = rd->ns;

	if (rd->resolve_writes) {
		as_bin* b = as_bin_get_or_create_w_len(rd, op->name, op->name_sz,
				result);

		if (b == NULL) {
			return false;
		}

		if (rd->ns->storage_data_in_memory) {
			append_bin_to_destroy(b, cleanup_bins, p_n_cleanup_bins);
		}

		b->state = AS_BIN_STATE_TOMBSTONE;
		b->particle = NULL; // not needed - but polite

		if (msg_lut != 0) {
			uint64_t op_lut = as_msg_op_get_lut(op);

			b->xdr_write = 1;
			b->lut = op_lut == 0 ? get_src_lut(msg_lut) : op_lut;
			b->src_id = get_src_id(msg_lut);
		}
	}
	else if (rd->xdr_bin_writes) {
		cf_assert(! ns->single_bin, AS_RW, "single-bin making bin tombstone");

		as_bin* b = as_bin_get_live_w_len(rd, op->name, op->name_sz);

		if (b != NULL) {
			if (ns->storage_data_in_memory) {
				append_bin_to_destroy(b, cleanup_bins, p_n_cleanup_bins);
			}

			b->state = AS_BIN_STATE_TOMBSTONE;
			b->particle = NULL; // not needed - but polite

			b->xdr_write = 0;
			b->lut = 0;
			b->src_id = 0;
		}
	}
	else {
		as_bin cleanup_bin;

		if (as_bin_pop_w_len(rd, op->name, op->name_sz, &cleanup_bin) &&
				ns->storage_data_in_memory) {
			append_bin_to_destroy(&cleanup_bin, cleanup_bins, p_n_cleanup_bins);
		}
	}

	return true;
}


bool
udf_delete_bin(as_storage_rd* rd, const char* name, as_bin* cleanup_bins,
		uint32_t* p_n_cleanup_bins, int* result)
{
	as_namespace* ns = rd->ns;

	if (rd->resolve_writes) {
		as_bin* b = as_bin_get_or_create(rd, name, result);

		if (b == NULL) {
			return false;
		}

		if (rd->ns->storage_data_in_memory) {
			append_bin_to_destroy(b, cleanup_bins, p_n_cleanup_bins);
		}

		b->state = AS_BIN_STATE_TOMBSTONE;
		b->particle = NULL; // not needed - but polite
	}
	else if (rd->xdr_bin_writes) {
		cf_assert(! ns->single_bin, AS_RW, "single-bin making bin tombstone");

		as_bin* b = as_bin_get_live(rd, name);

		if (b != NULL) {
			if (ns->storage_data_in_memory) {
				append_bin_to_destroy(b, cleanup_bins, p_n_cleanup_bins);
			}

			b->state = AS_BIN_STATE_TOMBSTONE;
			b->particle = NULL; // not needed - but polite

			b->xdr_write = 0;
			b->lut = 0;
			b->src_id = 0;
		}
	}
	else {
		as_bin cleanup_bin;

		if (as_bin_pop(rd, name, &cleanup_bin) && ns->storage_data_in_memory) {
			append_bin_to_destroy(&cleanup_bin, cleanup_bins, p_n_cleanup_bins);
		}
	}

	return true;
}


void
write_resolved_bin(as_storage_rd* rd, const as_msg_op* op, uint64_t msg_lut,
		as_bin* b)
{
	if (rd->resolve_writes && msg_lut != 0) {
		uint64_t op_lut = as_msg_op_get_lut(op);

		b->xdr_write = 1;
		b->lut = op_lut == 0 ? get_src_lut(msg_lut) : op_lut;
		b->src_id = get_src_id(msg_lut);
	}
}


// Caller has already handled destroying all bins' particles.
void
delete_all_bins(as_storage_rd* rd)
{
	if (rd->xdr_bin_writes) {
		cf_assert(! rd->ns->single_bin, AS_RW, "single-bin doesn't make bin tombstones");

		for (uint16_t i = 0; i < rd->n_bins; i++) {
			as_bin* b = &rd->bins[i];

			// TODO - for development only?
			cf_assert(b->state != AS_BIN_STATE_UNUSED, AS_BIN, "unexpected empty bin");

			if (b->state != AS_BIN_STATE_TOMBSTONE) {
				b->state = AS_BIN_STATE_TOMBSTONE;
				b->particle = NULL; // not needed - but polite

				b->xdr_write = 0;
				b->lut = 0;
				b->src_id = 0;
			}
		}
	}
	else {
		rd->n_bins = 0;
	}
}


//==========================================================
// Private API - for enterprise separation only.
//

void
write_delete_record(as_record* r, as_index_tree* tree)
{
	// Drop record (remove from index) only if not leaving a tombstone.
	if (r->tombstone == 0) {
		as_index_delete(tree, &r->keyd);
	}
}


uint32_t
dup_res_pack_repl_state_info(const as_record *r, const as_namespace* ns)
{
	uint32_t info = 0;

	if (ns->cp && r->repl_state != AS_REPL_STATE_REPLICATED) {
		info |= RW_INFO_UNREPLICATED;
	}

	return info;
}


bool
dup_res_should_retry_transaction(rw_request* rw, uint32_t result_code)
{
	if (! rw->rsv.ns->cp) {
		return false;
	}

	return ! (result_code == AS_OK ||
			// These errors treated as successful no-ops:
			result_code == AS_ERR_NOT_FOUND ||
			result_code == AS_ERR_GENERATION ||
			result_code == AS_ERR_RECORD_EXISTS);
}


void
dup_res_handle_tie(rw_request* rw, const msg* m, uint32_t result_code)
{
	if (! rw->rsv.ns->cp || result_code != AS_ERR_RECORD_EXISTS) {
		return;
	}

	uint32_t info = 0;

	msg_get_uint32(m, RW_FIELD_INFO, &info);

	if ((info & RW_INFO_UNREPLICATED) == 0) {
		rw->tie_was_replicated = true;
	}
}


void
apply_if_tie(rw_request* rw)
{
	as_namespace* ns = rw->rsv.ns;

	if (! ns->cp || ! rw->tie_was_replicated) {
		return;
	}

	as_index_ref r_ref;

	if (as_record_get(rw->rsv.tree, &rw->keyd, &r_ref) == 0) {
		as_record* r = r_ref.r;

		if (r->generation == rw->best_dup_gen &&
				r->last_update_time == rw->best_dup_lut) {
			as_set_repl_state(ns, r, AS_REPL_STATE_REPLICATED);
		}

		as_record_done(&r_ref, ns);
	}
}


void
dup_res_translate_result_code(rw_request* rw)
{
	if (rw->rsv.ns->cp) {
		// TODO - conflate errors applying remote winner to generic
		// dup-res-failed error ???
		return;
	}

	rw->result_code = AS_OK;
}


void
dup_res_init_repl_state(as_remote_record* rr, uint32_t info)
{
	if (rr->rsv->ns->cp && (info & RW_INFO_UNREPLICATED) != 0) {
		rr->repl_state = AS_REPL_STATE_UNREPLICATED;
	}
}


void
repl_write_init_repl_state(as_remote_record* rr, bool from_replica)
{
	as_namespace* ns = rr->rsv->ns;

	if (! ns->cp) {
		return;
	}

	if (ns->cfg_replication_factor > 2) {
		rr->repl_state = AS_REPL_STATE_UNREPLICATED;
	}
	else if (ns->cfg_replication_factor == 2) {
		rr->repl_state = from_replica ?
				AS_REPL_STATE_REPLICATED : AS_REPL_STATE_UNREPLICATED;
	}
	else { // repl-factor 1
		rr->repl_state = AS_REPL_STATE_REPLICATED;
	}
}


conflict_resolution_pol
repl_write_conflict_resolution_policy(const as_namespace* ns)
{
	return ns->cp ?
			AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_CP :
			AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_LAST_UPDATE_TIME;
}


bool
repl_write_should_retransmit_replicas(rw_request* rw, uint32_t result_code)
{
	if (rw->rsv.ns->cp) {
		switch (result_code) {
		case AS_OK:
		case AS_ERR_RECORD_EXISTS: // must have been our retransmit
			return false;
		case AS_ERR_GENERATION:
			// Don't force pointless retransmits, let transaction time out.
			return true;
		default:
			rw->xmit_ms = 0; // force retransmit on next cycle
			return true;
		}
	}

	switch (result_code) {
	case AS_ERR_CLUSTER_KEY_MISMATCH:
		rw->xmit_ms = 0; // force retransmit on next cycle
		return true;
	default:
		return false;
	}
}


void
repl_write_send_confirmation(rw_request* rw)
{
	as_namespace* ns = rw->rsv.ns;

	if (! ns->cp) {
		return;
	}

	if (rw->n_dest_nodes == 1 || IS_FULL_DROP(rw)) {
		return;
	}

	msg* m = as_fabric_msg_get(M_TYPE_RW);

	msg_set_uint32(m, RW_FIELD_OP, RW_OP_REPL_CONFIRM);
	msg_set_buf(m, RW_FIELD_NAMESPACE, (uint8_t*)ns->name, strlen(ns->name),
			MSG_SET_COPY);
	msg_set_buf(m, RW_FIELD_DIGEST, (void*)&rw->keyd, sizeof(cf_digest),
			MSG_SET_COPY);
	msg_set_uint32(m, RW_FIELD_GENERATION, rw->generation);
	msg_set_uint64(m, RW_FIELD_LAST_UPDATE_TIME, rw->last_update_time);

	for (uint32_t i = 0; i < rw->n_dest_nodes; i++) {
		msg_incr_ref(m);

		if (as_fabric_send(rw->dest_nodes[i], m, AS_FABRIC_CHANNEL_RW) !=
				AS_FABRIC_SUCCESS) {
			as_fabric_msg_put(m);
		}
	}

	as_fabric_msg_put(m);
}


void
repl_write_handle_confirmation(msg* m)
{
	uint8_t* ns_name;
	size_t ns_name_len;

	if (msg_get_buf(m, RW_FIELD_NAMESPACE, &ns_name, &ns_name_len,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_RW, "repl_write_handle_confirmation: no namespace");
		as_fabric_msg_put(m);
		return;
	}

	as_namespace* ns = as_namespace_get_bybuf(ns_name, ns_name_len);

	if (! (ns && ns->cp)) {
		cf_warning(AS_RW, "repl_write_handle_confirmation: invalid namespace or 'strong-consistency' not configured");
		as_fabric_msg_put(m);
		return;
	}

	cf_digest* keyd;

	if (msg_get_buf(m, RW_FIELD_DIGEST, (uint8_t**)&keyd, NULL,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_RW, "repl_write_handle_confirmation: no digest");
		as_fabric_msg_put(m);
		return;
	}

	uint32_t generation;

	if (msg_get_uint32(m, RW_FIELD_GENERATION, &generation) != 0 ||
			generation == 0) {
		cf_warning(AS_RW, "repl_write_handle_confirmation: no or bad generation");
		as_fabric_msg_put(m);
		return;
	}

	uint64_t last_update_time;

	if (msg_get_uint64(m, RW_FIELD_LAST_UPDATE_TIME,
			&last_update_time) != 0) {
		cf_warning(AS_RW, "repl_write_handle_confirmation: no last-update-time");
		as_fabric_msg_put(m);
		return;
	}

	as_partition_reservation rsv;

	// TODO - better to reserve replica ???
	as_partition_reserve(ns, as_partition_getid(keyd), &rsv);

	as_index_ref r_ref;

	if (as_record_get(rsv.tree, keyd, &r_ref) == 0) {
		as_record* r = r_ref.r;

		if ((uint16_t)generation == r->generation &&
				last_update_time == r->last_update_time &&
				r->repl_state == AS_REPL_STATE_UNREPLICATED) {
			as_set_repl_state(ns, r, AS_REPL_STATE_REPLICATED);
		}

		as_record_done(&r_ref, ns);
	}

	as_partition_release(&rsv);
	as_fabric_msg_put(m);
}


int
record_replace_check(as_record* r, as_namespace* ns)
{
	if (! ns->cp) {
		return 0;
	}

	switch (r->repl_state) {
	case AS_REPL_STATE_REPLICATED:
	case AS_REPL_STATE_UNREPLICATED:
		// Ok to apply remote record, move along.
		return 0;
	case AS_REPL_STATE_REPLICATING:
	case AS_REPL_STATE_RE_REPLICATING:
		// A replication crossing race.
		return -1;
	default:
		cf_crash(AS_RW, "unexpected repl-state %u", r->repl_state);
		return 0;
	}
}


void
record_replaced(as_record* r, as_remote_record* rr)
{
	as_namespace* ns = rr->rsv->ns;

	if (ns->cp) {
		as_set_repl_state(ns, r, rr->repl_state);
	}
}
