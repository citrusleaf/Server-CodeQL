/*
 * migrate_ee.c
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

#include "fabric/migrate.h"
#include "fabric/migrate_ee.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_queue.h"

#include "cf_mutex.h"
#include "cf_thread.h"
#include "log.h"
#include "msg.h"
#include "node.h"
#include "rchash.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "fabric/exchange.h"
#include "fabric/fabric.h"
#include "fabric/meta_batch.h"
#include "fabric/meta_batch_ee.h"
#include "fabric/partition.h"
#include "fabric/partition_balance.h"
#include "transaction/re_replicate_ee.h"


//==========================================================
// Typedefs & constants.
//

const uint32_t MY_MIG_FEATURES = MIG_FEATURE_MERGE;

#define MAX_IMMIG_EMIG_RATIO 4096


//==========================================================
// Globals.
//

static cf_queue g_emigration_fill_q;
static cf_mutex g_fill_q_lock = CF_MUTEX_INIT;


//==========================================================
// Forward declarations.
//

void *run_emigration_fill(void *arg);

// Meta sender.
void *run_immigration_meta_load(void *arg);
void *run_immigration_meta_send(void *arg);
bool immigration_meta_reduce_fn(as_index_ref *r_ref, void *udata);
bool immigration_meta_batch_send(immigration *immig);


//==========================================================
// Inlines & macros.
//

static inline bool
immigration_meta_should_abort(const immigration *immig)
{
	return immig->cluster_key != as_exchange_cluster_key() ||
			cf_atomic32_get(immig->done_recv) != 0;
}


//==========================================================
// Public API - enterprise only.
//

void
as_migrate_clear_fill_queue()
{
	emigration *emig;

	cf_mutex_lock(&g_fill_q_lock);

	while (cf_queue_pop(&g_emigration_fill_q, (void *)&emig,
			CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
		cf_queue_push(&g_emigration_q, &emig);
	}

	cf_mutex_unlock(&g_fill_q_lock);
}


//==========================================================
// Private API - for enterprise separation only.
//

void
emigrate_fill_queue_init()
{
	cf_queue_init(&g_emigration_fill_q, sizeof(emigration*), 4096, false);
	cf_thread_create_detached(run_emigration_fill, NULL);
}


void
emigrate_queue_push(emigration *emig)
{
	if ((emig->tx_flags & (TX_FLAGS_LEAD | TX_FLAGS_CONTINGENT)) != 0 ||
			emig->rsv.ns->ignore_migrate_fill_delay) {
		cf_queue_push(&g_emigration_q, &emig);
	}
	else { // "fill" migrations (generated on rebalance)
		cf_mutex_lock(&g_fill_q_lock);
		cf_queue_push(&g_emigration_fill_q, &emig);
		cf_mutex_unlock(&g_fill_q_lock);
	}
}


bool
should_emigrate_record(emigration *emig, as_index_ref *r_ref)
{
	if (emig->meta_q->is_done) {
		return true;
	}

	as_record *r = r_ref->r;
	as_namespace *ns = emig->rsv.ns;

	cf_digest rec_keyd = r->keyd;
	uint16_t rec_gen = r->generation;
	uint64_t rec_last_update_time = r->last_update_time;

	meta_in_q_result peek_rv;
	meta_record *mrec = NULL;

	while ((peek_rv = meta_in_q_current_rec(emig->meta_q, &mrec)) !=
			META_IN_Q_DONE) {
		if (emig->cluster_key != as_exchange_cluster_key()) {
			return false;
		}

		if (peek_rv == META_IN_Q_EAGAIN) {
			// We can't leave the record locked while we're blocked.

			as_index_reserve(r);
			cf_mutex_unlock(r_ref->olock);

			usleep(200);

			cf_mutex_lock(r_ref->olock);
			as_index_release(r);

			// Ignore this record if it's been deleted.
			if (! as_index_is_valid_record(r)) {
				return false;
			}

			continue; // more expected
		}

		int cmp = cf_digest_compare(&rec_keyd, &mrec->keyd);

		if (cmp > 0) {
			break;
		}

		meta_in_q_next_rec(emig->meta_q);

		if (cmp == 0) {
			int winner = as_record_resolve_conflict(
					ns->conflict_resolution_policy,
					rec_gen, rec_last_update_time,
					mrec->generation, mrec->last_update_time);

			if (winner >= 0) {
				// TODO - If winner > 0 then remote wins, we could fetch it now.
				cf_atomic_int_incr(&ns->migrate_records_skipped);
				return false;
			}
			// else - Local wins, ship it.

			break;
		}

		// TODO - This is a record the remote has and local doesn't, fetch it.
	}

	return true;
}


uint32_t
emigration_pack_info(const emigration *emig, const as_record *r)
{
	as_namespace *ns = emig->rsv.ns;
	uint32_t info = 0;

	if (ns->cp && r->repl_state != AS_REPL_STATE_REPLICATED &&
			(ns->cfg_replication_factor > 2 || ! emig->from_replica)) {
		info |= MIG_INFO_UNREPLICATED;
	}

	return info;
}


void
emigration_handle_meta_batch_request(cf_node src, msg *m)
{
	uint32_t emig_id;

	if (msg_get_uint32(m, MIG_FIELD_EMIG_ID, &emig_id) != 0) {
		cf_warning(AS_MIGRATE, "merge start request: msg get for emig id failed");
		as_fabric_msg_put(m);
		return;
	}

	uint32_t sequence;

	if (msg_get_uint32(m, MIG_FIELD_META_SEQUENCE, &sequence) != 0) {
		cf_warning(AS_MIGRATE, "merge start request: msg get for sequence failed");
		as_fabric_msg_put(m);
		return;
	}

	emigration *emig;

	if (cf_rchash_get(g_emigration_hash, (void *)&emig_id, (void **)&emig) ==
			CF_RCHASH_OK) {
		if (meta_in_q_handle_sequence(emig->meta_q, sequence)) {
			uint32_t final = 0;

			msg_get_uint32(m, MIG_FIELD_META_SEQUENCE_FINAL, &final);

			meta_batch batch = { final != 0, 0, NULL };
			size_t size = 0;

			if (msg_get_buf(m, MIG_FIELD_META_RECORDS,
					(uint8_t**)&batch.records, &size,
					MSG_GET_COPY_MALLOC) != 0 && final == 0) {
				cf_warning(AS_MIGRATE, "merge start request: msg get for meta records failed");
				emigration_release(emig);
				as_fabric_msg_put(m);
				return;
			}

			batch.n_records = size / sizeof(meta_record);

			meta_in_q_push_batch(emig->meta_q, &batch);
		}

		emigration_release(emig);
	}
	// else - This must be a migration that has already finished.

	msg_preserve_fields(m, 2, MIG_FIELD_EMIG_ID, MIG_FIELD_META_SEQUENCE);

	msg_set_uint32(m, MIG_FIELD_OP, OPERATION_MERGE_META_ACK);

	if (as_fabric_send(src, m, AS_FABRIC_CHANNEL_BULK) != AS_FABRIC_SUCCESS) {
		as_fabric_msg_put(m);
	}
}


void
immigration_init_repl_state(as_remote_record* rr, uint32_t info)
{
	if (rr->rsv->ns->cp && (info & MIG_INFO_UNREPLICATED) != 0) {
		rr->repl_state = AS_REPL_STATE_UNREPLICATED;
	}
}


void
immigration_handle_meta_batch_ack(cf_node src, msg *m)
{
	uint32_t emig_id;

	if (msg_get_uint32(m, MIG_FIELD_EMIG_ID, &emig_id) != 0) {
		cf_warning(AS_MIGRATE, "merge start request: msg get for emig id failed");
		as_fabric_msg_put(m);
		return;
	}

	uint32_t sequence;

	if (msg_get_uint32(m, MIG_FIELD_META_SEQUENCE, &sequence) != 0) {
		cf_warning(AS_MIGRATE, "merge start request: msg get for meta sequence failed");
		as_fabric_msg_put(m);
		return;
	}

	as_fabric_msg_put(m);

	immigration_hkey hkey;
	immigration *immig;

	hkey.src = src;
	hkey.emig_id = emig_id;

	if (cf_rchash_get(g_immigration_hash, (void *)&hkey, (void **)&immig) !=
			CF_RCHASH_OK) {
		// Emigrator sent 'done' before immigrator sent all meta batches.
		return;
	}

	meta_out_q_sequence_ack(immig->meta_q, sequence);
	immigration_release(immig);
}


bool
immigration_start_meta_sender(immigration *immig, uint32_t emig_features,
		uint64_t emig_n_recs)
{
	if ((emig_features & MIG_FEATURE_MERGE) == 0) {
		return false;
	}

	uint64_t n_elements = as_index_tree_size(immig->rsv.tree);

	if (n_elements == 0 || n_elements / MAX_IMMIG_EMIG_RATIO >= emig_n_recs) {
		return false;
	}

	cf_rc_reserve(immig); // reserved for load thread
	cf_thread_create_transient(run_immigration_meta_load, (void*)immig);

	cf_rc_reserve(immig); // reserved for send thread
	cf_thread_create_transient(run_immigration_meta_send, (void*)immig);

	return true;
}


//==========================================================
// Local helpers - emigration.
//

void *
run_emigration_fill(void *arg)
{
	while (true) {
		sleep(1);

		// Ensure new round of fill migrations can't get to fill queue between
		// delay check and transfer from fill queue to regular queue.
		cf_mutex_lock(&g_fill_q_lock);

		uint32_t n_fill_emigs = cf_queue_sz(&g_emigration_fill_q);
		uint32_t delay = as_load_uint32(&g_config.migrate_fill_delay);

		if (n_fill_emigs == 0 || cf_get_seconds() < g_rebalance_sec + delay) {
			cf_mutex_unlock(&g_fill_q_lock);
			continue;
		}

		cf_info(AS_MIGRATE, "allowing %u fill-migrations after %u seconds delay",
				n_fill_emigs, delay);

		emigration *emig;

		while (cf_queue_pop(&g_emigration_fill_q, (void *)&emig,
				CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
			cf_queue_push(&g_emigration_q, &emig);
		}

		cf_mutex_unlock(&g_fill_q_lock);
	}

	return NULL;
}


//==========================================================
// Local helpers - meta sender helpers.
//

void *
run_immigration_meta_load(void *arg)
{
	immigration *immig = (immigration *)arg;

	as_index_reduce(immig->rsv.tree, immigration_meta_reduce_fn, immig);
	meta_out_q_batch_close(immig->meta_q);
	immigration_release(immig);

	return NULL;
}


void *
run_immigration_meta_send(void *arg)
{
	immigration *immig = (immigration *)arg;

	while (immigration_meta_batch_send(immig)) {
		;
	}

	immigration_release(immig);

	return NULL;
}


bool
immigration_meta_reduce_fn(as_index_ref *r_ref, void *udata)
{
	immigration *immig = (immigration *)udata;
	as_namespace *ns = immig->rsv.ns;

	if (immigration_meta_should_abort(immig)) {
		as_record_done(r_ref, ns);
		return true;
	}

	meta_out_q_add_rec(immig->meta_q, r_ref->r);

	as_record_done(r_ref, ns);

	return true;
}


bool
immigration_meta_batch_send(immigration *immig)
{
	meta_out_q *imq = immig->meta_q;
	meta_batch batch = { false, 0, NULL };

	// Might block here.
	meta_out_q_next_batch(imq, &batch);

	msg *m = as_fabric_msg_get(M_TYPE_MIGRATE);

	if (batch.n_records != 0) {
		msg_set_buf(m, MIG_FIELD_META_RECORDS,
				(uint8_t *)batch.records,
				sizeof(meta_record) * batch.n_records,
				MSG_SET_HANDOFF_MALLOC);
	}

	msg_set_uint32(m, MIG_FIELD_OP, OPERATION_MERGE_META);
	msg_set_uint32(m, MIG_FIELD_EMIG_ID, immig->emig_id);
	msg_set_uint32(m, MIG_FIELD_META_SEQUENCE, ++imq->sequence);

	if (batch.is_final) {
		msg_set_uint32(m, MIG_FIELD_META_SEQUENCE_FINAL, 1);
	}

	uint64_t next_send = 0;

	while (! is_meta_out_q_synced(imq)) {
		if (immigration_meta_should_abort(immig)) {
			as_fabric_msg_put(m);
			return false;
		}

		uint64_t current_time = cf_getms();

		if (next_send < current_time) {
			as_fabric_retransmit(immig->src, m,
					AS_FABRIC_CHANNEL_BULK);
			next_send = current_time + META_BATCH_RETRANSMIT_MS;
		}

		usleep(200);
	}

	as_fabric_msg_put(m);

	return ! batch.is_final;
}
