/*
 * appeal_ee.c
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

#include "fabric/appeal_ee.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

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
#include "fabric/partition_balance_ee.h"
#include "transaction/re_replicate_ee.h"


//==========================================================
// Typedefs & constants.
//

typedef enum {
	// These values go on the wire, so mind backward compatibility if changing.
	APPEAL_FIELD_OP,
	APPEAL_FIELD_APPEAL_ID,
	APPEAL_FIELD_NAMESPACE,
	APPEAL_FIELD_PARTITION,
	APPEAL_FIELD_CLUSTER_KEY,
	APPEAL_FIELD_META_RECORDS,
	APPEAL_FIELD_META_SEQUENCE,
	APPEAL_FIELD_META_SEQUENCE_FINAL,

	NUM_APPEAL_FIELDS
} appeal_msg_fields;

#define APPEAL_OP_APPEAL_START 1
#define APPEAL_OP_APPEAL_DONE 2
#define APPEAL_OP_START_ACK_OK 3
#define APPEAL_OP_START_ACK_FAIL 4
#define APPEAL_OP_START_ACK_EAGAIN 5
#define APPEAL_OP_DONE_ACK 6
#define APPEAL_OP_MERGE_META 7
#define APPEAL_OP_MERGE_META_ACK 8

const msg_template appeal_mt[] = {
		{ APPEAL_FIELD_OP, M_FT_UINT32 },
		{ APPEAL_FIELD_APPEAL_ID, M_FT_UINT32 },
		{ APPEAL_FIELD_NAMESPACE, M_FT_BUF },
		{ APPEAL_FIELD_PARTITION, M_FT_UINT32 },
		{ APPEAL_FIELD_CLUSTER_KEY, M_FT_UINT64 },
		{ APPEAL_FIELD_META_RECORDS, M_FT_BUF },
		{ APPEAL_FIELD_META_SEQUENCE, M_FT_UINT32 },
		{ APPEAL_FIELD_META_SEQUENCE_FINAL, M_FT_UINT32 },
};

COMPILER_ASSERT(sizeof(appeal_mt) / sizeof(msg_template) == NUM_APPEAL_FIELDS);

#define APPEAL_MSG_SCRATCH_SIZE 32

typedef struct appeal_s {
	cf_node dest;
	uint64_t cluster_key;
	uint32_t id;

	cf_queue *ctrl_q;
	meta_in_q *meta_q;

	as_partition_reservation rsv;
} appeal;

typedef struct assist_s {
	cf_node src;
	uint64_t cluster_key;
	as_namespace *ns;
	uint32_t pid;

	uint32_t appeal_id;
	meta_out_q *meta_q;

	bool started;
	assist_start_result start_result;
	cf_atomic32 done_recv;
} assist;

typedef struct assist_hkey_s {
	cf_node src;
	uint32_t appeal_id;
} __attribute__((__packed__)) assist_hkey;

#define MIN_APPEAL_THREADS 16

#define APPEAL_THREAD_WAIT_MS (1000 * 10) // 10 seconds

#define APPEAL_RETRANSMIT_CTRL_MS 1000 // for now, not configurable


//==========================================================
// Globals.
//

static cf_queue g_appeal_q;
static cf_rchash *g_appeal_hash = NULL;
static cf_rchash *g_assist_hash = NULL;
static cf_atomic32 g_appeal_id = 0;


//==========================================================
// Forward declarations.
//

// Various initializers and destructors.
void appeal_init(appeal *ap);
void appeal_destroy(void *parm);
void appeal_release(appeal *ap);
void assist_destroy(void *parm);
void assist_release(assist *ast);

// Appeal.
void *run_appeal(void *arg);
void appeal_hash_insert(appeal *ap);
void appeal_hash_delete(appeal *ap);
void appeal_partition(appeal *ap);
bool appeal_send_start(appeal *ap);
bool appeal_tree_reduce_fn(as_index_ref *r_ref, void *udata);
void appeal_send_done(appeal *ap);
bool appeal_should_exonerate_record(appeal *ap, as_index_ref *r_ref);

// Assist.
int assist_clear_reduce_fn(const void *key, void *object, void *udata);
uint32_t assist_hash_fn(const void *key);
void assist_ack_start_request(cf_node src, msg *m, uint32_t op);
bool assist_start_meta_sender(assist *ast);
void *run_assist_meta_load(void *arg);
void *run_assist_meta_send(void *arg);
bool assist_meta_reduce_fn(as_index_ref *r_ref, void *udata);
bool assist_meta_batch_send(assist *ast);

// Appeal fabric message handling.
int appeal_receive_msg_cb(cf_node src, msg *m, void *udata);
void appeal_handle_meta_batch_request(cf_node src, msg *m);
void assist_handle_start_request(cf_node src, msg *m);
void assist_handle_done_request(cf_node src, msg *m);
void appeal_handle_ctrl_ack(cf_node src, msg *m, uint32_t op);
void assist_handle_meta_batch_ack(cf_node src, msg *m);


//==========================================================
// Inlines & macros.
//

static inline bool
assist_meta_should_abort(const assist *ast)
{
	return ast->cluster_key != as_exchange_cluster_key() ||
			cf_atomic32_get(ast->done_recv) != 0;
}


//==========================================================
// Public API - enterprise only.
//

void
as_appeal_init_appeal()
{
	cf_queue_init(&g_appeal_q, sizeof(appeal *), 4096, true);

	g_appeal_hash = cf_rchash_create(cf_rchash_fn_u32, appeal_destroy,
			sizeof(uint32_t), 64);

	uint32_t n_appeal_threads = cf_topo_count_cpus();

	if (n_appeal_threads < MIN_APPEAL_THREADS) {
		n_appeal_threads = MIN_APPEAL_THREADS;
	}

	cf_info(AS_APPEAL, "starting %u appeal threads", n_appeal_threads);

	for (uint32_t i = 0; i < n_appeal_threads; i++) {
		cf_thread_create_transient(run_appeal, NULL);
	}
}

void
as_appeal_init_assist()
{
	g_assist_hash = cf_rchash_create(assist_hash_fn, assist_destroy,
			sizeof(assist_hkey), 64);

	as_fabric_register_msg_fn(M_TYPE_APPEAL, appeal_mt, sizeof(appeal_mt),
			APPEAL_MSG_SCRATCH_SIZE, appeal_receive_msg_cb, NULL);

	cf_info(AS_APPEAL, "ready to handle appeals from other nodes");
}

void
as_appeal_begin(const pb_task *task)
{
	appeal *ap = cf_rc_alloc(sizeof(appeal));

	ap->dest = task->dest;
	ap->cluster_key = task->cluster_key;
	ap->id = cf_atomic32_incr(&g_appeal_id);

	// Create these later only when we need them - we'll get lots at once.
	ap->ctrl_q = NULL;
	ap->meta_q = NULL;

	as_partition_reserve(task->ns, task->pid, &ap->rsv);

	cf_queue_push(&g_appeal_q, &ap);
}

void
as_appeal_clear_assists()
{
	// TODO - currently, we might leave assist objects around indefinitely,
	// until a rebalance followed by no further appeals. We may want to add a
	// way to reap them, e.g. using signals.

	if (g_assist_hash) {
		cf_rchash_reduce(g_assist_hash, assist_clear_reduce_fn, NULL);
	}
}


//==========================================================
// Local helpers - various initializers and destructors.
//

void
appeal_init(appeal *ap)
{
	ap->ctrl_q = cf_queue_create(sizeof(int), true);
	ap->meta_q = meta_in_q_create();
}

// Destructor handed to rchash.
void
appeal_destroy(void *parm)
{
	appeal *ap = (appeal *)parm;

	if (ap->ctrl_q) {
		cf_queue_destroy(ap->ctrl_q);
	}

	if (ap->meta_q) {
		meta_in_q_destroy(ap->meta_q);
	}

	as_partition_release(&ap->rsv);
}

void
appeal_release(appeal *ap)
{
	if (cf_rc_release(ap) == 0) {
		appeal_destroy((void *)ap);
		cf_rc_free(ap);
	}
}

// Destructor handed to rchash.
void
assist_destroy(void *parm)
{
	assist *ast = (assist *)parm;

	meta_out_q_destroy(ast->meta_q);
}

void
assist_release(assist *ast)
{
	if (cf_rc_release(ast) == 0) {
		assist_destroy((void *)ast);
		cf_rc_free(ast);
	}
}


//==========================================================
// Local helpers - appeal.
//

void *
run_appeal(void *arg)
{
	while (true) {
		appeal *ap;

		if (cf_queue_pop(&g_appeal_q, (void *)&ap, APPEAL_THREAD_WAIT_MS) !=
				CF_QUEUE_OK) {
			if (! g_appeal_phase) {
				break;
			}

			continue;
		}

		if (ap->cluster_key != as_exchange_cluster_key()) {
			appeal_hash_delete(ap);
			continue;
		}

		as_namespace *ns = ap->rsv.ns;

		// Add the appeal to the global hash so acks can find it.
		appeal_hash_insert(ap);
		cf_atomic_int_incr(&ns->appeals_tx_active);

		appeal_partition(ap);

		cf_atomic_int_decr(&ns->appeals_tx_active);
		appeal_hash_delete(ap);
	}

	return NULL;
}

void
appeal_hash_insert(appeal *ap)
{
	if (! ap->ctrl_q) {
		appeal_init(ap); // creates ap->ctrl_q etc.

		cf_rchash_put(g_appeal_hash, (void *)&ap->id, (void *)ap);
	}
}

void
appeal_hash_delete(appeal *ap)
{
	if (ap->ctrl_q) {
		cf_rchash_delete(g_appeal_hash, (void *)&ap->id);
	}
	else {
		appeal_release(ap);
	}
}

void
appeal_partition(appeal *ap)
{
	//--------------------------------------------
	// Send START request.
	//

	if (! appeal_send_start(ap)) {
		return;
	}

	//--------------------------------------------
	// Receive replicated records.
	//

	if (! as_index_reduce(ap->rsv.tree, appeal_tree_reduce_fn, ap)) {
		return; // aborted
	}

	//--------------------------------------------
	// Send DONE request.
	//

	as_partition_appeal_done(ap->rsv.ns, ap->rsv.p->id, ap->cluster_key);

	appeal_send_done(ap);
}

bool
appeal_send_start(appeal *ap)
{
	as_namespace *ns = ap->rsv.ns;
	msg *m = as_fabric_msg_get(M_TYPE_APPEAL);

	msg_set_uint32(m, APPEAL_FIELD_OP, APPEAL_OP_APPEAL_START);
	msg_set_uint32(m, APPEAL_FIELD_APPEAL_ID, ap->id);
	msg_set_uint64(m, APPEAL_FIELD_CLUSTER_KEY, ap->cluster_key);
	msg_set_buf(m, APPEAL_FIELD_NAMESPACE, (const uint8_t *)ns->name,
			strlen(ns->name), MSG_SET_COPY);
	msg_set_uint32(m, APPEAL_FIELD_PARTITION, ap->rsv.p->id);

	uint64_t start_xmit_ms = 0;

	while (true) {
		if (ap->cluster_key != as_exchange_cluster_key()) {
			as_fabric_msg_put(m);
			return false;
		}

		uint64_t now = cf_getms();

		if (cf_queue_sz(ap->ctrl_q) == 0 &&
				start_xmit_ms + APPEAL_RETRANSMIT_CTRL_MS < now) {
			msg_incr_ref(m);

			if (as_fabric_send(ap->dest, m, AS_FABRIC_CHANNEL_CTRL) !=
					AS_FABRIC_SUCCESS) {
				as_fabric_msg_put(m);
			}

			start_xmit_ms = now;
		}

		int op;

		if (cf_queue_pop(ap->ctrl_q, &op, APPEAL_RETRANSMIT_CTRL_MS) ==
				CF_QUEUE_OK) {
			switch (op) {
			case APPEAL_OP_START_ACK_OK:
				as_fabric_msg_put(m);
				return true;
			case APPEAL_OP_START_ACK_EAGAIN:
				break;
			case APPEAL_OP_START_ACK_FAIL:
				cf_warning(AS_APPEAL, "remote node failed assist");
				as_fabric_msg_put(m);
				return false;
			default:
				cf_warning(AS_APPEAL, "unexpected ctrl op %d", op);
				break;
			}
		}
	}

	// Should never get here.
	cf_crash(AS_APPEAL, "unexpected - exited infinite while loop");

	return false;
}

bool
appeal_tree_reduce_fn(as_index_ref *r_ref, void *udata)
{
	appeal *ap = (appeal *)udata;
	as_namespace *ns = ap->rsv.ns;

	if (r_ref->r->repl_state != AS_REPL_STATE_UNREPLICATED) {
		as_record_done(r_ref, ns);
		return ap->cluster_key == as_exchange_cluster_key();
	}

	if (appeal_should_exonerate_record(ap, r_ref)) {
		as_set_repl_state(ns, r_ref->r, AS_REPL_STATE_REPLICATED);
		cf_atomic_int_incr(&ns->appeals_records_exonerated);
	}

	as_record_done(r_ref, ns);

	return ap->cluster_key == as_exchange_cluster_key();
}

void
appeal_send_done(appeal *ap)
{
	msg *m = as_fabric_msg_get(M_TYPE_APPEAL);

	msg_set_uint32(m, APPEAL_FIELD_OP, APPEAL_OP_APPEAL_DONE);
	msg_set_uint32(m, APPEAL_FIELD_APPEAL_ID, ap->id);

	uint64_t done_xmit_ms = 0;

	while (true) {
		if (ap->cluster_key != as_exchange_cluster_key()) {
			as_fabric_msg_put(m);
			return;
		}

		uint64_t now = cf_getms();

		if (done_xmit_ms + APPEAL_RETRANSMIT_CTRL_MS < now) {
			msg_incr_ref(m);

			if (as_fabric_send(ap->dest, m, AS_FABRIC_CHANNEL_CTRL) !=
					AS_FABRIC_SUCCESS) {
				as_fabric_msg_put(m);
			}

			done_xmit_ms = now;
		}

		int op;

		if (cf_queue_pop(ap->ctrl_q, &op, APPEAL_RETRANSMIT_CTRL_MS) ==
				CF_QUEUE_OK) {
			if (op == APPEAL_OP_DONE_ACK) {
				as_fabric_msg_put(m);

				return;
			}
		}
	}

	// Should never get here.
	cf_crash(AS_APPEAL, "unexpected - exited infinite while loop");
}

bool
appeal_should_exonerate_record(appeal *ap, as_index_ref *r_ref)
{
	if (ap->meta_q->is_done) {
		return false;
	}

	as_record *r = r_ref->r;

	cf_digest rec_keyd = r->keyd;
	uint16_t rec_gen = r->generation;
	uint64_t rec_last_update_time = r->last_update_time;

	meta_in_q_result peek_rv;
	meta_record *mrec = NULL;

	while ((peek_rv = meta_in_q_current_rec(ap->meta_q, &mrec)) !=
			META_IN_Q_DONE) {
		if (ap->cluster_key != as_exchange_cluster_key()) {
			return false;
		}

		if (peek_rv == META_IN_Q_EAGAIN) {
			// We can't leave the record locked while we're blocked.

			as_index_reserve(r);
			cf_mutex_unlock(r_ref->olock);

			usleep(100);

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
			// Remote doesn't have this record, do not mark as replicated.
			return false;
		}

		meta_in_q_next_rec(ap->meta_q);

		if (cmp == 0) {
			// Ok to mark as replicated if local matches remote.
			return rec_gen == mrec->generation &&
					rec_last_update_time == mrec->last_update_time;
		}
	}

	return false;
}


//==========================================================
// Local helpers - assist.
//

int
assist_clear_reduce_fn(const void *key, void *object, void *udata)
{
	return ((assist *)object)->started ? CF_RCHASH_REDUCE_DELETE : CF_RCHASH_OK;
}

uint32_t
assist_hash_fn(const void *key)
{
	return ((const assist_hkey *)key)->appeal_id;
}

void
assist_ack_start_request(cf_node src, msg *m, uint32_t op)
{
	msg_set_uint32(m, APPEAL_FIELD_OP, op);

	if (as_fabric_send(src, m, AS_FABRIC_CHANNEL_CTRL) != AS_FABRIC_SUCCESS) {
		as_fabric_msg_put(m);
	}
}

bool
assist_start_meta_sender(assist *ast)
{
	cf_rc_reserve(ast); // reserved for load thread
	cf_thread_create_transient(run_assist_meta_load, (void*)ast);

	cf_rc_reserve(ast); // reserved for send thread
	cf_thread_create_transient(run_assist_meta_send, (void*)ast);

	return true;
}

void *
run_assist_meta_load(void *arg)
{
	assist *ast = (assist *)arg;
	as_partition_reservation rsv;

	as_partition_reserve(ast->ns, ast->pid, &rsv);
	as_index_reduce(rsv.tree, assist_meta_reduce_fn, ast);
	as_partition_release(&rsv);

	meta_out_q_batch_close(ast->meta_q);
	assist_release(ast);

	return NULL;
}

void *
run_assist_meta_send(void *arg)
{
	assist *ast = (assist *)arg;

	while (assist_meta_batch_send(ast)) {
		;
	}

	assist_release(ast);

	return NULL;
}

bool
assist_meta_reduce_fn(as_index_ref *r_ref, void *udata)
{
	assist *ast = (assist *)udata;
	as_namespace *ns = ast->ns;

	if (assist_meta_should_abort(ast)) {
		as_record_done(r_ref, ns);
		return true;
	}

	if (r_ref->r->repl_state == AS_REPL_STATE_REPLICATED) {
		meta_out_q_add_rec(ast->meta_q, r_ref->r);
	}

	as_record_done(r_ref, ns);

	return true;
}

bool
assist_meta_batch_send(assist *ast)
{
	meta_out_q *oq = ast->meta_q;
	meta_batch batch = { false, 0, NULL };

	// Might block here.
	meta_out_q_next_batch(oq, &batch);

	msg *m = as_fabric_msg_get(M_TYPE_APPEAL);

	if (batch.n_records != 0) {
		msg_set_buf(m, APPEAL_FIELD_META_RECORDS, (uint8_t *)batch.records,
				sizeof(meta_record) * batch.n_records, MSG_SET_HANDOFF_MALLOC);
	}

	msg_set_uint32(m, APPEAL_FIELD_OP, APPEAL_OP_MERGE_META);
	msg_set_uint32(m, APPEAL_FIELD_APPEAL_ID, ast->appeal_id);
	msg_set_uint32(m, APPEAL_FIELD_META_SEQUENCE, ++oq->sequence);

	if (batch.is_final) {
		msg_set_uint32(m, APPEAL_FIELD_META_SEQUENCE_FINAL, 1);
	}

	uint64_t next_send = 0;

	while (! is_meta_out_q_synced(oq)) {
		if (assist_meta_should_abort(ast)) {
			as_fabric_msg_put(m);
			return false;
		}

		uint64_t current_time = cf_getms();

		if (next_send < current_time) {
			as_fabric_retransmit(ast->src, m, AS_FABRIC_CHANNEL_BULK);
			next_send = current_time + META_BATCH_RETRANSMIT_MS;
		}

		usleep(200);
	}

	as_fabric_msg_put(m);

	return ! batch.is_final;
}


//==========================================================
// Local helpers - fabric message handling.
//

int
appeal_receive_msg_cb(cf_node src, msg *m, void *udata)
{
	uint32_t op;

	if (msg_get_uint32(m, APPEAL_FIELD_OP, &op) != 0) {
		cf_warning(AS_APPEAL, "received message with no op");
		as_fabric_msg_put(m);
		return 0;
	}

	switch (op) {
	//--------------------------------------------
	// Appeal - handle requests:
	//
	case APPEAL_OP_MERGE_META:
		appeal_handle_meta_batch_request(src, m);
		break;

	//--------------------------------------------
	// Assist - handle requests:
	//
	case APPEAL_OP_APPEAL_START:
		assist_handle_start_request(src, m);
		break;
	case APPEAL_OP_APPEAL_DONE:
		assist_handle_done_request(src, m);
		break;

	//--------------------------------------------
	// Appeal - handle acknowledgments:
	//
	case APPEAL_OP_START_ACK_OK:
	case APPEAL_OP_START_ACK_EAGAIN:
	case APPEAL_OP_START_ACK_FAIL:
	case APPEAL_OP_DONE_ACK:
		appeal_handle_ctrl_ack(src, m, op);
		break;

	//--------------------------------------------
	// Assist - handle acknowledgments:
	//
	case APPEAL_OP_MERGE_META_ACK:
		assist_handle_meta_batch_ack(src, m);
		break;

	default:
		cf_detail(AS_APPEAL, "received unexpected message op %u", op);
		as_fabric_msg_put(m);
		break;
	}

	return 0;
}


//----------------------------------------------------------
// Appeal - request message handling.
//

void
appeal_handle_meta_batch_request(cf_node src, msg *m)
{
	uint32_t appeal_id;

	if (msg_get_uint32(m, APPEAL_FIELD_APPEAL_ID, &appeal_id) != 0) {
		cf_warning(AS_APPEAL, "merge start request: msg get for appeal id failed");
		as_fabric_msg_put(m);
		return;
	}

	uint32_t sequence;

	if (msg_get_uint32(m, APPEAL_FIELD_META_SEQUENCE, &sequence) != 0) {
		cf_warning(AS_APPEAL, "merge start request: msg get for sequence failed");
		as_fabric_msg_put(m);
		return;
	}

	appeal *ap;

	if (cf_rchash_get(g_appeal_hash, (void *)&appeal_id, (void **)&ap) ==
			CF_RCHASH_OK) {
		if (meta_in_q_handle_sequence(ap->meta_q, sequence)) {
			uint32_t final = 0;

			msg_get_uint32(m, APPEAL_FIELD_META_SEQUENCE_FINAL, &final);

			meta_batch batch = { final != 0, 0, NULL };
			size_t size = 0;

			if (msg_get_buf(m, APPEAL_FIELD_META_RECORDS,
					(uint8_t **)&batch.records, &size,
					MSG_GET_COPY_MALLOC) != 0 && final == 0) {
				cf_warning(AS_APPEAL, "merge start request: msg get for meta records failed");
				appeal_release(ap);
				as_fabric_msg_put(m);
				return;
			}

			batch.n_records = size / sizeof(meta_record);

			meta_in_q_push_batch(ap->meta_q, &batch);
		}

		appeal_release(ap);
	}
	// else - this must be an appeal that has already finished.

	msg_preserve_fields(m, 2, APPEAL_FIELD_APPEAL_ID,
			APPEAL_FIELD_META_SEQUENCE);

	msg_set_uint32(m, APPEAL_FIELD_OP, APPEAL_OP_MERGE_META_ACK);

	if (as_fabric_send(src, m, AS_FABRIC_CHANNEL_BULK) != AS_FABRIC_SUCCESS) {
		as_fabric_msg_put(m);
	}
}


//----------------------------------------------------------
// Assist - request message handling.
//

void
assist_handle_start_request(cf_node src, msg *m)
{
	uint32_t appeal_id;

	if (msg_get_uint32(m, APPEAL_FIELD_APPEAL_ID, &appeal_id) != 0) {
		cf_warning(AS_APPEAL, "handle start: msg get for emig id failed");
		as_fabric_msg_put(m);
		return;
	}

	uint64_t cluster_key;

	if (msg_get_uint64(m, APPEAL_FIELD_CLUSTER_KEY, &cluster_key) != 0) {
		cf_warning(AS_APPEAL, "handle start: msg get for cluster key failed");
		as_fabric_msg_put(m);
		return;
	}

	uint8_t *ns_name;
	size_t ns_name_len;

	if (msg_get_buf(m, APPEAL_FIELD_NAMESPACE, &ns_name, &ns_name_len,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_APPEAL, "handle start: msg get for namespace failed");
		as_fabric_msg_put(m);
		return;
	}

	as_namespace *ns = as_namespace_get_bybuf(ns_name, ns_name_len);

	if (! ns) {
		cf_warning(AS_APPEAL, "handle start: bad namespace");
		as_fabric_msg_put(m);
		return;
	}

	uint32_t pid;

	if (msg_get_uint32(m, APPEAL_FIELD_PARTITION, &pid) != 0) {
		cf_warning(AS_APPEAL, "handle start: msg get for pid failed");
		as_fabric_msg_put(m);
		return;
	}

	msg_preserve_fields(m, 1, APPEAL_FIELD_APPEAL_ID);

	assist *ast = cf_rc_alloc(sizeof(assist));

	ast->src = src;
	ast->cluster_key = cluster_key;
	ast->ns = ns;
	ast->pid = pid;
	ast->appeal_id = appeal_id;
	ast->meta_q = meta_out_q_create();
	ast->started = false;
	ast->done_recv = 0;

	assist_hkey hkey;

	hkey.src = src;
	hkey.appeal_id = appeal_id;

	while (true) {
		if (cf_rchash_put_unique(g_assist_hash, (void *)&hkey, (void *)ast) ==
				CF_RCHASH_OK) {
			cf_rc_reserve(ast); // so either put or get yields ref-count 2

			// First start request (not a retransmit) for this pid this round,
			// or we had ack'd previous start request with 'EAGAIN'.
			ast->start_result = as_partition_assist_start(ns, pid, cluster_key);
			break;
		}

		assist *ast0;

		if (cf_rchash_get(g_assist_hash, (void *)&hkey, (void *)&ast0) ==
				CF_RCHASH_OK) {
			assist_release(ast); // free just-alloc'd assist ...

			if (! ast0->started) {
				assist_release(ast0);
				return; // allow previous thread to respond
			}

			if (ast0->cluster_key != cluster_key) {
				assist_release(ast0);
				return; // other node reused an appeal_id, allow clearing
			}

			ast = ast0; // ... and use original
			break;
		}
	}

	switch (ast->start_result) {
	case ASSIST_START_RESULT_OK:
		break;
	case ASSIST_START_RESULT_ERROR:
		ast->started = true; // permits clearing
		assist_release(ast);
		assist_ack_start_request(src, m, APPEAL_OP_START_ACK_FAIL);
		return;
	case ASSIST_START_RESULT_EAGAIN:
		// Remove from hash so that the assist can be tried again.
		// Note - no real need to specify object, but paranoia costs nothing.
		cf_rchash_delete_object(g_assist_hash, (void *)&hkey, (void *)ast);
		assist_release(ast);
		assist_ack_start_request(src, m, APPEAL_OP_START_ACK_EAGAIN);
		return;
	default:
		cf_crash(AS_APPEAL, "bad assist start-result %d", ast->start_result);
		break;
	}

	if (! ast->started) {
		cf_atomic_int_incr(&ns->appeals_rx_active);

		assist_start_meta_sender(ast);

		ast->started = true; // permits clearing
	}

	assist_release(ast);
	assist_ack_start_request(src, m, APPEAL_OP_START_ACK_OK);
}

void
assist_handle_done_request(cf_node src, msg *m)
{
	uint32_t appeal_id;

	if (msg_get_uint32(m, APPEAL_FIELD_APPEAL_ID, &appeal_id) != 0) {
		cf_warning(AS_APPEAL, "handle done: msg get for appeal id failed");
		as_fabric_msg_put(m);
		return;
	}

	msg_preserve_fields(m, 1, APPEAL_FIELD_APPEAL_ID);

	// See if this assist already exists & has been notified.
	assist_hkey hkey;

	hkey.src = src;
	hkey.appeal_id = appeal_id;

	assist *ast;

	if (cf_rchash_get(g_assist_hash, (void *)&hkey, (void **)&ast) ==
			CF_RCHASH_OK) {
		if (ast->start_result != ASSIST_START_RESULT_OK || ! ast->started) {
			// If this assist didn't start, it's likely in the hash on a
			// retransmit and this DONE is for the original - ignore, and let
			// this assist proceed.
			assist_release(ast);
			as_fabric_msg_put(m);
			return;
		}

		if (cf_atomic32_incr(&ast->done_recv) == 1) {
			cf_atomic_int_decr(&ast->ns->appeals_rx_active);
			// Don't need to call any done function in partition_balance_ee.
		}
		// else - was likely a retransmitted done message.

		assist_release(ast);
	}
	// else - garbage, or super-stale retransmitted done message.

	msg_set_uint32(m, APPEAL_FIELD_OP, APPEAL_OP_DONE_ACK);

	if (as_fabric_send(src, m, AS_FABRIC_CHANNEL_CTRL) != AS_FABRIC_SUCCESS) {
		as_fabric_msg_put(m);
	}
}


//----------------------------------------------------------
// Appeal - acknowledgment message handling.
//

void
appeal_handle_ctrl_ack(cf_node src, msg *m, uint32_t op)
{
	uint32_t appeal_id;

	if (msg_get_uint32(m, APPEAL_FIELD_APPEAL_ID, &appeal_id) != 0) {
		cf_warning(AS_APPEAL, "ctrl ack: msg get for appeal id failed");
		as_fabric_msg_put(m);
		return;
	}

	as_fabric_msg_put(m);

	appeal *ap;

	if (cf_rchash_get(g_appeal_hash, (void *)&appeal_id, (void **)&ap) ==
			CF_RCHASH_OK) {
		if (ap->dest == src) {
			cf_queue_push(ap->ctrl_q, &op);
		}
		else {
			cf_warning(AS_APPEAL, "ctrl ack (%d): unexpected source %lx", op,
					src);
		}

		appeal_release(ap);
	}
}


//----------------------------------------------------------
// Assist - acknowledgment message handling.
//

void
assist_handle_meta_batch_ack(cf_node src, msg *m)
{
	uint32_t appeal_id;

	if (msg_get_uint32(m, APPEAL_FIELD_APPEAL_ID, &appeal_id) != 0) {
		cf_warning(AS_APPEAL, "meta batch ack: msg get for appeal id failed");
		as_fabric_msg_put(m);
		return;
	}

	uint32_t sequence;

	if (msg_get_uint32(m, APPEAL_FIELD_META_SEQUENCE, &sequence) != 0) {
		cf_warning(AS_APPEAL, "meta batch ack: msg get for meta sequence failed");
		as_fabric_msg_put(m);
		return;
	}

	as_fabric_msg_put(m);

	assist_hkey hkey;
	assist *ast;

	hkey.src = src;
	hkey.appeal_id = appeal_id;

	if (cf_rchash_get(g_assist_hash, (void *)&hkey, (void **)&ast) !=
			CF_RCHASH_OK) {
		// Appealer sent 'done' before assister sent all meta batches.
		return;
	}

	meta_out_q_sequence_ack(ast->meta_q, sequence);
	assist_release(ast);
}
