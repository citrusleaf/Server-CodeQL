/*
 * replica_ping_ee.c
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

#include "transaction/replica_ping.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "citrusleaf/cf_digest.h"

#include "cf_mutex.h"
#include "log.h"
#include "msg.h"
#include "node.h"

#include "base/datamodel.h"
#include "base/proto.h"
#include "base/service.h"
#include "base/transaction.h"
#include "fabric/fabric.h"
#include "fabric/partition.h"
#include "fabric/partition_ee.h"
#include "transaction/rw_request.h"
#include "transaction/rw_request_hash.h"


//==========================================================
// Forward declarations.
//

void send_repl_ping_ack(cf_node node, msg* m, uint32_t result);


//==========================================================
// Public API.
//

bool
repl_ping_check(as_transaction* tr)
{
	as_namespace* ns = tr->rsv.ns;

	if (ns->cp) {
		if (as_transaction_is_linearized_read(tr) &&
				ns->cfg_replication_factor > 1) {
			tr->flags |= AS_TRANSACTION_FLAG_MUST_PING;
		}

		return true;
	}

	if (as_transaction_is_linearized_read(tr)) {
		cf_warning(AS_RW, "'linearize-read' policy is only applicable with 'strong-consistency'");
		tr->result_code = AS_ERR_UNSUPPORTED_FEATURE;
		return false;
	}

	return true;
}

void
repl_ping_make_message(rw_request* rw, as_transaction* tr)
{
	if (rw->dest_msg) {
		as_fabric_msg_put(rw->dest_msg);
	}

	rw->dest_msg = as_fabric_msg_get(M_TYPE_RW);

	as_namespace* ns = tr->rsv.ns;
	msg* m = rw->dest_msg;

	msg_set_uint32(m, RW_FIELD_OP, RW_OP_REPL_PING);
	msg_set_buf(m, RW_FIELD_NAMESPACE, (uint8_t*)ns->name, strlen(ns->name),
			MSG_SET_COPY);
	msg_set_uint32(m, RW_FIELD_NS_IX, ns->ix);
	msg_set_buf(m, RW_FIELD_DIGEST, (void*)&tr->keyd, sizeof(cf_digest),
			MSG_SET_COPY);
	msg_set_uint32(m, RW_FIELD_TID, rw->tid);
	msg_set_uint32(m, RW_FIELD_REGIME, tr->rsv.regime);
}

void
repl_ping_setup_rw(rw_request* rw, as_transaction* tr,
		repl_ping_done_cb repl_ping_cb, timeout_done_cb timeout_cb)
{
	rw->msgp = tr->msgp;
	tr->msgp = NULL;

	rw->msg_fields = tr->msg_fields;
	rw->origin = tr->origin;
	rw->from_flags = tr->from_flags;

	rw->from.any = tr->from.any;
	rw->from_data.any = tr->from_data.any;
	tr->from.any = NULL;

	rw->start_time = tr->start_time;
	rw->benchmark_time = tr->benchmark_time;

	as_partition_reservation_copy(&rw->rsv, &tr->rsv);
	// Hereafter, rw_request must release reservation - happens in destructor.

	rw->end_time = tr->end_time;
	// Note - don't need as_transaction's other 'container' members.

	rw->repl_ping_cb = repl_ping_cb;
	rw->timeout_cb = timeout_cb;

	rw->xmit_ms = cf_getms() + g_config.transaction_retry_ms;
	rw->retry_interval_ms = g_config.transaction_retry_ms;

	for (uint32_t i = 0; i < rw->n_dest_nodes; i++) {
		rw->dest_complete[i] = false;
	}

	// Allow retransmit thread to destroy rw_request as soon as we unlock.
	rw->is_set_up = true;
}

void
repl_ping_reset_rw(rw_request* rw, as_transaction* tr, repl_ping_done_cb cb)
{
	// Reset rw->from.any which was set null in tr setup.
	rw->from.any = tr->from.any;

	rw->repl_ping_cb = cb;

	// TODO - is this better than not resetting? Note - xmit_ms not volatile.
	rw->xmit_ms = cf_getms() + g_config.transaction_retry_ms;
	rw->retry_interval_ms = g_config.transaction_retry_ms;

	for (uint32_t i = 0; i < rw->n_dest_nodes; i++) {
		rw->dest_complete[i] = false;
	}
}

void
repl_ping_handle_op(cf_node node, msg* m)
{
	uint8_t* ns_name;
	size_t ns_name_len;

	if (msg_get_buf(m, RW_FIELD_NAMESPACE, &ns_name, &ns_name_len,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_RW, "repl_ping_handle_op: no namespace");
		send_repl_ping_ack(node, m, AS_ERR_UNKNOWN);
		return;
	}

	as_namespace* ns = as_namespace_get_bybuf(ns_name, ns_name_len);

	if (! ns) {
		cf_warning(AS_RW, "repl_ping_handle_op: invalid namespace");
		send_repl_ping_ack(node, m, AS_ERR_UNKNOWN);
		return;
	}

	cf_digest* keyd;

	if (msg_get_buf(m, RW_FIELD_DIGEST, (uint8_t**)&keyd, NULL,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_RW, "repl_ping_handle_op: no digest");
		send_repl_ping_ack(node, m, AS_ERR_UNKNOWN);
		return;
	}

	uint32_t regime;

	if (msg_get_uint32(m, RW_FIELD_REGIME, &regime) != 0) {
		cf_warning(AS_RW, "repl_ping_handle_op: no regime");
		send_repl_ping_ack(node, m, AS_ERR_UNKNOWN);
		return;
	}

	uint32_t result = as_partition_check_repl_ping(ns, as_partition_getid(keyd),
			regime, node);

	send_repl_ping_ack(node, m, result);
}

void
repl_ping_handle_ack(cf_node node, msg* m)
{
	uint32_t ns_ix;

	if (msg_get_uint32(m, RW_FIELD_NS_IX, &ns_ix) != 0) {
		cf_warning(AS_RW, "repl-ping ack: no ns-ix");
		as_fabric_msg_put(m);
		return;
	}

	cf_digest* keyd;

	if (msg_get_buf(m, RW_FIELD_DIGEST, (uint8_t**)&keyd, NULL,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_RW, "repl-ping ack: no digest");
		as_fabric_msg_put(m);
		return;
	}

	uint32_t tid;

	if (msg_get_uint32(m, RW_FIELD_TID, &tid) != 0) {
		cf_warning(AS_RW, "repl-ping ack: no tid");
		as_fabric_msg_put(m);
		return;
	}

	rw_request_hkey hkey = { .ns_ix = ns_ix, .keyd = *keyd };
	rw_request* rw = rw_request_hash_get(&hkey);

	if (! rw) {
		// Extra ack, after rw_request is already gone.
		as_fabric_msg_put(m);
		return;
	}

	cf_mutex_lock(&rw->lock);

	if (rw->tid != tid || rw->repl_ping_complete) {
		// Extra ack - rw_request is newer transaction for same digest, or ack
		// is arriving after rw_request was aborted.
		cf_mutex_unlock(&rw->lock);
		rw_request_release(rw);
		as_fabric_msg_put(m);
		return;
	}

	if (! rw->from.any) {
		// Lost race against timeout in retransmit thread.
		cf_mutex_unlock(&rw->lock);
		rw_request_release(rw);
		as_fabric_msg_put(m);
		return;
	}

	// Find remote node in replicas list.
	int i = index_of_node(rw->dest_nodes, rw->n_dest_nodes, node);

	if (i == -1) {
		cf_warning(AS_RW, "repl-ping ack: from non-dest node %lx", node);
		cf_mutex_unlock(&rw->lock);
		rw_request_release(rw);
		as_fabric_msg_put(m);
		return;
	}

	if (rw->dest_complete[i]) {
		// Extra ack for this replica ping.
		cf_mutex_unlock(&rw->lock);
		rw_request_release(rw);
		as_fabric_msg_put(m);
		return;
	}

	rw->dest_complete[i] = true;

	uint32_t result_code;

	if (msg_get_uint32(m, RW_FIELD_RESULT, &result_code) != 0) {
		cf_warning(AS_RW, "repl-ping ack: no result_code");
		result_code = AS_ERR_UNKNOWN;
	}

	// Anything other than success, retry transaction from the beginning.
	if (result_code != AS_OK) {
		as_transaction tr;
		as_transaction_init_head_from_rw(&tr, rw);

		// Note that tr now owns msgp - make sure rw destructor doesn't free it.
		// Note also that rw will release rsv - tr will get a new one.
		rw->msgp = NULL;

		tr.from_flags |= FROM_FLAG_RESTART;
		as_service_enqueue_internal(&tr);

		rw->repl_ping_complete = true;

		cf_mutex_unlock(&rw->lock);
		rw_request_hash_delete(&hkey, rw);
		rw_request_release(rw);
		as_fabric_msg_put(m);
		return;
	}

	for (uint32_t j = 0; j < rw->n_dest_nodes; j++) {
		if (! rw->dest_complete[j]) {
			// Still haven't heard from all replicas.
			cf_mutex_unlock(&rw->lock);
			rw_request_release(rw);
			as_fabric_msg_put(m);
			return;
		}
	}

	// Success for all replicas.
	rw->repl_ping_cb(rw);

	rw->repl_ping_complete = true;

	cf_mutex_unlock(&rw->lock);
	rw_request_hash_delete(&hkey, rw);
	rw_request_release(rw);
	as_fabric_msg_put(m);
}


//==========================================================
// Local helpers.
//

void
send_repl_ping_ack(cf_node node, msg* m, uint32_t result)
{
	msg_preserve_fields(m, 3, RW_FIELD_NS_IX, RW_FIELD_DIGEST, RW_FIELD_TID);

	msg_set_uint32(m, RW_FIELD_OP, RW_OP_REPL_PING_ACK);
	msg_set_uint32(m, RW_FIELD_RESULT, result);

	if (as_fabric_send(node, m, AS_FABRIC_CHANNEL_RW) != AS_FABRIC_SUCCESS) {
		as_fabric_msg_put(m);
	}
}
