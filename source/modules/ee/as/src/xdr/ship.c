/*
 * ship.c
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

#include "xdr/ship.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <zlib.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_byte_order.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_queue.h"

#include "log.h"
#include "socket.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "base/proto.h"
#include "base/security.h"
#include "base/security_ee.h"
#include "base/xdr.h"
#include "fabric/hb.h"
#include "fabric/partition.h"
#include "storage/storage.h"
#include "xdr/cluster.h"
#include "xdr/dc.h"
#include "xdr/dc_manager.h"
#include "xdr/xdr_ee.h"

//#include "warnings.h" // generates warnings we're living with for now


//==========================================================
// Typedefs & constants.
//

#define MAX_RESPONSES_SZ 1024 // holds ~30 server responses
#define AUTH_RESPONSE_SZ (sizeof(as_proto) + sizeof(as_sec_msg))
#define WATCHDOG_PERIOD 2
#define IO_TIMEOUT (10 * 1000)

typedef enum {
	CONN_NOT_CONNECTED,
	CONN_CONNECTING,
	CONN_TLS_HANDSHAKE,
	CONN_AUTH_SEND,
	CONN_AUTH_RECEIVE,
	CONN_SENDING,
	CONN_AVAILABLE
} connection_state;

typedef struct req_buf_s {
	uint8_t* data;
	uint32_t sz;
	uint32_t off;
} req_buf;

typedef struct connection_s {
	uint8_t poll_data_type; // one of CF_POLL_DATA_* - must be first

	connection_state state;
	cluster_node* node;
	cf_socket sock;
	cf_queue in_flight_q; // relies on in-order responses
	req_buf auth;
	req_buf record;
	uint8_t* responses;
	uint32_t responses_sz;
	uint64_t last_responded;
} connection;

typedef struct watchdog_s {
	uint8_t poll_data_type; // one of CF_POLL_DATA_* - must be first

	int32_t timer_fd;
} watchdog;

typedef struct write_params_s {
	as_xdr_write_policy write_policy;
	as_xdr_bin_policy bin_policy;
	bool ship_changes;
	bool ship_luts;
	uint64_t lut_cutoff;
} write_params;


//==========================================================
// Globals.
//

static __thread cf_poll g_poll; // service thread's epoll instance
static __thread connection* g_connections; // AS_XDR_MAX_DCS * AS_CLUSTER_SZ
static __thread watchdog* g_lassie;


//==========================================================
// Forward declarations.
//

static connection* get_connection(uint32_t dc_ix, uint32_t ns_ix, uint32_t pid, void* udata);
static void reset_connection(connection* conn);
static void connection_error(connection* conn, const char* tag);
static void clear_connection_io_events(const connection* conn, cf_poll_event* events, int32_t n_events, uint32_t e_ix);

static void do_connecting(uint32_t mask, connection* conn);
static void do_tls_handshake(uint32_t mask, connection* conn);
static void do_auth_send(uint32_t mask, connection* conn);
static void do_auth_receive(uint32_t mask, connection* conn);
static void do_sending(uint32_t mask, connection* conn);
static void do_available(uint32_t mask, connection* conn);

static bool try_to_send(cf_socket* sock, req_buf* req);
static bool handle_auth_response(connection* conn);
static bool handle_responses(connection* conn);

static void set_auth_request(connection* conn);
static uint8_t* create_auth_request(const cluster_node* n, const char* user, uint32_t* req_sz);

static uint8_t* create_write_request(const as_xdr_dc_cfg* dc_cfg, as_storage_rd* rd, const write_params* wp, uint32_t* request_sz, as_proto_comp_stat* comp_stat);
static uint8_t* create_delete_request(const as_xdr_dc_cfg* dc_cfg, const as_storage_rd* rd, uint32_t* request_sz);
static size_t size_fields(const char* ns_name, const as_storage_rd* rd, bool ship_lut, uint16_t* n_fields);
static uint8_t* add_fields(const char* ns_name, const as_storage_rd* rd, bool ship_lut, uint8_t* buf);


//==========================================================
// Inlines & macros.
//

static inline void
modify_poll(uint32_t mask, connection* conn) {
	cf_poll_modify_socket(g_poll, &conn->sock, EPOLLRDHUP | EPOLLONESHOT | mask,
			conn);
}

static inline void
to_connecting(connection* conn)
{
	cf_poll_add_socket(g_poll, &conn->sock, EPOLLOUT, conn);
	conn->state = CONN_CONNECTING;
}

static inline void
to_tls_handshake(connection* conn)
{
	modify_poll(EPOLLOUT, conn);
	conn->state = CONN_TLS_HANDSHAKE;
}

static inline void
to_auth_send(connection* conn)
{
	modify_poll(EPOLLOUT, conn);
	conn->state = CONN_AUTH_SEND;
}

static inline void
to_auth_receive(connection* conn)
{
	modify_poll(EPOLLIN, conn);
	conn->state = CONN_AUTH_RECEIVE;
}

static inline void
to_sending(connection* conn)
{
	modify_poll(EPOLLIN | EPOLLOUT, conn);
	conn->state = CONN_SENDING;
}

static inline void
to_available(connection* conn)
{
	modify_poll(EPOLLIN, conn);
	conn->state = CONN_AVAILABLE;
}

static inline void
to_sending_or_available(connection* conn)
{
	if (conn->record.data == NULL) {
		to_available(conn);
	}
	else {
		to_sending(conn);
	}
}

static inline bool
select_bin(const as_bin* b, const as_xdr_dc_ns_cfg* cfg, const write_params* wp)
{
	if (b->xdr_write == 1 && ! cfg->forward) {
		return false;
	}

	uint8_t bin_ship_cfg = cfg->bins[b->id];

	switch (wp->bin_policy) {
	case XDR_BIN_POLICY_ALL:
		return bin_ship_cfg != SHIPPING_DISABLED;
	case XDR_BIN_POLICY_ONLY_CHANGED:
		return b->lut >= wp->lut_cutoff && bin_ship_cfg != SHIPPING_DISABLED;
	case XDR_BIN_POLICY_CHANGED_AND_SPECIFIED:
		return b->lut >= wp->lut_cutoff && bin_ship_cfg == SHIPPING_ENABLED;
	case XDR_BIN_POLICY_CHANGED_OR_SPECIFIED:
		return b->lut >= wp->lut_cutoff || bin_ship_cfg == SHIPPING_ENABLED;
	default:
		cf_crash(AS_XDR, "invalid 'bin-policy' %d", (int)wp->bin_policy);
		return false;
	}
}

#define CONNECTION(dc_ix, node_ix) \
	&g_connections[(dc_ix * AS_CLUSTER_SZ) + node_ix]


//==========================================================
// Public API.
//

void
as_xdr_init_poll(cf_poll poll)
{
	g_poll = poll;

	int32_t timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

	if (timer_fd < 0) {
		cf_crash(AS_XDR_CLIENT, "timerfd_create() failed: %d (%s)", errno,
				cf_strerror(errno));
	}

	struct itimerspec spec = {
			.it_interval = { .tv_sec = WATCHDOG_PERIOD, .tv_nsec = 0 },
			.it_value = { .tv_sec = WATCHDOG_PERIOD, .tv_nsec = 0 }
	};

	if (timerfd_settime(timer_fd, 0, &spec, NULL) < 0) {
		cf_crash(AS_XDR_CLIENT, "timerfd_settime() failed: %d (%s)", errno,
				cf_strerror(errno));
	}

	g_lassie = cf_malloc(sizeof(watchdog));

	g_lassie->poll_data_type = CF_POLL_DATA_XDR_TIMER,
	g_lassie->timer_fd = timer_fd;

	cf_poll_add_fd(poll, timer_fd, EPOLLIN, g_lassie);

	// Use calloc - we rely on connection.state starting as CONN_NOT_CONNECTED.
	g_connections =
			cf_calloc(1, sizeof(connection) * AS_XDR_MAX_DCS * AS_CLUSTER_SZ);
}

void
as_xdr_shutdown_poll(void)
{
	cf_poll_delete_fd(g_poll, g_lassie->timer_fd);
	CF_NEVER_FAILS(close(g_lassie->timer_fd));

	cf_free(g_lassie);

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		for (uint32_t node_ix = 0; node_ix < AS_CLUSTER_SZ; node_ix++) {
			connection* conn = CONNECTION(dc_ix, node_ix);

			if (conn->state != CONN_NOT_CONNECTED) {
				reset_connection(conn);
			}
		}
	}

	cf_free(g_connections);
}

// Note - only happens once per connection per event loop.
void
as_xdr_io_event(uint32_t mask, void* data)
{
	if (mask == 0) {
		// Lost to timer event earlier in event loop. State may not be
		// CONN_NOT_CONNECTED if new connection was started by send_record().
		return;
	}

	connection* conn = (connection*)data;

	if (conn->state == CONN_NOT_CONNECTED) {
		// Lost to a send_record() error earlier in event loop.
		return;
	}

	if ((mask & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) != 0) {
		reset_connection(conn);
		return;
	}

	switch (conn->state) {
	case CONN_CONNECTING:
		do_connecting(mask, conn);
		break;
	case CONN_TLS_HANDSHAKE:
		do_tls_handshake(mask, conn);
		break;
	case CONN_AUTH_SEND:
		do_auth_send(mask, conn);
		break;
	case CONN_AUTH_RECEIVE:
		do_auth_receive(mask, conn);
		break;
	case CONN_SENDING:
		do_sending(mask, conn);
		break;
	case CONN_AVAILABLE:
		do_available(mask, conn);
		break;
	case CONN_NOT_CONNECTED:
	default:
		cf_crash(AS_XDR_CLIENT, "bad state %d", conn->state);
		break;
	}
}

void
as_xdr_timer_event(uint32_t sid, cf_poll_event* events, int32_t n_events,
		uint32_t e_ix)
{
	uint32_t mask = events[e_ix].events;

	cf_assert(mask == EPOLLIN, AS_XDR_CLIENT, "unexpected event: 0x%0x", mask);

	watchdog* lassie = (watchdog*)events[e_ix].data;
	uint64_t dummy;

	if (read(lassie->timer_fd, &dummy, sizeof(dummy)) < 0) {
		cf_crash(AS_XDR_CLIENT, "read() failed: %d (%s)", errno,
				cf_strerror(errno));
	}

	uint64_t now = cf_getms();

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_xdr_dc_cfg* cfg = as_dc_manager_get_cfg_by_ix(dc_ix);
		uint32_t max_threads = as_load_uint32(&cfg->max_used_service_threads);
		bool idle_sid = max_threads != 0 && sid >= max_threads;

		for (uint32_t node_ix = 0; node_ix < AS_CLUSTER_SZ; node_ix++) {
			connection* conn = CONNECTION(dc_ix, node_ix);
			cluster_node* n = conn->node;

			if (conn->state == CONN_NOT_CONNECTED) {
				continue;
			}

			cf_assert(NODE_IS_LIVE(n), AS_XDR_CLIENT,
					"timer found node %s in state %d", n->connected_to,
					n->state);

			if (n->state == NODE_DRAINING || idle_sid) {
				reset_connection(conn);
				clear_connection_io_events(conn, events, n_events, e_ix);
				continue;
			}

			switch (conn->state) {
			case CONN_CONNECTING:
			case CONN_TLS_HANDSHAKE:
			case CONN_AUTH_SEND:
			case CONN_AUTH_RECEIVE:
				if (now - conn->last_responded >= IO_TIMEOUT) {
					connection_error(conn, "timeout connecting");
					clear_connection_io_events(conn, events, n_events, e_ix);
				}
				break;
			case CONN_SENDING:
			case CONN_AVAILABLE:
				if (cf_queue_sz(&conn->in_flight_q) != 0 &&
						now - conn->last_responded >= IO_TIMEOUT) {
					connection_error(conn, "network timeout");
					clear_connection_io_events(conn, events, n_events, e_ix);
				}
				break;
			case CONN_NOT_CONNECTED:
			default:
				cf_crash(AS_XDR_CLIENT, "bad state %d", conn->state);
				break;
			}
		}
	}
}


//==========================================================
// Public API - enterprise only.
//

// Note - only happens once per connection per event loop.
void
as_ship_send_record(uint32_t dc_ix, const as_xdr_dc_cfg* dc_cfg,
		as_storage_rd* rd, ship_request* req, tl_ns_stats* stats)
{
	as_record* r = rd->r;

	uint32_t ns_ix = rd->ns->ix;
	connection* conn = get_connection(dc_ix, ns_ix,
			as_partition_getid(&r->keyd), (void*)req);

	if (conn == NULL) {
		return;
	}

	as_xdr_dc_ns_cfg* dc_ns_cfg = dc_cfg->ns_cfgs[ns_ix];
	write_params wp;

	// Make sure these are consistent if dynamically changed separately.
	wp.write_policy = as_load_uint32(&dc_ns_cfg->write_policy);
	wp.bin_policy = wp.write_policy == XDR_WRITE_POLICY_REPLACE ?
			XDR_BIN_POLICY_ALL : as_load_uint32(&dc_ns_cfg->bin_policy);
	wp.ship_changes = ships_changed_bins(wp.bin_policy);
	wp.ship_luts = wp.ship_changes && as_load_bool(&dc_ns_cfg->ship_bin_luts);
	wp.lut_cutoff = wp.ship_changes ? req->lut_cutoff : 0;

	req_buf* record = &conn->record;

	record->data = r->tombstone == 0 ||
			(r->xdr_bin_cemetery == 1 && wp.ship_luts) ?
					create_write_request(dc_cfg, rd, &wp, &record->sz,
							&stats->compression) :
					create_delete_request(dc_cfg, rd, &record->sz);

	if (record->data == NULL) {
		as_dc_client_cb(LOCAL_ERR_REC_FILTERED_OUT, (void*)req);
		return;
	}

	record->off = 0;

	if (cf_queue_sz(&conn->in_flight_q) == 0) {
		// Start timeout window for fresh connection or restart window in case
		// it's the first transaction in a while.
		conn->last_responded = cf_getms();
	}

	cf_queue_push(&conn->in_flight_q, &req);

	if (conn->state == CONN_CONNECTING) {
		return;
	}
	// else - state == CONN_AVAILABLE.

	if (! try_to_send(&conn->sock, record)) {
		connection_error(conn, "send error");
		return;
	}

	to_sending_or_available(conn);
}


//==========================================================
// Local helpers - handle connections.
//

static connection*
get_connection(uint32_t dc_ix, uint32_t ns_ix, uint32_t pid, void* udata)
{
	cluster_node* n = as_cluster_get_node_optimistic(dc_ix, ns_ix, pid);

	if (n == NULL) {
		as_dc_client_cb(LOCAL_ERR_NO_NODE, udata);
		return NULL;
	}

	connection* conn = CONNECTION(dc_ix, n->ix);

	if (conn->state == CONN_AVAILABLE) {
		// Node may go from active -> draining but no further if CONN_AVAILABLE.
		cf_assert(NODE_IS_LIVE(n), AS_XDR_CLIENT,
				"connected node %s in state %d", n->connected_to, n->state);
		return conn;
	}

	if (conn->state != CONN_NOT_CONNECTED) {
		as_dc_client_cb(LOCAL_ERR_CONN_BUSY, udata);
		return NULL; // another request already in progress
	}
	// else - state == CONN_NOT_CONNECTED.

	// Creating a connection - make this thread's reservation.
	if (! as_cluster_reserve_node(n)) {
		as_dc_client_cb(LOCAL_ERR_NO_NODE, udata);
		return NULL;
	}

	conn->poll_data_type = CF_POLL_DATA_XDR_IO;
	conn->node = n;

	cf_mutex_lock(&n->tend_lock);

	// Valid n->tend_sock_cfg was required for this node to be in partition map.
	int32_t rv = cf_socket_init_client(&n->tend_sock_cfg, 0, &conn->sock);

	cf_mutex_unlock(&n->tend_lock);

	if (rv < 0) {
		as_cluster_release_node(n);
		as_dc_client_cb(LOCAL_ERR_CONN_RESET, udata);
		return NULL;
	}

	if (n->tls_name != NULL) {
		tls_socket_prepare_xdr_client(as_cluster_get_tls_info(dc_ix),
				&n->tls_names, &conn->sock);
	}

	cf_queue_init(&conn->in_flight_q, sizeof(void*), 32, false);

	conn->responses = cf_malloc(MAX_RESPONSES_SZ);
	conn->responses_sz = 0;

	to_connecting(conn);
	return conn;
}

static void
reset_connection(connection* conn)
{
	cf_poll_delete_socket(g_poll, &conn->sock);

	cf_socket_close(&conn->sock);
	cf_socket_term(&conn->sock);

	void* udata;

	while (cf_queue_pop(&conn->in_flight_q, &udata, CF_QUEUE_NOWAIT) ==
			CF_QUEUE_OK) {
		as_dc_client_cb(LOCAL_ERR_CONN_RESET, udata);
	}

	cf_queue_destroy(&conn->in_flight_q);

	if (conn->auth.data != NULL) {
		cf_free(conn->auth.data);
		conn->auth.data = NULL; // allocated after TLS handshake - cover gap
	}

	if (conn->record.data != NULL) {
		cf_free(conn->record.data);
	}

	cf_free(conn->responses);

	as_cluster_release_node(conn->node);

	conn->state = CONN_NOT_CONNECTED;
}

static void
connection_error(connection* conn, const char* tag)
{
	cf_sock_addr addr;
	const char* addr_str = cf_socket_remote_name(&conn->sock, &addr) < 0 ?
		"(no connection)" : cf_sock_addr_print(&addr);

	const char* dc_name = as_cluster_get_dc_name(conn->node->dc_ix);

	cf_warning(AS_XDR_CLIENT, "DC %s %s on %s", dc_name, tag, addr_str);

	reset_connection(conn);
}

static void
clear_connection_io_events(const connection* conn, cf_poll_event* events,
		int32_t n_events, uint32_t e_ix)
{
	for (uint32_t i = e_ix + 1; i < (uint32_t)n_events; i++) {
		cf_poll_event* poll_event = &events[i];
		void* data = poll_event->data;

		if (*(uint8_t*)data == CF_POLL_DATA_XDR_IO &&
				(const connection*)data == conn) {
			poll_event->events = 0; // flag to ignore
		}
	}
}


//==========================================================
// Local helpers - handle states.
//

static void
do_connecting(uint32_t mask, connection* conn)
{
	cf_assert(mask == EPOLLOUT, AS_XDR_CLIENT, "unexpected event 0x%x", mask);

	cluster_node* n = conn->node;

	if (n->tls_name != NULL) {
		to_tls_handshake(conn);
		return;
	}

	if (n->session_token != NULL) {
		set_auth_request(conn);
		to_auth_send(conn);
		return;
	}

	to_sending_or_available(conn);
}

static void
do_tls_handshake(uint32_t mask, connection* conn)
{
	cf_assert(mask == EPOLLIN || mask == EPOLLOUT, AS_XDR_CLIENT,
			"unexpected event 0x%x", mask);

	cluster_node* n = conn->node;
	uint32_t tls_mask = (uint32_t)tls_socket_connect(&conn->sock);

	if (tls_mask == EPOLLERR) {
		connection_error(conn, "TLS handshake error");
		return;
	}

	if (tls_mask != 0) {
		modify_poll((uint32_t)tls_mask, conn);
		return;
	}
	// else - done with TLS.

	if (n->session_token != NULL) {
		set_auth_request(conn);
		to_auth_send(conn);
		return;
	}

	to_sending_or_available(conn);
}

void
do_auth_send(uint32_t mask, connection* conn)
{
	cf_assert(mask == EPOLLOUT, AS_XDR_CLIENT, "unexpected event 0x%x", mask);

	req_buf* auth = &conn->auth;

	if (! try_to_send(&conn->sock, auth)) {
		connection_error(conn, "send error");
		return;
	}

	if (auth->data == NULL) {
		to_auth_receive(conn);
		return;
	}

	// Did not finish sending.
	to_auth_send(conn);
}

static void
do_auth_receive(uint32_t mask, connection* conn)
{
	cf_assert(mask == EPOLLIN, AS_XDR_CLIENT, "unexpected event 0x%x", mask);

	cluster_node* n = conn->node;

	(void)n;

	if (! handle_auth_response(conn)) {
		connection_error(conn, "auth receive error");
		return;
	}

	if (conn->responses_sz == AUTH_RESPONSE_SZ) {
		conn->responses_sz = 0; // prepare for fresh write responses
		to_sending_or_available(conn);
		return;
	}

	// Did not finish receiving.
	to_auth_receive(conn);
}

static void
do_sending(uint32_t mask, connection* conn)
{
	cf_assert((mask & (uint32_t)~(EPOLLIN | EPOLLOUT)) == 0, AS_XDR_CLIENT,
			"unexpected event 0x%x", mask);

	if ((mask & EPOLLIN) != 0 && ! handle_responses(conn)) {
		connection_error(conn, "receive error [1]");
		return;
	}

	if ((mask & EPOLLOUT) != 0) {
		req_buf* record = &conn->record;

		if (! try_to_send(&conn->sock, record)) {
			connection_error(conn, "send error");
			return;
		}

		if (record->data == NULL) {
			to_available(conn);
			return;
		}
	}

	// Did not finish sending.
	to_sending(conn);
}

static void
do_available(uint32_t mask, connection* conn)
{
	cf_assert(mask == EPOLLIN, AS_XDR_CLIENT, "unexpected event 0x%x", mask);

	if (! handle_responses(conn)) {
		connection_error(conn, "receive error [2]");
		return;
	}

	to_available(conn);
}


//==========================================================
// Local helpers - send and receive.
//

static bool
try_to_send(cf_socket* sock, req_buf* req)
{
	int32_t send_sz = cf_socket_send(sock, req->data + req->off,
			req->sz - req->off, 0);

	if (send_sz < 0) {
		if (errno != EAGAIN) {
			return false;
		}

		send_sz = 0;
	}

	req->off += (uint32_t)send_sz;

	if (req->off == req->sz) {
		cf_free(req->data);
		req->data = NULL;
	}

	return true;
}

static bool
handle_auth_response(connection* conn)
{
	int32_t recv_sz = cf_socket_recv(&conn->sock,
			conn->responses + conn->responses_sz,
			MAX_RESPONSES_SZ - conn->responses_sz, 0);

	if (recv_sz < 0) {
		return false;
	}

	conn->responses_sz += (uint32_t)recv_sz;

	if (conn->responses_sz < sizeof(as_proto)) {
		return true;
	}

	as_proto proto = *(as_proto*)conn->responses; // make copy for swapping

	if (! validate_and_swap_proto(&proto, PROTO_TYPE_SECURITY,
			AUTH_RESPONSE_SZ, conn->node->connected_to)) {
		return false;
	}

	if (conn->responses_sz < sizeof(as_proto) + proto.sz) {
		return true;
	}

	if (proto.sz < sizeof(as_sec_msg)) {
		cf_warning(AS_XDR_CLIENT, "bad proto size %lu", (uint64_t)proto.sz);
		return false;
	}

	const as_sec_msg* m = (as_sec_msg*)(conn->responses + sizeof(as_proto));

	if (m->result != AS_OK) {
		cf_warning(AS_XDR_CLIENT, "auth failed - error %u", m->result);
		return false;
	}

	return true;
}

static bool
handle_responses(connection* conn)
{
	int32_t recv_sz = cf_socket_recv(&conn->sock,
			conn->responses + conn->responses_sz,
			MAX_RESPONSES_SZ - conn->responses_sz, 0);

	if (recv_sz < 0) {
		return false;
	}

	conn->responses_sz += (uint32_t)recv_sz;

	uint8_t* at = conn->responses;

	while (true) {
		if (conn->responses_sz < sizeof(as_proto)) {
			break;
		}

		as_proto proto = *(as_proto*)at; // make copy for swapping

		if (! validate_and_swap_proto(&proto, PROTO_TYPE_AS_MSG,
				MAX_RESPONSES_SZ, conn->node->connected_to)) {
			return false;
		}

		uint32_t total_sz = (uint32_t)(sizeof(as_proto) + proto.sz);

		if (conn->responses_sz < total_sz) {
			break;
		}

		if (proto.sz < sizeof(as_msg)) {
			cf_warning(AS_XDR_CLIENT, "bad proto size %lu", (uint64_t)proto.sz);
			return false;
		}

		const as_msg* m = (as_msg*)(at + sizeof(as_proto));

		void* udata;
		int32_t rv = cf_queue_pop(&conn->in_flight_q, &udata, CF_QUEUE_NOWAIT);

		cf_assert(rv == CF_QUEUE_OK, AS_XDR_CLIENT, "queue underflow");

		as_dc_client_cb(m->result_code, udata);

		at += total_sz;
		conn->responses_sz -= total_sz;
	}

	if (at != conn->responses) {
		memcpy(conn->responses, at, conn->responses_sz);
	}

	conn->last_responded = cf_getms();

	return true;
}


//==========================================================
// Local helpers - authenticate.
//

static void
set_auth_request(connection* conn)
{
	cluster_node* n = conn->node;
	req_buf* auth = &conn->auth;
	const char* user = as_cluster_get_user(n->dc_ix);

	cf_mutex_lock(&n->tend_lock);

	auth->data = create_auth_request(n, user, &auth->sz);
	auth->off = 0;

	cf_mutex_unlock(&n->tend_lock);
}

static uint8_t*
create_auth_request(const cluster_node* n, const char* user, uint32_t* req_sz)
{
	uint32_t user_len;

	uint8_t n_fields = 1;
	uint32_t msg_sz = (uint32_t)(sizeof(as_sec_msg) +
			sizeof(as_sec_msg_field) + n->session_token_sz);

	if (user != NULL) {
		user_len = (uint32_t)strlen(user);

		n_fields++;
		msg_sz += sizeof(as_sec_msg_field) + user_len;
	}

	*req_sz = (uint32_t)sizeof(as_proto) + msg_sz;

	uint8_t* req = cf_malloc(*req_sz);
	as_proto* proto = (as_proto*)req;
	as_sec_msg* m = (as_sec_msg*)proto->body;

	*proto = (as_proto){
			.version = PROTO_VERSION,
			.type = PROTO_TYPE_SECURITY,
			.sz = msg_sz
	};

	as_proto_swap(proto);

	*m = (as_sec_msg){
			.scheme = AS_SEC_MSG_SCHEME,
			.command = AS_SEC_CMD_AUTHENTICATE,
			.n_fields = n_fields
	};

	// No multi-byte values in header - no need to swap.

	uint8_t* at = m->fields;
	as_sec_msg_field* f;

	// User.
	if (user != NULL) {
		f = (as_sec_msg_field*)at;

		f->size = cf_swap_to_be32(1 + user_len);
		f->id = AS_SEC_FIELD_USER;
		memcpy(f->value, user, user_len);

		at += sizeof(as_sec_msg_field) + user_len;
	}

	// Token.
	f = (as_sec_msg_field*)at;

	f->size = cf_swap_to_be32(1 + n->session_token_sz);
	f->id = AS_SEC_FIELD_SESSION_TOKEN;
	memcpy(f->value, n->session_token, n->session_token_sz);

	return req;
}


//==========================================================
// Local helpers - packing records.
//

static uint8_t*
create_write_request(const as_xdr_dc_cfg* dc_cfg, as_storage_rd* rd,
		const write_params* wp, uint32_t* request_sz,
		as_proto_comp_stat* comp_stat)
{
	as_namespace* ns = rd->ns;
	as_record* r = rd->r;
	as_xdr_dc_ns_cfg* dc_ns_cfg = dc_cfg->ns_cfgs[ns->ix];
	bool ship_rec_lut = wp->ship_luts || dc_cfg->connector;

	char* ns_name = dc_ns_cfg->remote_namespace != NULL ?
			dc_ns_cfg->remote_namespace : ns->name;

	uint16_t n_fields;
	size_t msg_sz = size_fields(ns_name, rd, ship_rec_lut, &n_fields);

	if (wp->bin_policy == XDR_BIN_POLICY_NO_BINS) {
		rd->n_bins = 0;
	}

	uint16_t n_selected = 0;
	bool selected[rd->n_bins];

	for (uint16_t i = 0; i < rd->n_bins; i++) {
		as_bin* b = &rd->bins[i];

		if (! ns->single_bin) {
			if (wp->ship_changes) {
				if (b->lut == 0) {
					b->xdr_write = r->xdr_write;
					b->lut = r->last_update_time;
				}
			}
			else {
				// Ignore residual tombstones and metadata - config may have
				// been switched off between record write and XDR read.

				if (as_bin_is_tombstone(b)) {
					as_bin_remove(rd, i--); // changes rd->n_bins
					continue;
				}

				b->xdr_write = 0;
				b->lut = 0;
			}

			if (! select_bin(b, dc_ns_cfg, wp)) {
				selected[i] = false;
				continue;
			}
		}

		msg_sz += sizeof(as_msg_op);

		if (! ns->single_bin) {
			msg_sz += strlen(as_bin_get_name_from_id(ns, b->id));

			if (wp->ship_luts && b->lut != r->last_update_time) {
				msg_sz += sizeof(uint64_t);
			}
		}

		msg_sz += as_bin_particle_client_value_size(b);

		n_selected++;
		selected[i] = true;
	}

	uint16_t n_bins = rd->n_bins;

	if (n_selected == 0 && n_bins != 0) {
		return NULL; // all bins filtered out
	}

	uint8_t policy;

	switch (wp->write_policy) {
	case XDR_WRITE_POLICY_AUTO:
		policy = wp->ship_changes || n_selected != n_bins ?
				0 : AS_MSG_INFO3_CREATE_OR_REPLACE;
		break;
	case XDR_WRITE_POLICY_UPDATE:
		policy = 0;
		break;
	case XDR_WRITE_POLICY_REPLACE:
		policy = AS_MSG_INFO3_CREATE_OR_REPLACE;
		break;
	default:
		cf_crash(AS_XDR_CLIENT, "invalid write-policy %d", wp->write_policy);
		return NULL;
	}

	size_t proto_sz = sizeof(as_proto) + msg_sz;
	as_proto* proto = cf_malloc(proto_sz);

	*proto = (as_proto){
			.version = PROTO_VERSION,
			.type = PROTO_TYPE_AS_MSG,
			.sz = msg_sz
	};

	as_proto_swap(proto);

	as_msg* m = (as_msg*)proto->body;

	*m = (as_msg){
			.header_sz = sizeof(as_msg),

			.info1 = AS_MSG_INFO1_XDR,
			.info2 = AS_MSG_INFO2_WRITE |
					(wp->ship_luts ? AS_MSG_INFO2_DURABLE_DELETE : 0),
			.info3 = policy,

			.generation = plain_generation(r->generation, ns),
			.record_ttl = cf_server_void_time_to_ttl(r->void_time),
			.transaction_ttl = 0,

			.n_fields = n_fields,
			.n_ops = n_selected
	};

	as_msg_swap_header(m);

	uint8_t* buf = add_fields(ns_name, rd, ship_rec_lut, m->data);

	for (uint16_t i = 0; i < n_bins; i++) {
		if (! selected[i]) {
			continue;
		}

		as_bin* b = &rd->bins[i];
		as_msg_op* op = (as_msg_op*)buf;

		*op = (as_msg_op){
				.op = AS_MSG_OP_WRITE,
				.name_sz = (uint8_t)as_bin_memcpy_name(ns, op->name, b)
		};

		op->op_sz = (uint32_t)OP_FIXED_SZ + op->name_sz;

		buf += sizeof(as_msg_op) + op->name_sz;

		if (wp->ship_luts && b->lut != r->last_update_time) {
			op->has_lut = 1;
			op->op_sz += sizeof(uint64_t);

			*(uint64_t*)buf = (uint64_t)b->lut;
			buf += sizeof(uint64_t);
		}

		buf += as_bin_particle_to_client(b, op);

		as_msg_swap_op(op);
	}

	uint8_t* final_proto = (uint8_t*)proto;

	if (dc_ns_cfg->compression_enabled) {
		final_proto = as_proto_compress_alloc_xdr((const uint8_t*)proto,
				&proto_sz, dc_ns_cfg->compression_level,
				dc_ns_cfg->compression_threshold, comp_stat);

		if (final_proto != (uint8_t*)proto) {
			cf_free(proto);
		}
	}

	*request_sz = (uint32_t)proto_sz;

	return final_proto;
}

static uint8_t*
create_delete_request(const as_xdr_dc_cfg* dc_cfg, const as_storage_rd* rd,
		uint32_t* request_sz)
{
	as_namespace* ns = rd->ns;
	as_record* r = rd->r;
	as_xdr_dc_ns_cfg* dc_ns_cfg = dc_cfg->ns_cfgs[ns->ix];
	bool ship_rec_lut = dc_cfg->connector;

	char* ns_name = dc_ns_cfg->remote_namespace ?
			dc_ns_cfg->remote_namespace : ns->name;

	uint16_t n_fields;
	size_t msg_sz = size_fields(ns_name, rd, ship_rec_lut, &n_fields);

	size_t proto_sz = sizeof(as_proto) + msg_sz;
	as_proto* proto = cf_malloc(proto_sz);

	*proto = (as_proto){
			.version = PROTO_VERSION,
			.type = PROTO_TYPE_AS_MSG,
			.sz = msg_sz
	};

	as_proto_swap(proto);

	as_msg* m = (as_msg*)proto->body;

	*m = (as_msg){
			.header_sz = sizeof(as_msg),

			.info1 = AS_MSG_INFO1_XDR,
			.info2 = AS_MSG_INFO2_WRITE | AS_MSG_INFO2_DELETE |
					(r->xdr_tombstone == 1 ? 0 : AS_MSG_INFO2_DURABLE_DELETE),

			.generation = plain_generation(r->generation, ns),
			.transaction_ttl = 0,

			.n_fields = n_fields
	};

	as_msg_swap_header(m);

	add_fields(ns_name, rd, ship_rec_lut, m->data);

	*request_sz = (uint32_t)proto_sz;

	return (uint8_t*)proto;
}

static size_t
size_fields(const char* ns_name, const as_storage_rd* rd, bool ship_lut,
		uint16_t* n_fields)
{
	*n_fields = 2; // always add namespace and digest

	size_t msg_sz = sizeof(as_msg) +
			sizeof(as_msg_field) + strlen(ns_name) +
			sizeof(as_msg_field) + sizeof(cf_digest);

	if (rd->set_name != NULL) {
		(*n_fields)++;
		msg_sz += sizeof(as_msg_field) + rd->set_name_len;
	}

	if (rd->key != NULL) {
		(*n_fields)++;
		msg_sz += sizeof(as_msg_field) + rd->key_size;
	}

	if (ship_lut) {
		(*n_fields)++;
		msg_sz += sizeof(as_msg_field) + sizeof(uint64_t);
	}

	return msg_sz;
}

static uint8_t*
add_fields(const char* ns_name, const as_storage_rd* rd, bool ship_lut,
		uint8_t* buf)
{
	as_record* r = rd->r;

	size_t ns_name_len = strlen(ns_name);
	as_msg_field* mf = (as_msg_field*)buf;

	*mf = (as_msg_field){
			.field_sz = (uint32_t)ns_name_len + 1,
			.type = AS_MSG_FIELD_TYPE_NAMESPACE
	};

	memcpy(mf->data, ns_name, ns_name_len);
	as_msg_swap_field(mf);
	buf += sizeof(as_msg_field) + ns_name_len;

	mf = (as_msg_field*)buf;

	*mf = (as_msg_field){
			.field_sz = sizeof(cf_digest) + 1,
			.type = AS_MSG_FIELD_TYPE_DIGEST_RIPE
	};

	memcpy(mf->data, &r->keyd, sizeof(cf_digest));
	as_msg_swap_field(mf);
	buf += sizeof(as_msg_field) + sizeof(cf_digest);

	if (rd->set_name != NULL) {
		mf = (as_msg_field*)buf;

		*mf = (as_msg_field){
				.field_sz = rd->set_name_len + 1,
				.type = AS_MSG_FIELD_TYPE_SET
		};

		memcpy(mf->data, rd->set_name, rd->set_name_len);
		as_msg_swap_field(mf);
		buf += sizeof(as_msg_field) + rd->set_name_len;
	}

	if (rd->key != NULL) {
		mf = (as_msg_field*)buf;

		*mf = (as_msg_field){
				.field_sz = rd->key_size + 1,
				.type = AS_MSG_FIELD_TYPE_KEY
		};

		memcpy(mf->data, rd->key, rd->key_size);
		as_msg_swap_field(mf);
		buf += sizeof(as_msg_field) + rd->key_size;
	}

	if (ship_lut) {
		mf = (as_msg_field*)buf;

		*mf = (as_msg_field){
				.field_sz = sizeof(uint64_t) + 1,
				.type = AS_MSG_FIELD_TYPE_LUT
		};

		uint64_t lut =
				((uint64_t)g_config.xdr_cfg.src_id << 40) | r->last_update_time;

		*(uint64_t*)mf->data = cf_swap_to_be64(lut);
		as_msg_swap_field(mf);
		buf += sizeof(as_msg_field) + sizeof(uint64_t);
	}

	return buf;
}
