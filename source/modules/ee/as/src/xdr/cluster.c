/*
 * cluster.c
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

#include "xdr/cluster.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aerospike/as_atomic.h"
#include "aerospike/as_password.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_b64.h"
#include "citrusleaf/cf_byte_order.h"
#include "citrusleaf/cf_queue.h"

#include "cf_mutex.h"
#include "cf_str.h"
#include "cf_thread.h"
#include "fetch.h"
#include "log.h"
#include "node.h"
#include "socket.h"
#include "tls.h"
#include "tls_ee.h"
#include "vector.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/proto.h"
#include "base/security.h"
#include "base/security_config.h"
#include "base/security_ee.h"
#include "base/xdr.h"
#include "fabric/hb.h"
#include "fabric/partition.h"
#include "xdr/xdr_ee.h"

//#include "warnings.h" // generates warnings we're living with for now


//==========================================================
// Typedefs & constants.
//

#define MAX_STACK_SZ (16 * 1024)

#define CONNECT_TIMEOUT_MS (3 * 1000)
#define INFO_TIMEOUT_MS (3 * 1000)
#define MAX_REFRESH_FAILURES 5
#define TEND_PERIOD_US (1 * 1000 * 1000)
#define MAX_INFO_RESPONSE_SZ (16 * 1024 * 1024) // ~ pmap for 32 ns * 256 repls
#define MAX_SECURITY_RESPONSE_SZ (1 * 1024)
#define MAX_REQ_SZ (2 * 1024) // used by info and login
#define RENEWAL_MARGIN 60

#define MAX_NODES (AS_CLUSTER_SZ * 2)
#define INVALID_NODE_IX -1

#define MAX_PORT_SZ 6

#define CONNECTOR_MAX_CHECK_FAILS 5
#define CONNECTOR_CHECK_INTERVAL_MS (5L * 1000)

typedef struct ownership_s {
	uint32_t regime;
	int16_t node_ix;
} ownership;

typedef enum {
	NOT_RUNNING,
	RUNNING,
	EXITING,
	EXITING_TO_DELETE
} tend_state;

typedef struct cluster_s {
	as_xdr_dc_cfg* cfg;

	cf_tls_info* tls;

	uint32_t n_used;
	uint32_t n_used_max;
	cluster_node nodes[MAX_NODES]; // maybe > AS_CLUSTER_SZ in flux
	ownership map[AS_NAMESPACE_SZ][AS_PARTITIONS];

	uint32_t tend_cycle;
	tend_state tend_state;

	// Connector node management.

	cf_queue seed_q;
	seed_node_cfg* remove_cfg;
} cluster;

typedef struct seed_change_s {
	bool add;
	seed_node_cfg node_cfg;
} seed_change;

typedef struct endpoint_s {
	char* host;
	char* port;
} endpoint;

typedef struct parse_peers_context_s {
	char default_port[MAX_PORT_SZ];
	cluster_node* peer;
	cf_vector* endpoints;
} parse_peers_context;

typedef bool (*parse_fn)(cluster* c, cluster_node* n, char* response);

typedef struct info_cmd_s {
	const char* name;
	parse_fn parse;
} info_cmd;

typedef enum {
	CMD_NODE,
	CMD_FEATURES,
	CMD_PARTITIONS,
	CMD_PEERS_GENERATION,
	CMD_PARTITION_GENERATION,
	CMD_PEERS_CLEAR_STD,
	CMD_PEERS_CLEAR_ALT,
	CMD_PEERS_TLS_STD,
	CMD_PEERS_TLS_ALT,
	CMD_REPLICAS,
	CMD_REPLICAS_MAX,
	CMD_UNDEF
} info_cmd_id;


//==========================================================
// Globals.
//

static cluster g_clusters[AS_XDR_MAX_DCS];

static __thread uint32_t g_node_rr = 0;


//==========================================================
// Forward declarations.
//

static void clear_map(cluster* c, const cluster_node* n);
static void cluster_disconnected(cluster* c);
static void cluster_deleted(cluster* c);
static void drain_seed_q(cluster* c);

static cluster_node* get_aero_node_optimistic(uint32_t dc_ix, uint32_t ns_ix, uint32_t pid);
static cluster_node* get_connector_node_optimistic(uint32_t dc_ix);

static void* run_tend(void* udata);
static void connect_seeds(cluster* c);
static void handle_connector_seeds(cluster* c);
static bool connect_aero_seed(cluster* c, seed_node_cfg* handoff_cfg);
static bool connect_connector_seed(cluster* c, seed_node_cfg* handoff_cfg);
static void set_endpoints_from_cfg(cluster_node* n, seed_node_cfg* handoff_cfg);
static void refresh_aero_node(cluster* c, cluster_node* n);
static void refresh_connector_node(cluster* c, cluster_node* n);
static bool refresh_connection(cluster* c, cluster_node* n);
static void refresh_session_token(cluster* c, cluster_node* n);
static void refresh_node_peers(cluster* c, cluster_node* n);
static void refresh_node_partitions(cluster* c, cluster_node* n);
static bool should_destroy_aero_node(const cluster* c, const cluster_node* n);
static bool should_destroy_connector_node(cluster* c, const cluster_node* n);

static cluster_node* find_aero_node(cluster* c, cf_node id);
static cluster_node* find_connector_node(cluster* c, seed_node_cfg* node_cfg);
static cluster_node* find_unused_node(cluster* c);
static void init_node(cluster_node* n);
static void activate_node(cluster* c, cluster_node* n);
static void destroy_node(cluster* c, cluster_node* n);
static void free_endpoints(cf_vector* endpoints);

static bool login_node(cluster* c, cluster_node* n);
static uint32_t create_login_request(const as_xdr_dc_cfg* cfg, uint8_t* req);
static bool handle_login_response(cluster_node* n, const uint8_t* resp, uint32_t resp_sz);

static bool info_command(cluster* c, cluster_node* n, uint32_t n_cmds, const info_cmd_id* cmd_ids);
static bool info_transaction(cluster* c, cluster_node* n, uint32_t n_cmds, const info_cmd_id* cmd_ids);
static bool parse_info_response(cluster* c, cluster_node* n, uint32_t n_cmds, const info_cmd_id* cmd_ids, uint8_t* buf);

static bool parse_node(cluster* c, cluster_node* n, char* response);
static bool parse_features(cluster* c, cluster_node* n, char* response);
static bool parse_partitions(cluster* c, cluster_node* n, char* response);
static bool parse_peers_generation(cluster* c, cluster_node* n, char* response);
static bool parse_partition_generation(cluster* c, cluster_node* n, char* response);
static bool parse_peers(cluster* c, cluster_node* n, char* response);
static bool parse_replicas(cluster* c, cluster_node* n, char* response);

static bool parse_peer(cluster* c, char** begin_r, parse_peers_context* ctx);
static cluster_node* create_peer(cluster* c, cf_node id, const char* tls_name);
static bool parse_endpoint(const char* dc_name, char** begin_r, parse_peers_context* ctx);
static void append_peer_endpoint(const char* dc_name, parse_peers_context* ctx, const char* host, const char* port);
static bool parse_replicas_ns(cluster* c, const cluster_node* n, char* begin);
static as_namespace* get_local_namespace(const cluster* c, const char* ns_name);

static bool connect_node_endpoints(cluster* c, cluster_node* n);
static bool connect_node_host_port(cluster* c, cluster_node* n, const char* host, const char* port);
static bool connect_node_addr(cluster* c, cluster_node* n);


//==========================================================
// Info command table.
//

// Keep this array in sync with info_cmd_id enum.
static const info_cmd info_cmds[] = {
		{ "node", parse_node },
		{ "features", parse_features },
		{ "partitions", parse_partitions },
		{ "peers-generation", parse_peers_generation },
		{ "partition-generation", parse_partition_generation },
		{ "peers-clear-std", parse_peers },
		{ "peers-clear-alt", parse_peers },
		{ "peers-tls-std", parse_peers },
		{ "peers-tls-alt", parse_peers },
		{ "replicas", parse_replicas },
		{ "replicas:max=1", parse_replicas }
};

COMPILER_ASSERT(sizeof(info_cmds) / sizeof(info_cmd) == CMD_UNDEF);


//==========================================================
// Inlines & macros.
//

static inline cluster_node*
get_node_optimistic(uint32_t dc_ix, uint32_t ns_ix, uint32_t pid)
{
	return g_clusters[dc_ix].cfg->connector ?
			get_connector_node_optimistic(dc_ix) :
			get_aero_node_optimistic(dc_ix, ns_ix, pid);
}

static inline bool
connect_seed(cluster* c, seed_node_cfg* node_cfg)
{
	return c->cfg->connector ?
			connect_connector_seed(c, node_cfg) :
			connect_aero_seed(c, node_cfg);
}

static inline void
refresh_node(cluster* c, cluster_node* n)
{
	c->cfg->connector ?
			refresh_connector_node(c, n) : refresh_aero_node(c, n);
}

static inline bool
should_destroy_node(cluster* c, const cluster_node* n)
{
	return c->cfg->connector ?
			should_destroy_connector_node(c, n) :
			should_destroy_aero_node(c, n);
}

static inline info_cmd_id
peers_command(const as_xdr_dc_cfg* cfg)
{
	info_cmd_id cmd = cfg->tls_spec == NULL ?
			CMD_PEERS_CLEAR_STD : CMD_PEERS_TLS_STD;

	if (cfg->use_alternate_access_address) {
		cmd = cfg->tls_spec == NULL ? CMD_PEERS_CLEAR_ALT : CMD_PEERS_TLS_ALT;
	}

	return cmd;
}

static inline void
destroy_node_early(cluster* c, cluster_node* n)
{
	n->rc--; // node not used by anyone else - state is NODE_ACTIVE and rc = 1
	destroy_node(c, n);
}

static inline bool
is_exiting(const cluster* c)
{
	return c->tend_state == EXITING || c->tend_state == EXITING_TO_DELETE;
}

static inline bool
is_bit_set(const uint8_t* bitmap, uint32_t pos)
{
	uint32_t byte = pos / 8;
	uint8_t mask = (uint8_t)(0x80 >> (pos % 8));

	return (bitmap[byte] & mask) == mask;
}


//==========================================================
// Public API - enterprise only - cluster lifecycle.
//

bool
as_cluster_reusable(uint32_t dc_ix)
{
	cluster* c = &g_clusters[dc_ix];

	if (c->tend_state == NOT_RUNNING) {
		drain_seed_q(c);
		return true;
	}

	return false;
}

void
as_cluster_create(uint32_t dc_ix, as_xdr_dc_cfg* cfg)
{
	cluster* c = &g_clusters[dc_ix];

	c->cfg = cfg;
	c->n_used = 0;
	c->n_used_max = 0;
	c->tend_state = NOT_RUNNING;

	cf_queue_init(&c->seed_q, sizeof(seed_change), 2, true);

	for (int16_t node_ix = 0; node_ix < MAX_NODES; node_ix++) {
		cluster_node* n = &c->nodes[node_ix];

		cf_mutex_init(&n->lock);
		n->state = NODE_UNUSED;
		n->rc = 0;

		n->dc_ix = dc_ix;
		n->ix = node_ix;

		n->tls_names.n_names = 1;
		n->tls_names.names = &n->tls_name;
	}

	clear_map(c, NULL);
}

bool
as_cluster_delete(uint32_t dc_ix)
{
	cluster* c = &g_clusters[dc_ix];

	switch (c->tend_state) {
	case NOT_RUNNING:
		cluster_deleted(c);
		return true;
	case RUNNING:
		c->tend_state = EXITING_TO_DELETE;
		return true;
	case EXITING:
		cf_warning(AS_XDR_CLIENT, "previous disconnect pending");
		return false; // avoid race with run_tend()
	case EXITING_TO_DELETE:
	default:
		cf_crash(AS_XDR_CLIENT, "bad state %d", c->tend_state);
		return false;
	}
}

bool
as_cluster_connect(uint32_t dc_ix)
{
	cluster* c = &g_clusters[dc_ix];

	switch (c->tend_state) {
	case NOT_RUNNING:
		break; // continue and start tend thread
	case EXITING:
		cf_warning(AS_XDR_CLIENT, "previous disconnect pending");
		return false;
	case RUNNING:
	case EXITING_TO_DELETE:
	default:
		cf_crash(AS_XDR_CLIENT, "bad state %d", c->tend_state);
		break;
	}

	// Config may change, including when DC slot gets reused.

	cf_assert(c->tls == NULL, AS_XDR_CLIENT, "connect found non-null tls");

	as_xdr_dc_cfg* cfg = c->cfg;

	if (cfg->tls_spec != NULL) {
		c->tls = tls_config_xdr_client_context(cfg->tls_spec);

		if (c->tls == NULL) {
			return false;
		}
	}

	// Can't fail after this - may now change state.

	c->tend_state = RUNNING;

	cf_thread_create_transient(run_tend, c);

	return true;
}

void
as_cluster_disconnect(uint32_t dc_ix)
{
	cluster* c = &g_clusters[dc_ix];

	switch (c->tend_state) {
	case RUNNING:
		c->tend_state = EXITING;
		break;
	case NOT_RUNNING:
	case EXITING:
	case EXITING_TO_DELETE:
	default:
		cf_crash(AS_XDR_CLIENT, "bad state %d", c->tend_state);
		break;
	}
}

void
as_cluster_info(uint32_t dc_ix, cluster_info* cinfo)
{
	cluster* c = &g_clusters[dc_ix];

	cinfo->n_nodes = c->n_used;
}


//==========================================================
// Public API - enterprise only - record shipping.
//

cluster_node*
as_cluster_get_node_optimistic(uint32_t dc_ix, uint32_t ns_ix, uint32_t pid)
{
	return get_node_optimistic(dc_ix, ns_ix, pid);
}

bool
as_cluster_reserve_node(cluster_node* n)
{
	cf_mutex_lock(&n->lock);

	if (n->state != NODE_ACTIVE) {
		cf_mutex_unlock(&n->lock);
		return false;
	}

	n->rc++;

	cf_mutex_unlock(&n->lock);

	return true;
}

void
as_cluster_release_node(cluster_node* n)
{
	cf_mutex_lock(&n->lock);

	cf_assert(NODE_IS_LIVE(n), AS_XDR_CLIENT, "releasing node %s in state %d",
			n->connected_to, n->state);

	n->rc--;

	cf_assert(n->rc >= 0, AS_XDR_CLIENT, "ref count underflow %d", n->rc);

	if (n->rc > 0) {
		cf_mutex_unlock(&n->lock);
		return;
	}

	cf_assert(n->state == NODE_DRAINING, AS_XDR_CLIENT,
			"drained active node %s", n->connected_to);

	n->state = NODE_DRAINED; // signal tend thread to destroy

	cf_mutex_unlock(&n->lock);
}

const char*
as_cluster_get_dc_name(uint32_t dc_ix)
{
	return g_clusters[dc_ix].cfg->name;
}

cf_tls_info*
as_cluster_get_tls_info(uint32_t dc_ix)
{
	return g_clusters[dc_ix].tls;
}

const char*
as_cluster_get_user(uint32_t dc_ix)
{
	as_xdr_dc_cfg* cfg = g_clusters[dc_ix].cfg;

	return cfg->auth_mode == XDR_AUTH_PKI ? NULL : cfg->auth_user;
}

// TODO - move to proto ?
bool
validate_and_swap_proto(as_proto* proto, uint8_t type, uint64_t max_sz,
		const char* tag)
{
	uint64_t original = *(uint64_t*)proto;

	if (proto->version != PROTO_VERSION) {
		cf_warning(AS_XDR_CLIENT, "bad proto version %u - 0x%016lx %s",
				proto->version, original, tag == NULL ? "" : tag);
		return false;
	}

	if (proto->type != type) {
		cf_warning(AS_XDR_CLIENT, "bad proto type - expected %u, got %u - 0x%016lx %s",
				type, proto->type, original, tag == NULL ? "" : tag);
		return false;
	}

	as_proto_swap(proto);

	if (proto->sz > max_sz) {
		cf_warning(AS_XDR_CLIENT, "bad proto size %lu - 0x%016lx %s",
				(uint64_t)proto->sz, original, tag == NULL ? "" : tag);
		return false;
	}

	return true;
}


//==========================================================
// Public API - enterprise only - node management.
//

void
as_cluster_queue_seed(uint32_t dc_ix, bool add, const char* host,
		const char* port, const char* tls_name)
{
	cluster* c = &g_clusters[dc_ix];

	if (! c->cfg->connector) {
		return;
	}

	seed_change ele = {
			.add = add,
			.node_cfg = {
					.host = cf_strdup(host),
					.port = cf_strdup(port),
					.tls_name = tls_name != NULL ? cf_strdup(tls_name) : NULL
			}
	};

	cf_queue_push(&c->seed_q, &ele);
}


//==========================================================
// Local helpers - cluster lifecycle.
//

static void
clear_map(cluster* c, const cluster_node* n)
{
	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
			ownership* owner = &c->map[ns_ix][pid];

			if (n == NULL || owner->node_ix == n->ix) {
				owner->regime = 0;
				owner->node_ix = INVALID_NODE_IX;
			}
		}
	}
}

static void
cluster_disconnected(cluster* c)
{
	clear_map(c, NULL); // don't use destroyed nodes on cluster re-use

	// Always set when connecting - config may change.
	if (c->tls != NULL) {
 		tls_info_free(c->tls);
 		c->tls = NULL;
	}

	// Always drain seed q as this DC may be 'connector' type earlier.
	drain_seed_q(c);

	cf_info(AS_XDR_CLIENT, "DC %s disconnected", c->cfg->name);
}

static void
cluster_deleted(cluster* c)
{
	cf_info(AS_XDR_CLIENT, "DC %s deleted", c->cfg->name);
}

static void
drain_seed_q(cluster* c)
{
	seed_change ele;

	while (cf_queue_pop(&c->seed_q, &ele, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
		seed_node_cfg_cleanup(&ele.node_cfg);
	}
}


//==========================================================
// Local helpers - record shipping.
//

static cluster_node*
get_aero_node_optimistic(uint32_t dc_ix, uint32_t ns_ix, uint32_t pid)
{
	cluster* c = &g_clusters[dc_ix];
	int16_t node_ix = c->map[ns_ix][pid].node_ix;

	if (node_ix == INVALID_NODE_IX) {
		return NULL;
	}

	cluster_node* n = &c->nodes[node_ix];

	return n->state == NODE_ACTIVE ? n : NULL;
}

static cluster_node*
get_connector_node_optimistic(uint32_t dc_ix)
{
	cluster* c = &g_clusters[dc_ix];

	if (c->n_used == 0) {
		return NULL;
	}

	uint32_t n_used_max = as_load_uint32(&c->n_used_max);

	for (uint32_t i = 0; i < n_used_max; i++) {
		uint32_t ix = (i + g_node_rr) % n_used_max;
		cluster_node* n = &c->nodes[ix];

		if (n->state != NODE_ACTIVE || // includes NODE_UNUSED
				n->n_checks_failed > CONNECTOR_MAX_CHECK_FAILS) {
			continue;
		}

		g_node_rr = ix + 1;

		return n;
	}

	return NULL;
}


//==========================================================
// Local helpers - tend loop.
//

static void*
run_tend(void* udata)
{
	cluster* c = (cluster*)udata;

	while (true) {
		uint64_t start = cf_getus();
		bool exiting = is_exiting(c);

		c->tend_cycle++;

		if (c->n_used == 0) {
			if (exiting) {
				break;
			}

			connect_seeds(c);
		}

		if (! exiting && c->cfg->connector) {
			// Handle pending changes - add/remove one per tend cycle.
			handle_connector_seeds(c);
		}

		// Use c->n_used_max since c->n_used may decrease during loop.
		for (uint32_t ix = 0; ix < c->n_used_max; ix++) {
			cluster_node* n = &c->nodes[ix];

			if (n->state == NODE_UNUSED || n->state == NODE_DRAINING) {
				continue;
			}

			if (n->state == NODE_DRAINED) {
				destroy_node(c, n);
				continue;
			}

			// Node is active.

			refresh_node(c, n);

			if (exiting || should_destroy_node(c, n)) {
				cf_mutex_lock(&n->lock);

				n->state = NODE_DRAINING;

				cf_mutex_unlock(&n->lock);

				as_cluster_release_node(n);
				continue;
			}
		}

		cf_assert(c->remove_cfg == NULL, AS_XDR_CLIENT, "remove seed failed");

		uint32_t lap_us = (uint32_t)(cf_getus() - start);

		if (lap_us < TEND_PERIOD_US) {
			usleep(TEND_PERIOD_US - lap_us);
		}
	}

	cluster_disconnected(c);

	if (c->tend_state == EXITING_TO_DELETE) {
		cluster_deleted(c);
	}

	c->tend_state = NOT_RUNNING;

	return NULL;
}

static void
connect_seeds(cluster* c)
{
	cf_info(AS_XDR_CLIENT, "starting with seed nodes for %s", c->cfg->name);

	cf_mutex_lock(&c->cfg->seed_lock);

	cf_vector* nv = &c->cfg->seed_nodes;
	uint32_t sz = cf_vector_size(nv);

	seed_node_cfg handoff_cfgs[sz];

	for (uint32_t i = 0; i < sz; i++) {
		seed_node_cfg node_cfg;

		cf_vector_get(nv, i, &node_cfg);

		handoff_cfgs[i] = (seed_node_cfg){
				.host = cf_strdup(node_cfg.host),
				.port = cf_strdup(node_cfg.port),
				.tls_name = node_cfg.tls_name == NULL ?
						NULL : cf_strdup(node_cfg.tls_name)
		};
	}

	cf_mutex_unlock(&c->cfg->seed_lock);

	for (uint32_t i = 0; i < sz; i++) {
		if (connect_seed(c, &handoff_cfgs[i])) {
			for (uint32_t j = i + 1; j < sz; j++) {
				seed_node_cfg_cleanup(&handoff_cfgs[j]);
			}

			break;
		}
	}
}

static void
handle_connector_seeds(cluster* c)
{
	seed_change ele;

	// One at a time - avoid races adding & removing same seed.
	if (cf_queue_pop(&c->seed_q, &ele, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
		if (ele.add) {
			connect_connector_seed(c, &ele.node_cfg);
		}
		else {
			c->remove_cfg = cf_malloc(sizeof(seed_node_cfg));
			*c->remove_cfg = ele.node_cfg;
		}
	}
}

static bool
connect_aero_seed(cluster* c, seed_node_cfg* handoff_cfg)
{
	cluster_node* n = find_unused_node(c);

	init_node(n);

	if (handoff_cfg->tls_name != NULL) {
		n->tls_name = handoff_cfg->tls_name;
		handoff_cfg->tls_name = NULL;
	}

	if (! connect_node_host_port(c, n, handoff_cfg->host, handoff_cfg->port)) {
		cf_warning(AS_XDR_CLIENT, "failed to connect to %s %s:%s", c->cfg->name,
				handoff_cfg->host, handoff_cfg->port);
		if (n->tls_name != NULL) {
			cf_free(n->tls_name); // can't destroy node until activated
		}

		seed_node_cfg_cleanup(handoff_cfg);
		return false;
	}

	activate_node(c, n); // before info cmd - prevent peers from using this slot

	info_cmd_id cmd_peers = peers_command(c->cfg);

	info_cmd_id cmds[] = {
			CMD_NODE,
			CMD_FEATURES,
			CMD_PARTITIONS,
			cmd_peers
	};

	if (! info_command(c, n, sizeof(cmds) / sizeof(info_cmd_id), cmds)) {
		destroy_node_early(c, n);
		seed_node_cfg_cleanup(handoff_cfg);
		return false;
	}

	if (! n->features_compatible) {
		cf_warning(AS_XDR_CLIENT, "incompatible node %s %s", c->cfg->name,
				n->connected_to);
		destroy_node_early(c, n);
		seed_node_cfg_cleanup(handoff_cfg);
		return false;
	}

	if (c->n_used != 1) {
		// Found peers - destroy this node (it could be a 'forwarder', e.g. a
		// load balancer). Peers will add it back later in this tend cycle.
		destroy_node_early(c, n);
		seed_node_cfg_cleanup(handoff_cfg);
	}
	else {
		set_endpoints_from_cfg(n, handoff_cfg); // won't get from peers
	}

	return true;
}

static bool
connect_connector_seed(cluster* c, seed_node_cfg* handoff_cfg)
{
	// Dynamic config may re-attempt to connect a connected node via DC config.
	if (find_connector_node(c, handoff_cfg) != NULL) {
		cf_free(handoff_cfg->host);
		cf_free(handoff_cfg->port);

		if (handoff_cfg->tls_name != NULL) {
			cf_free(handoff_cfg->tls_name);
		}

		return false;
	}

	cluster_node* n = find_unused_node(c);

	init_node(n);

	if (handoff_cfg->tls_name != NULL) {
		n->tls_name = handoff_cfg->tls_name;
		handoff_cfg->tls_name = NULL;
	}

	if (! connect_node_host_port(c, n, handoff_cfg->host, handoff_cfg->port)) {
		cf_warning(AS_XDR_CLIENT, "failed to connect to %s %s:%s", c->cfg->name,
				handoff_cfg->host, handoff_cfg->port);
		// Note - activate node anyway to try restoring healthy status.
	}

	activate_node(c, n);

	set_endpoints_from_cfg(n, handoff_cfg); // won't get from peers

	// Connector DCs do not honor info commands.
	n->features_compatible = true;

	return false; // not an error - caller continues to process other seeds
}

static void
set_endpoints_from_cfg(cluster_node* n, seed_node_cfg* handoff_cfg)
{
	n->endpoints = cf_vector_create(sizeof(endpoint), 4, 0);

	endpoint ep = {
			.host = handoff_cfg->host,
			.port = handoff_cfg->port
	};

	cf_vector_append(n->endpoints, &ep);
}

static void
refresh_aero_node(cluster* c, cluster_node* n)
{
	if (! refresh_connection(c, n)) {
		n->peers_generation = (uint32_t)-1;
		n->partition_generation = (uint32_t)-1;
		n->refresh_failures++;
		return;
	}

	refresh_session_token(c, n);

	static info_cmd_id cmds[] = {
			CMD_PEERS_GENERATION,
			CMD_PARTITION_GENERATION,
			CMD_FEATURES
	};

	uint32_t n_commands = n->features_checked ? 2 : 3;

	if (! info_command(c, n, n_commands, cmds)) {
		n->peers_generation = (uint32_t)-1;
		n->partition_generation = (uint32_t)-1;
		n->refresh_failures++;
		return;
	}

	n->refresh_failures = 0;

	if (n->peers_generation_latest != n->peers_generation) {
		refresh_node_peers(c, n);
	}

	// TODO - handle single rogue node owning all partitions ???

	if (n->partition_generation_latest != n->partition_generation) {
		refresh_node_partitions(c, n);
	}
}

static void
refresh_connector_node(cluster* c, cluster_node* n)
{
	uint64_t now = cf_getms();

	if (now - n->last_check_ms < CONNECTOR_CHECK_INTERVAL_MS) {
		return;
	}

	n->last_check_ms = now;

	// Try with previously used address first, then with full resolution.
	if (connect_node_addr(c, n) || connect_node_endpoints(c, n)) {
		n->n_checks_failed = 0;

		cf_socket* sock = &n->tend_sock;

		cf_socket_close(sock);
		cf_socket_term(sock);

		return;
	}

	if (++n->n_checks_failed < CONNECTOR_MAX_CHECK_FAILS) {
		return;
	}

	if (n->n_checks_failed % CONNECTOR_MAX_CHECK_FAILS == 0) {
		cf_warning(AS_XDR_CLIENT, "%s %s failed check %u times", c->cfg->name,
				n->connected_to, n->n_checks_failed);
	}
}

static bool
refresh_connection(cluster* c, cluster_node* n)
{
	if (cf_socket_exists(&n->tend_sock)) {
		return true;
	}

	// Try with previously used address first, then with full resolution.
	if (! connect_node_addr(c, n) && ! connect_node_endpoints(c, n)) {
		cf_ticker_warning(AS_XDR_CLIENT, "failed to connect to %s %s",
				c->cfg->name, n->connected_to);
		return false;
	}

	return true;
}

static void
refresh_session_token(cluster* c, cluster_node* n)
{
	cf_socket* sock = &n->tend_sock;

	if (c->cfg->auth_mode == XDR_AUTH_NONE ||
			! cf_socket_exists(sock) ||
			n->session_renewal == 0 ||
			cf_get_seconds() < n->session_renewal) {
		return;
	}

	cf_detail(AS_XDR_CLIENT, "refreshing session token for %s %s", c->cfg->name,
				n->connected_to);

	if (! login_node(c, n)) {
		cf_socket_close(sock);
		cf_socket_term(sock);
	}
}

static void
refresh_node_peers(cluster* c, cluster_node* n)
{
	info_cmd_id cmd_peers = peers_command(c->cfg);

	info_command(c, n, 1, &cmd_peers);
}

static void
refresh_node_partitions(cluster* c, cluster_node* n)
{
	info_cmd_id cmds[] = {
			CMD_PARTITION_GENERATION,
			n->use_replicas_max ? CMD_REPLICAS_MAX : CMD_REPLICAS
	};

	info_command(c, n, sizeof(cmds) / sizeof(info_cmd_id), cmds);
}

static bool
should_destroy_aero_node(const cluster* c, const cluster_node* n)
{
	if (n->refresh_failures < MAX_REFRESH_FAILURES) {
		return false;
	}

	if (c->n_used == 1) {
		return true; // no other node to replace single node in partition map
	}

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
			if (c->map[ns_ix][pid].node_ix == n->ix) {
				return false;
			}
		}
	}

	return true;
}

static bool
should_destroy_connector_node(cluster* c, const cluster_node* n)
{
	seed_node_cfg* cfg = c->remove_cfg;

	if (cfg == NULL) {
		return false;
	}

	endpoint ep;

	cf_vector_get(n->endpoints, 0, &ep);

	if (strcmp(ep.host, cfg->host) == 0 && strcmp(ep.port, cfg->port) == 0) {
		cf_free(cfg->host);
		cf_free(cfg->port);

		if (cfg->tls_name != NULL) {
			cf_free(cfg->tls_name);
		}

		cf_free(cfg);
		c->remove_cfg = NULL;

		return true;
	}

	return false;
}


//==========================================================
// Local helpers - node lifecycle.
//

static cluster_node*
find_aero_node(cluster* c, cf_node id)
{
	for (uint32_t ix = 0; ix < c->n_used_max; ix++) {
		cluster_node* n = &c->nodes[ix];

		if (n->state == NODE_UNUSED) {
			continue;
		}

		if (n->id == id) {
			return n;
		}
	}

	return NULL;
}

static cluster_node*
find_connector_node(cluster* c, seed_node_cfg* node_cfg)
{
	for (uint32_t ix = 0; ix < c->n_used_max; ix++) {
		cluster_node* n = &c->nodes[ix];

		if (n->state == NODE_UNUSED) {
			continue;
		}

		endpoint ep;

		cf_vector_get(n->endpoints, 0, &ep);

		if (strcmp(ep.host, node_cfg->host) == 0 &&
				strcmp(ep.port, node_cfg->port) == 0) {
			return n;
		}
	}

	return NULL;
}

static cluster_node*
find_unused_node(cluster* c)
{
	for (uint32_t ix = 0; ix < MAX_NODES; ix++) {
		cluster_node* n = &c->nodes[ix];

		// Note - no race for state change - called only from tend thread.
		if (n->state == NODE_UNUSED) {
			return n;
		}
	}

	// Should never get here.
	cf_crash(AS_XDR_CLIENT, "failed to find free slot for new node");

	return NULL;
}

static void
init_node(cluster_node* n)
{
	n->session_token = NULL;
	n->session_token_sz = 0;
	n->session_renewal = 0;
	n->id = 0;
	n->features_checked = false;
	n->features_compatible = false;
	n->use_replicas_max = false;
	n->tls_name = NULL;
	n->endpoints = NULL;
	n->endpoints_tend_cycle = 0;
	cf_socket_init(&n->tend_sock);
	cf_sock_cfg_init(&n->tend_sock_cfg, CF_SOCK_OWNER_XDR_CLIENT);
	n->refresh_failures = 0;
	n->peers_generation = (uint32_t)-1;
	n->partition_generation = (uint32_t)-1;

	n->n_checks_failed = 0;
	n->last_check_ms = 0;
}

static void
activate_node(cluster* c, cluster_node* n)
{
	cf_mutex_lock(&n->lock);

	n->rc = 1;
	n->state = NODE_ACTIVE;

	cf_mutex_unlock(&n->lock);

	c->n_used++;

	if (c->n_used > c->n_used_max) {
		c->n_used_max = c->n_used;
	}

	cf_detail(AS_XDR_CLIENT, "activated %s %lx %u", c->cfg->name, n->id,
			c->n_used);
}

static void
destroy_node(cluster* c, cluster_node* n)
{
	cf_assert(n->rc == 0, AS_XDR_CLIENT, "destroying node with rc %d", n->rc);

	clear_map(c, n);

	if (n->session_token != NULL) {
		cf_free(n->session_token);
	}

	if (cf_socket_exists(&n->tend_sock)) {
		cf_socket_close(&n->tend_sock);
		cf_socket_term(&n->tend_sock);
	}

	if (n->endpoints != NULL) {
		free_endpoints(n->endpoints);
	}

	if (n->tls_name != NULL) {
		cf_free(n->tls_name);
	}

	n->state = NODE_UNUSED;

	c->n_used--;

	cf_detail(AS_XDR_CLIENT, "destroyed %s %s %u", c->cfg->name,
			n->connected_to, c->n_used);
}

static void
free_endpoints(cf_vector* endpoints)
{
	uint32_t sz = cf_vector_size(endpoints);

	for (uint32_t i = 0; i < sz; i++) {
		endpoint ep;

		cf_vector_get(endpoints, i, &ep);
		cf_free(ep.host);
		cf_free(ep.port);
	}

	cf_vector_destroy(endpoints);
}


//==========================================================
// Local helpers - login.
//

static bool
login_node(cluster* c, cluster_node* n)
{
	as_xdr_dc_cfg* cfg = c->cfg;
	uint8_t req[MAX_REQ_SZ]; // TODO - not enough for kerberos

	uint32_t req_sz = create_login_request(cfg, req);

	if (req_sz == 0) {
		return false;
	}

	cf_socket* sock = &n->tend_sock;

	if (cf_socket_send_all(sock, req, req_sz, MSG_NOSIGNAL,
			INFO_TIMEOUT_MS) != 0) {
		cf_warning(AS_XDR_CLIENT, "error sending to node %s - %s",
				n->connected_to, cf_strerror(errno));
		return false;
	}

	as_proto proto;

	if (cf_socket_recv_all(sock, &proto, sizeof(as_proto), 0,
			INFO_TIMEOUT_MS) != 0) {
		cf_warning(AS_XDR_CLIENT, "error receiving from node %s - %s",
				n->connected_to, cf_strerror(errno));
		return false;
	}

	if (! validate_and_swap_proto(&proto, PROTO_TYPE_SECURITY,
			MAX_SECURITY_RESPONSE_SZ, n->connected_to)) {
		return false;
	}

	uint8_t resp[proto.sz];

	if (cf_socket_recv_all(sock, resp, proto.sz, 0, INFO_TIMEOUT_MS) != 0) {
		cf_warning(AS_XDR_CLIENT, "error receiving from node %s - %s",
				n->connected_to, cf_strerror(errno));
		return false;
	}

	return handle_login_response(n, resp, (uint32_t)proto.sz);
}

static uint32_t
create_login_request(const as_xdr_dc_cfg* cfg, uint8_t* req)
{
	bool send_user;
	bool send_pw_hash;
	bool send_pw_clear;
	uint8_t n_fields;

	switch (cfg->auth_mode) {
	case XDR_AUTH_INTERNAL:
		send_user = true;
		send_pw_hash = true;
		send_pw_clear = false;
		n_fields = 2;
		break;
	case XDR_AUTH_EXTERNAL:
	case XDR_AUTH_EXTERNAL_INSECURE:
		send_user = true;
		send_pw_hash = true; // only a dummy to satisfy 4.7-.
		send_pw_clear = true;
		n_fields = 3;
		break;
	case XDR_AUTH_PKI:
		send_user = false;
		send_pw_hash = false;
		send_pw_clear = false;
		n_fields = 0;
		break;
	default:
		cf_crash(AS_XDR, "unsupported authentication mode");
		return 0;
	}

	as_proto* proto = (as_proto*)req;
	as_sec_msg* m = (as_sec_msg*)proto->body;

	*m = (as_sec_msg){
			.scheme = AS_SEC_MSG_SCHEME,
			.command = AS_SEC_CMD_LOGIN,
			.n_fields = n_fields
	};

	// No multi-byte values in header - no need to swap.

	uint8_t* at = m->fields;
	as_sec_msg_field* f = (as_sec_msg_field*)at;

	if (send_user) {
		uint32_t len = (uint32_t)strlen(cfg->auth_user);

		f->size = cf_swap_to_be32(1 + len);
		f->id = AS_SEC_FIELD_USER;
		memcpy(f->value, cfg->auth_user, len);

		at += sizeof(as_sec_msg_field) + len;
		f = (as_sec_msg_field*)at;
	}

	if (send_pw_hash || send_pw_clear) {
		if (cfg->auth_password_file == NULL) {
			cf_warning(AS_XDR, "DC %s has no 'auth-password-file'", cfg->name);
			return 0;
		}

		char* pw = cf_fetch_string(cfg->auth_password_file);

		if (pw == NULL) {
			cf_warning(AS_XDR, "DC %s login can't read password", cfg->name);
			return 0;
		}

		if (send_pw_hash) {
			char pw_hash[AS_PASSWORD_HASH_SIZE];

			as_password_get_constant_hash(pw, pw_hash);

			f->size = cf_swap_to_be32(1 + PASSWORD_LEN);
			f->id = AS_SEC_FIELD_CREDENTIAL;
			memcpy(f->value, pw_hash, PASSWORD_LEN);

			at += sizeof(as_sec_msg_field) + PASSWORD_LEN;
			f = (as_sec_msg_field*)at;
		}

		if (send_pw_clear) {
			uint32_t len = (uint32_t)strlen(pw);

			f->size = cf_swap_to_be32(1 + len);
			f->id = AS_SEC_FIELD_CLEAR_PASSWORD;
			memcpy(f->value, pw, len);

			at += sizeof(as_sec_msg_field) + len;
			f = (as_sec_msg_field*)at;
		}

		cf_free(pw);
	}

	uint32_t req_sz = (uint32_t)(at - req);

	*proto = (as_proto){
			.version = PROTO_VERSION,
			.type = PROTO_TYPE_SECURITY,
			.sz = req_sz - sizeof(as_proto)
	};

	as_proto_swap(proto);

	return req_sz;
}

static bool
handle_login_response(cluster_node* n, const uint8_t* resp, uint32_t resp_sz)
{
	if (resp_sz < sizeof(as_sec_msg)) {
		cf_warning(AS_XDR_CLIENT, "incomplete as_sec_msg");
		return false;
	}

	const as_sec_msg* m = (const as_sec_msg*)resp;

	if (m->scheme != AS_SEC_MSG_SCHEME) {
		cf_warning(AS_XDR_CLIENT, "bad security scheme: %d", m->scheme);
		return false;
	}

	if (m->command != 0) {
		cf_warning(AS_XDR_CLIENT, "bad security command: %d", m->command);
		return false;
	}

	if (m->result == AS_SEC_ERR_NOT_CONFIGURED) {
		if (n->session_token != NULL) {
			cf_free(n->session_token);
			n->session_token = NULL;
		}

		return true;
	}

	if (m->result != AS_OK) {
		cf_ticker_warning(AS_XDR_CLIENT, "login failed: %d", m->result);
		return false;
	}

	const uint8_t* at = m->fields;
	const uint8_t* end = resp + resp_sz;

	const uint8_t* session_token = NULL;
	uint32_t session_token_sz = 0;
	uint32_t session_ttl = 0;

	for (uint8_t i = 0; i < m->n_fields; i++) {
		if (at + sizeof(as_sec_msg_field) > end) {
			cf_warning(AS_XDR_CLIENT, "incomplete as_sec_msg_field");
			return false;
		}

		const as_sec_msg_field* f = (const as_sec_msg_field*)at;
		uint32_t sz = cf_swap_from_be32(f->size) - 1;

		at = f->value + sz;

		if (at > end) {
			cf_warning(AS_XDR_CLIENT, "incomplete security message field");
			return false;
		}

		switch (f->id) {
		case AS_SEC_FIELD_SESSION_TOKEN:
			session_token = f->value;
			session_token_sz = sz;
			break;
		case AS_SEC_FIELD_SESSION_TTL:
			session_ttl = cf_swap_from_be32(*(uint32_t*)f->value);
			break;
		}
	}

	if (at != end) {
		cf_warning(AS_XDR_CLIENT, "extra bytes follow fields");
		return false;
	}

	if (session_token == NULL) {
		cf_warning(AS_XDR_CLIENT, "no session token");
		return false;
	}

	if (session_ttl != 0 && (session_ttl < SECURITY_SESSION_TTL_MIN ||
			session_ttl > SECURITY_SESSION_TTL_MAX)) {
		cf_warning(AS_XDR_CLIENT, "bad session ttl - %u", session_ttl);
		return false;
	}

	cf_mutex_lock(&n->tend_lock);

	if (n->session_token != NULL) {
		cf_free(n->session_token);
	}

	n->session_token = cf_malloc(session_token_sz);
	memcpy(n->session_token, session_token, session_token_sz);
	n->session_token_sz = session_token_sz;
	n->session_renewal = session_ttl == 0 ?
			0 : (uint32_t)cf_get_seconds() + session_ttl - RENEWAL_MARGIN;

	cf_mutex_unlock(&n->tend_lock);

	return true;
}


//==========================================================
// Local helpers - info request.
//

static bool
info_command(cluster* c, cluster_node* n, uint32_t n_cmds,
		const info_cmd_id* cmd_ids)
{
	if (! cf_socket_exists(&n->tend_sock)) {
		return false;
	}

	if (info_transaction(c, n, n_cmds, cmd_ids)) {
		return true;
	}

	cf_socket_close(&n->tend_sock);
	cf_socket_term(&n->tend_sock);

	return false;
}

static bool
info_transaction(cluster* c, cluster_node* n, uint32_t n_cmds,
		const info_cmd_id* cmd_ids)
{
	char req[MAX_REQ_SZ];
	as_proto* proto = (as_proto*)req;
	uint64_t req_sz = sizeof(as_proto);

	for (uint32_t i = 0; i < n_cmds; i++) {
		const info_cmd* cmd = &info_cmds[cmd_ids[i]];
		req_sz += (uint64_t)sprintf(&req[req_sz], "%s\n", cmd->name);
	}

	*proto = (as_proto){
			.version = PROTO_VERSION,
			.type = PROTO_TYPE_INFO,
			.sz = req_sz - sizeof(as_proto)
	};

	as_proto_swap(proto);

	cf_socket* sock = &n->tend_sock;

	if (cf_socket_send_all(sock, req, req_sz, MSG_NOSIGNAL,
			INFO_TIMEOUT_MS) != 0) {
		cf_warning(AS_XDR_CLIENT, "error sending to node %s - %s",
				n->connected_to, cf_strerror(errno));
		return false;
	}

	if (cf_socket_recv_all(sock, proto, sizeof(as_proto), 0,
			INFO_TIMEOUT_MS) != 0) {
		cf_warning(AS_XDR_CLIENT, "error receiving from node %s - %s",
				n->connected_to, cf_strerror(errno));
		return false;
	}

	if (! validate_and_swap_proto(proto, PROTO_TYPE_INFO, MAX_INFO_RESPONSE_SZ,
			n->connected_to)) {
		return false;
	}

	uint8_t stack_resp[MAX_STACK_SZ + 1];
	uint8_t* resp = proto->sz > MAX_STACK_SZ ?
			cf_malloc(proto->sz + 1) : stack_resp;

	if (cf_socket_recv_all(sock, resp, proto->sz, 0, INFO_TIMEOUT_MS) != 0) {
		cf_warning(AS_XDR_CLIENT, "error receiving from node %s - %s",
				n->connected_to, cf_strerror(errno));

		if (resp != stack_resp) {
			cf_free(resp);
		}

		return false;
	}

	resp[proto->sz] = '\0';

	bool rv = parse_info_response(c, n, n_cmds, cmd_ids, resp);

	if (resp != stack_resp) {
		cf_free(resp);
	}

	return rv;
}

// Info response format: cmd1\tresp1\ncmd2\tresp2\n...
static bool
parse_info_response(cluster* c, cluster_node* n, uint32_t n_cmds,
		const info_cmd_id* cmd_ids, uint8_t* buf)
{
	uint32_t cmd_ix = 0;
	char* save_ptr = NULL;

	char* tok = strtok_r((char*)buf, "\t", &save_ptr);

	while (tok != NULL) {
		// Check command name token.
		if (cmd_ix >= n_cmds) {
			cf_warning(AS_XDR_CLIENT, "from %s - got extra response '%s'",
					n->connected_to, tok);
			return false;
		}

		const info_cmd* cmd = &info_cmds[cmd_ids[cmd_ix]];

		if (strcmp(tok, cmd->name) != 0) {
			cf_warning(AS_XDR_CLIENT, "from %s - expected command '%s', got '%s'",
					n->connected_to, cmd->name, tok);
			return false;
		}

		// Parse response token.
		tok = strtok_r(NULL, "\n", &save_ptr);

		if (tok == NULL) {
			cf_warning(AS_XDR_CLIENT, "from %s - no response for command '%s'",
					n->connected_to, cmd->name);
			return false;
		}

		if (! cmd->parse(c, n, tok)) {
			cf_warning(AS_XDR_CLIENT, "from %s - bad response for command '%s' - %s",
					n->connected_to, cmd->name, tok);
			return false;
		}

		// Prepare for next command.
		cmd_ix++;
		tok = strtok_r(NULL, "\t", &save_ptr);
	}

	if (cmd_ix != n_cmds) {
		cf_warning(AS_XDR_CLIENT, "from %s - expected responses %u, got %u",
				n->connected_to, n_cmds, cmd_ix);
		return false;
	}

	return true;
}


//==========================================================
// Local helpers - info callbacks.
//

static bool
parse_node(cluster* c, cluster_node* n, char* response)
{
	(void)c;

	if (cf_strtoul_x64(response, &n->id) < 0 || n->id == 0) {
		cf_warning(AS_XDR_CLIENT, "ignoring invalid node-id %s", response);
		return false;
	}

	return true;
}

static bool
parse_features(cluster* c, cluster_node* n, char* response)
{
	(void)c;

	n->features_checked = true;

	n->features_compatible =
			strstr(response, ";peers;") != NULL &&
			strstr(response, ";pipelining;") != NULL &&
			strstr(response, ";replicas;") != NULL;

	n->use_replicas_max = strstr(response, ";replicas-max;") != NULL;

	return true;
}

static bool
parse_partitions(cluster* c, cluster_node* n, char* response)
{
	(void)c;
	(void)n;

	uint32_t n_partitions;

	if (cf_strtoul_u32(response, &n_partitions) < 0 ||
			n_partitions != AS_PARTITIONS) {
		cf_warning(AS_XDR_CLIENT, "invalid partition count %s", response);
		return false;
	}

	return true;
}

static bool
parse_peers_generation(cluster* c, cluster_node* n, char* response)
{
	(void)c;

	uint64_t peers_generation;

	if (cf_strtoul_u64(response, &peers_generation) < 0) {
		cf_warning(AS_XDR_CLIENT, "invalid peers generation %s", response);
		return false;
	}

	n->peers_generation_latest = peers_generation;

	return true;

}

static bool
parse_partition_generation(cluster* c, cluster_node* n, char* response)
{
	(void)c;

	int32_t partition_generation;

	if (cf_strtol_i32(response, &partition_generation) < 0) {
		cf_warning(AS_XDR_CLIENT, "invalid partition generation %s", response);
		return false;
	}

	n->partition_generation_latest = (uint32_t)partition_generation;

	return true;
}

// Output spec - {generation}, {default-port},
// [
// 		[{node-id-1}, {TLS-name-1}, [endpoint-1.1, endpoint-1.2]],
//		[{node-id-2}, {TLS-name-2}, [endpoint-2.1, endpoint-2.2, endpoint-2.3]],
//		...
// ]
static bool
parse_peers(cluster* c, cluster_node* n, char* response)
{
	// Peers generation.
	char* begin = response;
	char* end = strchr(begin, ',');

	if (end == NULL) {
		return false;
	}

	*end = 0;

	if (! parse_peers_generation(c, n, begin)) {
		return false;
	}

	// Default port.
	begin = end + 1;
	end = strchr(begin, ',');

	if (end == NULL || end - begin >= MAX_PORT_SZ) {
		return false;
	}

	*end = 0;

	parse_peers_context ctx;

	strcpy(ctx.default_port, begin);

	// Individual peers.
	begin = end + 1;

	if (*begin != '[') {
		return false;
	}

	if (*(begin + 1) == ']') {
		n->peers_generation = n->peers_generation_latest;
		return true; // no peers
	}

	do {
		begin++; // skip '[' first then ','s

		if (! parse_peer(c, &begin, &ctx)) {
			return false;
		}
	} while (*begin == ',');

	if (*begin != ']') {
		return false;
	}

	n->peers_generation = n->peers_generation_latest;

	return true;
}

// Output spec
// ns1:regime,n_repls,<repl-0 bitmap>,<repl-1 bitmap>,...;
// ns2:regime,n_repls,<repl-0 bitmap>,<repl-1 bitmap>,...
static bool
parse_replicas(cluster* c, cluster_node* n, char* response)
{
	char* save_ptr = NULL;
	char* tok = strtok_r((char*)response, ";", &save_ptr);

	while (tok != NULL) {
		if (! parse_replicas_ns(c, n, tok)) {
			return false;
		}

		tok = strtok_r(NULL, ";", &save_ptr);
	}

	n->partition_generation = n->partition_generation_latest;

	return true;
}


//==========================================================
// Local helpers - info response parsing.
//

static bool
parse_peer(cluster* c, char** begin_r, parse_peers_context* ctx)
{
	char* begin = *begin_r;

	if (*begin != '[') {
		return false;
	}

	// Node id.
	begin++;

	char* end = strchr(begin, ',');

	if (end == NULL) {
		return false;
	}

	*end = 0;

	cf_node peer_id;

	if (cf_strtoul_x64(begin, &peer_id) < 0 || peer_id == 0) {
		return false;
	}

	// TLS name.
	begin = end + 1;
	end = strchr(begin, ',');

	if (end == NULL) {
		return false;
	}

	*end = 0;

	cluster_node* peer = find_aero_node(c, peer_id);

	if (peer == NULL) {
		cf_detail(AS_XDR_CLIENT, "discovered new node %s %lx", c->cfg->name,
				peer_id);

		peer = create_peer(c, peer_id, *begin == 0 ? NULL : begin);
	}

	ctx->peer = peer;
	ctx->endpoints = c->tend_cycle == peer->endpoints_tend_cycle ?
			NULL : cf_vector_create(sizeof(endpoint), 4, 0);

	// Endpoints.
	begin = end + 1;

	if (*begin != '[') {
		return false;
	}

	if (*(begin + 1) == ']') {
		return false; // must have endpoints
	}

	do {
		begin++; // skip '[' first then ','s

		if (! parse_endpoint(c->cfg->name, &begin, ctx)) {
			return false;
		}
	}
	while (*begin == ',');

	if (*begin != ']') { // end of last endpoint
		return false;
	}

	if (*(begin + 1) != ']') { // end of the peer
		return false;
	}

	if (ctx->endpoints != NULL) {
		if (peer->endpoints != NULL) {
			free_endpoints(peer->endpoints);
		}

		peer->endpoints = ctx->endpoints;
		peer->endpoints_tend_cycle = c->tend_cycle;
	}

	*begin_r = begin + 2;
	return true;
}

static cluster_node*
create_peer(cluster* c, cf_node id, const char* tls_name)
{
	cluster_node* n = find_unused_node(c);

	init_node(n);

	n->id = id;

	if (tls_name != NULL) {
		n->tls_name = cf_strdup(tls_name);
	}

	activate_node(c, n);

	return n;
}

// Endpoint examples. May terminate with ',' or ']'
// ipv4
// [i:p:v:6]
// ipv4:port
// [i:p:v:6]:port
static bool
parse_endpoint(const char* dc_name, char** begin_r, parse_peers_context* ctx)
{
	char* begin = *begin_r;
	char* at = begin;

	// Find end of endpoint while handling ipv6.
	if (*begin == '[') {
		while (*at != ']' && *at != 0) {
			at++;
		}

		if (*at == 0) {
			return false; // reached end without finding delimiter
		}

		at++;
	}

	while (*at != ',' && *at != ']' && *at != 0) {
		at++;
	}

	if (*at == 0) {
		return false; // reached end without finding delimiter
	}

	uint32_t len = (uint32_t)(at - begin);

	// Duplicate endpoint for manipulation.
	if (len >= MAX_STACK_SZ) {
		return false;
	}

	char ep_raw[len + 1];

	memcpy(ep_raw, begin, len);
	ep_raw[len] = 0;

	char* host = ep_raw;
	char* search_port = host;

	if (*host == '[') { // ipv6
		host++;

		char* host_end = strchr(host, ']');

		if (host_end == NULL) {
			return false;
		}

		*host_end = 0;
		search_port = host_end + 1;
	}

	char* port = strchr(search_port, ':');

	if (port != NULL) {
		*port = 0; // null terminate host
		port++;
	}
	else {
		port = ctx->default_port;
	}

	if (ctx->endpoints != NULL) {
		append_peer_endpoint(dc_name, ctx, host, port);
	}

	*begin_r = at;
	return true;
}

static void
append_peer_endpoint(const char* dc_name, parse_peers_context* ctx,
		const char* host, const char* port)
{
	cluster_node* peer = ctx->peer;
	endpoint ep = { .host = cf_strdup(host), .port = cf_strdup(port) };

	cf_vector_append(ctx->endpoints, &ep);

	cf_detail(AS_XDR_CLIENT, "discovered endpoint %s %lx - %s:%s", dc_name,
			peer->id, host, port);
}

static bool
parse_replicas_ns(cluster* c, const cluster_node* n, char* begin)
{
	char* save_ptr = NULL;

	// Namespace name.
	char* tok = strtok_r(begin, ":", &save_ptr);

	if (tok == NULL) {
		return false;
	}

	as_namespace* ns = as_namespace_get_byname(tok);

	if (ns != NULL) {
		if (c->cfg->ns_cfgs[ns->ix]->remote_namespace != NULL) {
			cf_warning(AS_XDR, "DC %s namespace '%s' is mapped but exists on remote",
					c->cfg->name, ns->name);
			return true;
		}
	}
	else if ((ns = get_local_namespace(c, tok)) == NULL) {
		return true; // ignore namespaces that are neither local nor mapped
	}

	// Regime.
	tok = strtok_r(NULL, ",", &save_ptr);

	if (tok == NULL) {
		return false;
	}

	uint32_t regime;

	if (cf_strtoul_u32(tok, &regime) < 0) {
		return false;
	}

	// Replica count.
	tok = strtok_r(NULL, ",", &save_ptr);

	if (tok == NULL) {
		return false;
	}

	uint64_t n_repls;

	if (cf_strtoul_u64(tok, &n_repls) < 0 || n_repls == 0) {
		return false;
	}

	// First replica (master) bitmap. Parsing master is enough.
	tok = strtok_r(NULL, ",", &save_ptr);

	if (tok == NULL) {
		return false;
	}

	uint32_t enc_len = (uint32_t)strlen(tok);
	uint32_t dec_len = cf_b64_decoded_buf_size(enc_len);

	// Find the nearest multiple of 3 (in bytes) for AS_PARTITIONS bits.
	if (dec_len != (((AS_PARTITIONS / 8) + 2) / 3) * 3) {
		return false;
	}

	uint8_t masters[dec_len];

	if (! cf_b64_validate_and_decode(tok, enc_len, masters, &dec_len) ) {
		return false;
	}

	// Update partition map.
	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		if (! is_bit_set(masters, pid)) {
			continue;
		}

		ownership* owner = &c->map[ns->ix][pid];

		// Allow equality to handle AP mode - regime is always 0.
		if (regime < owner->regime) {
			continue;
		}

		int16_t old_node_ix = owner->node_ix;

		if (old_node_ix != INVALID_NODE_IX && old_node_ix != n->ix) {
			// Force refresh for the losing master.
			c->nodes[old_node_ix].partition_generation = (uint32_t)-1;
		}

		owner->node_ix = n->ix;
		owner->regime = regime;
	}

	return true;
}

static as_namespace*
get_local_namespace(const cluster* c, const char* ns_name)
{
	as_xdr_dc_cfg* dc_cfg = c->cfg;

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_xdr_dc_ns_cfg* dc_ns_cfg = dc_cfg->ns_cfgs[ns_ix];

		if (dc_ns_cfg->remote_namespace != NULL &&
				strcmp(dc_ns_cfg->remote_namespace, ns_name) == 0) {
			return as_namespace_get_byname(dc_ns_cfg->ns_name);
		}
	}

	return NULL;
}


//==========================================================
// Local helpers - connection utilities.
//

static bool
connect_node_endpoints(cluster* c, cluster_node* n)
{
	cf_vector* endpoints = n->endpoints;

	if (endpoints == NULL) {
		return false;
	}

	uint32_t sz = cf_vector_size(endpoints);

	for (uint32_t i = 0; i < sz; i++) {
		endpoint ep;

		cf_vector_get(endpoints, i, &ep);

		if (connect_node_host_port(c, n, ep.host, ep.port)) {
			return true;
		}
	}

	return false;
}

static bool
connect_node_host_port(cluster* c, cluster_node* n, const char* host,
		const char* port)
{
	cf_ip_addr addrs[CF_SOCK_CFG_MAX];
	uint32_t n_addrs = CF_SOCK_CFG_MAX;
	cf_ip_port p;

	if (cf_ip_port_from_string(port, &p) != 0 ||
			cf_ip_addr_from_string_multi(host, addrs, &n_addrs) != 0) {
		return false;
	}

	for (uint32_t i = 0; i < n_addrs; i++) {
		cf_mutex_lock(&n->tend_lock);

		cf_sock_cfg* cfg = &n->tend_sock_cfg;

		*cfg = (cf_sock_cfg){
				.owner = CF_SOCK_OWNER_XDR_CLIENT,
				.addr = addrs[i],
				.port = p
		};

		cf_mutex_unlock(&n->tend_lock);

		if (connect_node_addr(c, n)) {
			return true;
		}
	}

	return false;
}

static bool
connect_node_addr(cluster* c, cluster_node* n)
{
	cf_sock_cfg* cfg = &n->tend_sock_cfg;
	cf_socket* sock = &n->tend_sock;

	if (cfg->port == 0) {
		// Normal for newly discovered node - do not warn.
		return false;
	}

	if (cf_socket_init_client(cfg, CONNECT_TIMEOUT_MS, sock) < 0) {
		return false;
	}

	if (c->tls != NULL) {
		tls_socket_prepare_xdr_client(c->tls, &n->tls_names, sock);

		if (tls_socket_connect_block(sock, CONNECT_TIMEOUT_MS) != 1) {
			cf_socket_close(sock);
			cf_socket_term(sock);
			return false;
		}
	}

	cf_ip_addr_port_to_string_safe(&cfg->addr, cfg->port, n->connected_to,
			sizeof(n->connected_to));

	cf_detail(AS_XDR_CLIENT, "connected to %s %s", c->cfg->name,
			n->connected_to);

	if (c->cfg->auth_mode != XDR_AUTH_NONE && ! login_node(c, n)) {
		cf_socket_close(sock);
		cf_socket_term(sock);
		return false;
	}

	return true;
}
