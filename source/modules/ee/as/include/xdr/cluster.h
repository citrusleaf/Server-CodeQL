/*
 * cluster.h
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

#include "cf_mutex.h"
#include "node.h"
#include "socket.h"
#include "tls_ee.h"
#include "vector.h"


//==========================================================
// Forward declarations.
//

struct as_proto_s;
struct as_xdr_dc_cfg_s;


//==========================================================
// Typedefs & constants.
//

typedef enum {
	NODE_UNUSED,
	NODE_ACTIVE,
	NODE_DRAINING,
	NODE_DRAINED
} node_state;

typedef struct cluster_node_s {
	cf_mutex lock;
	node_state state;
	int32_t rc;

	uint32_t dc_ix;
	int16_t ix;

	// Cluster management.

	cf_mutex tend_lock;
	cf_sock_cfg tend_sock_cfg;
	uint8_t* session_token;
	uint32_t session_token_sz;
	uint32_t session_renewal;

	cf_node id;
	char connected_to[64];
	bool features_checked;
	bool features_compatible;
	bool use_replicas_max;
	cf_tls_peer_names tls_names;
	char* tls_name;
	cf_vector* endpoints;
	uint32_t endpoints_tend_cycle;
	cf_socket tend_sock;
	uint32_t refresh_failures;
	uint64_t peers_generation_latest;
	uint32_t partition_generation_latest;
	uint64_t peers_generation;
	uint32_t partition_generation;

	// Connector cluster management.

	uint32_t n_checks_failed;
	uint64_t last_check_ms;
} cluster_node;

typedef struct cluster_info_s {
	uint32_t n_nodes;
} cluster_info;


//==========================================================
// Public API.
//

bool as_cluster_reusable(uint32_t dc_ix);
void as_cluster_create(uint32_t dc_ix, struct as_xdr_dc_cfg_s* cfg);
bool as_cluster_delete(uint32_t dc_ix);
bool as_cluster_connect(uint32_t dc_ix);
void as_cluster_disconnect(uint32_t dc_ix);
void as_cluster_info(uint32_t dc_ix, cluster_info* cinfo);

cluster_node* as_cluster_get_node_optimistic(uint32_t dc_ix, uint32_t ns_ix, uint32_t pid);
bool as_cluster_reserve_node(cluster_node* n);
void as_cluster_release_node(cluster_node* n);
const char* as_cluster_get_dc_name(uint32_t dc_ix);
cf_tls_info* as_cluster_get_tls_info(uint32_t dc_ix);
const char* as_cluster_get_user(uint32_t dc_ix);
// TODO - move to proto ?
bool validate_and_swap_proto(struct as_proto_s* proto, uint8_t type, uint64_t max_sz, const char* tag);

void as_cluster_queue_seed(uint32_t dc_ix, bool add, const char* host, const char* port, const char* tls_name);

#define NODE_IS_LIVE(node) \
	(node->state == NODE_ACTIVE || node->state == NODE_DRAINING)
