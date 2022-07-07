/*
 * roster_ee.c
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

#include "fabric/roster.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "node.h"

#include "base/datamodel.h"
#include "base/smd.h"
#include "fabric/exchange.h"
#include "fabric/hb.h"


//==========================================================
// Typedefs & constants.
//

typedef struct id_pair_s {
	cf_node node_id;
	uint32_t rack_id;
} id_pair;


//==========================================================
// Forward declarations.
//

static uint32_t validate_and_sort_nodes(const char* nodes, id_pair* pairs);
static uint32_t list_to_id_pairs(const char* nodes, id_pair* pairs);
static void nodes_to_smd_value(const id_pair* pairs, uint32_t n_pairs, char* nodes);
static void roster_smd_accept_cb(const cf_vector* items, as_smd_accept_type accept_type);
static void roster_action_set(as_namespace* ns, const as_smd_item* item);
static void log_roster_pairs(const id_pair* pairs, uint32_t n_pairs);


//==========================================================
// Inlines & macros.
//

// A comparison_fn_t used with qsort() - yields descending node-id order.
static inline int
compare_id_pairs(const void* pa, const void* pb)
{
	uint64_t a = (uint64_t)((const id_pair*)pa)->node_id;
	uint64_t b = (uint64_t)((const id_pair*)pb)->node_id;

	return a > b ? -1 : (a == b ? 0 : 1);
}


//==========================================================
// Public API.
//

void
as_roster_init(void)
{
	as_smd_module_load(AS_SMD_MODULE_ROSTER, roster_smd_accept_cb, NULL, NULL);
}

// SMD key is "ns-name".
// SMD value is comma-separated hex strings (without preceding 0x).
bool
as_roster_set_nodes_cmd(const char* ns_name, const char* nodes)
{
	id_pair pairs[AS_CLUSTER_SZ];
	uint32_t n_pairs = validate_and_sort_nodes(nodes, pairs);

	if (n_pairs == 0) {
		cf_warning(AS_ROSTER, "{%s} invalid node list %s", ns_name, nodes);
		return false;
	}

	// +1 for clean use of sprintf(), where we overwrite final separator.
	char new_nodes[(n_pairs * ROSTER_STRING_ELE_LEN) + 1];

	nodes_to_smd_value(pairs, n_pairs, new_nodes);

	cf_info(AS_ROSTER, "{%s} got command to set roster to %s", ns_name,
			new_nodes);

	// Broadcast the SMD command to all nodes (including this one).
	return as_smd_set_blocking(AS_SMD_MODULE_ROSTER, ns_name, new_nodes, 0);
}


//==========================================================
// Local helpers.
//

static uint32_t
validate_and_sort_nodes(const char* nodes, id_pair* pairs)
{
	uint32_t n_pairs = list_to_id_pairs(nodes, pairs);

	if (n_pairs == 0) {
		return 0;
	}

	qsort(pairs, n_pairs, sizeof(id_pair), compare_id_pairs);

	// Don't allow duplicates.
	for (uint32_t n = 1; n < n_pairs; n++) {
		if (pairs[n - 1].node_id == pairs[n].node_id) {
			return 0;
		}
	}

	return n_pairs;
}

static uint32_t
list_to_id_pairs(const char* nodes, id_pair* pairs)
{
	uint32_t n_pairs = 0;
	char* tok = (char*)nodes;

	while (true) {
		cf_node node_id = (cf_node)strtoul(tok, &tok, 16);

		if (node_id == 0 || node_id == UINT64_MAX) {
			cf_warning(AS_ROSTER, "illegal node id %lx", node_id);
			return 0;
		}

		id_pair* pair = &pairs[n_pairs];

		pair->node_id = node_id;

		if (*tok == ROSTER_ID_PAIR_SEPARATOR) {
			tok++;

			uint64_t rack_id = strtoul(tok, &tok, 10);

			if (rack_id > MAX_RACK_ID) {
				cf_warning(AS_ROSTER, "illegal rack id %lu", rack_id);
				return 0;
			}

			pair->rack_id = (uint32_t)rack_id;
		}
		else {
			pair->rack_id = 0;
		}

		n_pairs++;

		if (*tok == '\0') {
			break;
		}

		tok++; // move past one character delimiter
	}

	return n_pairs;
}

static void
nodes_to_smd_value(const id_pair* pairs, uint32_t n_pairs, char* nodes)
{
	char* at = nodes;

	for (uint32_t n = 0; n < n_pairs; n++) {
		const id_pair* pair = &pairs[n];

		if (pair->rack_id == 0) {
			at += sprintf(at, "%lx|", pair->node_id);
		}
		else {
			at += sprintf(at, "%lx%c%u|", pair->node_id,
					ROSTER_ID_PAIR_SEPARATOR, pair->rack_id);
		}
	}

	*(at - 1) = '\0'; // remove final '|' - relies on n_ids > 0
}

static void
roster_smd_accept_cb(const cf_vector* items, as_smd_accept_type accept_type)
{
	for (uint32_t i = 0; i < cf_vector_size(items); i++) {
		as_smd_item* item = cf_vector_get_ptr(items, i);
		uint32_t ns_len = strlen(item->key);
		as_namespace* ns = as_namespace_get_bybuf((uint8_t*)item->key, ns_len);

		if (ns == NULL) {
			cf_detail(AS_ROSTER, "skipping invalid ns");
			continue;
		}

		if (item->value != NULL) {
			roster_action_set(ns, item);
		}
		else {
			cf_warning(AS_ROSTER, "{%s} unexpected smd delete", ns->name);
		}
	}
}

static void
roster_action_set(as_namespace* ns, const as_smd_item* item)
{
	id_pair pairs[AS_CLUSTER_SZ];
	uint32_t n_pairs = list_to_id_pairs(item->value, pairs);

	if (n_pairs == 0) {
		// Paranoia - should never happen.
		cf_warning(AS_ROSTER, "{%s} invalid node list %s", item->key,
				item->value);
		return;
	}

	// Validate sorted and de-dup'd.
	for (uint32_t n = 1; n < n_pairs; n++) {
		if (pairs[n - 1].node_id <= pairs[n].node_id) {
			// Paranoia - should never happen.
			cf_warning(AS_ROSTER, "{%s} invalid node list %s", item->key,
					item->value);
			return;
		}
	}

	as_exchange_info_lock();

	if (ns->smd_roster_generation != 0) {
		cf_info(AS_ROSTER, "{%s} set smd-roster gen %u nodes %u ...", ns->name,
				item->generation, n_pairs);

		log_roster_pairs(pairs, n_pairs);
	}

	ns->smd_roster_generation = item->generation;
	ns->smd_roster_count = n_pairs;

	for (uint32_t n = 0; n < n_pairs; n++) {
		const id_pair* pair = &pairs[n];

		ns->smd_roster[n] = pair->node_id;
		ns->smd_roster_rack_ids[n] = pair->rack_id;
	}

	as_exchange_info_unlock();
}

static void
log_roster_pairs(const id_pair* pairs, uint32_t n_pairs)
{
	char line[1024];
	char* at = line;
	uint32_t last_n = n_pairs - 1;

	for (uint32_t n = 0; n < n_pairs; n++) {
		const id_pair* pair = &pairs[n];

		if (pair->rack_id == 0) {
			at += sprintf(at, "%lx|", pair->node_id);
		}
		else {
			at += sprintf(at, "%lx%c%u|", pair->node_id,
					ROSTER_ID_PAIR_SEPARATOR, pair->rack_id);
		}

		if (n % 10 == 9 || n == last_n) {
			if (n == last_n) {
				*(at - 1) = '\0'; // remove final '|' - relies on n_ids > 0
			}

			cf_info(AS_ROSTER, "   %s", line);
			at = line;
		}
	}
}
