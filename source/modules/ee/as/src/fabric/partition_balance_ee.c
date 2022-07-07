/*
 * partition_balance_ee.c
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

#include "fabric/partition_balance.h"
#include "fabric/partition_balance_ee.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "citrusleaf/cf_hash_math.h"
#include "citrusleaf/cf_queue.h"

#include "cf_mutex.h"
#include "compare.h"
#include "dynbuf.h"
#include "log.h"
#include "node.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "fabric/appeal_ee.h"
#include "fabric/exchange.h"
#include "fabric/migrate.h"
#include "fabric/migrate_ee.h"
#include "fabric/partition.h"
#include "storage/storage.h"


//==========================================================
// Globals.
//

// TODO - this won't be needed when g_n_appeals_remaining can be declared as
// non-volatile but still atomically decremented. Keeping it for now for speed.
bool g_appeal_phase = false;

static cf_mutex g_appeals_lock = CF_MUTEX_INIT;
static cf_atomic32 g_n_appeals_remaining = 0;
static cf_atomic32 g_n_live_appeals_remaining = 0;

static uint32_t g_claims_row_size;


//==========================================================
// Forward declarations.
//

bool node_was_removed_from_roster(const as_namespace* ns);
void balance_namespace_cp(as_namespace* ns, cf_queue* mq);
void ignore_non_roster_nodes(as_namespace* ns);
uint64_t ignore_ckey_mismatched_nodes(as_namespace* ns);
void ignore_self(as_namespace* ns);
void adjust_replication_factor(as_namespace* ns);
uint32_t roster_rack_count(const as_namespace* ns);
uint32_t live_roster_rack_count(const as_namespace* ns);
uint32_t rack_id_count(uint32_t* ids, uint32_t n_ids);
void init_target_claims_cp(const as_namespace* ns, uint32_t* target_claims);
void fill_roster_node_seq(const as_namespace* ns, uint32_t pid, const uint64_t* hashed_nodes, cf_node* roster_node_seq, sl_ix_t* ns_roster_sl_ix);
void uniform_adjust_row_cp(cf_node* ns_roster_node_seq, sl_ix_t* ns_roster_sl_ix, cf_node* ns_node_seq, sl_ix_t* ns_sl_ix, const as_namespace* ns, uint32_t* roster_claims, const uint32_t* roster_target_claims, uint32_t n_roster_racks, uint32_t n_racks);
void rack_aware_adjust_row_cp(cf_node* ns_roster_node_seq, sl_ix_t* ns_roster_sl_ix, cf_node* ns_node_seq, sl_ix_t* ns_sl_ix, const as_namespace* ns, uint32_t n_roster_racks, uint32_t n_racks);
void follow_adjusted_roster(cf_node* ns_roster_node_seq, sl_ix_t* ns_roster_sl_ix, cf_node* ns_node_seq, sl_ix_t* ns_sl_ix, const as_namespace* ns, uint32_t n_racks);
bool is_rack_distinct_before_n(const sl_ix_t* ns_sl_ix, const uint32_t* rack_ids, uint32_t rack_id, uint32_t n);
void fix_lagging_partition(as_partition* p, const cf_node* ns_roster_node_seq, const cf_node* ns_node_seq, const sl_ix_t* ns_sl_ix, as_namespace* ns, uint32_t max_regime);
void validate_one_master(const as_partition* p, const cf_node* ns_node_seq, const sl_ix_t* ns_sl_ix, const as_namespace* ns);
bool partition_is_alive(const as_partition* p, const cf_node* ns_roster_node_seq, const cf_node* ns_node_seq, const sl_ix_t* ns_sl_ix, const as_namespace* ns, uint32_t lead_flags[]);
uint32_t find_n_roster_replicas(const cf_node* ns_roster_node_seq, const cf_node* ns_node_seq, const as_namespace* ns, uint32_t lead_flags[]);
int find_working_master_cp(const as_partition* p, const sl_ix_t* ns_sl_ix, const as_namespace* ns);
uint32_t find_duplicates_cp(const as_partition* p, const cf_node* ns_node_seq, const sl_ix_t* ns_sl_ix, const struct as_namespace_s* ns, uint32_t working_master_n, cf_node dupls[]);
void advance_version_cp(as_partition* p, const sl_ix_t* ns_sl_ix, as_namespace* ns, uint32_t self_n, uint32_t working_master_n, uint32_t n_dupl);
bool queue_appeal(as_partition* p, as_namespace* ns, uint32_t self_n, uint32_t working_master_n, cf_queue* mq);


//==========================================================
// Inlines & macros.
//

static inline void
partition_appeal_done(as_partition* p, const as_namespace* ns)
{
	if (p->must_appeal) {
		p->must_appeal = false;

		if (cf_atomic32_decr(&g_n_live_appeals_remaining) == 0) {
			cf_mutex_unlock(&g_appeals_lock);
			cf_info(AS_PARTITION, "appeal round is complete - exonerated %lu",
					ns->appeals_records_exonerated);
		}

		if (cf_atomic32_decr(&g_n_appeals_remaining) == 0) {
			g_appeal_phase = false;
			cf_info(AS_PARTITION, "appeal phase is complete");
		}
	}
}

static inline void
partition_balance_appeal_done(as_partition* p, const as_namespace* ns)
{
	if (p->must_appeal) {
		p->must_appeal = false;

		if (cf_atomic32_decr(&g_n_appeals_remaining) == 0) {
			g_appeal_phase = false;
			cf_info(AS_PARTITION, "appeal round and phase is complete - exonerated %lu",
					ns->appeals_records_exonerated);
		}
	}
}

// Get a claim by replica index and node index.
#define TARGET_CLAIMS(r, n) target_claims[((r) * g_claims_row_size) + (n)]
#define CLAIMS_P(r, n) (&claims[((r) * g_claims_row_size) + (n)])

// Get the rack-id that was input by exchange.
#define RACK_ID(_n) (rack_ids[ns_sl_ix[_n]])


//==========================================================
// Public API.
//

void
as_partition_balance_emigration_yield()
{
	if (g_appeal_phase) {
		cf_mutex_lock(&g_appeals_lock);
		cf_mutex_unlock(&g_appeals_lock);
	}
}

bool
as_partition_balance_revive(as_namespace* ns)
{
	// TODO - when caller is CE/EE split, check and warn appropriately for AP.
	if (! ns->cp) {
		return true;
	}

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition* p = &ns->partitions[pid];

		cf_mutex_lock(&p->lock);

		if (! g_allow_migrations) {
			cf_mutex_unlock(&p->lock);
			return false;
		}

		if (p->version.evade == 1) {
			p->version.evade = 0;
			p->version.revived = 1;
			as_storage_cache_pmeta(ns, p);
		}

		cf_mutex_unlock(&p->lock);
	}

	as_storage_flush_pmeta(ns, 0, AS_PARTITIONS);

	return true;
}

void
as_partition_balance_protect_roster_set(as_namespace* ns)
{
	if (! ns->cp || ns->smd_roster_generation == ns->roster_generation) {
		return;
	}

	if (as_partition_balance_is_init_resolved() &&
			! node_was_removed_from_roster(ns)) {
		return;
	}

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition* p = &ns->partitions[pid];

		// No lock - call is made only when migrations are disallowed.

		if (as_exchange_min_compatibility_id() >= 11 ||
				as_partition_version_is_null(&p->version)) {
			p->version.revived = 1;
			as_storage_cache_pmeta(ns, p);
		}
	}

	as_storage_flush_pmeta(ns, 0, AS_PARTITIONS);
}

void
as_partition_balance_effective_rack_ids(cf_dyn_buf* db)
{
	as_exchange_info_lock();

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_namespace *ns = g_config.namespaces[ns_ix];

		cf_dyn_buf_append_string(db, ns->name);
		cf_dyn_buf_append_char(db, ':');

		if (ns->cp) {
			for (uint32_t n = 0; n < ns->roster_count; n++) {
				if (g_config.self_node == ns->roster[n]) {
					cf_dyn_buf_append_uint32(db, ns->roster_rack_ids[n]);
					break;
				}
			}
		}
		else {
			for (uint32_t n = 0; n < ns->cluster_size; n++) {
				if (g_config.self_node == ns->succession[n]) {
					cf_dyn_buf_append_uint32(db, ns->rack_ids[n]);
					break;
				}
			}
		}

		cf_dyn_buf_append_char(db, ';');
	}

	cf_dyn_buf_chomp(db);
	as_exchange_info_unlock();
}

bool
as_partition_pre_emigrate_done(as_namespace* ns, uint32_t pid,
		uint64_t orig_cluster_key, uint32_t tx_flags)
{
	if (! ns->cp) {
		return true;
	}

	as_partition* p = &ns->partitions[pid];

	cf_mutex_lock(&p->lock);

	if (! g_allow_migrations || orig_cluster_key != as_exchange_cluster_key()) {
		cf_debug(AS_PARTITION, "{%s:%u} pre_emigrate_done - cluster key mismatch",
				ns->name, pid);
		cf_mutex_unlock(&p->lock);
		return false;
	}

	if ((tx_flags & TX_FLAGS_ACTING_MASTER) != 0) {
		p->working_master = (cf_node)0;
		p->n_dupl = 0;
		p->version.master = 0;

		if (! is_self_replica(p)) {
			p->version.subset = 1;
		}

		as_storage_save_pmeta(ns, p);

		if (client_replica_maps_update(ns, pid)) {
			cf_atomic32_incr(&g_partition_generation);
		}
	}

	cf_mutex_unlock(&p->lock);

	return true;
}


//==========================================================
// Public API - enterprise only.
//

void
as_partition_appeal_done(as_namespace* ns, uint32_t pid,
		uint64_t orig_cluster_key)
{
	as_partition* p = &ns->partitions[pid];

	cf_mutex_lock(&p->lock);

	if (! g_allow_migrations || orig_cluster_key != as_exchange_cluster_key()) {
		cf_debug(AS_PARTITION, "{%s:%u} appeal_done - cluster key mismatch",
				ns->name, pid);
		cf_mutex_unlock(&p->lock);
		return;
	}

	partition_appeal_done(p, ns);

	cf_atomic_int_decr(&ns->appeals_tx_remaining);

	cf_mutex_unlock(&p->lock);
}

assist_start_result
as_partition_assist_start(as_namespace* ns, uint32_t pid,
		uint64_t orig_cluster_key)
{
	as_partition* p = &ns->partitions[pid];

	cf_mutex_lock(&p->lock);

	if (! g_allow_migrations || orig_cluster_key != as_exchange_cluster_key()) {
		cf_debug(AS_PARTITION, "{%s:%u} assist_start - cluster key mismatch",
				ns->name, pid);
		cf_mutex_unlock(&p->lock);
		return ASSIST_START_RESULT_EAGAIN;
	}

	if (! as_partition_version_has_data(&p->version)) {
		cf_warning(AS_PARTITION, "non-working-master got appeal");
		cf_mutex_unlock(&p->lock);
		return ASSIST_START_RESULT_ERROR;
	}

	cf_mutex_unlock(&p->lock);

	return ASSIST_START_RESULT_OK;
}


//==========================================================
// Private API - for enterprise separation only.
//

void
partition_balance_init()
{
	bool may_assist = false;

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_namespace* ns = g_config.namespaces[ns_ix];

		if (! ns->cp) {
			continue;
		}

		may_assist = true; // even without persistence - support mixed cluster

		as_storage_load_regime(ns);

		if (ns->rebalance_regime == 0) {
			ns->eventual_regime = 1;
			ns->rebalance_regime = 1;
		}

		as_storage_load_roster_generation(ns);

		if (ns->storage_type == AS_STORAGE_ENGINE_MEMORY || ! ns->cold_start) {
			continue;
		}

		for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
			as_partition* p = &ns->partitions[pid];

			if (as_partition_version_has_data(&p->version) &&
					as_index_tree_size(p->tree) != 0) {
				p->must_appeal = true;
				g_n_appeals_remaining++;
				g_appeal_phase = true;
			}
		}
	}

	if (g_appeal_phase) {
		g_n_live_appeals_remaining = g_n_appeals_remaining; // anything non-zero
		cf_mutex_lock(&g_appeals_lock);
		as_appeal_init_appeal();
	}

	if (may_assist) {
		as_appeal_init_assist();
	}
}

void
balance_namespace(as_namespace* ns, cf_queue* mq)
{
	if (ns->cp) {
		balance_namespace_cp(ns, mq);
	}
	else {
		balance_namespace_ap(ns, mq);
	}

	ns->hub = ns->succession[0];
}

void
prepare_for_appeals()
{
	as_appeal_clear_assists();

	uint32_t n_live_appeals = 0;

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_namespace* ns = g_config.namespaces[ns_ix];

		if (ns->cp) {
			n_live_appeals += ns->appeals_tx_remaining;
		}
	}

	if (g_n_live_appeals_remaining == 0 && n_live_appeals != 0) {
		cf_mutex_lock(&g_appeals_lock);
	}
	else if (g_n_live_appeals_remaining != 0 && n_live_appeals == 0) {
		cf_mutex_unlock(&g_appeals_lock);
	}

	if (g_n_appeals_remaining != 0 || g_n_live_appeals_remaining != 0 ||
			n_live_appeals != 0) {
		cf_info(AS_PARTITION, "appeals-on-rebalance: all %u previous-live %u live %u",
				g_n_appeals_remaining, g_n_live_appeals_remaining,
				n_live_appeals);
	}

	g_n_live_appeals_remaining = n_live_appeals;
}

void
process_pb_tasks(cf_queue* tq)
{
	as_migrate_clear_fill_queue();

	pb_task task;

	while (cf_queue_pop(tq, &task, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
		if (task.type == PB_TASK_APPEAL) {
			as_appeal_begin(&task);
		}
		else {
			as_migrate_emigrate(&task);
		}
	}
}

void
set_active_size(as_namespace* ns)
{
	ns->active_size = ns->cluster_size;

	for (uint32_t n = 0; n < ns->cluster_size; n++) {
		if (ns->quiesced[n]) {
			ns->active_size--;
		}
	}

	if (ns->active_size != ns->cluster_size) {
		cf_info(AS_PARTITION, "{%s} %u of %u nodes are quiesced", ns->name,
				ns->cluster_size - ns->active_size, ns->cluster_size);
	}

	if (ns->active_size == 0) {
		cf_warning(AS_PARTITION, "{%s} can't quiesce all nodes - ignoring",
				ns->name);

		ns->active_size = ns->cluster_size;
		ns->is_quiesced = false;
		memset(ns->quiesced, 0, sizeof(ns->quiesced));
	}
}

uint32_t
rack_count(const as_namespace* ns)
{
	uint32_t ids[ns->active_size];
	uint32_t write_n = 0;
	uint32_t n = 0;

	while (write_n < ns->active_size) {
		if (! ns->quiesced[n]) {
			ids[write_n++] = ns->rack_ids[n];
		}

		n++;
	}

	return rack_id_count(ids, ns->active_size);
}

// When total number of partitions is not evenly divisible by number of nodes,
// attempt to spread extra claims for different replicas across different nodes.
//
// E.g. 5 nodes, replication factor 2:
// "Remainder" is 4096 % 5 = 1, so for each replica 4 nodes claim 819 partitions
// and 1 node (the "remainder") claims 820. This algorithm ensures the remainder
// node is different for each replica. Here node A claims 820 for the master,
// and node B claims 820 for the prole.
//
//       A  B  C  D  E
//      --------------
// r0   +1
// r1      +1
//
// E.g. 6 nodes, replication factor 3:
// "Remainder" is 4096 % 6 = 4, so for each replica 2 nodes claim 682 partitions
// and 4 nodes (the "remainder") claim 683.
//
//       A  B  C  D  E  F
//      -----------------
// r0   +1 +1 +1 +1
// r1   +1 +1       +1 +1
// r2         +1 +1 +1 +1
//
// (The +1's above indicate the target is increased by 1.)
//
// In AP, we use the translation array to skip slots corresponding to nodes not
// present in the current cluster. We need a full-size claims array, since we'll
// later use ns_sl_ix to map back to this array, and and ns_sl_ix yields indexes
// in the full-size range.
void
init_target_claims_ap(const as_namespace* ns, const int translation[],
		uint32_t* target_claims)
{
	g_claims_row_size = g_cluster_size;

	uint32_t n_nodes = ns->active_size;

	// Special case rf=all to only balance masters.
	uint32_t n_replicas = ns->replication_factor == n_nodes ?
			1 : ns->replication_factor;

	uint32_t claims_size = n_replicas * g_claims_row_size;
	uint32_t min_claims = AS_PARTITIONS / n_nodes;

	for (uint32_t t = 0; t < claims_size; t++) {
		target_claims[t] = min_claims;
	}

	uint32_t remainder = AS_PARTITIONS % n_nodes;

	if (remainder == 0) {
		return;
	}

	uint32_t r = 0;
	uint32_t n = 0;
	uint32_t n_used = 0;

	while (r < n_replicas) {
		if ((ns->cluster_size != g_cluster_size && translation[n] == -1) ||
				ns->quiesced[n]) {
			n++; // skip this node's slot completely
		}
		else {
			TARGET_CLAIMS(r, n)++;
			n_used++;
			n++;

			if (n_used == remainder) {
				n_used = 0;
				r++;
			}
		}

		if (n == g_claims_row_size) {
			n = 0;
		}
	}
}

void
quiesce_adjust_row(cf_node* ns_node_seq, sl_ix_t* ns_sl_ix, as_namespace* ns)
{
	uint32_t n_quiesced_nodes = ns->cluster_size - ns->active_size;
	cf_node quiesced_node_seq[n_quiesced_nodes];
	sl_ix_t quiesced_sl_ix[n_quiesced_nodes];
	uint32_t quiesced_n = 0;
	uint32_t write_n = 0;

	for (uint32_t n = 0; n < ns->cluster_size; n++) {
		if (ns->quiesced[ns_sl_ix[n]]) {
			// Move quiesced node to temporary array.
			quiesced_node_seq[quiesced_n] = ns_node_seq[n];
			quiesced_sl_ix[quiesced_n] = ns_sl_ix[n];
			quiesced_n++;
			continue;
		}

		if (write_n != n) {
			// Move active nodes to fill vacated slots.
			ns_node_seq[write_n] = ns_node_seq[n];
			ns_sl_ix[write_n] = ns_sl_ix[n];
		}

		write_n++;
	}

	// Copy quiesced nodes from temporary array to end of list.
	memcpy(&ns_node_seq[write_n], quiesced_node_seq,
			quiesced_n * sizeof(cf_node));
	memcpy(&ns_sl_ix[write_n], quiesced_sl_ix, quiesced_n * sizeof(sl_ix_t));
}

// Adjust each partition's node sequence in order to achieve better balance of
// replicas across nodes.
//
// For each replica, each node maintains a "claim" - the number of partitions
// for which the node owns this replica. When a claim exceeds a calculated
// threshold, swap (if possible) with another node in the row which has the
// smallest claim for that replica.
//
// Heuristics determine the calculated thresholds - too much to describe here.
// If rack-aware, rack restrictions are imposed when trying to adjust the row.
void
uniform_adjust_row(cf_node* node_seq, uint32_t n_nodes, sl_ix_t* ns_sl_ix,
		uint32_t n_replicas, uint32_t* claims, const uint32_t* target_claims,
		const uint32_t* rack_ids, uint32_t n_racks)
{
	if (n_replicas == n_nodes) {
		n_replicas = 1; // special case rf=all to only balance masters
	}

	uint32_t lower_by = n_racks == 1 ? 128 : 1024;
	uint32_t threshold = (AS_PARTITIONS - lower_by) / n_nodes;

	for (uint32_t cur_n = 0; cur_n < n_replicas; cur_n++) {
		uint32_t* p_cur_claim = CLAIMS_P(cur_n, ns_sl_ix[cur_n]);

		uint32_t cur_rack_id = RACK_ID(cur_n);
		bool is_rack_safe = cur_n == 0 || cur_n >= n_racks ||
				is_rack_distinct_before_n(ns_sl_ix, rack_ids, cur_rack_id,
						cur_n);

		if (is_rack_safe && *p_cur_claim < threshold) {
			(*p_cur_claim)++;
			continue;
		}

		uint32_t swap_n = cur_n;
		uint32_t* p_swap_claim = p_cur_claim;
		uint32_t swap_target_claim = TARGET_CLAIMS(swap_n, ns_sl_ix[swap_n]);
		int32_t swap_score =
				(int32_t)swap_target_claim - (int32_t)*p_swap_claim;

		for (uint32_t next_n = cur_n + 1; next_n < n_nodes; next_n++) {
			if (cur_n < n_racks) {
				uint32_t next_rack_id = RACK_ID(next_n);

				if (! is_rack_distinct_before_n(ns_sl_ix, rack_ids,
						next_rack_id, cur_n)) {
					continue; // not rack safe
				}
			}
			// else - next is rack safe

			uint32_t* p_next_claim = CLAIMS_P(cur_n, ns_sl_ix[next_n]);
			uint32_t next_target_claim = TARGET_CLAIMS(cur_n, ns_sl_ix[next_n]);
			int32_t next_score =
					(int32_t)next_target_claim - (int32_t)*p_next_claim;

			if (! is_rack_safe) {
				swap_n = next_n;
				p_swap_claim = p_next_claim;
				swap_target_claim = next_target_claim;
				swap_score = next_score;
				is_rack_safe = true;

				if (*p_cur_claim < threshold) {
					break;
				}

				continue;
			}

			if (next_score > swap_score ||
					(next_score == swap_score &&
							// Pick node with lower target - if it eventually
							// runs over, it won't look as bad (will look like
							// it was a node with a remainder target).
							next_target_claim < swap_target_claim)) {
				swap_n = next_n;
				p_swap_claim = p_next_claim;
				swap_target_claim = next_target_claim;
				swap_score = next_score;
			}
		}

		if (swap_n != cur_n) {
			// Swap node.
			cf_node temp_node = node_seq[swap_n];

			node_seq[swap_n] = node_seq[cur_n];
			node_seq[cur_n] = temp_node;

			// Swap succession list index.
			sl_ix_t temp_ix = ns_sl_ix[swap_n];

			ns_sl_ix[swap_n] = ns_sl_ix[cur_n];
			ns_sl_ix[cur_n] = temp_ix;
		}

		(*p_swap_claim)++;
	}
}

// When "rack aware", nodes are in "racks".
//
//  Nodes and racks in the cluster
//  +---------------+
//  | Rack1 | Rack2 |
//  +---------------+
//  | A | B | C | D |
//  +---------------+
//
// Proles for a partition can't be in the same rack as the master, e.g. for
// replication factor 2:
//
//  Node sequence table      Succession list index table
//   pid                      pid
//  +===+-------+-------+    +===+-------+-------+
//  | 0 | C | B | A | D |    | 0 | 2 | 1 | 0 | 3 |
//  +===+-------+-------+    +===+-------+-------+
//  | 1 | A | D | C | B |    | 1 | 0 | 3 | 2 | 1 |
//  +===+-------+-------+    +===+-------+-------+
//  | 2 | D |<C>| B | A |    | 2 | 3 |<2>| 1 | 0 | <= adjustment needed
//  +===+-------+-------+    +===+-------+-------+
//  | 3 | B |<A>| D | C |    | 3 | 1 |<0>| 3 | 2 | <= adjustment needed
//  +===+-------+-------+    +===+-------+-------+
//  | 4 | D | B | C | A |    | 4 | 3 | 1 | 2 | 0 |
//  +===+-------+-------+    +===+-------+-------+
//  ... to pid 4095.
//
// To adjust a table row, we swap the prole with the first non-replica.
void
rack_aware_adjust_row(cf_node* ns_node_seq, sl_ix_t* ns_sl_ix,
		uint32_t replication_factor, const uint32_t* rack_ids, uint32_t n_ids,
		uint32_t n_racks, uint32_t start_n)
{
	uint32_t n_needed = n_racks < replication_factor ?
			n_racks : replication_factor;

	uint32_t next_n = n_needed; // next candidate index to swap with

	for (uint32_t cur_n = start_n; cur_n < n_needed; cur_n++) {
		uint32_t cur_rack_id = RACK_ID(cur_n);

		// If cur_rack_id is unique for nodes < cur_n, continue to next node.
		if (is_rack_distinct_before_n(ns_sl_ix, rack_ids, cur_rack_id, cur_n)) {
			continue;
		}

		// Find rack-id after cur_n that's unique for rack-ids before cur_n.
		uint32_t swap_n = cur_n; // if swap cannot be found then no change

		while (next_n < n_ids) {
			uint32_t next_rack_id = RACK_ID(next_n);

			if (is_rack_distinct_before_n(ns_sl_ix, rack_ids, next_rack_id,
					cur_n)) {
				swap_n = next_n;
				next_n++;
				break;
			}

			next_n++;
		}

		cf_assert(swap_n > cur_n, AS_PARTITION, "no eligible rack (%u,%u)",
				swap_n, cur_n);

		// Now swap cur_n with swap_n.

		// Swap node.
		cf_node temp_node = ns_node_seq[swap_n];

		ns_node_seq[swap_n] = ns_node_seq[cur_n];
		ns_node_seq[cur_n] = temp_node;

		// Swap succession list index.
		sl_ix_t temp_ix = ns_sl_ix[swap_n];

		ns_sl_ix[swap_n] = ns_sl_ix[cur_n];
		ns_sl_ix[cur_n] = temp_ix;
	}
}

void
emig_lead_flags_ap(const as_partition* p, const sl_ix_t* ns_sl_ix,
		const as_namespace* ns, uint32_t lead_flags[])
{
	for (uint32_t repl_ix = 0; repl_ix < ns->replication_factor; repl_ix++) {
		const as_partition_version* version = INPUT_VERSION(repl_ix);

		lead_flags[repl_ix] =
				as_partition_version_has_data(version) && version->evade == 0 ?
						TX_FLAGS_LEAD : TX_FLAGS_NONE;
	}
}

bool
drop_superfluous_version(as_partition* p, as_namespace* ns)
{
	if (ns->is_quiesced) {
		return false;
	}

	p->version = ZERO_VERSION;

	return true;
}

// Called only for quiesced non-replicas with non-null version (right after
// drop_superfluous_version() returns false).
bool
adjust_superfluous_version(as_partition* p, as_namespace* ns)
{
	if (ns->cp) {
		// Should already be subset - no families to worry about.

		if (p->version.evade == 0 && p->version.revived == 0) {
			return false;
		}

		p->version.evade = 0;
		p->version.revived = 0;

		return true;
	}

	as_partition_version subset_version = p->final_version;

	subset_version.subset = 1;

	if (as_partition_version_same(&p->version, &subset_version)) {
		return false; // perhaps the quiesced node that was acting master
	}
	// else - was an "extra" quiesced node - adjust to subset of final version.

	p->version = subset_version;

	return true;
}

void
emigrate_done_advance_non_master_version(as_namespace* ns, as_partition* p,
		uint32_t tx_flags)
{
	if (! ns->cp) {
		emigrate_done_advance_non_master_version_ap(ns, p, tx_flags);
	}
}

void
immigrate_start_advance_non_master_version(as_namespace* ns, as_partition* p)
{
	if (ns->cp) {
		cf_assert(p->version.master == 0, AS_PARTITION, "non master had master flag set");
	}
	else {
		immigrate_start_advance_non_master_version_ap(p);
	}
}

void
immigrate_done_advance_final_master_version(as_namespace* ns, as_partition* p)
{
	if (ns->cp) {
		p->regime++;
	}
	else {
		immigrate_done_advance_final_master_version_ap(ns, p);
	}
}

bool
immigrate_yield()
{
	return g_appeal_phase && g_n_live_appeals_remaining != 0;
}


//==========================================================
// Local helpers.
//

bool
node_was_removed_from_roster(const as_namespace* ns)
{
	uint32_t n_smd = 0;

	for (uint32_t n = 0; n < ns->roster_count; n++) {
		cf_node node = ns->roster[n];
		bool found = false;

		while (n_smd < ns->smd_roster_count) {
			cf_node smd_node = ns->smd_roster[n_smd++];

			if (smd_node == node) {
				found = true;
				break;
			}

			if (smd_node < node) {
				return true;
			}
		}

		if (! found) {
			return true;
		}
	}

	return false;
}

void
balance_namespace_cp(as_namespace* ns, cf_queue* mq)
{
	if (ns->cluster_size != g_cluster_size) {
		cf_info(AS_PARTITION, "{%s} is on %u of %u nodes", ns->name,
				ns->cluster_size, g_cluster_size);
	}

	// Preserve namespace succession list for roster info command.
	ns->observed_cluster_size = ns->cluster_size;
	memcpy(ns->observed_succession, ns->succession,
			sizeof(cf_node) * ns->cluster_size);

	cf_info(AS_PARTITION, "{%s} rebalance with roster gen %u nodes %u",
			ns->name, ns->roster_generation, ns->roster_count);

	ignore_non_roster_nodes(ns);

	uint64_t inception_key = ignore_ckey_mismatched_nodes(ns);

	if (! contains_self(ns->succession, ns->cluster_size)) {
		ignore_self(ns);
		return;
	}

	// Make sure replication factor doesn't exceed roster size.
	adjust_replication_factor(ns);

	uint32_t n_roster_racks = roster_rack_count(ns);
	uint32_t n_racks = n_roster_racks;

	// Active size will be less than cluster size if nodes are quiesced.
	set_active_size(ns);

	// If namespace is rack-aware or uniform balance is preferred or nodes are
	// quiesced, we'll adjust the node sequences.
	bool will_adjust_rows = n_roster_racks != 1 || ns->prefer_uniform_balance ||
			ns->active_size != ns->cluster_size;

	if (will_adjust_rows && ns->active_size != ns->roster_count) {
		n_racks = live_roster_rack_count(ns);
	}

	// ns->cluster_size decreases if nodes are ignored - check again here.
	bool ns_less_than_global = ns->cluster_size != g_cluster_size;

	// If namespace is not on all nodes, or nodes were ignored, or we'll adjust
	// rows, it can't use the global node sequence and index tables.
	bool ns_not_equal_global = ns_less_than_global || will_adjust_rows;

	// The translation array is used to convert global table rows to namespace
	// rows, if  necessary.
	int translation[ns_less_than_global ? g_cluster_size : 0];

	if (ns_less_than_global) {
		fill_translation(translation, ns);
	}

	// Pre-hash roster node-ids.
	uint64_t hashed_roster_nodes[ns->roster_count];

	for (uint32_t n = 0; n < ns->roster_count; n++) {
		hashed_roster_nodes[n] = cf_hash_fnv64((const uint8_t*)&ns->roster[n],
				sizeof(cf_node));
	}

	uint32_t claims_size = ns->prefer_uniform_balance ?
			ns->replication_factor * ns->roster_count : 0;
	uint32_t roster_claims[claims_size];
	uint32_t roster_target_claims[claims_size];

	if (ns->prefer_uniform_balance) {
		memset(roster_claims, 0, sizeof(roster_claims));
		init_target_claims_cp(ns, roster_target_claims);
	}

	cf_info(AS_PARTITION, "{%s} %u of %u nodes participating - regime %u -> %u",
			ns->name, ns->cluster_size, g_cluster_size, ns->rebalance_regime,
			ns->eventual_regime);

	cf_assert(ns->rebalance_regime < ns->eventual_regime, AS_PARTITION,
			"{%s} regime must advance - regime %u eventual %u", ns->name,
			ns->rebalance_regime, ns->eventual_regime);

	uint32_t max_regime = ns->eventual_regime - 2;

	uint32_t ns_pending_emigrations = 0;
	uint32_t ns_pending_lead_emigrations = 0;
	uint32_t ns_pending_immigrations = 0;
	uint32_t ns_pending_signals = 0;

	uint32_t ns_pending_appeals = 0;
	uint32_t ns_unavailable_partitions = 0;

	for (uint32_t pid_group = 0; pid_group < NUM_PID_GROUPS; pid_group++) {
		uint32_t start_pid = pid_group * PIDS_PER_GROUP;
		uint32_t end_pid = start_pid + PIDS_PER_GROUP;

		for (uint32_t pid = start_pid; pid < end_pid; pid++) {
			as_partition* p = &ns->partitions[pid];

			cf_node ns_roster_node_seq[ns->roster_count];
			sl_ix_t ns_roster_sl_ix[ns->roster_count];

			fill_roster_node_seq(ns, pid, hashed_roster_nodes,
					ns_roster_node_seq, ns_roster_sl_ix);

			cf_node* full_node_seq = &FULL_NODE_SEQ(pid, 0);
			sl_ix_t* full_sl_ix = &FULL_SL_IX(pid, 0);

			// Usually a namespace can simply use the global tables...
			cf_node* ns_node_seq = full_node_seq;
			sl_ix_t* ns_sl_ix = full_sl_ix;

			cf_node stack_node_seq[ns_not_equal_global ? ns->cluster_size : 0];
			sl_ix_t stack_sl_ix[ns_not_equal_global ? ns->cluster_size : 0];

			// ... but sometimes a namespace is different.
			if (ns_not_equal_global) {
				ns_node_seq = stack_node_seq;
				ns_sl_ix = stack_sl_ix;

				fill_namespace_rows(full_node_seq, full_sl_ix, ns_node_seq,
						ns_sl_ix, ns, translation);

				if (ns->active_size != ns->cluster_size) {
					quiesce_adjust_row(ns_node_seq, ns_sl_ix, ns);
				}

				if (ns->prefer_uniform_balance) {
					uniform_adjust_row_cp(ns_roster_node_seq, ns_roster_sl_ix,
							ns_node_seq, ns_sl_ix, ns, roster_claims,
							roster_target_claims, n_roster_racks, n_racks);
				}
				else if (n_roster_racks != 1) {
					rack_aware_adjust_row_cp(ns_roster_node_seq,
							ns_roster_sl_ix, ns_node_seq, ns_sl_ix, ns,
							n_roster_racks, n_racks);
				}
			}

			cf_mutex_lock(&p->lock);

			p->working_master = (cf_node)0;

			p->n_dupl = 0;

			p->pending_emigrations = 0;
			p->pending_lead_emigrations = 0;
			p->pending_immigrations = 0;

			memset(p->immigrators, 0, ns->replication_factor * sizeof(bool));

			p->n_witnesses = 0;

			fix_lagging_partition(p, ns_roster_node_seq, ns_node_seq, ns_sl_ix,
					ns, max_regime);

			// Temporary paranoia:
			validate_one_master(p, ns_node_seq, ns_sl_ix, ns);

			uint32_t lead_flags[ns->replication_factor];

			memset(lead_flags, 0, sizeof(lead_flags));

			if (! partition_is_alive(p, ns_roster_node_seq, ns_node_seq,
					ns_sl_ix, ns, lead_flags)) {
				// <><><><><><>  Unavailable Partition  <><><><><><>

				ns_unavailable_partitions++;

				p->n_nodes = 0;
				p->n_replicas = 0;

				p->final_version = ZERO_VERSION;

				// Treat version as if node down & back.
				if (as_partition_version_has_data(&p->version)) {
					p->version.master = 0;
					p->version.subset = 1;
				}

				// Report no ownership.
				client_replica_maps_update(ns, pid);

				// No unlock - done in groups.
				continue;
			}
			// else - <><><><><><>  Live Partition  <><><><><><>

			p->n_nodes = ns->cluster_size;
			p->n_replicas = ns->replication_factor;
			memcpy(p->replicas, ns_node_seq, p->n_nodes * sizeof(cf_node));

			uint32_t self_n = find_self(ns_node_seq, ns);

			as_partition_version final_version = {
					.ckey = inception_key,
					.master = self_n == 0 ? 1 : 0
			};

			p->final_version = final_version;

			int working_master_n = find_working_master_cp(p, ns_sl_ix, ns);

			uint32_t n_dupl = 0;
			cf_node dupls[ns->cluster_size];

			as_partition_version orig_version = p->version;

			// TEMPORARY debugging.
			uint32_t debug_n_immigrators = 0;

			if (working_master_n == -1) {
				// No existing versions - assign fresh version to replicas.
				working_master_n = 0;

				// Zero non-replicas only to clear 'r' flags.
				p->version = self_n < p->n_replicas ?
						p->final_version : ZERO_VERSION;
			}
			else {
				n_dupl = find_duplicates_cp(p, ns_node_seq, ns_sl_ix, ns,
						(uint32_t)working_master_n, dupls);

				uint32_t n_immigrators = fill_immigrators(p, ns_sl_ix, ns,
						(uint32_t)working_master_n, n_dupl);

				// TEMPORARY debugging.
				debug_n_immigrators = n_immigrators;

				if (n_immigrators != 0) {
					// Migrations required - advance versions for next
					// rebalance, queue migrations for this rebalance.

					advance_version_cp(p, ns_sl_ix, ns, self_n,
							(uint32_t)working_master_n, n_dupl);

					if (queue_appeal(p, ns, self_n, (uint32_t)working_master_n,
							mq)) {
						ns_pending_appeals++;
					}

					queue_namespace_migrations(p, ns, self_n,
							ns_node_seq[working_master_n], n_dupl, dupls,
							lead_flags, mq);

					if (self_n == 0) {
						fill_witnesses(p, ns_node_seq, ns_sl_ix, ns);
						ns_pending_signals += p->n_witnesses;
					}
				}
				else if (self_n < p->n_replicas) {
					// No migrations required, appeals are done - but may have
					// shifted master flag.
					p->version = p->final_version;
				}
				else {
					// No migrations required - drop superfluous non-replica
					// partitions immediately.
					if (! as_partition_version_is_null(&p->version) &&
							! drop_superfluous_version(p, ns)) {
						// Quiesced nodes already subset, but clear other flags.
						adjust_superfluous_version(p, ns);
					}

					//  Cancel appeal if such.
					partition_balance_appeal_done(p, ns);
				}
			}

			if (self_n == 0 || self_n == working_master_n) {
				p->working_master = ns_node_seq[working_master_n];
			}

			p->regime = working_master_n == 0 ?
					ns->eventual_regime : ns->eventual_regime - 1;

			handle_version_change(p, ns, &orig_version);

			ns_pending_emigrations += p->pending_emigrations;
			ns_pending_lead_emigrations += p->pending_lead_emigrations;
			ns_pending_immigrations += p->pending_immigrations;

			// TEMPORARY debugging.
			if (pid < 20) {
				cf_debug(AS_PARTITION, "{%s} ck%012lX %02u rg %u (%hu %hu) %s -> %s - self_n %u wm_n %d repls %u dupls %u immigrators %u",
						ns->name, as_exchange_cluster_key(), pid, p->regime,
						p->pending_emigrations, p->pending_immigrations,
						VERSION_AS_STRING(&orig_version),
						VERSION_AS_STRING(&p->version), self_n,
						working_master_n, p->n_replicas, n_dupl,
						debug_n_immigrators);
			}

			client_replica_maps_update(ns, pid);
		}

		// Flush partition metadata for this group of partitions ...
		as_storage_flush_pmeta(ns, start_pid, PIDS_PER_GROUP);

		// ... and unlock the group.
		for (uint32_t pid = start_pid; pid < end_pid; pid++) {
			as_partition* p = &ns->partitions[pid];

			cf_mutex_unlock(&p->lock);
		}
	}

	// After updating client map - can't have new regime with stale map.
	ns->rebalance_regime = ns->eventual_regime;

	// Ensure startup will detect roster reduction that didn't complete safely.
	as_storage_save_roster_generation(ns);

	if (ns_unavailable_partitions != 0 &&
			ns->cluster_size == ns->roster_count) {
		cf_warning(AS_PARTITION, "{%s} rebalanced: regime %u expected-migrations (%u,%u,%u) expected-appeals %u dead-partitions %u",
				ns->name, ns->rebalance_regime, ns_pending_emigrations,
				ns_pending_immigrations, ns_pending_signals, ns_pending_appeals,
				ns_unavailable_partitions);

		ns->n_dead_partitions = ns_unavailable_partitions;
		ns->n_unavailable_partitions = 0;
	}
	else {
		cf_info(AS_PARTITION, "{%s} rebalanced: regime %u expected-migrations (%u,%u,%u) expected-appeals %u unavailable-partitions %u",
				ns->name, ns->rebalance_regime, ns_pending_emigrations,
				ns_pending_immigrations, ns_pending_signals, ns_pending_appeals,
				ns_unavailable_partitions);

		ns->n_dead_partitions = 0;
		ns->n_unavailable_partitions = ns_unavailable_partitions;
	}

	ns->migrate_tx_partitions_initial = ns_pending_emigrations;
	ns->migrate_tx_partitions_remaining = ns_pending_emigrations;
	ns->migrate_tx_partitions_lead_remaining = ns_pending_lead_emigrations;

	ns->migrate_rx_partitions_initial = ns_pending_immigrations;
	ns->migrate_rx_partitions_remaining = ns_pending_immigrations;

	ns->migrate_signals_remaining = ns_pending_signals;

	ns->appeals_tx_remaining = ns_pending_appeals;
}

void
ignore_non_roster_nodes(as_namespace* ns)
{
	uint32_t n = 0;
	uint32_t roster_n = 0;
	uint32_t write_n = 0;

	while (n < ns->cluster_size && roster_n < ns->roster_count) {
		if (ns->succession[n] == ns->roster[roster_n]) {
			if (write_n != n) {
				ns->succession[write_n] = ns->succession[n];
				memcpy(&ns->cluster_versions[write_n], &ns->cluster_versions[n],
						sizeof(as_partition_version) * AS_PARTITIONS);
				ns->rebalance_regimes[write_n] = ns->rebalance_regimes[n];
				ns->quiesced[write_n] = ns->quiesced[n];
			}

			n++;
			roster_n++;
			write_n++;
		}
		else if (ns->succession[n] > ns->roster[roster_n]) {
			cf_warning(AS_PARTITION, "{%s} ignoring node %lx - not on roster",
					ns->name, ns->succession[n]);

			n++;
		}
		else { // roster node not in cluster
			roster_n++;
		}
	}

	while (n < ns->cluster_size) {
		cf_warning(AS_PARTITION, "{%s} ignoring node %lx - not on roster",
				ns->name, ns->succession[n]);

		n++;
	}

	ns->cluster_size = write_n;
}

uint64_t
ignore_ckey_mismatched_nodes(as_namespace* ns)
{
	if (ns->cluster_size == 0) {
		return 0; // initial cluster formation
	}

	uint64_t ckeys[ns->cluster_size];

	memset(ckeys, 0, sizeof(ckeys));

	for (uint32_t n = 0; n < ns->cluster_size; n++) {
		for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
			uint64_t ckey = ns->cluster_versions[n][pid].ckey;

			if (ckey != 0) {
				ckeys[n] = ckey;
				break;
			}
		}
	}

	uint64_t sorted_ckeys[ns->cluster_size];

	memcpy(sorted_ckeys, ckeys, sizeof(ckeys));
	qsort(sorted_ckeys, ns->cluster_size, sizeof(uint64_t),
			cf_compare_uint64_desc);

	uint64_t best_ckey = 0;
	uint32_t best_ckey_count = 0;
	uint64_t cur_ckey = 0;
	uint32_t cur_ckey_count = 0;

	for (uint32_t n = 0; n < ns->cluster_size; n++) {
		uint64_t ckey_n = sorted_ckeys[n];

		if (ckey_n == 0) {
			break;
		}

		if (ckey_n == cur_ckey) {
			cur_ckey_count++;
			continue;
		}

		if (cur_ckey_count > best_ckey_count) {
			best_ckey = cur_ckey;
			best_ckey_count = cur_ckey_count;
		}

		cur_ckey = ckey_n;
		cur_ckey_count = 1;
	}

	if (best_ckey == 0) {
		// All non-zero ckeys are the same, or all ckeys are zero.
		return cur_ckey != 0 ? cur_ckey : as_exchange_cluster_key();
	}

	uint32_t write_n = 0;

	for (uint32_t n = 0; n < ns->cluster_size; n++) {
		uint64_t ckey_n = ckeys[n];

		if (ckey_n == best_ckey || ckey_n == 0) {
			if (write_n != n) {
				ns->succession[write_n] = ns->succession[n];
				memcpy(&ns->cluster_versions[write_n], &ns->cluster_versions[n],
						sizeof(as_partition_version) * AS_PARTITIONS);
				ns->rebalance_regimes[write_n] = ns->rebalance_regimes[n];
			}

			write_n++;
		}
		else {
			cf_warning(AS_PARTITION, "{%s} ignoring node %lx - mismatched ckey",
					ns->name, ns->succession[n]);
		}
	}

	ns->cluster_size = write_n;

	return best_ckey;
}

void
ignore_self(as_namespace* ns)
{
	cf_info(AS_PARTITION, "{%s} self node %lx excluded from cluster", ns->name,
			g_config.self_node);

	ns->replication_factor = 0;
	ns->cluster_size = 0;
	ns->active_size = 0;
	ns->is_quiesced = false;

	client_replica_maps_clear(ns);

	bool has_data = false;

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition* p = &ns->partitions[pid];

		cf_mutex_lock(&p->lock);

		as_partition_freeze(p);
		as_partition_isolate_version(ns, p);

		if (as_partition_version_has_data(&p->version)) {
			cf_mutex_unlock(&p->lock);

			has_data = true;
			break;
		}

		// If it's an empty node, assume it's ok to trust it and include it in
		// super majority logic ...

		p->version.evade = 0;
		p->version.revived = 0;
		as_storage_cache_pmeta(ns, p);

		cf_mutex_unlock(&p->lock);
	}

	if (! has_data) {
		as_storage_flush_pmeta(ns, 0, AS_PARTITIONS);
		return;
	}

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition* p = &ns->partitions[pid];

		cf_mutex_lock(&p->lock);

		as_partition_freeze(p);
		as_partition_isolate_version(ns, p);

		// ... otherwise, assume it may be missing the latest data and should
		// not participate in super majority logic.

		p->version.evade = 1;
		p->version.revived = 0;
		as_storage_cache_pmeta(ns, p);

		cf_mutex_unlock(&p->lock);
	}

	as_storage_flush_pmeta(ns, 0, AS_PARTITIONS);
}

void
adjust_replication_factor(as_namespace* ns)
{
	// Deal with oversize ns->cfg_replication_factor.
	ns->replication_factor = ns->cfg_replication_factor > ns->roster_count ?
			ns->roster_count : ns->cfg_replication_factor;

	// Note - if ns->cluster_size ends up less than ns->replication_factor,
	// partitions will all be unavailable.

	cf_info(AS_PARTITION, "{%s} replication factor is %u", ns->name,
			ns->replication_factor);
}

uint32_t
roster_rack_count(const as_namespace* ns)
{
	uint32_t ids[ns->roster_count];

	memcpy(ids, ns->roster_rack_ids, sizeof(ids));

	return rack_id_count(ids, ns->roster_count);
}

uint32_t
live_roster_rack_count(const as_namespace* ns)
{
	uint32_t ids[ns->active_size];
	uint32_t write_n = 0;
	uint32_t n = 0;
	uint32_t roster_n = 0;

	while (write_n < ns->active_size) {
		if (ns->succession[n] == ns->roster[roster_n]) {
			if (! ns->quiesced[n]) {
				ids[write_n++] = ns->roster_rack_ids[roster_n];
			}

			n++;
		}

		roster_n++;
	}

	return rack_id_count(ids, ns->active_size);
}

uint32_t
rack_id_count(uint32_t* ids, uint32_t n_ids)
{
	qsort(ids, n_ids, sizeof(uint32_t), cf_compare_uint32_desc);

	if (ids[0] == ids[n_ids - 1]) {
		return 1; // common path - not rack-aware
	}

	uint32_t n_racks = 1;
	uint32_t cur_id = ids[0];

	for (uint32_t i = 1; i < n_ids; i++) {
		if (ids[i] != cur_id) {
			cur_id = ids[i];
			n_racks++;
		}
	}

	return n_racks;
}

// Just like init_target_claims_ap(), except we're generating claims for the
// roster, independent of which nodes are present in the current cluster.
// Therefore no translation table is necessary.
void
init_target_claims_cp(const as_namespace* ns, uint32_t* target_claims)
{
	g_claims_row_size = ns->roster_count;

	uint32_t n_nodes = ns->roster_count;

	// Special case rf=all to only balance masters.
	uint32_t n_replicas = ns->replication_factor == n_nodes ?
			1 : ns->replication_factor;

	uint32_t claims_size = n_replicas * g_claims_row_size;
	uint32_t min_claims = AS_PARTITIONS / n_nodes;

	for (uint32_t t = 0; t < claims_size; t++) {
		target_claims[t] = min_claims;
	}

	uint32_t remainder = AS_PARTITIONS % ns->roster_count;

	if (remainder == 0) {
		return;
	}

	uint32_t r = 0;
	uint32_t n = 0;
	uint32_t n_used = 0;

	while (r < n_replicas) {
		TARGET_CLAIMS(r, n)++;
		n_used++;
		n++;

		if (n_used == remainder) {
			n_used = 0;
			r++;
		}

		if (n == g_claims_row_size) {
			n = 0;
		}
	}
}

void
fill_roster_node_seq(const as_namespace* ns, uint32_t pid,
		const uint64_t* hashed_nodes, cf_node* roster_node_seq,
		sl_ix_t* ns_roster_sl_ix)
{
	inter_hash h;

	h.hashed_pid = g_hashed_pids[pid];

	for (uint32_t n = 0; n < ns->roster_count; n++) {
		h.hashed_node = hashed_nodes[n];

		cf_node* node_p = &roster_node_seq[n];

		*node_p = cf_hash_jen64((const uint8_t*)&h, sizeof(h));

		// Overlay index onto last byte.
		*node_p &= AS_CLUSTER_SZ_MASKP;
		*node_p += n;
	}

	// Sort the hashed node values.
	qsort(roster_node_seq, ns->roster_count, sizeof(cf_node),
			cf_node_compare_desc);

	// Overwrite the sorted hash values with the original node IDs.
	for (uint32_t n = 0; n < ns->roster_count; n++) {
		cf_node* node_p = &roster_node_seq[n];
		sl_ix_t sl_ix = (sl_ix_t)(*node_p & AS_CLUSTER_SZ_MASKN);

		*node_p = ns->roster[sl_ix];

		// Saved to refer back to roster-rack-id list.
		ns_roster_sl_ix[n] = sl_ix;
	}
}

void
uniform_adjust_row_cp(cf_node* ns_roster_node_seq, sl_ix_t* ns_roster_sl_ix,
		cf_node* ns_node_seq, sl_ix_t* ns_sl_ix, const as_namespace* ns,
		uint32_t* roster_claims, const uint32_t* roster_target_claims,
		uint32_t n_roster_racks, uint32_t n_racks)
{
	// Adjust roster.
	uniform_adjust_row(ns_roster_node_seq, ns->roster_count, ns_roster_sl_ix,
			ns->replication_factor, roster_claims, roster_target_claims,
			ns->roster_rack_ids, n_roster_racks);

	// Rearrange ns_node_seq to follow adjusted roster. Also apply rack-aware
	// second pass if applicable.
	follow_adjusted_roster(ns_roster_node_seq, ns_roster_sl_ix, ns_node_seq,
			ns_sl_ix, ns, n_racks);
}

void
rack_aware_adjust_row_cp(cf_node* ns_roster_node_seq, sl_ix_t* ns_roster_sl_ix,
		cf_node* ns_node_seq, sl_ix_t* ns_sl_ix, const as_namespace* ns,
		uint32_t n_roster_racks, uint32_t n_racks)
{
	if (ns->cluster_size < ns->replication_factor) {
		return; // will be unavailable - don't bother
	}

	// Apply rack-aware algorithm to full roster.
	rack_aware_adjust_row(ns_roster_node_seq, ns_roster_sl_ix,
			ns->replication_factor, ns->roster_rack_ids, ns->roster_count,
			n_roster_racks, 1);

	// Often, roster replicas will all be present and in original order.
	if (memcmp(ns_roster_node_seq, ns_node_seq,
			sizeof(cf_node) * ns->replication_factor) == 0) {
		return; // already rack-aware
	}

	// Rearrange ns_node_seq to follow rack-aware roster. Also apply rack-aware
	// second pass if applicable.
	follow_adjusted_roster(ns_roster_node_seq, ns_roster_sl_ix, ns_node_seq,
			ns_sl_ix, ns, n_racks);
}

void
follow_adjusted_roster(cf_node* ns_roster_node_seq, sl_ix_t* ns_roster_sl_ix,
		cf_node* ns_node_seq, sl_ix_t* ns_sl_ix, const as_namespace* ns,
		uint32_t n_racks)
{
	// Set up roster rack-ids in layout of full_node_seq - this is how ns_sl_ix
	// will find rack-ids if we apply rack-aware a second time below.
	uint32_t rack_ids[g_cluster_size];

	// Rearrange into these arrays.
	cf_node tmp_node_seq[ns->active_size];
	sl_ix_t tmp_sl_ix[ns->active_size];
	uint32_t write_n = 0;

	uint32_t n_roster_replicas = 0; // roster replicas present

	// Handle anything which may have moved.
	for (uint32_t roster_n = 0;
			roster_n < ns->roster_count && write_n < ns->active_size;
			roster_n++) {
		cf_node roster_node = ns_roster_node_seq[roster_n];

		// Check the matching location first - high odds it's there.
		if (roster_node == ns_node_seq[write_n]) {
			tmp_node_seq[write_n] = roster_node;
			tmp_sl_ix[write_n] = ns_sl_ix[write_n];
			rack_ids[ns_sl_ix[write_n]] =
					ns->roster_rack_ids[ns_roster_sl_ix[roster_n]];
			write_n++;

			if (roster_n < ns->replication_factor) {
				n_roster_replicas++;
			}

			continue;
		}

		for (uint32_t n = 0; n < ns->active_size; n++) {
			if (roster_node == ns_node_seq[n]) {
				tmp_node_seq[write_n] = roster_node;
				tmp_sl_ix[write_n] = ns_sl_ix[n];
				rack_ids[ns_sl_ix[n]] =
						ns->roster_rack_ids[ns_roster_sl_ix[roster_n]];
				write_n++;

				if (roster_n < ns->replication_factor) {
					n_roster_replicas++;
				}

				break;
			}
		}
	}

	// Use rearranged sequence that follows adjusted roster.
	memcpy(ns_node_seq, tmp_node_seq, ns->active_size * sizeof(cf_node));
	memcpy(ns_sl_ix, tmp_sl_ix, ns->active_size * sizeof(sl_ix_t));

	// All roster replicas present (but rearranged) - as rack-aware as possible.
	if (n_roster_replicas == ns->replication_factor) {
		return;
	}

	// No roster replicas present, will be unavailable - don't bother.
	if (n_roster_replicas == 0) {
		return;
	}

	// Roster replica(s) missing - must apply rack-aware algorithm again,
	// starting at the first interim replica.
	if (n_racks != 1) {
		rack_aware_adjust_row(ns_node_seq, ns_sl_ix, ns->replication_factor,
				rack_ids, ns->active_size, n_racks, n_roster_replicas);
	}
}

// Returns true if rack_id is unique within nodes list indices less than n.
bool
is_rack_distinct_before_n(const sl_ix_t* ns_sl_ix, const uint32_t* rack_ids,
		uint32_t rack_id, uint32_t n)
{
	for (uint32_t cur_n = 0; cur_n < n; cur_n++) {
		uint32_t cur_rack_id = RACK_ID(cur_n);

		if (cur_rack_id == rack_id) {
			return false;
		}
	}

	return true;
}

void
fix_lagging_partition(as_partition* p, const cf_node* ns_roster_node_seq,
		const cf_node* ns_node_seq, const sl_ix_t* ns_sl_ix, as_namespace* ns,
		uint32_t max_regime)
{
	if (max_regime == 0 || ns->cfg_replication_factor == 1) {
		return;
	}

	// If all roster replicas' regimes match - and no other nodes are full or
	// master - it's ok to keep full or master roster replicas even if their
	// regimes lag. This preserves some availability in very special cases ...

	bool regimes_match = true;
	uint32_t n = 0;
	uint32_t rebalance_regime = 0;

	for (uint32_t roster_n = 0;
			roster_n < ns->replication_factor && n < ns->cluster_size;
			roster_n++) {
		if (ns_node_seq[n] == ns_roster_node_seq[roster_n]) {
			uint32_t regime_n = ns->rebalance_regimes[ns_sl_ix[n]];

			if (rebalance_regime == 0) {
				rebalance_regime = regime_n;
			}
			else if (rebalance_regime != regime_n) {
				regimes_match = false;
				break;
			}

			n++;
		}
	}

	if (regimes_match && n == ns->replication_factor) {
		while (n < ns->cluster_size) {
			as_partition_version* version = INPUT_VERSION(n);

			if (as_partition_version_has_data(version) &&
					(version->subset == 0 || version->master == 1)) {
				break;
			}

			n++;
		}

		if (n == ns->cluster_size) {
			return;
		}
	}

	// ... but normally, don't keep full or master status if the regime lags.

	for (n = 0; n < ns->cluster_size; n++) {
		as_partition_version* version = INPUT_VERSION(n);

		if (as_partition_version_has_data(version) &&
				(version->subset == 0 || version->master == 1) &&
				max_regime > ns->rebalance_regimes[ns_sl_ix[n]]) {
			version->master = 0;
			version->subset = 1;

			if (g_config.self_node == ns_node_seq[n]) {
				p->version.master = 0;
				p->version.subset = 1;
			}
		}
	}
}

// Temporary paranoia:
void
validate_one_master(const as_partition* p, const cf_node* ns_node_seq,
		const sl_ix_t* ns_sl_ix, const as_namespace* ns)
{
	uint32_t m = 0;
	cf_node master = (cf_node)0;
	const as_partition_version* master_version = NULL;
	uint32_t master_regime = 0;

	for (uint32_t n = 0; n < ns->cluster_size; n++) {
		const as_partition_version* version = INPUT_VERSION(n);

		if (version->master == 1) {
			cf_assert(master == (cf_node)0, AS_PARTITION,
					"{%s} pid %u has 2 masters [%u:%lx:%s:%u] [%u:%lx:%s:%u]",
					ns->name, p->id,
					m, master, VERSION_AS_STRING(master_version), master_regime,
					n, ns_node_seq[n], VERSION_AS_STRING(version),
					ns->rebalance_regimes[ns_sl_ix[n]]);

			m = n;
			master = ns_node_seq[n];
			master_version = version;
			master_regime = ns->rebalance_regimes[ns_sl_ix[n]];
		}
	}
}

bool
partition_is_alive(const as_partition* p, const cf_node* ns_roster_node_seq,
		const cf_node* ns_node_seq, const sl_ix_t* ns_sl_ix,
		const as_namespace* ns, uint32_t lead_flags[])
{
	if (ns->cluster_size < ns->replication_factor) {
		return false; // can't ever fully replicate - unavailable
	}

	uint32_t n_roster_replicas = find_n_roster_replicas(ns_roster_node_seq,
			ns_node_seq, ns, lead_flags);

	if (n_roster_replicas == 0) {
		return false; // no roster replicas - unavailable
	}

	bool has_full_version = false;
	bool has_data = false;
	uint32_t n_not_trusted = 0;
	uint32_t n_revived = 0;

	for (uint32_t n = 0; n < ns->cluster_size; n++) {
		const as_partition_version* version = INPUT_VERSION(n);

		if (as_partition_version_has_data(version)) {
			has_data = true;

			if (version->subset == 0) {
				has_full_version = true;
				break; // there's a full version - that's all the info we need
			}
		}

		if (version->evade == 1) {
			n_not_trusted++;
		}

		if (version->revived == 1) {
			n_revived++;
		}
	}

	if (! has_data) {
		// If all roster nodes are present and trusted - live (inception).
		return n_not_trusted == 0 && ns->cluster_size == ns->roster_count;
	}

	uint32_t half = ns->roster_count / 2; // rounded down
	bool majority = ns->cluster_size > half;
	bool winning_tie = ns->cluster_size == half &&
			(ns->roster_count & 1) == 0 &&
			ns_roster_node_seq[0] == ns_node_seq[0];

	// Handle majority or winning tie - need either full version and any
	// "roster replica", or "super majority" and any "roster replica".
	if (majority || winning_tie) {
		if (has_full_version) {
			return true;
		}
		// else - has only subsets.

		uint32_t n_missing = ns->roster_count - ns->cluster_size;

		// Revived node(s) need whole cluster to proceed.
		if (n_revived != 0) {
			return as_exchange_min_compatibility_id() < 11 ?
					n_missing == 0 : n_missing == 0 && n_not_trusted == 0;
		}

		// May promote subsets only if "super majority".
		if (n_missing + n_not_trusted < ns->replication_factor) {
			return true;
		}

		return false; // can't promote subsets - unavailable
	}

	// Minority, or losing tie - need full version and all "roster replicas".
	return has_full_version && n_roster_replicas == ns->replication_factor;
}

uint32_t
find_n_roster_replicas(const cf_node* ns_roster_node_seq,
		const cf_node* ns_node_seq, const as_namespace* ns,
		uint32_t lead_flags[])
{
	uint32_t n = 0;

	for (uint32_t roster_n = 0;
			roster_n < ns->replication_factor && n < ns->active_size;
			roster_n++) {
		if (ns_node_seq[n] == ns_roster_node_seq[roster_n]) {
			lead_flags[n++] = TX_FLAGS_LEAD;
		}
	}

	if (ns->active_size == ns->cluster_size || n == ns->replication_factor) {
		return n;
	}
	// else - roster replica(s) may be quiesced - check quiesced nodes.

	for (uint32_t roster_n = 0; roster_n < ns->replication_factor; roster_n++) {
		for (uint32_t q_n = ns->active_size; q_n < ns->cluster_size; q_n++) {
			if (ns_node_seq[q_n] == ns_roster_node_seq[roster_n]) {
				if (q_n < ns->replication_factor) {
					lead_flags[n] = TX_FLAGS_LEAD;
				}

				if (++n == ns->replication_factor) {
					return n;
				}
			}
		}
	}

	return n;
}

// Preference: Vm > V > Vs > absent.
int
find_working_master_cp(const as_partition* p, const sl_ix_t* ns_sl_ix,
		const as_namespace* ns)
{
	int best_n = -1;
	int best_score = -1;

	for (int n = 0; n < (int)ns->cluster_size; n++) {
		const as_partition_version* version = INPUT_VERSION(n);

		// Skip versions with no data.
		if (! as_partition_version_has_data(version)) {
			continue;
		}

		// If previous working master exists, use it.
		if (version->master == 1) {
			return shift_working_master(p, ns_sl_ix, ns, n, version);
		}
		// else - keep going but remember the best so far.

		// V = 1 > Vs = 0.
		int score = version->subset == 1 ? 0 : 1;

		if (score > best_score) {
			best_score = score;
			best_n = n;
		}
	}

	return best_n;
}

uint32_t
find_duplicates_cp(const as_partition* p, const cf_node* ns_node_seq,
		const sl_ix_t* ns_sl_ix, const as_namespace* ns,
		uint32_t working_master_n, cf_node dupls[])
{
	for (uint32_t n = 0; n < ns->cluster_size; n++) {
		const as_partition_version* version = INPUT_VERSION(n);

		if (as_partition_version_has_data(version) && version->subset == 0) {
			return 0;
		}
	}

	uint32_t n_dupl = 0;

	for (uint32_t n = 0; n < ns->cluster_size; n++) {
		if (n == working_master_n) {
			continue;
		}

		const as_partition_version* version = INPUT_VERSION(n);

		if (as_partition_version_has_data(version)) {
			dupls[n_dupl++] = ns_node_seq[n];
		}
	}

	return n_dupl;
}

void
advance_version_cp(as_partition* p, const sl_ix_t* ns_sl_ix, as_namespace* ns,
		uint32_t self_n, uint32_t working_master_n, uint32_t n_dupl)
{
	// Advance working master.
	if (self_n == working_master_n) {
		p->version.master = 1;

		if (n_dupl == 0) {
			// It's possible to have a lone version that's a subset - e.g.
			// VV000... -> Vs|Vs|000... -> Vs|Vs000...
			p->version.subset = 0;
		}

		return;
	}

	// When master shifts left, we must clear the master flag to the right.
	p->version.master = 0;

	bool has_data = as_partition_version_has_data(&p->version);

	// Advance eventual master and proles.
	if (self_n < p->n_replicas) {
		if (! has_data) {
			p->version.ckey = p->final_version.ckey;
			p->version.subset = 1;
		}

		return;
	}

	// Advance non-replicas.
	if (has_data) {
		p->version.subset = 1;
	}
	// else - leave version as-is.
}

bool
queue_appeal(as_partition* p, as_namespace* ns, uint32_t self_n,
		uint32_t working_master_n, cf_queue* mq)
{
	if (! p->must_appeal) {
		return false;
	}

	if (self_n == working_master_n) {
		// TODO - is it worth appealing to a non-working-master, or flagging to
		// avoid this node as master?
		partition_balance_appeal_done(p, ns);

		return false;
	}

	pb_task task;

	pb_task_init(&task, p->replicas[working_master_n], ns, p->id,
			as_exchange_cluster_key(), PB_TASK_APPEAL, TX_FLAGS_NONE);
	cf_queue_push(mq, &task);

	return true;
}
