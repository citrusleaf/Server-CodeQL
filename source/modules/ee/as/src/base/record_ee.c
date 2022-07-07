/*
 * record_ee.c
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

#include "base/record_ee.h"

#include <stdbool.h>
#include <stdint.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"

#include "log.h"
#include "msg.h"
#include "vmapx.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "base/set_index.h"
#include "fabric/clustering.h"
#include "fabric/exchange.h"
#include "fabric/partition.h"
#include "storage/storage.h"
#include "transaction/re_replicate_ee.h"
#include "transaction/rw_request_hash.h"
#include "transaction/rw_utils.h"


//==========================================================
// Typedefs & constants.
//

// Split 16-bit generation container into regime (high) and generation (low).
#define REGIME_BITS		6
#define GEN_BITS		(16 - REGIME_BITS)

COMPILER_ASSERT(REGIME_BITS <= sizeof(uint8_t) * 8);

#define REGIME_SHIFT	GEN_BITS
#define REGIME_MASK		((1 << REGIME_BITS) - 1)	// 0x3F
#define REGIME_WRAP		((1 << REGIME_BITS) / 2)	// 0x20

#define GEN_MASK		((1 << GEN_BITS) - 1)		// 0x3FF
#define GEN_OVERFLOW	(1 << GEN_BITS)				// 0x400
#define GEN_WRAP		(GEN_OVERFLOW / 2)			// 0x200

// Make sure CP nodes revert to orphan within regime reliability window.
COMPILER_ASSERT(((REGIME_WRAP / 2) - 2) > AS_EXCHANGE_REVERT_ORPHAN_INTERVALS);


//==========================================================
// Globals.
//

static uint64_t g_reliable_regime_ms = 0;
static uint64_t g_clock_skew_stop_writes_sec = 0;


//==========================================================
// Forward declarations.
//

void transition_set_stat_to_live(as_namespace* ns, uint16_t set_id);
void transition_set_stat_to_tombstone(as_namespace* ns, uint16_t set_id);
void drop_tombstone_set_stat(as_namespace* ns, uint16_t set_id);

void add_tombstone_partition_stat(as_namespace* ns, uint32_t pid);
void drop_tombstone_partition_stat(as_namespace* ns, uint32_t pid);


//==========================================================
// Inlines & macros.
//

static inline void
set_regime(as_record *r, uint32_t regime)
{
	r->generation = (r->generation & GEN_MASK) |
			((uint16_t)(regime & REGIME_MASK) << REGIME_SHIFT);
}

static inline bool
gen_less_than_cp(uint16_t left, uint16_t right)
{
	uint16_t plain_left = left & GEN_MASK;
	uint16_t plain_right = right & GEN_MASK;

	return ((plain_left - plain_right) & GEN_MASK) >= GEN_WRAP;
}

static inline int
resolve_generation_cp(uint16_t left, uint16_t right)
{
	return left == right ? 0 : (gen_less_than_cp(left, right) ? 1 : -1);
}


//==========================================================
// Public API.
//

// TODO - here because it needs the global - should probably be elsewhere.
uint32_t
clock_skew_stop_writes_sec()
{
	return (uint32_t)g_clock_skew_stop_writes_sec;
}


// TODO - here because it needs REGIME_WRAP - should probably be elsewhere.
bool
as_record_handle_clock_skew(as_namespace* ns, uint64_t skew_ms)
{
	if (! ns->cp) {
		return false;
	}

	g_reliable_regime_ms = as_clustering_quantum_interval() *
			((REGIME_WRAP / 2) - 1);

	g_clock_skew_stop_writes_sec = (((g_reliable_regime_ms * 3) / 4) / 1000);

	if (skew_ms > g_clock_skew_stop_writes_sec * 1000) {
		cf_ticker_warning(AS_RECORD, "{%s} clock-skew > %lu sec stopped writes",
				ns->name, g_clock_skew_stop_writes_sec);
		return true;
	}

	uint64_t skew_warn_sec = (g_clock_skew_stop_writes_sec * 3) / 4;

	if (skew_ms > skew_warn_sec * 1000) {
		cf_ticker_warning(AS_RECORD, "{%s} clock-skew > %lu sec", ns->name,
				skew_warn_sec);
	}

	return false;
}


uint16_t
plain_generation(uint16_t regime_generation, const as_namespace* ns)
{
	return ns->cp ? (regime_generation & GEN_MASK) : regime_generation;
}


void
as_record_set_lut(as_record *r, uint32_t regime, uint64_t now_ms,
		const as_namespace* ns)
{
	if (ns->cp) {
		set_regime(r, regime);
		r->last_update_time = now_ms;
	}
	else {
		// Note - last-update-time is not allowed to go backwards!
		if (r->last_update_time < now_ms) {
			r->last_update_time = now_ms;
		}
	}
}


void
as_record_increment_generation(as_record *r, const as_namespace* ns)
{
	// Note - tombstones always increment the live object's generation.

	if (ns->cp) {
		uint16_t plain_gen = r->generation & GEN_MASK;

		if (++plain_gen == GEN_OVERFLOW) {
			plain_gen = 1;
		}

		r->generation = (r->generation & ~GEN_MASK) | plain_gen;
	}
	else {
		// The generation might wrap - 0 is reserved as "uninitialized".
		if (++r->generation == 0) {
			r->generation = 1;
		}
	}
}


bool
as_record_is_binless(const as_record* r)
{
	return r->tombstone == 1 && r->xdr_bin_cemetery == 0;
}


bool
as_record_is_live(const as_record* r)
{
	return r->tombstone == 0;
}


int
as_record_get_live(as_index_tree* tree, const cf_digest* keyd,
		as_index_ref* r_ref, as_namespace* ns)
{
	int rv = as_index_get_vlock(tree, keyd, r_ref);

	// Treat tombstones as 'not found'.
	if (rv == 0 && r_ref->r->tombstone == 1) {
		as_record_done(r_ref, ns);
		return -1;
	}

	return rv;
}


void
as_record_drop_stats(as_record* r, as_namespace* ns)
{
	if (r->tombstone == 0) {
		cf_atomic64_decr(&ns->n_objects);

		// Note - no partition counter for live records.

		// Decrement set's live record count.
		as_namespace_release_set_id(ns, as_index_get_set_id(r));
	}
	else {
		cf_atomic64_decr(&ns->n_tombstones);

		as_decr_uint64(r->xdr_tombstone == 1 ?
				&ns->n_xdr_tombstones : &ns->n_durable_tombstones);

		if (r->xdr_bin_cemetery == 1) {
			as_decr_uint64(&ns->n_xdr_bin_cemeteries);
		}

		drop_tombstone_partition_stat(ns, as_partition_getid(&r->keyd));
		drop_tombstone_set_stat(ns, as_index_get_set_id(r));
	}

	if (ns->cp && r->repl_state == AS_REPL_STATE_UNREPLICATED) {
		as_decr_uint64(&ns->n_unreplicated_records);
	}
}


void
as_record_transition_stats(as_record* r, as_namespace* ns,
		const index_metadata* old)
{
	// Note - no partition counter for live records.

	bool was_live = ! old->tombstone;
	bool is_live = r->tombstone == 0; // or dropped

	bool was_xdr_tombstone = old->xdr_tombstone;
	bool was_bin_cemetery = old->xdr_bin_cemetery;

	if (was_live) {
		if (is_live) {
			// No tombstones involved, do nothing. Note that drops come here,
			// but no-op - they rely on as_record_destroy() called later.
			return;
		}
		// else - live record to tombstone.

		cf_atomic64_decr(&ns->n_objects);
		cf_atomic64_incr(&ns->n_tombstones);

		as_incr_uint64(r->xdr_tombstone == 1 ?
				&ns->n_xdr_tombstones : &ns->n_durable_tombstones);

		if (r->xdr_bin_cemetery == 1) {
			as_incr_uint64(&ns->n_xdr_bin_cemeteries);
		}

		add_tombstone_partition_stat(ns, as_partition_getid(&r->keyd));
		transition_set_stat_to_tombstone(ns, as_index_get_set_id(r));
		return;
	}
	// else - was tombstone.

	if (is_live) {
		// Tombstone to live record.
		cf_atomic64_incr(&ns->n_objects);
		cf_atomic64_decr(&ns->n_tombstones);

		as_decr_uint64(was_xdr_tombstone ?
				&ns->n_xdr_tombstones : &ns->n_durable_tombstones);

		if (was_bin_cemetery) {
			as_decr_uint64(&ns->n_xdr_bin_cemeteries);
		}

		drop_tombstone_partition_stat(ns, as_partition_getid(&r->keyd));
		transition_set_stat_to_live(ns, as_index_get_set_id(r));
		return;
	}
	// else - tombstone to tombstone. Any combo is possible at cold start.

	if (was_xdr_tombstone) {
		if (r->xdr_tombstone == 0) {
			// XDR to regular or bin cemetery.
			as_decr_uint64(&ns->n_xdr_tombstones);
			as_incr_uint64(&ns->n_durable_tombstones);

			if (r->xdr_bin_cemetery == 1) {
				as_incr_uint64(&ns->n_xdr_bin_cemeteries);
			}
		}
	}
	else if (was_bin_cemetery) {
		if (r->xdr_bin_cemetery == 0) {
			// Bin cemetery to regular or XDR.
			as_decr_uint64(&ns->n_xdr_bin_cemeteries);

			if (r->xdr_tombstone == 1) {
				as_incr_uint64(&ns->n_xdr_tombstones);
				as_decr_uint64(&ns->n_durable_tombstones);
			}
		}
	}
	else if (r->xdr_tombstone == 1) {
		// Regular to XDR.
		as_incr_uint64(&ns->n_xdr_tombstones);
		as_decr_uint64(&ns->n_durable_tombstones);
	}
	else if (r->xdr_bin_cemetery == 1) {
		// Regular to bin cemetery.
		as_incr_uint64(&ns->n_xdr_bin_cemeteries);
	}
}

// Must be called after as_record_transition_stats() which may bump set's
// n_objects from 0 to 1 - ensure either this or populator indexes this record.
void
as_record_transition_set_index(as_index_tree* tree, as_index_ref* r_ref,
		as_namespace* ns, uint16_t n_bins, const index_metadata* old)
{
	as_record* r = r_ref->r;

	bool is_delete = n_bins == 0 || r->tombstone == 1;
	bool inserted = old->generation == 0;
	bool existed_live = ! (inserted || old->tombstone);

	if (is_delete) {
		if (existed_live) {
			as_set_index_delete(ns, tree, as_index_get_set_id(r), r_ref->r_h);
		}
	}
	else if (! existed_live) { // new live
		as_set_index_insert(ns, tree, as_index_get_set_id(r), r_ref->r_h);
	}
}


//==========================================================
// Public API - enterprise only.
//

bool
as_record_write_lut_is_stale_cp(const as_record* r, uint32_t regime)
{
	uint16_t right_gen = (uint16_t)((regime & REGIME_MASK) << REGIME_SHIFT);

	// The generations passed in here are only regimes - low bits are stripped.
	return record_resolve_conflict_cp((r->generation & ~GEN_MASK),
			r->last_update_time, right_gen, cf_clepoch_milliseconds()) == -1;
}


//==========================================================
// Private API - for enterprise separation only.
//

int
record_resolve_conflict_cp(uint16_t left_gen, uint64_t left_lut,
		uint16_t right_gen, uint64_t right_lut)
{
	uint64_t delta_lut = left_lut > right_lut ?
			left_lut - right_lut : right_lut - left_lut;

	// If LUTs are far apart, can't trust regime, trust LUTs.
	if (delta_lut > g_reliable_regime_ms) {
		return left_lut > right_lut ? -1 : 1;
	}
	// else - they're close enough to trust regime.

	uint16_t left_regime = left_gen >> REGIME_SHIFT;
	uint16_t right_regime = right_gen >> REGIME_SHIFT;

	// Same regime - same master wrote this, trust LUT comparison.
	if (left_regime == right_regime) {
		int result = resolve_last_update_time(left_lut, right_lut);

		if (result == 0) {
			result = resolve_generation_cp(left_gen, right_gen);
		}

		return result;
	}

	return ((left_regime - right_regime) & REGIME_MASK) < REGIME_WRAP ? -1 : 1;
}


void
replace_index_metadata(const as_remote_record *rr, as_record *r)
{
	r->generation = (uint16_t)rr->generation;
	r->void_time = trim_void_time(rr->void_time);
	r->last_update_time = rr->last_update_time;

	r->xdr_write = rr->xdr_write ? 1 : 0;

	r->tombstone = rr->n_bins == 0 || rr->xdr_bin_cemetery ? 1 : 0;
	r->cenotaph = 0;
	r->xdr_tombstone = rr->xdr_tombstone ? 1 : 0;
	r->xdr_nsup_tombstone = rr->xdr_nsup_tombstone ? 1 : 0;
	r->xdr_bin_cemetery = rr->xdr_bin_cemetery ? 1 : 0;
}


//==========================================================
// Local helpers - set statistics.
//

void
transition_set_stat_to_live(as_namespace* ns, uint16_t set_id)
{
	if (set_id == INVALID_SET_ID) {
		return;
	}

	as_set* p_set;

	if (cf_vmapx_get_by_index(ns->p_sets_vmap, set_id - 1, (void**)&p_set) !=
			CF_VMAPX_OK) {
		cf_warning(AS_RECORD, "can't find set-id %u in vmap", set_id);
		return;
	}

	cf_atomic64_incr(&p_set->n_objects);

	if (cf_atomic64_decr(&p_set->n_tombstones) < 0) {
		cf_warning(AS_RECORD, "set_id %u - n_tombstones < 0", set_id);
	}
}


void
transition_set_stat_to_tombstone(as_namespace* ns, uint16_t set_id)
{
	if (set_id == INVALID_SET_ID) {
		return;
	}

	as_set* p_set;

	if (cf_vmapx_get_by_index(ns->p_sets_vmap, set_id - 1, (void**)&p_set) !=
			CF_VMAPX_OK) {
		cf_warning(AS_RECORD, "can't find set-id %u in vmap", set_id);
		return;
	}

	cf_atomic64_incr(&p_set->n_tombstones);

	if (cf_atomic64_decr(&p_set->n_objects) < 0) {
		cf_warning(AS_RECORD, "set_id %u - n_objects < 0", set_id);
	}
}


void
drop_tombstone_set_stat(as_namespace* ns, uint16_t set_id)
{
	if (set_id == INVALID_SET_ID) {
		return;
	}

	as_set* p_set;

	if (cf_vmapx_get_by_index(ns->p_sets_vmap, set_id - 1, (void**)&p_set) !=
			CF_VMAPX_OK) {
		cf_warning(AS_RECORD, "can't find set-id %u in vmap", set_id);
		return;
	}

	if (cf_atomic64_decr(&p_set->n_tombstones) < 0) {
		cf_warning(AS_RECORD, "set_id %u - n_tombstones < 0", set_id);
	}
}


//==========================================================
// Local helpers - partition statistics.
//

void
add_tombstone_partition_stat(as_namespace* ns, uint32_t pid)
{
	as_partition* p = &ns->partitions[pid];

	cf_atomic64_incr(&p->n_tombstones);
}


void
drop_tombstone_partition_stat(as_namespace* ns, uint32_t pid)
{
	as_partition* p = &ns->partitions[pid];

	if (cf_atomic64_decr(&p->n_tombstones) < 0) {
		cf_warning(AS_RECORD, "pid %u - n_tombstones < 0", pid);
	}
}
