/*
 * sindex_tree_ee.c
 *
 * Copyright (C) 2022 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "sindex/sindex_tree.h"

#include <stdbool.h>
#include <stdint.h>

#include "citrusleaf/cf_digest.h"

#include "log.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "fabric/partition.h"


//==========================================================
// Typedefs & constants.
//

typedef struct key_info_s {
	int64_t bval;
	cf_digest keyd;
} key_info;

typedef struct query_collect_no_rc_cb_info_s {
	cf_arenax* arena;
	as_index_tree* tree;

	uint32_t n_keys_reduced;
	uint32_t n_kis;
	key_info* kis;

	search_key last;
} query_collect_no_rc_cb_info;


//==========================================================
// Forward declarations.
//

static bool query_collect_no_rc_cb(const si_btree_key* key, void* udata);


//==========================================================
// Private API - for enterprise separation only.
//

void
query_reduce_no_rc(si_btree* bt, as_partition_reservation* rsv,
		int64_t start_bval, int64_t end_bval, int64_t resume_bval,
		cf_digest* keyd, as_sindex_reduce_fn cb, void* udata)
{
	key_info kis[MAX_QUERY_BURST];

	query_collect_no_rc_cb_info ci = {
			.arena = bt->arena,
			.tree = rsv->tree,
			.kis = kis,
			.last = { .bval = start_bval }
	};

	if (keyd != NULL && (bt->unsigned_bvals ?
			(uint64_t)resume_bval >= (uint64_t)start_bval :
			resume_bval >= start_bval)) {
		ci.last.bval = resume_bval;
		ci.last.has_digest = true;
		ci.last.keyd_stub = get_keyd_stub(keyd);
		ci.last.keyd = *keyd;
	}

	if (bt->unsigned_bvals ?
			(uint64_t)ci.last.bval > (uint64_t)end_bval :
			ci.last.bval > end_bval) {
		return;
	}

	search_key end_skey = { .bval = end_bval };

	while (true) {
		si_btree_reduce(bt, &ci.last, &end_skey, query_collect_no_rc_cb, &ci);

		for (uint32_t i = 0; i < ci.n_kis; i++) {
			key_info* ki = &kis[i];
			as_index_ref r_ref;

			if (as_record_get(rsv->tree, &ki->keyd, &r_ref) == 0 &&
					// Callback MUST call as_record_done() to unlock record.
					! cb(&r_ref, ki->bval, udata)) {
				return;
			}
		}

		if (ci.n_keys_reduced != MAX_QUERY_BURST) {
			return; // done with this physical tree
		}

		ci.n_keys_reduced = 0;
		ci.n_kis = 0;
	}
}


//==========================================================
// Local helpers.
//

static bool
query_collect_no_rc_cb(const si_btree_key* key, void* udata)
{
	query_collect_no_rc_cb_info* ci = (query_collect_no_rc_cb_info*)udata;
	as_index_tree* tree = ci->tree;

	as_index* r = cf_arenax_resolve(ci->arena, key->r_h);

	if (r->tree_id == tree->id && r->generation != 0) {
		if (r->rc > MAX_QUERY_BURST * 1024) {
			cf_crash(AS_SINDEX, "unexpected - query rc %hu", r->rc);
		}

		key_info* ki = &ci->kis[ci->n_kis++];

		ki->bval = key->bval;
		ki->keyd = r->keyd;
	}

	if (++ci->n_keys_reduced == MAX_QUERY_BURST) {
		ci->last.bval = key->bval;
		ci->last.has_digest = true;
		ci->last.keyd_stub = get_keyd_stub(&r->keyd);
		ci->last.keyd = r->keyd;

		return false; // stops si_btree_reduce()
	}

	return true;
}
