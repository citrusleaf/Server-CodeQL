/*
 * set_index_ee.c
 *
 * Copyright (C) 2021 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "base/set_index.h"

#include <stdbool.h>
#include <stdint.h>

#include "citrusleaf/cf_digest.h"

#include "arenax.h"
#include "arenax_ee.h"
#include "cf_mutex.h"
#include "log.h"

#include "base/datamodel.h"
#include "base/index.h"


//==========================================================
// Typedefs & constants.
//

typedef struct keyd_array_s {
	bool is_stack;
	uint32_t capacity;
	uint32_t n_used;
	cf_digest* keyds;
} keyd_array;


//==========================================================
// Forward declarations.
//

static void ssprig_traverse_no_rc(ssprig_reduce_info* ssri, uarena_handle r_h, keyd_array* keyd_a);


//==========================================================
// Inlines & macros.
//

// Identical to ssi_from_keyd() but returns the olock.
static inline cf_mutex*
ssi_olock_from_keyd(as_index_tree* tree, as_set_index_tree* stree,
		const cf_digest* keyd, ssprig_info* ssi)
{
	uint32_t bits = (((uint32_t)keyd->digest[1] & 0xF0) << 23) |
			((uint32_t)keyd->digest[2] << 19) |
			((uint32_t)keyd->digest[3] << 11) |
			((uint32_t)keyd->digest[4] << 3) |
			((uint32_t)keyd->digest[5] >> 5);

	uint32_t ssprig_i = bits >> 23;

	ssi->arena = tree->shared->arena;
	ssi->ua = &stree->ua;
	ssi->root = stree->roots + ssprig_i;
	ssi->keyd_stub = bits & ((1 << 23) - 1);
	ssi->keyd = keyd;

	return &(tree_locks(tree) + ssprig_i)->lock;
}


//==========================================================
// Public API - enterprise only.
//

// Only called if set is configured to be indexed.
void
as_set_index_insert_warm_restart(as_index_tree* tree, uint16_t set_id,
		uint64_t r_h)
{
	as_set_index_tree* stree = tree->set_trees[set_id];
	as_index* r = cf_arenax_resolve(tree->shared->arena, r_h);
	ssprig_info ssi;

	cf_mutex* olock = ssi_olock_from_keyd(tree, stree, &r->keyd, &ssi);

	cf_mutex_lock(olock);

	if (! ssprig_insert(&ssi, r_h)) {
		cf_warning(AS_INDEX, "insert found existing element - unexpected");
	}

	cf_mutex_unlock(olock);
}


//==========================================================
// Private API - enterprise separation only.
//

bool
ssprig_reduce_no_rc(as_index_tree* tree, ssprig_reduce_info* ssri,
		as_index_reduce_fn cb, void* udata)
{
	ssprig_info* ssi = (ssprig_info*)ssri;

	cf_mutex_lock(ssri->olock);

	// Very common to encounter empty sprigs - check again under lock.
	if (*ssi->root == SENTINEL_H) {
		cf_mutex_unlock(ssri->olock);
		return true;
	}

	cf_digest stack_keyds[MAX_STACK_PHS];
	keyd_array keyd_a = {
			.is_stack = true,
			.capacity = MAX_STACK_PHS,
			.keyds = stack_keyds
	};

	// Traverse just fills array, then we make callbacks afterwards.
	ssprig_traverse_no_rc(ssri, *ssi->root, &keyd_a);

	cf_mutex_unlock(ssri->olock);

	bool do_more = true;

	for (uint32_t i = 0; i < keyd_a.n_used; i++) {
		cf_digest* keyd = keyd_a.keyds + i;
		as_index_sprig isprig;

		as_index_sprig_from_keyd(tree, &isprig, keyd);

		as_index_ref r_ref;

		if (as_index_sprig_get_vlock(&isprig, keyd, &r_ref) == 0 &&
				// Callback MUST call as_record_done() to unlock record.
				! cb(&r_ref, udata)) {
			do_more = false;
			break;
		}
	}

	if (! keyd_a.is_stack) {
		cf_free(keyd_a.keyds);
	}

	return do_more;
}


//==========================================================
// Local helpers.
//

static void
ssprig_traverse_no_rc(ssprig_reduce_info* ssri, uarena_handle r_h,
		keyd_array* keyd_a)
{
	if (r_h == SENTINEL_H) {
		return;
	}

	ssprig_info* ssi = (ssprig_info*)ssri;

	index_ele* r = UA_RESOLVE(r_h);
	int cmp = 0; // initialized to satisfy compiler

	if (ssi->keyd == NULL || (cmp = ssprig_ele_cmp(ssi, r)) > 0) {
		ssprig_traverse_no_rc(ssri, r->left_h, keyd_a);
	}

	if (keyd_a->n_used == keyd_a->capacity) {
		uint32_t new_capacity = keyd_a->capacity * 2;
		size_t new_sz = sizeof(cf_digest) * new_capacity;

		if (keyd_a->is_stack) {
			cf_digest* keyds = cf_malloc(new_sz);

			memcpy(keyds, keyd_a->keyds, sizeof(cf_digest) * keyd_a->capacity);
			keyd_a->keyds = keyds;
			keyd_a->is_stack = false;
		}
		else {
			keyd_a->keyds = cf_realloc(keyd_a->keyds, new_sz);
		}

		keyd_a->capacity = new_capacity;
	}

	// We do not collect the element with the boundary digest.

	if (ssi->keyd == NULL || cmp > 0) {
		as_index* key_r = cf_arenax_resolve(ssi->arena, r->key_r_h);

		keyd_a->keyds[keyd_a->n_used] = key_r->keyd;
		keyd_a->n_used++;

		ssi->keyd = NULL;
	}

	ssprig_traverse_no_rc(ssri, r->right_h, keyd_a);
}
