/*
 * index_ee.c
 *
 * Copyright (C) 2008-2021 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "base/index.h"
#include "base/index_ee.h"

#include <stddef.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_digest.h"

#include "arenax.h"
#include "arenax_ee.h"
#include "cf_mutex.h"
#include "log.h"

#include "base/datamodel.h"


//==========================================================
// Typedefs & constants.
//

typedef struct filter_info_s {
	as_index_reduce_fn user_cb;
	void* user_udata;
} filter_info;

typedef struct as_index_keyd_array_s {
	bool is_stack;
	uint32_t capacity;
	uint32_t n_used;
	cf_digest* keyds;
} as_index_keyd_array;

static const size_t MAX_STACK_DIGESTS = 1024; // overkill for flash sprigs


//==========================================================
// Forward declarations.
//

static bool tombstone_filter_cb(as_index_ref* r_ref, void* filter_udata);
static void as_index_sprig_traverse_no_rc(as_index_sprig* isprig, const cf_digest* keyd, cf_arenax_handle r_h, as_index_keyd_array* keyds);
static void grow_keyd_array(as_index_keyd_array* keyd_a);


//==========================================================
// Public API.
//

// Resume a red-black tree in persistent memory.
as_index_tree*
as_index_tree_resume(as_index_tree_shared* shared, as_treex* xmem_trees,
		uint32_t pid, as_index_tree_done_fn cb, void* udata)
{
	int block_ix = xmem_trees->block_ix[pid];

	if (block_ix < 0) {
		return NULL; // didn't own this partition
	}

	uint64_t sprig_ix = (uint64_t)block_ix * shared->n_sprigs;
	as_sprigx* sprigx = &xmem_trees->sprigxs[sprig_ix];

	size_t locks_size = sizeof(cf_mutex) * NUM_LOCK_PAIRS * 2;
	size_t sprigs_size = sizeof(as_sprig) * shared->n_sprigs;
	size_t puddles_size = tree_puddles_size(shared);

	size_t tree_size = sizeof(as_index_tree) +
			locks_size + sprigs_size + puddles_size;

	as_index_tree* tree = cf_rc_alloc(tree_size);

	// We'll soon set tree->id to its restored value on reading drive headers.
	tree->done_cb = cb;
	tree->udata = udata;

	tree->shared = shared;
	tree->n_elements = 0; // will be updated after scanning index

	cf_mutex_init(&tree->set_trees_lock);
	memset(tree->set_trees, 0, sizeof(tree->set_trees));

	as_lock_pair* pair = tree_locks(tree);
	as_lock_pair* pair_end = pair + NUM_LOCK_PAIRS;

	while (pair < pair_end) {
		cf_mutex_init(&pair->lock);
		cf_mutex_init(&pair->reduce_lock);
		pair++;
	}

	as_sprig* sprig = tree_sprigs(tree);
	as_sprig* sprig_end = sprig + shared->n_sprigs;

	while (sprig < sprig_end) {
		// Resume the root.
		sprig->root_h = sprigx->root_h;

		sprigx++;
		sprig++;
	}

	memset(tree_puddles(tree), 0, puddles_size);

	return tree;
}

bool
as_index_reduce_live(as_index_tree* tree, as_index_reduce_fn cb, void* udata)
{
	filter_info fi = { .user_cb = cb, .user_udata = udata };

	return as_index_reduce(tree, tombstone_filter_cb, (void*)&fi);
}

bool
as_index_reduce_from_live(as_index_tree* tree, const cf_digest* keyd,
		as_index_reduce_fn cb, void* udata)
{
	filter_info fi = { .user_cb = cb, .user_udata = udata };

	return as_index_reduce_from(tree, keyd, tombstone_filter_cb, (void*)&fi);
}


//==========================================================
// Public API - enterprise only.
//

as_index_locked_puddle
as_index_puddle_for_element(as_index_tree* tree, const cf_digest* keyd)
{
	as_index_sprig isprig;
	as_index_sprig_from_keyd(tree, &isprig, keyd);

	return (as_index_locked_puddle) {
		.puddle = isprig.puddle,
		.lock = &isprig.pair->lock
	};
}

int
as_index_delete_element(as_index_tree* tree, const cf_digest* keyd)
{
	as_index_sprig isprig;
	as_index_sprig_from_keyd(tree, &isprig, keyd);

	cf_mutex_lock(&isprig.pair->lock);

	int result = as_index_sprig_delete(&isprig, keyd);

	cf_mutex_unlock(&isprig.pair->lock);

	// Note - don't decrement tree->n_elements.
	return result;
}

void
as_index_tree_shutdown(as_index_tree* tree, as_sprigx* sprigx)
{
	// Note - all sprigs are locked at this point.

	as_sprig* sprig = tree_sprigs(tree);
	as_sprig* sprig_end = sprig + tree->shared->n_sprigs;

	while (sprig < sprig_end) {
		// Save the root.
		sprigx->root_h = sprig->root_h;

		sprigx++;
		sprig++;
	}
}

void
as_index_prefetch(as_index_tree* tree, const cf_digest* keyd)
{
	if (tree == NULL) {
		return;
	}

	as_index_sprig isprig;
	as_index_sprig_from_keyd(tree, &isprig, keyd);

	cf_mutex_lock(&isprig.pair->lock);

	if (isprig.sprig->root_h != 0 &&
			cf_arenax_prefetch(tree->shared->arena, isprig.sprig->root_h) !=
					CF_ARENAX_OK) {
		cf_warning(AS_INDEX, "index element prefetch failed");
	}

	cf_mutex_unlock(&isprig.pair->lock);
}


//==========================================================
// Private API - enterprise separation only.
//

bool
as_index_sprig_reduce_no_rc(as_index_sprig* isprig, const cf_digest* keyd,
		as_index_reduce_fn cb, void* udata)
{
	cf_mutex_lock(&isprig->pair->reduce_lock);

	// Common to encounter empty sprigs.
	if (isprig->sprig->root_h == SENTINEL_H) {
		cf_mutex_unlock(&isprig->pair->reduce_lock);
		return true;
	}

	cf_digest stack_keyds[MAX_STACK_DIGESTS];
	as_index_keyd_array keyd_a = {
			.is_stack = true,
			.capacity = MAX_STACK_DIGESTS,
			.keyds = stack_keyds
	};

	uint64_t start_ms = cf_getms();

	// Traverse just fills array, then we make callbacks outside reduce lock.
	as_index_sprig_traverse_no_rc(isprig, keyd, isprig->sprig->root_h, &keyd_a);

	cf_detail(AS_INDEX, "sprig reduce took %lu ms", cf_getms() - start_ms);

	cf_mutex_unlock(&isprig->pair->reduce_lock);

	bool do_more = true;

	for (uint32_t i = 0; i < keyd_a.n_used; i++) {
		as_index_ref r_ref;

		if (as_index_sprig_get_vlock(isprig, keyd_a.keyds + i, &r_ref) == 0 &&
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

static bool
tombstone_filter_cb(as_index_ref* r_ref, void* filter_udata)
{
	filter_info* fi = (filter_info*)filter_udata;

	// Make the user callback if it's a live record.
	if (r_ref->r->tombstone == 0) {
		return fi->user_cb(r_ref, fi->user_udata);
	}
	// else - don't make the user callback if it's a tombstone.

	cf_mutex_unlock(r_ref->olock);

	return true;
}

static void
as_index_sprig_traverse_no_rc(as_index_sprig* isprig, const cf_digest* keyd,
		cf_arenax_handle r_h, as_index_keyd_array* keyd_a)
{
	if (r_h == SENTINEL_H) {
		return;
	}

	as_index* r = RESOLVE(r_h);
	int cmp = 0; // initialized to satisfy compiler

	if (keyd == NULL || (cmp = cf_digest_compare(&r->keyd, keyd)) < 0) {
		as_index_sprig_traverse_no_rc(isprig, keyd, r->left_h, keyd_a);
	}

	if (keyd_a->n_used == keyd_a->capacity) {
		grow_keyd_array(keyd_a);
	}

	// We do not collect the element with the boundary digest.

	if (keyd == NULL || cmp < 0) {
		// No ref-count increment.
		keyd_a->keyds[keyd_a->n_used++] = r->keyd;

		keyd = NULL;
	}

	as_index_sprig_traverse_no_rc(isprig, keyd, r->right_h, keyd_a);
}

static void
grow_keyd_array(as_index_keyd_array* keyd_a)
{
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
