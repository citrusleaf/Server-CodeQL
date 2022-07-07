/*
 * index_ee.h
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
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

#include <stdint.h>

#include "citrusleaf/cf_digest.h"

#include "arenax.h"
#include "cf_mutex.h"

#include "base/datamodel.h"
#include "base/index.h"


//==========================================================
// Forward declarations.
//

struct as_sprigx_s;


//==========================================================
// Typedefs & constants.
//

typedef void (*as_index_reduce_resume_fn) (as_index* value, void* udata);

typedef struct as_index_locked_puddle_s {
	cf_arenax_puddle* puddle;
	cf_mutex* lock; // sprig lock, to be used when accessing the puddle
} as_index_locked_puddle;

#define AS_INDEX_CHUNK_SIZE 4096
COMPILER_ASSERT(AS_INDEX_CHUNK_SIZE % sizeof(as_index) == 0);


//==========================================================
// Public API - enterprise only.
//

as_index_locked_puddle as_index_puddle_for_element(as_index_tree* tree, const cf_digest* keyd);
int as_index_delete_element(as_index_tree* tree, const cf_digest* keyd);
void as_index_tree_shutdown(as_index_tree* tree, struct as_sprigx_s* sprigx);
void as_index_prefetch(as_index_tree* tree, const cf_digest* keyd);

static inline uint32_t
as_index_chunk_count(const as_namespace* ns)
{
	return ns->tree_shared.puddles_offset != 0 ?
			AS_INDEX_CHUNK_SIZE / (uint32_t)sizeof(as_index) : 1;
}
