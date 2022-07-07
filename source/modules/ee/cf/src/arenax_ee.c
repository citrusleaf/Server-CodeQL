/*
 * arenax_ee.c
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

#include "arenax.h"
#include "arenax_ee.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"

#include "cf_mutex.h"
#include "cf_thread.h"
#include "hardware.h"
#include "log.h"
#include "xmem.h"
#include "xmem_ee.h"


//==========================================================
// Typedefs & constants.
//

typedef struct flush_thread_info_s {
	cf_arenax* arena;
	cf_atomic32 stage_id;
	cf_atomic32 i_cpu;
	volatile bool aborted;
} flush_thread_info;

#define MIN_INTERLEAVE 4

// TODO - move AS_INDEX_CHUNK_SIZE to cf somehow?
#define CHUNK_SIZE 4096 // same as AS_INDEX_CHUNK_SIZE, which is in as_index.h


//==========================================================
// Forward declarations.
//

static cf_arenax_err attach_existing_stages(cf_arenax* arena);
static cf_arenax_err arenax_detach(cf_arenax* arena);
static void* run_flush_arena_stages(void* pv_data);
static bool resume_stage_chunked(cf_arenax* arena, uint32_t stage_id,
		cf_arenax_resume_stage_cb cb, void* udata);
static void pool_push(cf_arenax* arena, cf_arenax_handle h);
static cf_arenax_handle pool_pop(cf_arenax* arena);


//==========================================================
// Public API.
//

bool
cf_arenax_want_prefetch(cf_arenax* arena)
{
	cf_xmem_props props;
	cf_xmem_get_props(arena->xmem_type, arena->xmem_type_cfg, &props);

	return props.want_prefetch;
}

void
cf_arenax_reclaim(cf_arenax* arena, cf_arenax_puddle* puddles,
		uint32_t n_puddles)
{
	if (n_puddles == 0) {
		return;
	}

	for (uint32_t i = 0; i < n_puddles; ++i) {
		uint32_t n_chunks = 0;
		uint32_t n_ele = 0;

		cf_arenax_handle chunks[100];
		cf_arenax_handle h = puddles[i].free_h;

		while (h != 0) {
			// If it's the first element of a chunk, then pool it.

			if ((h & (arena->chunk_count - 1)) == 0) {
				if (n_chunks == 100) {
					cf_crash(CF_ARENAX, "too many chunks");
				}

				chunks[n_chunks++] = h;
			}

			free_element* ele = cf_arenax_resolve(arena, h);
			h = ele->next_h;

			++n_ele;
		}

		cf_mutex_lock(&arena->lock);

		for (uint32_t k = 0; k < n_chunks; ++k) {
			pool_push(arena, chunks[k]);
		}

		cf_mutex_unlock(&arena->lock);

		as_add_uint64(&arena->alloc_sz, -(int64_t)(n_chunks * CHUNK_SIZE));

		// FIXME - paranoia
		cf_assert(n_ele % arena->chunk_count == 0, CF_ARENAX,
				"uneven free element count: %u", n_ele);

		// FIXME - paranoia
		cf_assert(n_ele / arena->chunk_count == n_chunks, CF_ARENAX,
				"invalid number of chunks: %u of %u", n_chunks, n_ele);
	}
}


//==========================================================
// Public API - enterprise only.
//

// Resume a cf_arenax object in persistent memory. Also find and attach all
// arena stages that were in use by this cf_arenax object.
//
// If call returns CF_ARENAX_ERR_STAGE_DETACH, persistent memory blocks may
// still be attached. Deleting them has no immediate effect - they linger until
// the server stops. So proceeding in this condition and doing a clean start
// would leak persistent memory.
cf_arenax_err
cf_arenax_resume(cf_arenax* arena, cf_xmem_type xmem_type,
		const void* xmem_type_cfg, key_t key_base, uint32_t element_size,
		uint32_t chunk_count, uint32_t stage_capacity, uint32_t max_stages)
{
	if (max_stages == 0) {
		max_stages = CF_ARENAX_MAX_STAGES;
	}
	else if (max_stages > CF_ARENAX_MAX_STAGES) {
		cf_warning(CF_ARENAX, "max stages %u too large", max_stages);
		return CF_ARENAX_ERR_BAD_PARAM;
	}

	if (arena->xmem_type != xmem_type) {
		cf_warning(CF_ARENAX, "resumed xmem type %d != xmem type %d",
				arena->xmem_type, xmem_type);
		return CF_ARENAX_ERR_BAD_PARAM;
	}

	if (arena->key_base != key_base) {
		cf_warning(CF_ARENAX, "resumed key base %x != key base %x",
				arena->key_base, key_base);
		return CF_ARENAX_ERR_BAD_PARAM;
	}

	if (arena->element_size != element_size) {
		cf_warning(CF_ARENAX, "resumed element size %u != element size %u",
				arena->element_size, element_size);
		return CF_ARENAX_ERR_BAD_PARAM;
	}

	// TODO - remove in "six months" when we believe there'll be no more
	// upgrades from 4.2. For now forfeit check that previous value is ok.
	if (chunk_count == 1) {
		arena->chunk_count = 1;
	}

	if (arena->chunk_count != chunk_count) {
		cf_warning(CF_ARENAX, "resumed chunk count %u != chunk count %u",
				arena->chunk_count, chunk_count);
		return CF_ARENAX_ERR_BAD_PARAM;
	}

	if (arena->stage_capacity != stage_capacity) {
		cf_warning(CF_ARENAX, "resumed stage capacity %u != stage capacity %u",
				arena->stage_capacity, stage_capacity);
		return CF_ARENAX_ERR_BAD_PARAM;
	}

	if (arena->stage_count > max_stages) {
		cf_warning(CF_ARENAX, "resumed stage count %u > max stages %u",
				arena->stage_count, max_stages);
		return CF_ARENAX_ERR_BAD_PARAM;
	}

	arena->xmem_type_cfg = xmem_type_cfg;
	arena->max_stages = max_stages;
	arena->unused = 0;

	if (chunk_count == 1) {
		arena->pool_len = 0;
		arena->pool_buf = NULL;
	}
	else {
		arena->pool_len = arena->stage_capacity;
		arena->pool_buf =
				cf_malloc(arena->pool_len * sizeof(cf_arenax_chunk));
	}

	arena->pool_i = 0;
	arena->alloc_sz = 0;

	cf_mutex_init(&arena->lock);

	// In case we add future members here, before harvesting this space.
	memset(arena->pad, 0, sizeof(arena->pad));

	memset(arena->stages, 0, sizeof(arena->stages));

	// Find all existing stages and rebuild stage pointer table.
	cf_arenax_err result = attach_existing_stages(arena);

	if (result != CF_ARENAX_OK) {
		cf_arenax_err detach_result = arenax_detach(arena);

		// If detach fails, it's more serious - override result.
		if (detach_result != CF_ARENAX_OK) {
			result = detach_result;
		}
	}

	// This is just for backward compatibility when first upgrading to a version
	// with arena leak detection and repair capability - remove it when we can.
	if (arena->free_h != 0 &&
			((free_element*)cf_arenax_resolve(arena, arena->free_h))->magic !=
					FREE_MAGIC) {
		// Assume if the head had wrong/no magic, everything else will too.
		cf_warning(CF_ARENAX, "wrong magic, treating free elements as lost");

		arena->free_h = 0;
	}

	return result;
}

// Return the maximum number of elements that have ever been in the arena,
// excluding null element. Not thread safe.
uint64_t
cf_arenax_hwm(cf_arenax* arena)
{
	return ((uint64_t)arena->at_stage_id * arena->stage_capacity) +
			arena->at_element_id - arena->chunk_count;
}

// Make specified callback for every element in specified stage. If the element
// is free, pass a null element pointer. Returns false if stage has never
// contained elements. Not thread safe.
bool
cf_arenax_resume_stage(cf_arenax* arena, uint32_t stage_id,
		cf_arenax_resume_stage_cb cb, void* udata)
{
	if (arena->chunk_count != 1) {
		return resume_stage_chunked(arena, stage_id, cb, udata);
	}

	if (stage_id > arena->at_stage_id) {
		return false;
	}

	uint32_t num_elements = stage_id == arena->at_stage_id ?
			arena->at_element_id : arena->stage_capacity;
	uint32_t element_id = 0;
	uint8_t* p_element = arena->stages[stage_id];
	uint8_t* p_end = p_element + ((uint64_t)num_elements * arena->element_size);

	// But skip the null element.
	if (stage_id == 0) {
		num_elements--;
		element_id = 1;
		p_element += arena->element_size;
	}

	while (p_element < p_end) {
		if (((free_element*)p_element)->magic == FREE_MAGIC) {
			cb(NULL, 0, udata);
		}
		else {
			cf_arenax_handle h;
			cf_arenax_set_handle(&h, stage_id, element_id);

			cf_arenax_element_result result = cb((void*)p_element, h, udata);

			if (result.free_it) {
				free_element* p_free_element = (free_element*)p_element;

				cf_mutex_lock(&arena->lock);

				p_free_element->magic = FREE_MAGIC;
				p_free_element->next_h = arena->free_h;
				arena->free_h = h;

				cf_mutex_unlock(&arena->lock);
			}
		}

		element_id++;
		p_element += arena->element_size;
	}

	return num_elements != 0;
}

// Make specified callback for every used element in specified stage. Returns
// false if stage has never contained elements. Not thread safe.
bool
cf_arenax_scan(cf_arenax* arena, uint32_t stage_id, cf_arenax_scan_cb cb,
		void* udata)
{
	if (stage_id > arena->at_stage_id) {
		return false;
	}

	uint32_t num_elements = stage_id == arena->at_stage_id ?
			arena->at_element_id : arena->stage_capacity;
	uint8_t* base = arena->stages[stage_id];
	uint8_t* p_scan = base;
	uint8_t* p_end = p_scan + ((uint64_t)num_elements * arena->element_size);

	if (cf_xmem_advise_scan(arena->xmem_type, base,
			arena->stage_capacity * arena->element_size, true) != CF_XMEM_OK) {
		cf_crash(AS_DRV_SSD, "error while enabling scan read-ahead");
	}

	// But skip the null element.
	if (stage_id == 0) {
		num_elements -= arena->chunk_count;
		p_scan += arena->element_size * arena->chunk_count;
	}

	while (p_scan < p_end) {
		if (((free_element*)p_scan)->magic != FREE_MAGIC) {
			cb((void*)p_scan, udata);
		}

		p_scan += arena->element_size;
	}

	if (cf_xmem_advise_scan(arena->xmem_type, base,
			arena->stage_capacity * arena->element_size, false) != CF_XMEM_OK) {
		cf_crash(AS_DRV_SSD, "error while disabling scan read-ahead");
	}

	return num_elements > 0;
}

// For NUMA pinning, we need to force the unused portion of the last arena stage
// to be mapped, so it can be migrated to the proper NUMA node.
void
cf_arenax_force_map_memory(cf_arenax* arena)
{
	if (arena->xmem_type != CF_XMEM_TYPE_SHMEM) {
		return; // irrelevant for pmem and ssd
	}

	// For now don't worry about 0:0 (null) element - element size is smaller
	// than memory page size, so starting at element 0:1 will map element 0:0.
	uint8_t* unused_from = arena->stages[arena->at_stage_id] +
			((uint64_t)arena->at_element_id * arena->element_size);

	// It's possible this is 0, that's ok to pass.
	size_t unused_size =
			(uint64_t)(arena->stage_capacity - arena->at_element_id) *
			arena->element_size;

	cf_topo_force_map_memory(unused_from, unused_size);
}

bool
cf_arenax_flush(cf_arenax* arena)
{
	if (arena->xmem_type == CF_XMEM_TYPE_SHMEM) {
		return true; // irrelevant for shmem
	}

	// Split this task across multiple threads.
	uint32_t n_cpus = cf_topo_count_cpus();
	cf_tid tids[n_cpus];
	flush_thread_info flush_info = {
			.arena = arena,
			.stage_id = -1,
			.i_cpu = -1,
			.aborted = false
	};

	for (uint32_t n = 0; n < n_cpus; n++) {
		tids[n] = cf_thread_create_joinable(run_flush_arena_stages,
				(void*)&flush_info);
	}

	for (uint32_t n = 0; n < n_cpus; n++) {
		cf_thread_join(tids[n]);
	}
	// Now we're single-threaded again.

	return ! flush_info.aborted;
}


//==========================================================
// Private API - for enterprise separation only.
//

// Create and attach a persistent memory block, and store its pointer in the
// stages array.
cf_arenax_err
cf_arenax_add_stage(cf_arenax* arena)
{
	if (arena->stage_count >= arena->max_stages) {
		cf_ticker_warning(CF_ARENAX, "can't allocate more than %u arena stages",
				arena->max_stages);
		return CF_ARENAX_ERR_STAGE_CREATE;
	}

	cf_xmem_err result = cf_xmem_create_block(arena->xmem_type,
			arena->xmem_type_cfg, arena->key_base + arena->stage_count,
			arena->stage_size, (void**)&arena->stages[arena->stage_count]);

	if (result != CF_XMEM_OK) {
		cf_ticker_warning(CF_ARENAX,
				"could not allocate %zu-byte arena stage %u: %s",
				arena->stage_size, arena->stage_count, cf_strerror(result));
		return CF_ARENAX_ERR_STAGE_CREATE;
	}

	arena->stage_count++;

	return CF_ARENAX_OK;
}

cf_arenax_err
cf_arenax_prefetch(cf_arenax* arena, cf_arenax_handle h)
{
	void* addr = cf_arenax_resolve(arena, h);

	return cf_xmem_prefetch(arena->xmem_type, addr) == CF_XMEM_OK ?
			CF_ARENAX_OK : CF_ARENAX_ERR_UNKNOWN;
}

cf_arenax_handle
cf_arenax_alloc_chunked(cf_arenax* arena, cf_arenax_puddle* puddle)
{
	cf_arenax_handle result_h;

	// First, try the puddle. We're already under the sprig lock.

	if (puddle->free_h != 0) {
		result_h = puddle->free_h;

		free_element* res_r = cf_arenax_resolve(arena, result_h);
		puddle->free_h = res_r->next_h;

		return result_h;
	}

	// Second, try the arena. For this we'll need the arena lock.

	cf_mutex_lock(&arena->lock);

	result_h = pool_pop(arena);

	// If the pool is empty, refill it. Grab multiple arena stages and
	// interleave them, so that index accesses load-balance across files.

	if (result_h == 0) {
		cf_xmem_props props;
		cf_xmem_get_props(arena->xmem_type, arena->xmem_type_cfg, &props);

		uint32_t n_inter = props.n_interleave;

		if (n_inter < MIN_INTERLEAVE) {
			n_inter = MIN_INTERLEAVE;
		}

		uint32_t start_sid;
		uint32_t added;

		// In general, at_stage_id is the last stage created by this function.
		//
		// However, when we get here for the very first time, we need to deal
		// with the first stage that cf_arenax_init() already created.

		if (arena->at_stage_id == 0) {
			// Start pooling chunks at cf_arenax_init()'s stage.
			start_sid = 0;
			// Create (n_inter - 1) stages to account for cf_arenax_init()'s
			// stage.
			added = 1;
		}
		else {
			// Start pooling chunks at the first stage that we're going to
			// create below.
			start_sid = arena->at_stage_id + 1;
			// Create n_inter stages.
			added = 0;
		}

		while (added < n_inter) {
			if (cf_arenax_add_stage(arena) != CF_ARENAX_OK) {
				break;
			}

			++added;
		}

		if (added == 0) {
			cf_mutex_unlock(&arena->lock);
			return 0;
		}

		uint32_t sid = start_sid;
		uint32_t eid = 0;

		// Skip the null element.

		if (sid == 0 && eid == 0) {
			++sid;
		}

		while (eid < arena->stage_capacity) {
			while (sid < start_sid + added) {
				cf_arenax_handle h;

				cf_arenax_set_handle(&h, sid, eid);
				pool_push(arena, h);

				++sid;
			}

			sid = start_sid;
			eid += arena->chunk_count;
		}

		// Establish invariant:
		//
		//   - at_stage_id = last stage created by this function
		//   - at_element_id = stage_capacity

		arena->at_stage_id = start_sid + added - 1;
		arena->at_element_id = arena->stage_capacity;

		result_h = pool_pop(arena);
	}

	// Now we can go back and work only under the sprig lock.

	cf_mutex_unlock(&arena->lock);

	uint32_t sid;
	uint32_t eid;

	cf_arenax_expand_handle(&sid, &eid, result_h);

	// We will return the first element. The remaining (chunk_count - 1)
	// elements go in the sprig's puddle.

	for (uint32_t i = arena->chunk_count - 1; i > 0; --i) {
		cf_arenax_handle h;
		cf_arenax_set_handle(&h, sid, eid + i);
		cf_arenax_free_chunked(arena, h, puddle);
	}

	as_add_uint64(&arena->alloc_sz, CHUNK_SIZE);

	return result_h;
}

void
cf_arenax_free_chunked(cf_arenax* arena, cf_arenax_handle h,
		cf_arenax_puddle* puddle)
{
	free_element* h_r = cf_arenax_resolve(arena, h);

	// We're already under the sprig lock, so we can modify the sprig's
	// puddle without any further locking.

	h_r->magic = FREE_MAGIC;
	h_r->next_h = puddle->free_h;
	puddle->free_h = h;
}


//==========================================================
// Local helpers.
//

// Find and attach all persistent memory blocks that were in use.
static cf_arenax_err
attach_existing_stages(cf_arenax* arena)
{
	for (uint32_t i = 0; i < arena->stage_count; i++) {
		cf_xmem_err result = cf_xmem_attach_block(arena->xmem_type,
				arena->xmem_type_cfg, arena->key_base + i, &arena->stage_size,
				(void**)&arena->stages[i]);

		if (result != CF_XMEM_OK) {
			cf_warning(CF_ARENAX, "failed attaching arena stage %u: %s", i,
					cf_strerror(result));
			return CF_ARENAX_ERR_STAGE_ATTACH;
		}
	}

	return CF_ARENAX_OK;
}

// Free internal resources and detach any attached stages. Don't call after
// failed cf_arenax_create() or cf_arenax_resume() call - those functions clean
// up on failure.
static cf_arenax_err
arenax_detach(cf_arenax* arena)
{
	cf_mutex_destroy(&arena->lock);

	cf_arenax_err result = CF_ARENAX_OK;

	for (uint32_t i = 0; i < arena->stage_count; i++) {
		uint8_t* p_stage = arena->stages[i];

		if (! p_stage) {
			// Happens if we got part way through attaching stages then failed.
			break;
		}

		if (cf_xmem_detach_block(arena->xmem_type, (void*)p_stage,
				arena->stage_size) != CF_XMEM_OK) {
			cf_warning(CF_ARENAX, "failed detaching arena stage %u", i);

			result = CF_ARENAX_ERR_STAGE_DETACH;
			// Something really out-of-whack, but keep going...
		}
	}

	return result;
}

static void*
run_flush_arena_stages(void* pv_data)
{
	flush_thread_info* flush_info = (flush_thread_info*)pv_data;
	cf_arenax* arena = flush_info->arena;

	cf_topo_pin_to_cpu(
			(cf_topo_cpu_index)cf_atomic32_incr(&flush_info->i_cpu));

	while (! flush_info->aborted) {
		uint32_t stage_id = (uint32_t)cf_atomic32_incr(&flush_info->stage_id);

		if (stage_id > arena->at_stage_id) {
			break; // done flushing all stages
		}

		uint8_t* p_stage = arena->stages[stage_id];

		cf_assert(p_stage, CF_ARENAX, "null stage %u", stage_id);

		if (cf_xmem_flush_block(arena->xmem_type, (void*)p_stage,
				arena->stage_size) != CF_XMEM_OK) {
			cf_warning(CF_ARENAX, "failed flushing arena stage %u", stage_id);
			flush_info->aborted = true; // failed to flush a stage - abandon
			break;
		}

		cf_detail(AS_DRV_SSD, "... flushed arena stage %u", stage_id);
		// May be more stages to flush.
	}

	return NULL;
}

static bool
resume_stage_chunked(cf_arenax* arena, uint32_t stage_id,
		cf_arenax_resume_stage_cb cb, void* udata)
{
	if (stage_id > arena->at_stage_id) {
		return false;
	}

	uint32_t lower = 0;

	// at_element_id != stage_capacity, if we trigger a warm restart between
	// cf_arenax_init() and the first call to cf_arenax_alloc_chunked().
	//
	// In this case, at_element_id == chunk_count, which makes us skip warm
	// restart. This avoids throwing stage 0's elements into the global pool
	// twice,
	//
	//   a) first during warm restart, and
	//   b) then again in the first call to cf_arenax_alloc_chunked().

	uint32_t upper = arena->at_element_id;

	if (stage_id == 0) {
		lower += arena->chunk_count; // skip null element
	}

	uint8_t* stage = arena->stages[stage_id];
	uint32_t stride = arena->chunk_count;

	uint8_t zero[arena->element_size];
	memset(zero, 0, arena->element_size);

	if (cf_xmem_advise_scan(arena->xmem_type, stage,
			arena->stage_capacity * arena->element_size, true) != CF_XMEM_OK) {
		cf_crash(AS_DRV_SSD, "error while enabling scan read-ahead");
	}

	uint32_t n_pooled = 0;

	for (uint32_t chunk = lower; chunk < upper; chunk += stride) {
		cf_arenax_puddle* puddle = NULL;
		cf_mutex* lock = NULL;

		// Elements that we'll add to either the arena pool or a puddle.
		cf_arenax_handle to_free[stride];
		uint32_t n_to_free = 0;

		uint32_t next_chunk = chunk + stride;
		uint8_t* walker = stage + chunk * arena->element_size;

		// Collect elements to be freed.

		for (uint32_t ele_id = chunk; ele_id < next_chunk; ele_id++) {
			free_element* ele = (free_element*)walker;

			cf_arenax_handle h;
			cf_arenax_set_handle(&h, stage_id, ele_id);

			// Mark pristine elements from the most recently added stages.

			if (memcmp(walker, zero, arena->element_size) == 0) {
				ele->magic = FREE_MAGIC;
			}

			// Add an element that was previously free.

			if (ele->magic == FREE_MAGIC) {
				cb(NULL, 0, udata);
				to_free[n_to_free++] = h;
				walker += arena->element_size;
				continue;
			}

			cf_arenax_element_result result = cb(ele, h, udata);

			// Add an element that belonged to a dropped tree or that has
			// expired, etc.

			if (result.free_it) {
				// Set the magic number. Below, we may not call cf_arenax_free()
				// for the to_free array (if we found stride-many of them).
				ele->magic = FREE_MAGIC;
				to_free[n_to_free++] = h;
				walker += arena->element_size;
				continue;
			}

			// The callback wants to keep the element. Conveniently, the
			// element tells us what this chunk's puddle is.

			puddle = result.puddle;
			lock = result.lock;

			walker += arena->element_size;
		}

		// If all elements ended up in to_free array, then the chunk is
		// completely unused. Add it to the global pool.

		if (n_to_free == stride) {
			cf_mutex_lock(&arena->lock);

			pool_push(arena, to_free[0]);

			cf_mutex_unlock(&arena->lock);

			n_pooled++;
			continue;
		}

		// Otherwise, add the elements to be freed to the puddle. We know the
		// puddle, because we encountered at least one still-used element.

		cf_mutex_lock(lock);

		for (uint32_t i = 0; i < n_to_free; i++) {
			cf_arenax_free(arena, to_free[i], puddle);
		}

		cf_mutex_unlock(lock);
	}

	if (cf_xmem_advise_scan(arena->xmem_type, stage,
			arena->stage_capacity * arena->element_size, false) != CF_XMEM_OK) {
		cf_crash(AS_DRV_SSD, "error while disabling scan read-ahead");
	}

	uint64_t n_chunks_used = (uint64_t)((upper - lower) / stride) - n_pooled;

	as_add_uint64(&arena->alloc_sz, (int64_t)(n_chunks_used * CHUNK_SIZE));

	return true;
}

static void
pool_push(cf_arenax* arena, cf_arenax_handle h)
{
	// FIXME - paranoia
	cf_assert(h % arena->chunk_count == 0, CF_ARENAX,
			"pooling unaligned chunk %lx", h);

	if (arena->pool_i >= arena->pool_len) {
		arena->pool_len *= 2;
		arena->pool_buf = cf_realloc(arena->pool_buf,
				arena->pool_len * sizeof(cf_arenax_chunk));
	}

	arena->pool_buf[arena->pool_i].base_h = h;
	++arena->pool_i;
}

static cf_arenax_handle
pool_pop(cf_arenax* arena)
{
	if (arena->pool_i == 0) {
		return 0;
	}

	if (arena->pool_len > arena->stage_capacity &&
			arena->pool_i < arena->pool_len / 3) {
		arena->pool_len /= 2;
		arena->pool_buf = cf_realloc(arena->pool_buf,
				arena->pool_len * sizeof(cf_arenax_chunk));
	}

	--arena->pool_i;
	return arena->pool_buf[arena->pool_i].base_h;
}
