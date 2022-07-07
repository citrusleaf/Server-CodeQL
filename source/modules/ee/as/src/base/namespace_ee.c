/*
 * namespace_ee.c
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

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"

#include "arenax.h"
#include "arenax_ee.h"
#include "cf_thread.h"
#include "hardware.h"
#include "log.h"
#include "vmapx_ee.h"
#include "xmem.h"
#include "xmem_ee.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "base/index_ee.h"
#include "fabric/partition.h"
#include "storage/drv_common_ee.h"


//==========================================================
// Typedefs & constants.
//

// Persistent memory key building blocks.
const key_t AS_XMEM_KEY_BASE       = 0xAE000000;
const key_t AS_XMEM_TREEX_KEY_BASE = 0x00000001;
const key_t AS_XMEM_ARENA_KEY_BASE = 0x00000100;

// Persistent memory key instance and namespace locations.
const int AS_XMEM_INSTANCE_KEY_SHIFT = 20;
const int AS_XMEM_NS_KEY_SHIFT = 12;

typedef enum {
	PREV_SHUTDOWN_NOT_TRUSTED = 0,
	PREV_SHUTDOWN_TRUSTED = 1
} as_prev_shutdown_status;

typedef struct as_xmem_scheme_s {
	uint32_t version;
	as_prev_shutdown_status prev_shutdown_status;
	uint32_t flags;
	uint32_t n_sprigs;
	uint64_t index_stage_size;
	uint32_t namespace_offset;
	uint32_t arena_offset;
	uint32_t sets_vmapx_offset;
	uint32_t bins_vmapx_offset;
} as_xmem_scheme;

const as_xmem_scheme AS_XMEM_NS_SCHEME = {
	10, // must update conversion code when bumping this version
	PREV_SHUTDOWN_NOT_TRUSTED,
	0, // flags come from config
	0, // number of sprigs comes from config
	0, // index stage size comes from config
	1024 * 1,   // namespace name is 32 bytes
	1024 * 2,   // arena takes 152 + (8 x 2048) = 16536
	1024 * 128, // sets take 128K + 64
	1024 * 512  // bins take 1M + 64
};

const size_t AS_XMEM_NS_BASE_BLOCK_SIZE = 2 * 1024 * 1024;

// For warm or cool restart conversion.
typedef struct convert_thread_info_s {
	cf_arenax* p_arena;
	cf_atomic32 stage_id;
	cf_atomic32 i_cpu;
	cf_arenax_scan_cb cb;
} convert_thread_info;


//==========================================================
// Forward declarations.
//

bool xmem_find_base_block(key_t ns_key_base, uint8_t** pp_block, cf_xmem_type* p_ns_xmem_type, const void** p_ns_xmem_type_cfg);
void xmem_delete_any_namespace_blocks(key_t ns_key_base, key_t ns_arena_key_base);
as_namespace* xmem_find_namespace_for_base_block(cf_xmem_type ns_xmem_type, const void* ns_xmem_type_cfg, const uint8_t* ns_xmem_base);
bool xmem_treex_block_size_check(as_namespace* ns, size_t treex_block_size);
size_t xmem_treex_block_size(as_namespace* ns);
void xmem_must_detach_base_block(cf_xmem_type ns_xmem_type, uint8_t* base_block);
void xmem_must_delete_base_block(cf_xmem_type ns_xmem_type, const void* ns_xmem_type_cfg, key_t ns_key_base);
void xmem_must_detach_treex_block(as_namespace* ns, size_t size);
void xmem_must_delete_treex_block(cf_xmem_type ns_xmem_type, const void* ns_xmem_type_cfg, key_t ns_key_base);
void xmem_delete_namespace_blocks(cf_xmem_type ns_xmem_type, const void* ns_xmem_type_cfg, key_t ns_key_base, key_t ns_arena_key_base);

bool ns_xmem_resume(as_namespace* ns, key_t ns_arena_key_base);
void ns_xmem_create(as_namespace* ns, key_t ns_key_base, key_t ns_arena_key_base);

void ns_xmem_set_pointers(as_namespace* ns);
bool ns_xmem_init_sets_cfg(as_namespace* ns);

void ns_xmem_convert(as_namespace* ns, as_xmem_scheme* scheme);
void ns_xmem_convert_index_elements(as_namespace* ns, cf_arenax_scan_cb cb);
void* run_convert(void* pv_data);


//==========================================================
// Inlines & macros.
//

static inline bool
xmem_can_convert(const as_xmem_scheme* scheme)
{
	// Can't convert any version for now.
	return false;
}


//==========================================================
// Globals.
//

static const void* g_xmem_type_cfgs_used[CF_NUM_XMEM_TYPES][AS_NAMESPACE_SZ] = {
		{ NULL }
};

static uint32_t g_xmem_type_cfg_used_counts[CF_NUM_XMEM_TYPES] = {
		0
};


//==========================================================
// Public API.
//

bool
as_namespace_xmem_shutdown(as_namespace* ns, uint32_t instance)
{
	if (! cf_arenax_flush(ns->arena)) {
		cf_warning(AS_NAMESPACE, "{%s} can't flush arenax stages", ns->name);
		return false;
	}

	cf_info(AS_NAMESPACE, "{%s} persisted arena stages", ns->name);

	uint32_t n_owned = 0;

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		if (ns->partitions[pid].tree) {
			n_owned++;
		}
	}

	size_t treex_size = sizeof(as_treex) +
			(sizeof(as_sprigx) * ns->tree_shared.n_sprigs * n_owned);

	// Create the treex block, which assigns its pointer.
	key_t ns_key_base = AS_XMEM_KEY_BASE | (instance << AS_XMEM_INSTANCE_KEY_SHIFT) | (ns->xmem_id << AS_XMEM_NS_KEY_SHIFT);
	as_treex* xmem_trees;
	cf_xmem_err xmem_result = cf_xmem_create_block(ns->xmem_type, ns->xmem_type_cfg, ns_key_base | AS_XMEM_TREEX_KEY_BASE, treex_size, (void**)&xmem_trees);

	if (xmem_result != CF_XMEM_OK) {
		cf_warning(AS_NAMESPACE, "{%s} can't create persistent memory treex block: %s", ns->name, cf_strerror(xmem_result));
		return false;
	}

	int block_ix = 0;

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		as_partition* p = &ns->partitions[pid];

		if (! p->tree) {
			xmem_trees->block_ix[pid] = -1; // not owned
			continue;
		}

		xmem_trees->block_ix[pid] = block_ix; // owned

		uint64_t sprig_ix = (uint64_t)block_ix * ns->tree_shared.n_sprigs;
		as_sprigx* sprigx = &xmem_trees->sprigxs[sprig_ix];

		as_index_tree_shutdown(p->tree, sprigx);

		block_ix++;
	}

	// Flush the treex block.
	if (cf_xmem_flush_block(ns->xmem_type, (void*)xmem_trees, treex_size) != CF_XMEM_OK) {
		cf_warning(AS_NAMESPACE, "{%s} can't flush persistent memory treex block", ns->name);
		return false;
	}

	cf_info(AS_NAMESPACE, "{%s} persisted tree roots", ns->name);

	// Create the base block, which assigns its pointer.
	uint8_t* xmem_base;

	xmem_result = cf_xmem_create_block(ns->xmem_type, ns->xmem_type_cfg, ns_key_base, AS_XMEM_NS_BASE_BLOCK_SIZE, (void**)&xmem_base);

	if (xmem_result != CF_XMEM_OK) {
		cf_warning(AS_NAMESPACE, "{%s} can't create persistent memory base block: %s", ns->name, cf_strerror(xmem_result));
		return false;
	}

	((as_xmem_scheme*)ns->xmem_base)->prev_shutdown_status = PREV_SHUTDOWN_NOT_TRUSTED;

	memcpy(xmem_base, ns->xmem_base, AS_XMEM_NS_BASE_BLOCK_SIZE);

	// Flush the whole base block, "untrusted".
	if (cf_xmem_flush_block(ns->xmem_type, (void*)xmem_base, AS_XMEM_NS_BASE_BLOCK_SIZE) != CF_XMEM_OK) {
		cf_warning(AS_NAMESPACE, "{%s} can't flush persistent memory base block", ns->name);
		return false;
	}

	((as_xmem_scheme*)xmem_base)->prev_shutdown_status = PREV_SHUTDOWN_TRUSTED;

	// Flush the first chunk of the base block, including "trusted".
	if (cf_xmem_flush_block(ns->xmem_type, (void*)xmem_base, sizeof(as_xmem_scheme)) != CF_XMEM_OK) {
		cf_warning(AS_NAMESPACE, "{%s} can't flush 'trusted' status", ns->name);
		return false;
	}

	cf_info(AS_NAMESPACE, "{%s} persisted trusted base block", ns->name);

	return true;
}


//==========================================================
// Private API - for enterprise separation only.
//

void
as_namespaces_setup(bool cold_start_cmd, uint32_t instance)
{
	// Unfortunately this can't be a compiler assert...
	cf_assert(
			AS_XMEM_NS_SCHEME.arena_offset - AS_XMEM_NS_SCHEME.namespace_offset >= AS_ID_NAMESPACE_SZ &&
			AS_XMEM_NS_SCHEME.sets_vmapx_offset - AS_XMEM_NS_SCHEME.arena_offset >= cf_arenax_sizeof() &&
			AS_XMEM_NS_SCHEME.bins_vmapx_offset - AS_XMEM_NS_SCHEME.sets_vmapx_offset >= cf_vmapx_sizeof(sizeof(as_set), AS_SET_MAX_COUNT) &&
			AS_XMEM_NS_BASE_BLOCK_SIZE - AS_XMEM_NS_SCHEME.bins_vmapx_offset >= cf_vmapx_sizeof(AS_BIN_NAME_MAX_SZ, MAX_BIN_NAMES),
			AS_NAMESPACE, "bad persistent memory scheme definition");

	cf_assert(instance <= 0xF, AS_NAMESPACE, "max allowed instance id is 15");

	if (cold_start_cmd) {
		cf_info(AS_NAMESPACE, "got cold-start command");
	}

	for (uint32_t i = 0; i < g_config.n_namespaces; i++) {
		as_namespace* ns = g_config.namespaces[i];

		// Cold start if manually forced.
		ns->cold_start = cold_start_cmd;

		// Can't warm or cool restart in some circumstances.
		if (! ns->cold_start) {
			if (ns->storage_type == AS_STORAGE_ENGINE_MEMORY) {
				ns->cold_start = true;
			}
			else if (! drv_peek_devices(ns)) {
				cf_info(AS_NAMESPACE, "{%s} found no stored data, will cold start", ns->name);
				ns->cold_start = true;
			}
		}

		uint32_t* p_count = &g_xmem_type_cfg_used_counts[ns->xmem_type];
		uint32_t cfg_ix;

		for (cfg_ix = 0; cfg_ix < *p_count; cfg_ix++) {
			if (cf_xmem_type_cfg_same(ns->xmem_type, ns->xmem_type_cfg,
					g_xmem_type_cfgs_used[ns->xmem_type][cfg_ix])) {
				break;
			}
		}

		if (cfg_ix == *p_count) {
			g_xmem_type_cfgs_used[ns->xmem_type][*p_count] = ns->xmem_type_cfg;
			(*p_count)++;
		}
	}

	// If we switch from using shmem indexes to pmem or SSD, we'll clean up
	// the old shmem blocks. Going the other way, we won't be able to clean up.
	if (g_xmem_type_cfg_used_counts[CF_XMEM_TYPE_SHMEM] == 0) {
		g_xmem_type_cfg_used_counts[CF_XMEM_TYPE_SHMEM] = 1;
	}

	bool available[AS_NAMESPACE_SZ + 1]; // for 1-based xmem IDs

	// Find and attach all existing base blocks, which assigns their pointers.
	for (uint32_t ns_xmem_id = 1; ns_xmem_id <= AS_NAMESPACE_SZ; ns_xmem_id++) {
		key_t ns_key_base = AS_XMEM_KEY_BASE | (instance << AS_XMEM_INSTANCE_KEY_SHIFT) | (ns_xmem_id << AS_XMEM_NS_KEY_SHIFT);
		uint8_t* ns_xmem_base = NULL;			// TODO - compile requires initialization - why?
		cf_xmem_type ns_xmem_type = -1;			// TODO - compile requires initialization - why?
		const void* ns_xmem_type_cfg = NULL;	// TODO - compile requires initialization - why?

		if (xmem_find_base_block(ns_key_base, &ns_xmem_base, &ns_xmem_type, &ns_xmem_type_cfg)) {
			as_namespace* ns = xmem_find_namespace_for_base_block(ns_xmem_type, ns_xmem_type_cfg, ns_xmem_base);
			size_t treex_block_size = 0;

			if (ns && ! ns->cold_start &&
					cf_xmem_attach_block(ns_xmem_type, ns_xmem_type_cfg, ns_key_base | AS_XMEM_TREEX_KEY_BASE, &treex_block_size, (void**)&ns->xmem_trees) == CF_XMEM_OK) {
				if (xmem_treex_block_size_check(ns, treex_block_size)) {
					ns->xmem_id = ns_xmem_id;

					ns->xmem_base = cf_malloc(AS_XMEM_NS_BASE_BLOCK_SIZE);
					memcpy(ns->xmem_base, ns_xmem_base, AS_XMEM_NS_BASE_BLOCK_SIZE);

					xmem_must_detach_base_block(ns_xmem_type, ns_xmem_base);
					xmem_must_delete_base_block(ns_xmem_type, ns_xmem_type_cfg, ns_key_base);

					available[ns_xmem_id] = false;
					continue;
				}

				xmem_must_detach_treex_block(ns, treex_block_size);
			}

			xmem_must_detach_base_block(ns_xmem_type, ns_xmem_base);
		}

		xmem_delete_any_namespace_blocks(ns_key_base, ns_key_base | AS_XMEM_ARENA_KEY_BASE);
		available[ns_xmem_id] = true;
	}

	uint32_t available_at = 0;

	for (uint32_t i = 0; i < g_config.n_namespaces; i++) {
		as_namespace* ns = g_config.namespaces[i];

		if (ns->xmem_id == 0) {
			while (++available_at <= AS_NAMESPACE_SZ) {
				if (available[available_at]) {
					ns->xmem_id = available_at;

					if (! ns->cold_start) {
						cf_info(AS_NAMESPACE, "{%s} found no valid persistent memory blocks, will cold start", ns->name);
						ns->cold_start = true;
					}

					break;
				}
			}

			cf_assert(available_at <= AS_NAMESPACE_SZ, AS_NAMESPACE, "no available namespace persistent memory ids");
		}

		key_t ns_key_base = AS_XMEM_KEY_BASE | (instance << AS_XMEM_INSTANCE_KEY_SHIFT) | (ns->xmem_id << AS_XMEM_NS_KEY_SHIFT);
		key_t ns_arena_key_base = ns_key_base | AS_XMEM_ARENA_KEY_BASE;

		// Warm or cool restart.
		if (! ns->cold_start) {
			cf_info(AS_NAMESPACE, "{%s} beginning %s restart", ns->name, as_namespace_start_mode_str(ns));

			if (! ns_xmem_resume(ns, ns_arena_key_base)) {
				cf_warning(AS_NAMESPACE, "{%s} aborted %s restart, will try cold start", ns->name, as_namespace_start_mode_str(ns));
				ns->cold_start = true;

				cf_free(ns->xmem_base);
				xmem_must_detach_treex_block(ns, xmem_treex_block_size(ns));
				xmem_delete_namespace_blocks(ns->xmem_type, ns->xmem_type_cfg, ns_key_base, ns_arena_key_base);
			}

			// Note - can't switch safely to cold start past this point!
		}

		// Cold start.
		if (ns->cold_start) {
			cf_info(AS_NAMESPACE, "{%s} beginning cold start", ns->name);

			ns_xmem_create(ns, ns_key_base, ns_arena_key_base);
		}
	}
}


void
as_namespace_finish_setup(as_namespace* ns, uint32_t instance)
{
	if (ns->cold_start) {
		return;
	}

	xmem_must_detach_treex_block(ns, xmem_treex_block_size(ns));

	key_t ns_key_base = AS_XMEM_KEY_BASE | (instance << AS_XMEM_INSTANCE_KEY_SHIFT) | (ns->xmem_id << AS_XMEM_NS_KEY_SHIFT);

	xmem_must_delete_treex_block(ns->xmem_type, ns->xmem_type_cfg, ns_key_base);
}


//==========================================================
// Local helpers.
//

bool
xmem_find_base_block(key_t ns_key_base, uint8_t** pp_block, cf_xmem_type* p_ns_xmem_type, const void** p_ns_xmem_type_cfg)
{
	cf_xmem_type attached_by = CF_XMEM_TYPE_UNDEFINED;

	for (cf_xmem_type type = 0; type < CF_NUM_XMEM_TYPES; type++) {
		uint32_t count = g_xmem_type_cfg_used_counts[type];

		for (uint32_t cfg_ix = 0; cfg_ix < count; cfg_ix++) {
			const void* cfg = g_xmem_type_cfgs_used[type][cfg_ix];
			size_t base_block_size = AS_XMEM_NS_BASE_BLOCK_SIZE;
			void* block;

			if (cf_xmem_attach_block(type, cfg, ns_key_base, &base_block_size, &block) == CF_XMEM_OK) {
				if (attached_by != CF_XMEM_TYPE_UNDEFINED) {
					xmem_must_detach_base_block(attached_by, *pp_block);
					xmem_must_detach_base_block(type, block);
					return false;
				}

				attached_by = type;

				*pp_block = block;
				*p_ns_xmem_type = type;
				*p_ns_xmem_type_cfg = cfg;
			}
		}
	}

	return attached_by != CF_XMEM_TYPE_UNDEFINED;
}

void
xmem_delete_any_namespace_blocks(key_t ns_key_base, key_t ns_arena_key_base)
{
	for (cf_xmem_type type = 0; type < CF_NUM_XMEM_TYPES; type++) {
		uint32_t count = g_xmem_type_cfg_used_counts[type];

		for (uint32_t cfg_ix = 0; cfg_ix < count; cfg_ix++) {
			const void* cfg = g_xmem_type_cfgs_used[type][cfg_ix];

			xmem_delete_namespace_blocks(type, cfg, ns_key_base, ns_arena_key_base);
		}
	}
}

as_namespace*
xmem_find_namespace_for_base_block(cf_xmem_type ns_xmem_type, const void* ns_xmem_type_cfg, const uint8_t* ns_xmem_base)
{
	// Check the existing persistent memory scheme. Version, partition count,
	// and all offsets must match.

	const as_xmem_scheme* scheme = (const as_xmem_scheme*)ns_xmem_base;

	if (scheme->version != AS_XMEM_NS_SCHEME.version && ! xmem_can_convert(scheme)) {
		cf_warning(AS_NAMESPACE, "can't convert persistent memory version %u to %u", scheme->version, AS_XMEM_NS_SCHEME.version);
		return NULL;
	}

	if (scheme->namespace_offset != AS_XMEM_NS_SCHEME.namespace_offset ||
		scheme->arena_offset != AS_XMEM_NS_SCHEME.arena_offset ||
		scheme->sets_vmapx_offset != AS_XMEM_NS_SCHEME.sets_vmapx_offset ||
		scheme->bins_vmapx_offset != AS_XMEM_NS_SCHEME.bins_vmapx_offset) {

		cf_warning(AS_NAMESPACE, "persistent memory scheme mismatch");
		return NULL;
	}

	char* ns_name = (char*)(ns_xmem_base + scheme->namespace_offset);
	uint32_t i;

	for (i = 0; i < g_config.n_namespaces; i++) {
		as_namespace* ns = g_config.namespaces[i];

		if (strcmp(ns_name, ns->name) == 0) {
			if (ns_xmem_type != ns->xmem_type) {
				cf_warning(AS_NAMESPACE, "{%s} persistent memory type %d doesn't match config %d", ns_name, ns_xmem_type, ns->xmem_type);
				return NULL;
			}

			if (! cf_xmem_type_cfg_same(ns_xmem_type, ns_xmem_type_cfg, ns->xmem_type_cfg)) {
				cf_warning(AS_NAMESPACE, "{%s} persistent memory type cfg doesn't match config", ns_name);
				return NULL;
			}

			if (scheme->flags != ns->xmem_flags) {
				cf_warning(AS_NAMESPACE, "{%s} persistent memory flags 0x%x don't match config 0x%x", ns_name, scheme->flags, ns->xmem_flags);
				return NULL;
			}

			if (scheme->n_sprigs != ns->tree_shared.n_sprigs) {
				cf_warning(AS_NAMESPACE, "{%s} persistent memory partition-tree-sprigs %u doesn't match config %u", ns_name, scheme->n_sprigs, ns->tree_shared.n_sprigs);
				return NULL;
			}

			if (scheme->index_stage_size != ns->index_stage_size) {
				cf_warning(AS_NAMESPACE, "{%s} persistent memory index-stage-size %lu doesn't match config %lu", ns_name, scheme->index_stage_size, ns->index_stage_size);
				return NULL;
			}

			return ns;
		}
	}

	// Found xmem with no owner - removed namespace from configuration?
	return NULL;
}

bool
xmem_treex_block_size_check(as_namespace* ns, size_t treex_block_size)
{
	if (treex_block_size < sizeof(as_treex)) {
		return false;
	}

	return xmem_treex_block_size(ns) == treex_block_size;
}

size_t
xmem_treex_block_size(as_namespace* ns)
{
	uint32_t n_owned = 0;

	for (uint32_t pid = 0; pid < AS_PARTITIONS; pid++) {
		if (ns->xmem_trees->block_ix[pid] >= 0) {
			n_owned++;
		}
	}

	return sizeof(as_treex) +
			(sizeof(as_sprigx) * ns->tree_shared.n_sprigs * n_owned);
}

void
xmem_must_detach_base_block(cf_xmem_type ns_xmem_type, uint8_t* base_block)
{
	cf_xmem_err result = cf_xmem_detach_block(ns_xmem_type, base_block, AS_XMEM_NS_BASE_BLOCK_SIZE);

	cf_assert(result == CF_XMEM_OK, AS_NAMESPACE, "can't detach persistent memory base block %p: %s", base_block, cf_strerror(result));
}

void
xmem_must_delete_base_block(cf_xmem_type ns_xmem_type, const void* ns_xmem_type_cfg, key_t ns_key_base)
{
	cf_xmem_err result = cf_xmem_destroy_block(ns_xmem_type, ns_xmem_type_cfg, ns_key_base);

	cf_assert(result == CF_XMEM_OK, AS_NAMESPACE, "can't remove persistent memory base block: %s", cf_strerror(result));
}

void
xmem_must_detach_treex_block(as_namespace* ns, size_t size)
{
	cf_xmem_err result = cf_xmem_detach_block(ns->xmem_type, (void*)ns->xmem_trees, size);

	cf_assert(result == CF_XMEM_OK, AS_NAMESPACE, "can't detach persistent memory treex block %p: %s", ns->xmem_trees, cf_strerror(result));
}

void
xmem_must_delete_treex_block(cf_xmem_type ns_xmem_type, const void* ns_xmem_type_cfg, key_t ns_key_base)
{
	cf_xmem_err result = cf_xmem_destroy_block(ns_xmem_type, ns_xmem_type_cfg, ns_key_base | AS_XMEM_TREEX_KEY_BASE);

	cf_assert(result == CF_XMEM_OK, AS_NAMESPACE, "can't remove persistent memory treex block: %s", cf_strerror(result));
}

void
xmem_delete_namespace_blocks(cf_xmem_type ns_xmem_type, const void* ns_xmem_type_cfg, key_t ns_key_base, key_t ns_arena_key_base)
{
	bool must_crash = false;
	cf_xmem_err result = cf_xmem_destroy_block(ns_xmem_type, ns_xmem_type_cfg, ns_key_base);

	if (result != CF_XMEM_OK && result != ENOENT) {
		cf_warning(AS_NAMESPACE, "can't remove persistent memory base block: %s", cf_strerror(result));
		must_crash = true;
	}

	result = cf_xmem_destroy_block(ns_xmem_type, ns_xmem_type_cfg, ns_key_base | AS_XMEM_TREEX_KEY_BASE);

	if (result != CF_XMEM_OK && result != ENOENT) {
		cf_warning(AS_NAMESPACE, "can't remove persistent memory treex block: %s", cf_strerror(result));
		must_crash = true;
	}

	for (key_t i = 0; i < CF_ARENAX_MAX_STAGES; i++) {
		result = cf_xmem_destroy_block(ns_xmem_type, ns_xmem_type_cfg, ns_arena_key_base + i);

		if (result != CF_XMEM_OK && result != ENOENT) {
			cf_warning(AS_NAMESPACE, "can't remove arena stage %u: %s", i, cf_strerror(result));
			must_crash = true;
		}
	}

	if (must_crash) {
		cf_crash(AS_NAMESPACE, "fail persistent memory delete");
	}
}

bool
ns_xmem_resume(as_namespace* ns, key_t ns_arena_key_base)
{
	as_xmem_scheme* scheme = (as_xmem_scheme*)ns->xmem_base;

	// Check the previous shutdown status - previous shutdown must be trusted.
	if (scheme->prev_shutdown_status != PREV_SHUTDOWN_TRUSTED) {
		cf_warning(AS_NAMESPACE, "{%s} previous shutdown not trusted", ns->name);
		return false;
	}

	// Set pointers of objects that live in persistent memory.
	ns_xmem_set_pointers(ns);

	// Resume these objects. Can't proceed past any failure that does not detach
	// all persistent memory blocks.

	cf_vmapx_err vmap_result = cf_vmapx_resume(ns->p_sets_vmap, sizeof(as_set), AS_SET_MAX_COUNT, 1024, AS_SET_NAME_MAX_SIZE);

	if (vmap_result != CF_VMAPX_OK) {
		cf_warning(AS_NAMESPACE, "{%s} can't resume sets vmap: %d", ns->name, vmap_result);
		return false;
	}

	if (! ns_xmem_init_sets_cfg(ns)) {
		cf_warning(AS_NAMESPACE, "{%s} can't configure sets", ns->name);
		cf_vmapx_release(ns->p_sets_vmap);
		return false;
	}

	if (! ns->single_bin) {
		vmap_result = cf_vmapx_resume(ns->p_bin_name_vmap, AS_BIN_NAME_MAX_SZ, MAX_BIN_NAMES, 64 * 1024, AS_BIN_NAME_MAX_SZ);

		if (vmap_result != CF_VMAPX_OK) {
			cf_warning(AS_NAMESPACE, "{%s} can't resume bins vmap: %d", ns->name, vmap_result);
			cf_vmapx_release(ns->p_sets_vmap);
			return false;
		}
	}

	uint32_t element_size = (uint32_t)sizeof(as_index);
	uint32_t chunk_count = as_index_chunk_count(ns);
	uint32_t stage_capacity = (uint32_t)(ns->index_stage_size / element_size);

	cf_arenax_err arena_result = cf_arenax_resume(ns->arena, ns->xmem_type, ns->xmem_type_cfg, ns_arena_key_base, element_size, chunk_count, stage_capacity, 0);

	if (arena_result != CF_ARENAX_OK) {
		cf_warning(AS_NAMESPACE, "{%s} can't resume arena: %s", ns->name, cf_arenax_errstr(arena_result));
		cf_vmapx_release(ns->p_bin_name_vmap);
		cf_vmapx_release(ns->p_sets_vmap);

		// Can't continue to cold start unless all stages detached.
		cf_assert(arena_result != CF_ARENAX_ERR_STAGE_DETACH, AS_NAMESPACE, "{%s} arena stage(s) still attached", ns->name);

		return false;
	}

	// Now that arenas are attached we can convert index data.
	if (xmem_can_convert(scheme)) {
		ns_xmem_convert(ns, scheme);
	}

	// Note - as_partition_init() resumes persistent memory trees info.
	return true;
}

void
ns_xmem_create(as_namespace* ns, key_t ns_key_base, key_t ns_arena_key_base)
{
	ns->xmem_base = cf_malloc(AS_XMEM_NS_BASE_BLOCK_SIZE);
	// Note - the treex block will be created at shutdown.

	// Prefer zero to junk - may help with future versions that add new content.
	memset(ns->xmem_base, 0, AS_XMEM_NS_BASE_BLOCK_SIZE);

	// Write the persistent memory scheme at the beginning of the base block.
	as_xmem_scheme* scheme = (as_xmem_scheme*)ns->xmem_base;

	// Write the constant part.
	*scheme = AS_XMEM_NS_SCHEME;

	// Write the configured part.
	scheme->flags = ns->xmem_flags;
	scheme->n_sprigs = ns->tree_shared.n_sprigs;
	scheme->index_stage_size = ns->index_stage_size;

	// Write the namespace name.
	strcpy((char*)(ns->xmem_base + scheme->namespace_offset), ns->name);

	// Set pointers of objects that live in persistent memory.
	ns_xmem_set_pointers(ns);

	// Initialize these objects. Can't proceed past failure.

	cf_vmapx_init(ns->p_sets_vmap, sizeof(as_set), AS_SET_MAX_COUNT, 1024, AS_SET_NAME_MAX_SIZE);

	if (! ns_xmem_init_sets_cfg(ns)) {
		cf_crash(AS_NAMESPACE, "{%s} can't configure sets", ns->name);
	}

	if (! ns->single_bin) {
		cf_vmapx_init(ns->p_bin_name_vmap, AS_BIN_NAME_MAX_SZ, MAX_BIN_NAMES, 64 * 1024, AS_BIN_NAME_MAX_SZ);
	}

	uint32_t element_size = (uint32_t)sizeof(as_index);
	uint32_t chunk_count = as_index_chunk_count(ns);
	uint32_t stage_capacity = (uint32_t)(ns->index_stage_size / element_size);

	cf_arenax_init(ns->arena, ns->xmem_type, ns->xmem_type_cfg, ns_arena_key_base, element_size, chunk_count, stage_capacity, 0);

	// Note - as_partition_init() initializes persistent memory trees info.
}

void
ns_xmem_set_pointers(as_namespace* ns)
{
	ns->arena = (cf_arenax*)(ns->xmem_base + AS_XMEM_NS_SCHEME.arena_offset);
	ns->tree_shared.arena = ns->arena;

	ns->p_sets_vmap = (cf_vmapx*)(ns->xmem_base + AS_XMEM_NS_SCHEME.sets_vmapx_offset);

	if (! ns->single_bin) {
		ns->p_bin_name_vmap = (cf_vmapx*)(ns->xmem_base + AS_XMEM_NS_SCHEME.bins_vmapx_offset);
	}
}

bool
ns_xmem_init_sets_cfg(as_namespace* ns)
{
	uint32_t sets_count = cf_vmapx_count(ns->p_sets_vmap);

	for (uint32_t idx = 0; idx < sets_count; idx++) {
		as_set* p_set = NULL;
		cf_vmapx_err result = cf_vmapx_get_by_index(ns->p_sets_vmap, idx, (void**)&p_set);

		if (result != CF_VMAPX_OK) {
			// Should be impossible - idx less than count.
			cf_warning(AS_NAMESPACE, "unexpected error %d", result);
			return false;
		}

		// Clear everything but set name - only name needs to be persistent.
		memset((uint8_t*)p_set + AS_SET_NAME_MAX_SIZE, 0, sizeof(as_set) - AS_SET_NAME_MAX_SIZE);
	}

	return as_namespace_configure_sets(ns);
}


//==========================================================
// Local helpers - warm or cool restart conversion.
//

void
ns_xmem_convert(as_namespace* ns, as_xmem_scheme* scheme)
{
	cf_info(AS_NAMESPACE, "{%s} converting persistent memory version %u to %u ...", ns->name, scheme->version, AS_XMEM_NS_SCHEME.version);

	// Can't convert any version for now - should never get here.
	cf_crash(AS_NAMESPACE, "{%s} persistent memory conversion unavailable", ns->name);

	// Conversion completed - write the new version.
	scheme->version = AS_XMEM_NS_SCHEME.version;

	cf_info(AS_NAMESPACE, "{%s} ... converted to persistent memory version %u", ns->name, AS_XMEM_NS_SCHEME.version);
}

void
ns_xmem_convert_index_elements(as_namespace* ns, cf_arenax_scan_cb cb)
{
	// Split this task across multiple threads.
	uint32_t n_cpus = cf_topo_count_cpus();
	cf_tid tids[n_cpus];
	convert_thread_info info = {
			.p_arena = ns->arena,
			.stage_id = -1,
			.i_cpu = -1,
			.cb = cb
	};

	for (uint32_t n = 0; n < n_cpus; n++) {
		tids[n] = cf_thread_create_joinable(run_convert, (void*)&info);
	}

	for (uint32_t n = 0; n < n_cpus; n++) {
		cf_thread_join(tids[n]);
	}
	// Now we're single-threaded again.
}

void*
run_convert(void* pv_data)
{
	convert_thread_info* p_info = (convert_thread_info*)pv_data;

	cf_topo_pin_to_cpu((cf_topo_cpu_index)cf_atomic32_incr(&p_info->i_cpu));

	while (true) {
		uint32_t stage_id = (uint32_t)cf_atomic32_incr(&p_info->stage_id);

		if (! cf_arenax_scan(p_info->p_arena, stage_id, p_info->cb, NULL)) {
			break;
		}

		cf_debug(AS_NAMESPACE, "... scanned arena stage %u", stage_id);
	}

	return NULL;
}
