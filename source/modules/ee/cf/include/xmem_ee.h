/*
 * xmem_ee.h
 *
 * Copyright (C) 2018-2020 Aerospike, Inc.
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
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "xmem.h"


//==========================================================
// Typedefs & constants.
//

typedef int cf_xmem_err; // these are errno values

#define CF_XMEM_OK 0

typedef struct cf_xmem_props_s {
	bool want_prefetch;
	uint32_t n_interleave;
} cf_xmem_props;

typedef bool (*xmem_type_cfg_init) (const char* mounts[], uint32_t n_mounts, uint64_t size_limit, const void** p_xmem_type_cfg);
typedef bool (*xmem_type_cfg_same) (const void* xmem_type_cfg1, const void* xmem_type_cfg2);
typedef void (*xmem_get_props) (const void* xmem_type_cfg, cf_xmem_props* props);
typedef cf_xmem_err (*xmem_create_block) (const void* xmem_type_cfg, key_t key, size_t size, void** pp_block);
typedef cf_xmem_err (*xmem_destroy_block) (const void* xmem_type_cfg, key_t key);
typedef cf_xmem_err (*xmem_attach_block) (const void* xmem_type_cfg, key_t key, size_t* p_size, void** pp_block);
typedef cf_xmem_err (*xmem_detach_block) (void* p_block, size_t size);
typedef cf_xmem_err (*xmem_flush_block) (void* p_block, size_t size);
typedef cf_xmem_err (*xmem_advise_scan) (void* p_block, size_t size, bool scan);
typedef cf_xmem_err (*xmem_prefetch) (void* addr);

typedef struct xmem_vtable_s {
	xmem_type_cfg_init type_cfg_init;
	xmem_type_cfg_same type_cfg_same;
	xmem_get_props get_props;
	xmem_create_block create_block;
	xmem_destroy_block destroy_block;
	xmem_attach_block attach_block;
	xmem_detach_block detach_block;
	xmem_flush_block flush_block;
	xmem_advise_scan advise_scan;
	xmem_prefetch prefetch;
} xmem_vtable;


//==========================================================
// Public API - vtable.
//

extern const xmem_vtable xmem_vtable_shmem;
extern const xmem_vtable xmem_vtable_pmem;
extern const xmem_vtable xmem_vtable_flash;

// Vtables array, indexed by cf_xmem_type.
extern const xmem_vtable* XMEM_VTABLES[];


//==========================================================
// Public API.
//

const char* cf_xmem_errstr(cf_xmem_err err);

static inline bool
cf_xmem_type_cfg_init(cf_xmem_type xmem_type, const char* mounts[], uint32_t n_mounts, uint64_t size_limit, const void** p_xmem_type_cfg)
{
	return XMEM_VTABLES[xmem_type]->type_cfg_init(mounts, n_mounts, size_limit, p_xmem_type_cfg);
}

static inline bool
cf_xmem_type_cfg_same(cf_xmem_type xmem_type, const void* xmem_type_cfg1, const void* xmem_type_cfg2)
{
	return XMEM_VTABLES[xmem_type]->type_cfg_same(xmem_type_cfg1, xmem_type_cfg2);
}

static inline void
cf_xmem_get_props(cf_xmem_type xmem_type, const void* xmem_type_cfg, cf_xmem_props* props)
{
	return XMEM_VTABLES[xmem_type]->get_props(xmem_type_cfg, props);
}

static inline cf_xmem_err
cf_xmem_create_block(cf_xmem_type xmem_type, const void* xmem_type_cfg, key_t key, size_t size, void** pp_block)
{
	return XMEM_VTABLES[xmem_type]->create_block(xmem_type_cfg, key, size, pp_block);
}

static inline cf_xmem_err
cf_xmem_destroy_block(cf_xmem_type xmem_type, const void* xmem_type_cfg, key_t key)
{
	return XMEM_VTABLES[xmem_type]->destroy_block(xmem_type_cfg, key);
}

static inline cf_xmem_err
cf_xmem_attach_block(cf_xmem_type xmem_type, const void* xmem_type_cfg, key_t key, size_t* p_size, void** pp_block)
{
	return XMEM_VTABLES[xmem_type]->attach_block(xmem_type_cfg, key, p_size, pp_block);
}

static inline cf_xmem_err
cf_xmem_detach_block(cf_xmem_type xmem_type, void* p_block, size_t size)
{
	return XMEM_VTABLES[xmem_type]->detach_block(p_block, size);
}

static inline cf_xmem_err
cf_xmem_flush_block(cf_xmem_type xmem_type, void* p_block, size_t size)
{
	return XMEM_VTABLES[xmem_type]->flush_block(p_block, size);
}

static inline cf_xmem_err
cf_xmem_advise_scan(cf_xmem_type xmem_type, void* p_block, size_t size, bool scan)
{
	return XMEM_VTABLES[xmem_type]->advise_scan(p_block, size, scan);
}

static inline cf_xmem_err
cf_xmem_prefetch(cf_xmem_type xmem_type, void* addr)
{
	return XMEM_VTABLES[xmem_type]->prefetch(addr);
}
