/*
 * xmem_pmem.c
 *
 * Copyright (C) 2018-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

// Steps to setup filesystem before you can create a block:
// 1. Create a mount point for pmem.
//     > sudo mkdir /mnt/pmem
// 2. Locate the path to pmem (look under /dev for pmem). Usually the path
//    is /dev/pmem but it can include a number (/dev/pmem11).
// 3. Make the filesystem on /dev/pmem.
//     > sudo mkfs.ext4 /dev/pmem
// 4. Mount the partition.
//     > sudo mount -o dax /dev/pmem /mnt/pmem
// We can now work from /mnt/pmem.
//
// Use namespace context configuration:
// ...
//     index-type pmem {
//         mount /mnt/pmem
//     }
// ...

//==========================================================
// Includes.
//

#include "xmem.h"
#include "xmem_ee.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "libpmem.h"

#include "citrusleaf/alloc.h"

#include "hardware.h"
#include "log.h"
#include "os.h"

#include "warnings.h"


//==========================================================
// Typedefs & constants.
//

typedef struct pmem_cfg_s {
	uint32_t n_mounts;
	const char** mounts;
} pmem_cfg;


//==========================================================
// Forward declarations.
//

static bool type_cfg_init(const char* mounts[], uint32_t n_mounts, uint64_t size_limit, const void** p_xmem_type_cfg);
static bool type_cfg_same(const void* xmem_type_cfg1, const void* xmem_type_cfg2);
static void get_props(const void* xmem_type_cfg, cf_xmem_props* props);
static cf_xmem_err create_block(const void* xmem_type_cfg, key_t key, size_t size, void** pp_block);
static cf_xmem_err destroy_block(const void* xmem_type_cfg, key_t key);
static cf_xmem_err attach_block(const void* xmem_type_cfg, key_t key, size_t* p_size, void** pp_block);
static cf_xmem_err detach_block(void* p_block, size_t size);
static cf_xmem_err flush_block(void* p_block, size_t size);
static cf_xmem_err advise_scan(void* p_block, size_t size, bool scan);
static cf_xmem_err prefetch(void* addr);


//==========================================================
// Inlines & macros.
//

static inline void
select_pmem_file(const pmem_cfg* cfg, key_t key, char* pmem_file)
{
	// If not NUMA pinned, use all mounts in round robin fashion.
	uint32_t i = (uint32_t)key % cfg->n_mounts;

	sprintf(pmem_file, "%s/%x", cfg->mounts[i], key);
}


//==========================================================
// Public API - vtable.
//

const xmem_vtable xmem_vtable_pmem = {
		type_cfg_init,
		type_cfg_same,
		get_props,
		create_block,
		destroy_block,
		attach_block,
		detach_block,
		flush_block,
		advise_scan,
		prefetch
};


//==========================================================
// Public API - implementation of vtable.
//

//------------------------------------------------
// Initialize configuration info.
//
static bool
type_cfg_init(const char* mounts[], uint32_t n_mounts, uint64_t size_limit,
		const void** p_xmem_type_cfg)
{
	if (n_mounts == 0) {
		return false;
	}

	const char** use_mounts =
			(const char**)cf_malloc(n_mounts * sizeof(const char*));
	uint32_t n_use_mounts = 0;

	uint64_t total = 0;

	for (uint32_t i = 0; i < n_mounts; i++) {
		if (! cf_mount_is_local(mounts[i])) {
			cf_info(CF_XMEM, "ignoring mount: %s", mounts[i]);
			continue;
		}

		cf_info(CF_XMEM, "using mount: %s", mounts[i]);

		use_mounts[n_use_mounts++] = mounts[i];

		if (cf_storage_is_root_fs(mounts[i])) {
			cf_warning(CF_XMEM, "no file system mounted at %s", mounts[i]);
		}

		int64_t size = cf_storage_file_system_size(mounts[i]);

		if (size < 0) {
			return false;
		}

		total += (uint64_t)size;
	}

	if (n_use_mounts == 0) {
		cf_warning(CF_XMEM, "found no mounts to use");
		return false;
	}

	if (size_limit > total) {
		cf_warning(CF_XMEM, "index device size limit %lu higher than total file system size %lu",
				size_limit, total);
		return false;
	}

	pmem_cfg* cfg = (pmem_cfg*)cf_malloc(sizeof(pmem_cfg));

	cfg->n_mounts = n_use_mounts;
	cfg->mounts = use_mounts;

	*p_xmem_type_cfg = (void*)cfg;

	return true;
}

//------------------------------------------------
// Compare configuration info.
//
static bool
type_cfg_same(const void* xmem_type_cfg1, const void* xmem_type_cfg2)
{
	pmem_cfg* cfg1 = (pmem_cfg*)xmem_type_cfg1;
	pmem_cfg* cfg2 = (pmem_cfg*)xmem_type_cfg2;

	if (cfg1->n_mounts != cfg2->n_mounts) {
		return false;
	}

	for (uint32_t i = 0; i < cfg1->n_mounts; i++) {
		if (strcmp(cfg1->mounts[i], cfg2->mounts[i]) != 0) {
			return false;
		}
	}

	return true;
}

//------------------------------------------------
// Get xmem properties.
//
static void
get_props(const void* xmem_type_cfg, cf_xmem_props* props)
{
	(void)xmem_type_cfg;

	props->want_prefetch = false;
	props->n_interleave = 1;
}

//------------------------------------------------
// Create a new persistent memory block and attach
// to it. Fail if a block already exists for
// specified key.
//
static cf_xmem_err
create_block(const void* xmem_type_cfg, key_t key, size_t size, void** pp_block)
{
	char pmem_file[1024];
	select_pmem_file((const pmem_cfg*)xmem_type_cfg, key, pmem_file);

	int is_pmem;

	// PMEM_FILE_CREATE | PMEM_FILE_EXCL ensures that if pathname already
	// exists, open() fails.
	void* block = pmem_map_file(pmem_file, size,
			PMEM_FILE_CREATE | PMEM_FILE_EXCL, cf_os_base_perms(), NULL,
			&is_pmem);

	if (block == NULL) {
		cf_warning(CF_XMEM, "%s size %zu pmem_map_file() create failed %d",
				pmem_file, size, errno);
		return errno;
	}

	if (is_pmem == 0) {
		cf_warning(CF_XMEM, "%s is not pmem", pmem_file);
	}

	cf_detail(CF_XMEM, "%s size %zu created", pmem_file, size);

	*pp_block = block;

	return CF_XMEM_OK;
}

//------------------------------------------------
// Destroy a persistent memory block. Fail if
// block is currently attached. Returns
// CF_XMEM_ERR_BLOCK_DOES_NOT_EXIST if no block
// exists for specified key - caller interprets
// whether or not this is an error.
//
static cf_xmem_err
destroy_block(const void* xmem_type_cfg, key_t key)
{
	char pmem_file[1024];
	select_pmem_file((const pmem_cfg*)xmem_type_cfg, key, pmem_file);

	// Includes ENOENT (block doesn't exist).
	return unlink(pmem_file) != 0 ? errno : CF_XMEM_OK;
}

//------------------------------------------------
// Attach to existing persistent memory block.
// Fail if no block exists for specified key.
//
static cf_xmem_err
attach_block(const void* xmem_type_cfg, key_t key, size_t* p_size,
		void** pp_block)
{
	char pmem_file[1024];
	select_pmem_file((const pmem_cfg*)xmem_type_cfg, key, pmem_file);

	size_t mapped_size;
	int is_pmem;

	// Fails if the file does not already exist.
	void* block = pmem_map_file(pmem_file, 0, 0, 0, &mapped_size, &is_pmem);

	if (block == NULL) {
		return errno;
	}

	if (is_pmem == 0) {
		cf_warning(CF_XMEM, "%s is not pmem", pmem_file);
	}

	if (*p_size != 0 && *p_size != mapped_size) {
		cf_warning(CF_XMEM, "%s size expected %zu actual %zu)", pmem_file,
				*p_size, mapped_size);
		pmem_unmap(block, mapped_size);
		return EINVAL;
	}

	cf_detail(CF_XMEM, "%s size %zu opened", pmem_file, mapped_size);

	*p_size = mapped_size;
	*pp_block = block;

	return CF_XMEM_OK;
}

//------------------------------------------------
// Detach from existing persistent memory block.
//
static cf_xmem_err
detach_block(void* p_block, size_t size)
{
	return pmem_unmap(p_block, size) != 0 ? errno : CF_XMEM_OK;
}

//------------------------------------------------
// Flush existing persistent memory block.
//
static cf_xmem_err
flush_block(void* p_block, size_t size)
{
	pmem_persist(p_block, size);

	return CF_XMEM_OK;
}

//------------------------------------------------
// Control read-ahead for persistent memory.
//
static cf_xmem_err
advise_scan(void* p_block, size_t size, bool scan)
{
	(void)p_block;
	(void)size;
	(void)scan;

	return CF_XMEM_OK;
}

//------------------------------------------------
// Prefetch a page of persistent memory.
//
static cf_xmem_err
prefetch(void* addr)
{
	(void)addr;

	return CF_XMEM_OK;
}
