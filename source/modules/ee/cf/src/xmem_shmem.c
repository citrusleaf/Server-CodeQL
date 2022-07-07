/*
 * xmem_shmem.c
 *
 * Copyright (C) 2018-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "xmem_ee.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>

#include "warnings.h"


//==========================================================
// Typedefs & constants.
//

const int SHMGET_FLAGS_CREATE_ONLY = IPC_CREAT | IPC_EXCL | 0666;
const int SHMGET_FLAGS_EXISTING = 0666;


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
// Public API - vtable.
//

const xmem_vtable xmem_vtable_shmem = {
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
	(void)mounts;
	(void)n_mounts;
	(void)size_limit;
	(void)p_xmem_type_cfg;

	// No shmem-specific configuration.
	return true;
}

//------------------------------------------------
// Compare configuration info.
//
static bool
type_cfg_same(const void* xmem_type_cfg1, const void* xmem_type_cfg2)
{
	(void)xmem_type_cfg1;
	(void)xmem_type_cfg2;

	// No shmem-specific configuration.
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
	(void)xmem_type_cfg;

	// Create the block if it doesn't exist, fail if it does.
	int shmid = shmget(key, size, SHMGET_FLAGS_CREATE_ONLY);

	if (shmid < 0) {
		return errno;
	}

	void* p_block = shmat(shmid, NULL, 0);

	if (p_block == (void*)-1) {
		return errno;
	}

	*pp_block = p_block;

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
	(void)xmem_type_cfg;

	// Attempt to get shmid for block - don't create if it doesn't exist. Pass
	// __size of 0 to be sure we get existing block whatever size it is.
	int shmid = shmget(key, 0, SHMGET_FLAGS_EXISTING);

	if (shmid < 0) {
		return errno; // includes ENOENT (block doesn't exist)
	}

	// Block exists - remove it unless it's attached.

	// Check if block is attached.
	struct shmid_ds ds;

	if (shmctl(shmid, IPC_STAT, &ds) != 0) {
		return errno;
	}

	// Fail if block is attached.
	if (ds.shm_nattch > 0) {
		return EBUSY;
	}

	return shmctl(shmid, IPC_RMID, NULL) != 0 ? errno : CF_XMEM_OK;
}

//------------------------------------------------
// Attach to existing persistent memory block.
// Fail if no block exists for specified key.
//
static cf_xmem_err
attach_block(const void* xmem_type_cfg, key_t key, size_t* p_size,
		void** pp_block)
{
	(void)xmem_type_cfg;

	size_t size = *p_size; // size may be 0

	// Attempt to get shmid for block - don't create if it doesn't exist.
	int shmid = shmget(key, size, SHMGET_FLAGS_EXISTING);

	if (shmid < 0) {
		return errno;
	}

	if (size == 0) {
		struct shmid_ds ds;
		int result = shmctl(shmid, IPC_STAT, &ds);

		if (result < 0) {
			return errno;
		}

		size = ds.shm_segsz;
	}

	void* p_block = shmat(shmid, NULL, 0);

	if (p_block == (void*)-1) {
		return errno;
	}

	*p_size = size;
	*pp_block = p_block;

	return CF_XMEM_OK;
}

//------------------------------------------------
// Detach from existing persistent memory block.
//
static cf_xmem_err
detach_block(void* p_block, size_t size)
{
	(void)size;

	return shmdt(p_block) != 0 ? errno : CF_XMEM_OK;
}

//------------------------------------------------
// Flush existing persistent memory block.
//
static cf_xmem_err
flush_block(void* p_block, size_t size)
{
	(void)p_block;
	(void)size;

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
