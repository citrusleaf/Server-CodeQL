/*
 * xmem_flash.c
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

#include "xmem.h"
#include "xmem_ee.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "citrusleaf/alloc.h"

#include "hardware.h"
#include "log.h"
#include "os.h"
#include "shash.h"

#include "warnings.h"


//==========================================================
// Typedefs & constants.
//

typedef struct ssd_cfg_s {
	uint32_t n_mounts;
	const char** mounts;
} ssd_cfg;

#define PAGE_SIZE 4096

// Transparent huge pages were introduced in Linux 2.6.38, together with the
// MADV_NOHUGEPAGE advice. We would like to allow compilation also with older
// kernel headers:

#if !defined MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif

// The idea is to not depend on the version of the kernel headers at compile
// time, but on the version of the kernel that we run on:
//
//   - When we run on a kernel without MADV_NOHUGEPAGE, madvise() returns
//     EINVAL and we know that the kernel is pre-2.6.38, i.e., that it does not
//     support transparent huge pages. So we're good.
//
//   - Otherwise, with a 2.6.38+ kernel, MADV_NOHUGEPAGE will work, which will
//     disable transparent huge pages for the mapped regions. So we're good.


//==========================================================
// Forward declarations.
//

static bool type_cfg_init(const char* mounts[], uint32_t n_mounts, uint64_t size_limit, const void** p_xmem_type_cfg);
static bool type_cfg_same(const void* xmem_type_cfg1, const void* xmem_type_cfg2);
static void get_props(const void* xmem_type_cfg, cf_xmem_props* props);
static cf_xmem_err create_block(const void* xmem_type_cfg, key_t key, size_t size, void** r_block);
static cf_xmem_err destroy_block(const void* xmem_type_cfg, key_t key);
static cf_xmem_err attach_block(const void* xmem_type_cfg, key_t key, size_t* r_size, void** r_block);
static cf_xmem_err detach_block(void* block, size_t size);
static cf_xmem_err flush_block(void* block, size_t size);
static cf_xmem_err advise_scan(void* block, size_t size, bool scan);
static cf_xmem_err prefetch(void* addr);


//==========================================================
// Inlines & macros.
//

static inline void
select_ssd_file(const ssd_cfg* cfg, key_t key, char* ssd_file)
{
	// If not NUMA pinned, use all mounts in round robin fashion.
	uint32_t i = (uint32_t)key % cfg->n_mounts;

	sprintf(ssd_file, "%s/%x", cfg->mounts[i], key);
}


//==========================================================
// Public API - vtable.
//

const xmem_vtable xmem_vtable_flash = {
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

static bool
type_cfg_init(const char* mounts[], uint32_t n_mounts,
		uint64_t size_limit, const void** p_xmem_type_cfg)
{
	cf_detail(CF_XMEM, "type_cfg_init() %u", n_mounts);

	if (n_mounts == 0) {
		return false;
	}

	uint64_t total = 0;

	for (uint32_t i = 0; i < n_mounts; i++) {
		if (cf_storage_is_root_fs(mounts[i])) {
			cf_warning(CF_XMEM, "no file system mounted at %s", mounts[i]);
		}

		int64_t size = cf_storage_file_system_size(mounts[i]);

		if (size < 0) {
			return false;
		}

		total += (uint64_t)size;
	}

	if (size_limit > total) {
		cf_warning(CF_XMEM, "index device size limit %lu higher than total file system size %lu",
				size_limit, total);
		return false;
	}

	ssd_cfg* cfg = (ssd_cfg*)cf_malloc(sizeof(ssd_cfg));

	cfg->n_mounts = n_mounts;
	cfg->mounts = mounts;

	*p_xmem_type_cfg = (void*)cfg;

	return true;
}

static bool
type_cfg_same(const void* xmem_type_cfg1, const void* xmem_type_cfg2)
{
	ssd_cfg* cfg1 = (ssd_cfg*)xmem_type_cfg1;
	ssd_cfg* cfg2 = (ssd_cfg*)xmem_type_cfg2;

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

static void
get_props(const void* xmem_type_cfg, cf_xmem_props* props)
{
	ssd_cfg* cfg = (ssd_cfg*)xmem_type_cfg;

	props->want_prefetch = true;
	props->n_interleave = cfg->n_mounts;
}

static cf_xmem_err
create_block(const void* xmem_type_cfg, key_t key, size_t size, void** r_block)
{
	char ssd_file[1024];
	select_ssd_file((const ssd_cfg*)xmem_type_cfg, key, ssd_file);

	int32_t fd = open(ssd_file, O_CREAT | O_EXCL | O_RDWR, cf_os_base_perms());

	if (fd < 0) {
		return errno;
	}

	cf_xmem_err err = posix_fallocate(fd, 0, (off_t)size);

	if (err != 0) {
		close(fd);
		unlink(ssd_file);
		return err;
	}

	void* block = mmap(NULL, size, PROT_READ | PROT_WRITE , MAP_SHARED, fd, 0);

	if (block == MAP_FAILED) {
		err = errno;
		close(fd);
		unlink(ssd_file);
		return err;
	}

	close(fd); // doesn't invalidate the mmap()

	if (madvise(block, size, MADV_RANDOM) != 0 ||
			// For the EINVAL story, see the #define for MADV_NOHUGEPAGE above.
			(madvise(block, size, MADV_NOHUGEPAGE) != 0 && errno != EINVAL)) {
		err = errno;
		munmap(block, size);
		unlink(ssd_file);
		return err;
	}

	cf_detail(CF_XMEM, "create_block() %x %s %p %zu",
			key, ssd_file, block, size);

	*r_block = block;

	return CF_XMEM_OK;
}

static cf_xmem_err
destroy_block(const void* xmem_type_cfg, key_t key)
{
	char ssd_file[1024];
	select_ssd_file((const ssd_cfg*)xmem_type_cfg, key, ssd_file);

	if (unlink(ssd_file) != 0) {
		return errno; // includes ENOENT (block doesn't exist)
	}

	cf_detail(CF_XMEM, "destroy_block() %x %s", key, ssd_file);

	return CF_XMEM_OK;
}

static cf_xmem_err
attach_block(const void* xmem_type_cfg, key_t key, size_t* r_size,
		void** r_block)
{
	char ssd_file[1024];
	select_ssd_file((const ssd_cfg*)xmem_type_cfg, key, ssd_file);

	int32_t fd = open(ssd_file, O_RDWR);

	if (fd < 0) {
		return errno;
	}

	struct stat buf;

	if (fstat(fd, &buf) != 0) {
		cf_xmem_err err = errno;
		close(fd);
		return err;
	}

	void* block = mmap(NULL, (size_t)buf.st_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);

	if (block == MAP_FAILED) {
		cf_xmem_err err = errno;
		close(fd);
		return err;
	}

	close(fd); // doesn't invalidate the mmap()

	if (madvise(block, (size_t)buf.st_size, MADV_RANDOM) != 0 ||
			// For the EINVAL story, see the #define for MADV_NOHUGEPAGE above.
			(madvise(block, (size_t)buf.st_size, MADV_NOHUGEPAGE) != 0
					&& errno != EINVAL)) {
		cf_xmem_err err = errno;
		munmap(block, (size_t)buf.st_size);
		return err;
	}

	cf_detail(CF_XMEM, "attach_block() %x %s %p %zu",
			key, ssd_file, block, buf.st_size);

	*r_size = (size_t)buf.st_size;
	*r_block = block;

	return CF_XMEM_OK;
}

static cf_xmem_err
detach_block(void* block, size_t size)
{
	cf_detail(CF_XMEM, "detach_block() %p %zu", block, size);

	return munmap(block, size) != 0 ? errno : CF_XMEM_OK;
}

static cf_xmem_err
flush_block(void* block, size_t size)
{
	return msync(block, size, MS_SYNC) != 0 ? errno : CF_XMEM_OK;
}

static cf_xmem_err
advise_scan(void* block, size_t size, bool scan)
{
	cf_detail(CF_XMEM, "advise_scan() %p %zu %d", block, size, scan);

	return madvise(block, size, scan ? MADV_SEQUENTIAL : MADV_RANDOM) != 0 ?
			errno : CF_XMEM_OK;
}

static cf_xmem_err
prefetch(void* addr)
{
	addr = (void*)((uintptr_t)addr & (uintptr_t)-PAGE_SIZE);

	return madvise(addr, PAGE_SIZE, MADV_WILLNEED) != 0 ? errno : CF_XMEM_OK;
}
