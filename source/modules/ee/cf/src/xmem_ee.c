/*
 * xmem_ee.c
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


//==========================================================
// Typedefs & constants.
//

const xmem_vtable* XMEM_VTABLES[] = {
		[CF_XMEM_TYPE_SHMEM] = &xmem_vtable_shmem,
		[CF_XMEM_TYPE_PMEM] = &xmem_vtable_pmem,
		[CF_XMEM_TYPE_FLASH] = &xmem_vtable_flash
};
