/*
 * vmapx_ee.c
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

#include "vmapx.h"
#include "vmapx_ee.h"

#include <stdint.h>
#include <string.h>

#include "cf_mutex.h"
#include "log.h"


//==========================================================
// Forward declarations.
//

static void rebuild_hash_map(cf_vmapx* vmap);


//==========================================================
// Public API - enterprise only.
//

// Resume a cf_vmapx object in persistent memory. The hash map is not in
// persistent memory - it is rebuilt from the vector of values, relying on each
// value beginning with its name (which is used as the hash key).
cf_vmapx_err
cf_vmapx_resume(cf_vmapx* vmap, uint32_t value_size, uint32_t max_count,
		uint32_t hash_size, uint32_t max_name_size)
{
	cf_assert(hash_size != 0, CF_VMAPX, "bad hash_size");

	if (vmap->value_size != value_size || vmap->key_size != max_name_size) {
		return CF_VMAPX_ERR_BAD_PARAM;
	}

	if (vmap->count > max_count) {
		return CF_VMAPX_ERR_BAD_PARAM;
	}

	vmap->max_count = max_count;

	vmap->hash = vhash_create(max_name_size, hash_size);
	rebuild_hash_map(vmap);

	cf_mutex_init(&vmap->write_lock);

	return CF_VMAPX_OK;
}


//==========================================================
// Local helpers.
//

// Rebuild the hash map from the vector data.
static void
rebuild_hash_map(cf_vmapx* vmap)
{
	const char* name = (const char*)vmap->values;
	const char* p_end = (const char*)vmapx_value_ptr(vmap, vmap->count);
	uint32_t index = 0;

	while (name < p_end) {
		// Add to hash.
		vhash_put(vmap->hash, name, strlen(name), index);

		name += vmap->value_size;
		index++;
	}
}
