/*
 * drv_common_ee.h
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

#include <stdbool.h>
#include <stdint.h>

#include "log.h"

#include "base/index.h"
#include "base/index_ee.h"
#include "storage/storage.h"


//==========================================================
// Forward declarations.
//

struct as_namespace_s;


//==========================================================
// Public API.
//

bool drv_peek_devices(struct as_namespace_s* ns);

void drv_init_sets_info(struct as_namespace_s* ns, bool sets_not_evicting[], uint64_t set_truncate_luts[], bool sets_indexed[]);
void drv_xts_encrypt(as_encryption_method meth, const uint8_t* key, uint64_t tweak, const uint8_t* in, size_t sz_in, uint8_t* out);
void drv_xts_decrypt(as_encryption_method meth, const uint8_t* key, uint64_t tweak, const uint8_t* in, size_t sz_in, uint8_t* out);
void drv_init_encryption_key(struct as_namespace_s* ns);

static inline void
drv_delete_element(as_index_tree* tree, as_index* r)
{
	if (as_index_delete_element(tree, &r->keyd) != 0) {
		cf_crash(AS_STORAGE, "failed index delete");
	}
}
