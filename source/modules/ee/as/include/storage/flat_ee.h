/*
 * flat_ee.h
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
#include <stddef.h>
#include <stdint.h>

#include "storage/flat.h"


//==========================================================
// Forward declarations.
//

struct as_namespace_s;


//==========================================================
// Public API.
//

bool as_flat_record_expired_or_evicted(const struct as_namespace_s* ns, uint32_t flat_void_time, uint32_t set_id);

static inline bool
as_flat_record_not_expired(const as_flat_record* flat, uint32_t now)
{
	return flat->has_void_time == 0 || *(uint32_t*)flat->data > now;
}

static inline void
as_flat_copy_wo_magic(as_flat_record* dest, const as_flat_record* source,
		size_t len)
{
	memcpy((uint8_t*)dest + sizeof(dest->magic),
			(uint8_t*)source + sizeof(source->magic),
			len - sizeof(source->magic));
}

static inline bool
as_flat_record_is_live(const as_flat_record* flat)
{
	if (flat->has_bins == 0) {
		return false;
	}

	return flat->has_extra_flags == 0 ||
			((const as_flat_extra_flags*)flat->data)->xdr_bin_cemetery == 0;
}
