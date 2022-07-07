/*
 * record_ee.h
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

#include "base/index.h"


//==========================================================
// Forward declarations.
//

struct as_index_s;


//==========================================================
// Public API.
//

bool as_record_write_lut_is_stale_cp(const struct as_index_s* r, uint32_t regime);

static inline bool
is_durable_tombstone(const as_index* r)
{
	return r->tombstone == 1 && r->xdr_tombstone == 0;
}
