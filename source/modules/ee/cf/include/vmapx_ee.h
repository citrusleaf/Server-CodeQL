/*
 * vmapx_ee.h
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

#include <stdint.h>

#include "vmapx.h"


//==========================================================
// Public API - enterprise only.
//

cf_vmapx_err cf_vmapx_resume(cf_vmapx* vmap, uint32_t value_size,
		uint32_t max_count, uint32_t hash_size, uint32_t max_name_size);
