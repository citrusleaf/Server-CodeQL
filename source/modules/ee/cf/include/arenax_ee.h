/*
 * arenax_ee.h
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

#include "arenax.h"
#include "cf_mutex.h"
#include "xmem.h"


//==========================================================
// Typedefs & constants.
//

typedef struct cf_arenax_element_result_s {
	bool free_it;
	cf_arenax_puddle* puddle;
	cf_mutex* lock; // sprig lock, to be used when accessing the puddle
} cf_arenax_element_result;

typedef cf_arenax_element_result (*cf_arenax_resume_stage_cb)
		(void* pv_element, cf_arenax_handle h, void* udata);
typedef void (*cf_arenax_scan_cb) (void* pv_element, void* udata);


//==========================================================
// Public API - enterprise only.
//

cf_arenax_err cf_arenax_resume(cf_arenax* arena, cf_xmem_type xmem_type,
		const void* xmem_type_cfg, key_t key_base, uint32_t element_size,
		uint32_t chunk_count, uint32_t stage_capacity, uint32_t max_stages);

uint64_t cf_arenax_hwm(cf_arenax* arena);
bool cf_arenax_resume_stage(cf_arenax* arena, uint32_t stage_id,
		cf_arenax_resume_stage_cb cb, void* udata);
bool cf_arenax_scan(cf_arenax* arena, uint32_t stage_id, cf_arenax_scan_cb cb,
		void* udata);

void cf_arenax_force_map_memory(cf_arenax* arena);

bool cf_arenax_flush(cf_arenax* arena);

cf_arenax_err cf_arenax_prefetch(cf_arenax* arena, cf_arenax_handle h);
