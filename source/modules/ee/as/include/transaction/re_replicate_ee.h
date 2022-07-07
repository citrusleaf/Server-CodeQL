/*
 * re_replicate_ee.h
 *
 * Copyright (C) 2017-2020 Aerospike, Inc.
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

#include "aerospike/as_atomic.h"
#include "citrusleaf/cf_digest.h"

#include "base/datamodel.h"
#include "base/index.h"


//==========================================================
// Forward declarations.
//

struct as_namespace_s;


//==========================================================
// Typedefs & constants.
//

#define AS_REPL_STATE_REPLICATED		0
#define AS_REPL_STATE_REPLICATING		1
#define AS_REPL_STATE_RE_REPLICATING	2
#define AS_REPL_STATE_UNREPLICATED		3


//==========================================================
// Public API.
//

void as_re_replicate(struct as_namespace_s* ns, const cf_digest* keyd);

static inline void
as_set_repl_state(as_namespace* ns, as_index* r, uint8_t state)
{
	if (state == r->repl_state) {
		return;
	}

	if (state == AS_REPL_STATE_UNREPLICATED) {
		as_incr_uint64(&ns->n_unreplicated_records);
	}
	else if (r->repl_state == AS_REPL_STATE_UNREPLICATED) {
		as_decr_uint64(&ns->n_unreplicated_records);
	}

	r->repl_state = state;
}
