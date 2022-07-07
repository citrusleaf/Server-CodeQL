/*
 * partition_balance_ee.h
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

#include <stdbool.h>
#include <stdint.h>

#include "fabric/appeal_ee.h"


//==========================================================
// Forward declarations.
//

struct as_namespace_s;


//==========================================================
// Public API.
//

void as_partition_appeal_done(struct as_namespace_s* ns, uint32_t pid, uint64_t orig_cluster_key);
assist_start_result as_partition_assist_start(struct as_namespace_s* ns, uint32_t pid, uint64_t orig_cluster_key);

extern bool g_appeal_phase;
