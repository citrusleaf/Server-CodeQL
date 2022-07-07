/*
 * set_index_ee.h
 *
 * Copyright (C) 2021 Aerospike, Inc.
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


//==========================================================
// Forward declarations.
//

struct as_index_tree_s;


//==========================================================
// Public API.
//

void as_set_index_insert_warm_restart(struct as_index_tree_s* tree, uint16_t set_id, uint64_t r_h);
