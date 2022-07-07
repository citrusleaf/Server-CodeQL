/*
 * partition_ee.h
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

#include "node.h"


//==========================================================
// Forward declarations.
//

struct as_namespace_s;


//==========================================================
// Typedefs & constants.
//

typedef enum {
	XDR_ROLE_NONE,
	XDR_ROLE_MASTER,
	XDR_ROLE_PROLE
} partition_xdr_role;

typedef struct partition_xdr_state_s {
	partition_xdr_role role;
	bool is_immigrating;
} partition_xdr_state;


//==========================================================
// Public API.
//

int as_partition_check_repl_ping(struct as_namespace_s* ns, uint32_t pid, uint32_t regime, cf_node src);
partition_xdr_state as_partition_xdr_state(struct as_namespace_s* ns, uint32_t pid);
