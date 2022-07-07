/*
 * sindex_tree_ce.c
 *
 * Copyright (C) 2022 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

//==========================================================
// Includes.
//

#include "sindex/sindex_tree.h"

#include <stdint.h>

#include "citrusleaf/cf_digest.h"

#include "log.h"

#include "fabric/partition.h"


//==========================================================
// Private API - for enterprise separation only.
//

void
query_reduce_no_rc(si_btree* bt, as_partition_reservation* rsv,
		int64_t start_bval, int64_t end_bval, int64_t resume_bval,
		cf_digest* keyd, as_sindex_reduce_fn cb, void* udata)
{
	cf_crash(AS_SINDEX, "CE code called query_reduce_no_rc()");
}
