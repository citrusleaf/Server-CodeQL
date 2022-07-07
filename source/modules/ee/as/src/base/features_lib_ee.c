/*
 * features_lib_ee.c
 *
 * Copyright (C) 2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "base/features.h"
#include "base/features_ee.h"

#include <stdbool.h>
#include <stdint.h>


//==========================================================
// Globals.
//

static const char* g_features_info = "null";


//==========================================================
// Public API.
//

const char*
as_features_info()
{
	return g_features_info;
}


//==========================================================
// Public API - enterprise only.
//

bool
as_features_init(const char* path)
{
	return true;
}

bool
as_features_change_notification(void)
{
	return false;
}

uint32_t
as_features_cluster_nodes_limit(void)
{
	return 0;
}

bool
as_features_compression(void)
{
	return false;
}

bool
as_features_encryption_at_rest(void)
{
	return false;
}

bool
as_features_ldap(void)
{
	return false;
}

bool
as_features_pmem(void)
{
	return false;
}

bool
as_features_strong_consistency(void)
{
	return false;
}

bool
as_features_by_name(const char* name)
{
	return false;
}
