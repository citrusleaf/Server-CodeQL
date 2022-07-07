/*
 * fips_ee.c
 *
 * Copyright (C) 2022 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "fips.h"
#include "fips_ee.h"

#include <openssl/crypto.h>
#include <stdbool.h>

#include "log.h"


//==========================================================
// Globals.
//

bool g_fips = AS_FIPS_MODE;


//==========================================================
// Public API.
//

void
cf_fips_init(void)
{
	if (g_fips && FIPS_mode_set(1) != 1) {
		cf_crash(CF_MISC, "FIPS mode not enabled");
	}
}
