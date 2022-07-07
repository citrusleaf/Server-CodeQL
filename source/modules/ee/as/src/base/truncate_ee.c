/*
 * truncate_ee.c
 *
 * Copyright (C) 2017-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "base/truncate.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "log.h"
#include "shash.h"

#include "base/datamodel.h"


//==========================================================
// Globals.
//

static uint64_t g_startup_clepoch_ms = 0;


//==========================================================
// Forward declarations.
//

int startup_reduce_cb(const void* key, void* data, void* udata);
int cenotaphs_reduce_cb(const void* key, void* data, void* udata);


//==========================================================
// Public API.
//

void
as_truncate_done_startup(as_namespace* ns)
{
	// One clock call covers everything.
	if (g_startup_clepoch_ms == 0) {
		g_startup_clepoch_ms = cf_clepoch_milliseconds();
	}

	if (ns->truncate.lut > g_startup_clepoch_ms) {
		cf_warning(AS_TRUNCATE, "{%s} tombstone lut %lu ms in the future",
				ns->name,ns->truncate.lut - g_startup_clepoch_ms);
	}

	cf_shash_reduce(ns->truncate.startup_set_hash, startup_reduce_cb, ns);
	cf_shash_destroy(ns->truncate.startup_set_hash);
}


void
as_truncate_list_cenotaphs(as_namespace* ns)
{
	cf_shash_reduce(ns->truncate.startup_set_hash, cenotaphs_reduce_cb, ns);
}


bool
as_truncate_lut_is_truncated(uint64_t rec_lut, as_namespace* ns,
		const char* set_name, uint32_t set_name_len)
{
	if (rec_lut < ns->truncate.lut) {
		return true;
	}

	if (! set_name || cf_shash_get_size(ns->truncate.startup_set_hash) == 0) {
		return false;
	}

	char hkey[AS_SET_NAME_MAX_SIZE] = { 0 }; // pad for consistent shash key

	memcpy(hkey, set_name, set_name_len);

	truncate_hval hval;

	if (cf_shash_get(ns->truncate.startup_set_hash, (void*)hkey, &hval) !=
			CF_SHASH_OK) {
		return false;
	}

	if (rec_lut >= hval.lut) {
		return false;
	}

	// Tombstone covers record - unmark cenotaph. Note - assuming it's ok for
	// the hash to be lockless although different threads may unmark cenotaph
	// concurrently.

	if (hval.cenotaph == 1) {
		hval.cenotaph = 0;
		cf_shash_put(ns->truncate.startup_set_hash, hkey, &hval);
	}

	return true;
}


//==========================================================
// Private API - for enterprise separation only.
//

void
truncate_startup_hash_init(as_namespace* ns)
{
	// Create the shash used at startup. (Will be destroyed after startup.)
	ns->truncate.startup_set_hash = cf_shash_create(cf_shash_fn_zstr,
			AS_SET_NAME_MAX_SIZE, sizeof(truncate_hval), 1024, false);
}


void
truncate_action_startup(as_namespace* ns, const char* set_name, uint64_t lut)
{
	if (! set_name) {
		ns->truncate.lut = lut;
		return;
	}

	char hkey[AS_SET_NAME_MAX_SIZE] = { 0 }; // pad for consistent shash key

	strcpy(hkey, set_name);

	truncate_hval hval = { .cenotaph = 1, .lut = lut };

	if (cf_shash_put_unique(ns->truncate.startup_set_hash, hkey, &hval) !=
			CF_SHASH_OK) {
		cf_crash(AS_TRUNCATE, "{%s|%s} failed startup-hash put", ns->name,
				set_name);
	}
}


//==========================================================
// Local helpers.
//

int
startup_reduce_cb(const void* key, void* data, void* udata)
{
	as_namespace* ns = (as_namespace*)udata;
	const char* set_name = (const char*)key;
	truncate_hval* hval = (truncate_hval*)data;

	if (hval->lut > g_startup_clepoch_ms) {
		cf_warning(AS_TRUNCATE, "{%s|%s} tombstone lut %lu ms in the future",
				ns->name, set_name, hval->lut - g_startup_clepoch_ms);
	}

	as_set* p_set = as_namespace_get_set_by_name(ns, set_name);

	if (! p_set) {
		cf_detail(AS_TRUNCATE, "{%s|%s} tombstone found for nonexistent set",
				ns->name, set_name);
		return CF_SHASH_OK;
	}

	// Transfer the last-update-time from the hash to the vmap.
	p_set->truncate_lut = hval->lut;

	return CF_SHASH_OK;
}

int
cenotaphs_reduce_cb(const void* key, void* data, void* udata)
{
	as_namespace* ns = (as_namespace*)udata;
	const char* set_name = (const char*)key;
	truncate_hval* hval = (truncate_hval*)data;

	if (hval->cenotaph == 1) {
		cf_info(AS_TRUNCATE, "{%s|%s} tombstone covers no records on this node",
				ns->name, set_name);
	}
	else {
		cf_detail(AS_TRUNCATE, "{%s|%s} tombstone in use - covers record(s)",
				ns->name, set_name);
	}

	return CF_SHASH_OK;
}
