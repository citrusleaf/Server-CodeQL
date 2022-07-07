/*
 * rate_quota.c
 *
 * Copyright (C) 2021 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "base/rate_quota.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_clock.h"

#include "cf_mutex.h"
#include "cf_thread.h"
#include "log.h"
#include "rchash.h"

#include "base/cfg.h"
#include "base/security_ee.h"


//==========================================================
// Forward declarations.
//

void* run_calculate_quotas(void* arg);
int calculate_quota_cb(const void* p_key, void* p_value, void* udata);


//==========================================================
// Globals.
//

cf_rchash* g_quotas = NULL;


//==========================================================
// Public API.
//

void
as_quotas_init()
{
	g_quotas = cf_rchash_create(cf_rchash_fn_zstr, NULL, MAX_USER_SIZE, 1024);

	cf_thread_create_detached(run_calculate_quotas, NULL);
}


//==========================================================
// Public API - qinfo.
//

qinfo*
qinfo_new_empty(void)
{
	qinfo* p_qinfo = cf_rc_alloc(sizeof(qinfo));

	*p_qinfo = (qinfo){ .rps_lock = CF_MUTEX_INIT };

	return p_qinfo;
}

qinfo*
qinfo_new_session(const char* roles, uint32_t num_roles)
{
	uint32_t user_read_quota = 0;
	uint32_t user_write_quota = 0;

	const char* role = roles;

	for (uint32_t r = 0; r < num_roles; r++) {
		uint32_t read_quota = 0;
		uint32_t write_quota = 0;

		role_quotas(role, &read_quota, &write_quota);

		if (read_quota > user_read_quota) {
			user_read_quota = read_quota;
		}

		if (write_quota > user_write_quota) {
			user_write_quota = write_quota;
		}

		role = role + MAX_ROLE_NAME_SIZE;
	}

	qinfo* p_qinfo = cf_rc_alloc(sizeof(qinfo));

	*p_qinfo = (qinfo){
			.read_quota = user_read_quota,
			.write_quota = user_write_quota,
			.rps_lock = CF_MUTEX_INIT
	};

	return p_qinfo;
}

qinfo*
qinfo_new_add_role(const char* role)
{
	uint32_t read_quota = 0;
	uint32_t write_quota = 0;

	role_quotas(role, &read_quota, &write_quota);

	qinfo* p_qinfo = cf_rc_alloc(sizeof(qinfo));

	*p_qinfo = (qinfo){
			.read_quota = read_quota,
			.write_quota = write_quota
	};

	return p_qinfo;
}

void
qinfo_adjust_add_role(qinfo* p_qinfo, const char* role)
{
	uint32_t read_quota = 0;
	uint32_t write_quota = 0;

	role_quotas(role, &read_quota, &write_quota);

	if (read_quota > p_qinfo->read_quota) {
		p_qinfo->read_quota = read_quota;
	}

	if (write_quota > p_qinfo->write_quota) {
		p_qinfo->write_quota = write_quota;
	}
}

void
qinfo_adjust_reset_roles(qinfo* p_qinfo, const char* roles, uint32_t num_roles)
{
	uint32_t user_read_quota = 0;
	uint32_t user_write_quota = 0;

	const char* role = roles;

	for (uint32_t r = 0; r < num_roles; r++) {
		uint32_t read_quota = 0;
		uint32_t write_quota = 0;

		role_quotas(role, &read_quota, &write_quota);

		if (read_quota > user_read_quota) {
			user_read_quota = read_quota;
		}

		if (write_quota > user_write_quota) {
			user_write_quota = write_quota;
		}

		role = role + MAX_ROLE_NAME_SIZE;
	}

	p_qinfo->read_quota = user_read_quota;
	p_qinfo->write_quota = user_write_quota;
}


//==========================================================
// Local helpers.
//

void*
run_calculate_quotas(void* arg)
{
	uint64_t scan_us = 0;

	while (true) {
		usleep(1000000 - scan_us);

		uint64_t begin = cf_getus();

		cf_rchash_reduce(g_quotas, calculate_quota_cb, NULL);

		scan_us = cf_getus() - begin;
	}

	return NULL;
}

int
calculate_quota_cb(const void* p_key, void* p_value, void* udata)
{
	qinfo* p_qinfo = (qinfo*)p_value;

	double weight = (double)as_load_uint32(&g_config.sec_cfg.tps_weight);
	double light = 1.0 / weight;
	double heavy = 1.0 - light;

	// First reads:

	uint64_t tr_total = as_load_uint64(&p_qinfo->read_tr_total);
	double tps = (double)(tr_total - p_qinfo->read_tr_prev_total);

	p_qinfo->read_tps = (uint32_t)
			(((double)p_qinfo->read_tps * heavy) + (tps * light));
	p_qinfo->read_tr_prev_total = tr_total;

	uint32_t quota = as_load_uint32(&p_qinfo->read_quota);
	bool quota_exceeded = quota != 0 &&
			(p_qinfo->read_tps + p_qinfo->read_rps) > quota;

	if (quota_exceeded && ! p_qinfo->read_quota_exceeded) {
		as_security_log_quota_violation((const char*)p_key, quota, false);
	}

	p_qinfo->read_quota_exceeded = quota_exceeded;

	// Then writes:

	tr_total = as_load_uint64(&p_qinfo->write_tr_total);
	tps = (double)(tr_total - p_qinfo->write_tr_prev_total);

	p_qinfo->write_tps = (uint32_t)
			(((double)p_qinfo->write_tps * heavy) + (tps * light));
	p_qinfo->write_tr_prev_total = tr_total;

	quota = as_load_uint32(&p_qinfo->write_quota);
	quota_exceeded = quota != 0 &&
			(p_qinfo->write_tps + p_qinfo->write_rps) > quota;

	if (quota_exceeded && ! p_qinfo->write_quota_exceeded) {
		as_security_log_quota_violation((const char*)p_key, quota, true);
	}

	p_qinfo->write_quota_exceeded = quota_exceeded;

	return CF_RCHASH_OK;
}
