/*
 * rate_quota.h
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

#include <stdbool.h>
#include <stdint.h>

#include "cf_mutex.h"
#include "rchash.h"

#include "base/security_config.h"


//==========================================================
// Typedefs & constants.
//

typedef struct qinfo_s {
	bool read_quota_exceeded;
	uint32_t read_quota;
		// For scans & long-running queries.
	uint32_t n_read_rps_zero;
	uint32_t read_rps;
		// For single record transactions:
	uint32_t read_tps;
	uint64_t read_tr_total;
	uint64_t read_tr_prev_total;

	bool write_quota_exceeded;
	uint32_t write_quota;
		// For scans & long-running queries.
	uint32_t n_write_rps_zero;
	uint32_t write_rps;
		// For single record transactions:
	uint32_t write_tps;
	uint64_t write_tr_total;
	uint64_t write_tr_prev_total;

	cf_mutex rps_lock;
} qinfo;


//==========================================================
// Globals.
//

extern cf_rchash* g_quotas;


//==========================================================
// Public API.
//

void as_quotas_init();


//==========================================================
// Public API - qinfo.
//

qinfo* qinfo_new_empty(void);
qinfo* qinfo_new_session(const char* roles, uint32_t num_roles);
qinfo* qinfo_new_add_role(const char* role);
void qinfo_adjust_add_role(qinfo* p_qinfo, const char* role);
void qinfo_adjust_reset_roles(qinfo* p_qinfo, const char* roles, uint32_t num_roles);
