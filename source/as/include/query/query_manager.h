/*
 * query_manager.h
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

#pragma once

//==========================================================
// Includes.
//

#include <stdbool.h>
#include <stdint.h>

#include "citrusleaf/cf_queue.h"

#include "cf_mutex.h"


//==========================================================
// Forward declarations.
//

struct as_mon_jobstat_s;
struct as_query_job_s;


//==========================================================
// Typedefs & constants.
//

typedef struct as_query_manager_s {
	cf_mutex lock;
	cf_queue* active_jobs;
	cf_queue* finished_jobs;
} as_query_manager;


//==========================================================
// Globals.
//

extern uint32_t g_n_query_threads;


//==========================================================
// Public API.
//

void as_query_manager_startup_init(void);
int as_query_manager_start_job(struct as_query_job_s* _job);
void as_query_manager_add_job_thread(struct as_query_job_s* _job);
void as_query_manager_add_max_job_threads(struct as_query_job_s* _job);
void as_query_manager_finish_job(struct as_query_job_s* _job);
void as_query_manager_abandon_job(struct as_query_job_s* _job, int reason);
bool as_query_manager_abort_job(uint64_t trid);
uint32_t as_query_manager_abort_all_jobs(void);
void as_query_manager_limit_finished_jobs(void);
struct as_mon_jobstat_s* as_query_manager_get_job_info(uint64_t trid);
struct as_mon_jobstat_s* as_query_manager_get_info(int* size);
uint32_t as_query_manager_get_active_job_count(void);
