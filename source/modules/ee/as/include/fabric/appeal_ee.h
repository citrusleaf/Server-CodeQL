/*
 * appeal_ee.h
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#pragma once

//==========================================================
// Forward declarations.
//

struct pb_task_s;


//==========================================================
// Typedefs & constants.
//

typedef enum {
	ASSIST_START_RESULT_OK,
	ASSIST_START_RESULT_ERROR,
	ASSIST_START_RESULT_EAGAIN
} assist_start_result;


//==========================================================
// Public API.
//

void as_appeal_init_appeal();
void as_appeal_init_assist();
void as_appeal_begin(const struct pb_task_s *task);
void as_appeal_clear_assists();
