/*
 * reader.h
 *
 * Copyright (C) 2020 Aerospike, Inc.
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

struct ship_request_s;


//==========================================================
// Public API.
//

void as_reader_enqueue(struct ship_request_s* req);
