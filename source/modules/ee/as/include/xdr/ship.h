/*
 * ship.h
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
// Includes.
//

#include <stdint.h>


//==========================================================
// Forward declarations.
//

struct as_storage_rd_s;
struct as_xdr_dc_cfg_s;
struct ship_request_s;
struct tl_ns_stats_s;


//==========================================================
// Public API.
//

void as_ship_send_record(uint32_t dc_ix, const struct as_xdr_dc_cfg_s* dc_cfg, struct as_storage_rd_s* rd, struct ship_request_s* req, struct tl_ns_stats_s* stats);
