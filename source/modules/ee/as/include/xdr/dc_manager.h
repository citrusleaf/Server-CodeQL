/*
 * dc_manager.h
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

#include <stdbool.h>
#include <stdint.h>

#include "dynbuf.h"


//==========================================================
// Forward declarations.
//

struct as_namespace_s;
struct as_xdr_dc_cfg_s;


//==========================================================
// Typedefs & constants.
//

#define DC_NAME_MAX_SZ 32

typedef enum {
	XDR_FIELD_DC_NAME,
	XDR_FIELD_NAMESPACE,
	XDR_FIELD_PID,
	XDR_FIELD_LST,

	NUM_XDR_FIELDS
} xdr_msg_field;

#define TOK_FILTER ('F')


//==========================================================
// Public API.
//

void as_dc_manager_cfg_post_process(void);
void as_dc_manager_init(void);
void as_dc_manager_start(void);

bool as_dc_manager_create_dc(const char* dc_name);
bool as_dc_manager_delete_dc(const char* dc_name);
bool as_dc_manager_dc_is_connected(const char* dc_name);
bool as_dc_manager_add_seed(const char* dc_name, const char* host, const char* port, const char* tls_name);
bool as_dc_manager_remove_seed(const char* dc_name, const char* host, const char* port);

bool as_dc_manager_add_ns(const char* dc_name, struct as_namespace_s* ns, uint32_t rewind);
bool as_dc_manager_remove_ns(const char* dc_name, struct as_namespace_s* ns);
bool as_dc_manager_update_ns_remote_namespace(const char* dc_name, const struct as_namespace_s* ns, const char* ns_name);

bool as_dc_manager_update_ns_bins(const char* dc_name, struct as_namespace_s* ns, const char* bin_name, bool enabled);
bool as_dc_manager_update_ns_sets(const char* dc_name, struct as_namespace_s* ns, const char* set_name, bool enabled);
void as_dc_manager_update_ns_ships_client_drops(const char* dc_name, struct as_namespace_s* ns);
void as_dc_manager_update_ns_ships_nsup_drops(const char* dc_name, struct as_namespace_s* ns);
void as_dc_manager_update_ns_ships_changed_bins(const char* dc_name, struct as_namespace_s* ns);
void as_dc_manager_update_ns_ships_bin_luts(const char* dc_name, struct as_namespace_s* ns);

uint64_t as_dc_manager_ns_min_lst(const struct as_namespace_s* ns);

struct as_xdr_dc_cfg_s* as_dc_manager_get_cfg(const char* dc_name);
struct as_xdr_dc_cfg_s* as_dc_manager_get_cfg_by_ix(uint32_t dc_ix);

void as_dc_manager_get_dcs(cf_dyn_buf* db);
void as_dc_manager_get_dc_config(const char* dc_name, const struct as_namespace_s* ns, cf_dyn_buf* db);
void as_dc_manager_get_dc_stats(const char* dc_name, const struct as_namespace_s* ns, cf_dyn_buf* db);
void as_dc_manager_get_dc_state(const char* dc_name, const struct as_namespace_s* ns, cf_dyn_buf* db);
void as_dc_manager_get_dc_display_filters(const char* dc_name, const struct as_namespace_s* ns, bool b64, cf_dyn_buf* db);

extern uint32_t g_n_dcs;
