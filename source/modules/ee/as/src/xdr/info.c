/*
 * info.c
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aerospike/as_atomic.h"
#include "aerospike/as_password.h"

#include "cf_str.h"
#include "fetch.h"
#include "log.h"
#include "vector.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/exp.h"
#include "base/features_ee.h"
#include "base/security_ee.h"
#include "base/service.h"
#include "base/smd.h"
#include "base/thr_info.h"
#include "base/xdr.h"
#include "xdr/dc_manager.h"
#include "xdr/xdr_ee.h"

//#include "warnings.h" // generates warnings we're living with for now


//==========================================================
// Typedefs & constants.
//

typedef enum {
	ACTION_INVALID,
	ACTION_ADD,
	ACTION_REMOVE,
	ACTION_CREATE,
	ACTION_DELETE
} action_t;

#define MAX_B64_FILTER_SZ (16 * 1024)


//==========================================================
// Forward declarations.
//

static bool set_config_dc(const char* cmd, const char* dc_name);
static bool set_config_dc_ns(const char* cmd, const char* dc_name, as_namespace* ns);
static bool add_seed(const char* dc_name, const char* tls_our_name, char* buf);
static bool remove_seed(const char* dc_name, char* buf);
static bool parse_endpoint(char* begin, char** host_r, char** port_r, char** tls_name_r);

static bool dyn_cfg_get(const char* cmd, const char* param_name, char* v, int* v_len);
static bool dyn_cfg_bool(const char* input, bool* field_r);
static bool extract_namespace(const char *cmd, as_namespace **ns_r);
static action_t parse_action(const char* cmd);


//==========================================================
// Inlines & macros.
//

static inline bool
warn_if_connected(const char* dc_name, const char* cmd)
{
	if (as_dc_manager_dc_is_connected(dc_name)) {
		cf_warning(AS_XDR, "DC %s connected - failed command %s", dc_name, cmd);
		return true;
	}

	return false;
}


//==========================================================
// Public API.
//

void
as_xdr_get_config(const char* cmd, cf_dyn_buf* db)
{
	char dc_name[DC_NAME_MAX_SZ];
	int dc_name_len = sizeof(dc_name);

	if (dyn_cfg_get(cmd, "dc", dc_name, &dc_name_len)) {
		as_namespace* ns;

		if (! extract_namespace(cmd, &ns)) {
			cf_dyn_buf_append_string(db, "ERROR::bad-namespace");
			return;
		}

		as_dc_manager_get_dc_config(dc_name, ns, db); // NULL ns is legal
		return;
	}

	as_dc_manager_get_dcs(db);

	info_append_uint32(db, "src-id", g_config.xdr_cfg.src_id);

	// For debugging.
	info_append_uint32(db, "trace-sample", g_config.xdr_cfg.trace_sample);
}

bool
as_xdr_set_config(const char* cmd)
{
	char dc_name[DC_NAME_MAX_SZ];
	int dc_name_len = sizeof(dc_name);

	if (dyn_cfg_get(cmd, "dc", dc_name, &dc_name_len)) {
		return set_config_dc(cmd, dc_name);
	}

	// Other XDR top-level (non-dc) config items.

	char v[1024];
	int v_len = sizeof(v);
	uint32_t v_u32;

	if (dyn_cfg_get(cmd, "src-id", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 ||
				v_u32 == 0 || v_u32 > UINT8_MAX) {
			cf_warning(AS_XDR, "invalid 'src-id' %s", v);
			return false;
		}

		g_config.xdr_cfg.src_id = v_u32;
		return true;
	}

	//------------------------------------------------------
	// For debugging.
	//

	if (dyn_cfg_get(cmd, "trace-sample", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0) {
			cf_warning(AS_XDR, "invalid 'trace-sample' in command %s", cmd);
			return false;
		}

		g_config.xdr_cfg.trace_sample = v_u32;

		return true;
	}

	cf_warning(AS_XDR, "bad XDR config parameter in command %s", cmd);
	return false;
}

void
as_xdr_get_stats(const char* cmd, cf_dyn_buf* db)
{
	char dc_name[DC_NAME_MAX_SZ];
	int dc_name_len = sizeof(dc_name);

	if (! dyn_cfg_get(cmd, "dc", dc_name, &dc_name_len)) {
		cf_warning(AS_XDR, "missing or bad DC name in command %s", cmd);
		cf_dyn_buf_append_string(db, "ERROR::DC-name");
		return;
	}

	as_namespace* ns;

	if (! extract_namespace(cmd, &ns)) {
		cf_dyn_buf_append_string(db, "ERROR::bad-namespace");
		return;
	}

	as_dc_manager_get_dc_stats(dc_name, ns, db); // NULL ns is legal
	cf_dyn_buf_chomp_char(db, ';');

	return;
}

// xdr-dc-state:dc=<dc-name>[;namespace=<ns-name>]
int
as_xdr_dc_state(char* name, char* cmd, cf_dyn_buf* db)
{
	(void)name;

	char dc_name[DC_NAME_MAX_SZ];
	int dc_name_len = sizeof(dc_name);

	if (! dyn_cfg_get(cmd, "dc", dc_name, &dc_name_len)) {
		cf_warning(AS_XDR, "missing or bad DC name in command %s", cmd);
		cf_dyn_buf_append_string(db, "ERROR::DC-name");
		return 0;
	}

	as_namespace* ns;

	if (! extract_namespace(cmd, &ns)) {
		cf_dyn_buf_append_string(db, "ERROR::bad-namespace");
		return 0;
	}

	as_dc_manager_get_dc_state(dc_name, ns, db); // NULL ns is legal
	cf_dyn_buf_chomp_char(db, ';');

	return 0;
}

// xdr-get-filter:dc=<dc-name>[;namespace=<ns-name>][;b64=<bool>]
int
as_xdr_get_filter(char* name, char* cmd, cf_dyn_buf* db)
{
	(void)name;

	char dc_name[DC_NAME_MAX_SZ];
	int dc_name_len = sizeof(dc_name);

	if (! dyn_cfg_get(cmd, "dc", dc_name, &dc_name_len)) {
		cf_warning(AS_XDR, "missing or bad DC name in command %s", cmd);
		cf_dyn_buf_append_string(db, "ERROR::DC-name");
		return 0;
	}

	bool b64 = false;
	char bool_val[8];
	int bool_val_len = sizeof(bool_val);

	if (dyn_cfg_get(cmd, "b64", bool_val, &bool_val_len) &&
			! dyn_cfg_bool(bool_val, &b64)) {
		cf_warning(AS_XDR, "bad b64 param in command %s", cmd);
		cf_dyn_buf_append_string(db, "ERROR::b64-param");
		return 0;
	}

	as_namespace* ns;

	if (! extract_namespace(cmd, &ns)) {
		cf_dyn_buf_append_string(db, "ERROR::bad-namespace");
		return 0;
	}

	as_dc_manager_get_dc_display_filters(dc_name, ns, b64, db); // NULL ns ok
	cf_dyn_buf_chomp_char(db, ';');

	return 0;
}

// xdr-set-filter:dc=<dc-name>;namespace=<ns-name>;exp=<base-64-exp>
int
as_xdr_set_filter(char* name, char* cmd, cf_dyn_buf* db)
{
	(void)name;

	char dc_name[DC_NAME_MAX_SZ];
	int dc_name_len = sizeof(dc_name);

	if (! dyn_cfg_get(cmd, "dc", dc_name, &dc_name_len)) {
		cf_warning(AS_XDR, "missing or bad DC name in command %s", cmd);
		cf_dyn_buf_append_string(db, "ERROR::DC-name");
		return 0;
	}

	char ns_name[AS_ID_NAMESPACE_SZ];
	int ns_name_len = sizeof(ns_name);

	if (! dyn_cfg_get(cmd, "namespace", ns_name, &ns_name_len)) {
		cf_warning(AS_XDR, "missing or bad namespace name in command %s", cmd);
		cf_dyn_buf_append_string(db, "ERROR::namespace-name");
		return 0;
	}

	char b64[MAX_B64_FILTER_SZ];
	int b64_len = sizeof(b64);

	if (! dyn_cfg_get(cmd, "exp", b64, &b64_len)) {
		cf_warning(AS_XDR, "missing or bad expression in command %s", cmd);
		cf_dyn_buf_append_string(db, "ERROR::expression");
		return 0;
	}

	char smd_key[dc_name_len + 1 + ns_name_len + 1 + 1 + 1];

	sprintf(smd_key, "%s%c%s%c%c",
			dc_name, TOK_DELIMITER, ns_name, TOK_DELIMITER, TOK_FILTER);

	if (strcmp(b64, "null") != 0) {
		as_exp* exp = as_exp_filter_build_base64(b64, strlen(b64));

		if (exp == NULL) {
			cf_warning(AS_XDR, "can't build expression in command %s", cmd);
			cf_dyn_buf_append_string(db, "ERROR::build-expression");
			return 0;
		}

		as_exp_destroy(exp);

		if (! as_smd_set_blocking(AS_SMD_MODULE_XDR, smd_key, b64, 0)) {
			cf_warning(AS_XDR, "failed to set filter via command %s", cmd);
			cf_dyn_buf_append_string(db, "ERROR::set-filter");
		}
	}
	else {
		if (! as_smd_delete_blocking(AS_SMD_MODULE_XDR, smd_key, 0)) {
			cf_warning(AS_XDR, "failed to delete filter via command %s", cmd);
			cf_dyn_buf_append_string(db, "ERROR::set-filter");
		}
	}

	cf_dyn_buf_append_string(db, "ok");

	return 0;
}


//==========================================================
// Local Helpers - set config.
//

// set-config:context=xdr;dc=dcname;action=create/delete
// set-config:context=xdr;dc=dcname;variable=value
// set-config:context=xdr;dc=dcname;variable=value;action=add/remove
static bool
set_config_dc(const char* cmd, const char* dc_name)
{
	as_namespace* ns;

	if (! extract_namespace(cmd, &ns)) {
		return false;
	}

	if (ns != NULL) {
		return set_config_dc_ns(cmd, dc_name, ns);
	}

	action_t action = parse_action(cmd);

	if (action == ACTION_CREATE) {
		return as_dc_manager_create_dc(dc_name);
	}

	if (action == ACTION_DELETE) {
		return as_dc_manager_delete_dc(dc_name);
	}

	as_xdr_dc_cfg* cfg = as_dc_manager_get_cfg(dc_name);

	if (cfg == NULL) {
		cf_warning(AS_XDR, "unknown DC %s", dc_name);
		return false;
	}

	char v[1024];
	int v_len = sizeof(v);
	uint32_t v_u32;

	if (dyn_cfg_get(cmd, "node-address-port", v, &v_len)) {
		switch(action) {
		case ACTION_ADD:
			return add_seed(dc_name, cfg->tls_our_name, v);
		case ACTION_REMOVE:
			return remove_seed(dc_name, v);
		default:
			cf_warning(AS_XDR, "'node-address-port' - missing or bad action");
			return false;
		}
	}

	//------------------------------------------------------
	// No configs which use 'action' after this.
	//

	if (action != ACTION_INVALID) {
		cf_warning(AS_XDR, "superfluous 'action' in command %s", cmd);
		return false;
	}

	if (dyn_cfg_get(cmd, "auth-mode", v, &v_len)) {
		if (warn_if_connected(dc_name, cmd)) {
			return false;
		}

		if (strcmp(v, "none") == 0) {
			cfg->auth_mode = XDR_AUTH_NONE;
			return true;
		}

		if (cfg->connector) {
			cf_warning(AS_XDR, "can't set 'auth-mode' if 'connector' is 'true'");
			return false;
		}

		if (strcmp(v, "internal") == 0) {
			cfg->auth_mode = XDR_AUTH_INTERNAL;
		}
		else if (strcmp(v, "external") == 0) {
			if (cfg->tls_spec == NULL) {
				cf_warning(AS_XDR, "'external' auth-mode requires tls");
				return false;
			}

			cfg->auth_mode = XDR_AUTH_EXTERNAL;
		}
		else if (strcmp(v, "external-insecure") == 0) {
			cfg->auth_mode = XDR_AUTH_EXTERNAL_INSECURE;
		}
		else if (strcmp(v, "pki") == 0) {
			if (cfg->tls_spec == NULL) {
				cf_warning(AS_XDR, "'pki' auth-mode requires tls");
				return false;
			}

			cfg->auth_mode = XDR_AUTH_PKI;
		}
		else {
			cf_warning(AS_XDR, "invalid 'auth-mode' %s", v);
			return false;
		}

		return true;
	}

	if (dyn_cfg_get(cmd, "auth-password-file", v, &v_len)) {
		if (warn_if_connected(dc_name, cmd)) {
			return false;
		}

		if (! cf_fetch_validate_string(v)) {
			cf_warning(AS_XDR, "can't read password");
			return false;
		}

		if (cfg->auth_password_file != NULL) {
			cf_free(cfg->auth_password_file);
		}

		cfg->auth_password_file = cf_strdup(v);
		return true;
	}

	if (dyn_cfg_get(cmd, "auth-user", v, &v_len)) {
		if (warn_if_connected(dc_name, cmd)) {
			return false;
		}

		if (v_len >= MAX_USER_SIZE) {
			cf_warning(AS_XDR, "'auth-user' too long");
			return false;
		}

		if (cfg->auth_user != NULL) {
			cf_free(cfg->auth_user);
		}

		cfg->auth_user = cf_strdup(v);
		return true;
	}

	if (dyn_cfg_get(cmd, "connector", v, &v_len)) {
		if (warn_if_connected(dc_name, cmd)) {
			return false;
		}

		if (cf_vector_size(&cfg->seed_nodes) != 0) {
			cf_warning(AS_XDR, "can't set 'connector' if seed nodes are configured");
			return false;
		}

		bool connector;

		if (! dyn_cfg_bool(v, &connector)) {
			return false;
		}

		if (connector && cfg->auth_mode != XDR_AUTH_NONE) {
			cf_warning(AS_XDR, "can't set 'connector' to 'true' if 'auth-mode' is set");
			return false;
		}

		if (connector && ! as_features_change_notification()) {
			cf_warning(AS_XDR, "'connector' not allowed by feature key");
			return false;
		}

		for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
			as_xdr_dc_ns_cfg* dc_ns_cfg = cfg->ns_cfgs[ns_ix];

			if (connector && dc_ns_cfg->ship_bin_luts) {
				cf_warning(AS_XDR, "{%s} can't set 'connector' to 'true' if 'ship-bin-luts' is 'true'",
						g_config.namespaces[ns_ix]->name);
				return false;
			}

			if (! connector &&
					dc_ns_cfg->bin_policy == XDR_BIN_POLICY_NO_BINS) {
				cf_warning(AS_XDR, "{%s} can't set 'connector' to 'false' if 'bin-policy' is 'no-bins'",
						g_config.namespaces[ns_ix]->name);
				return false;
			}
		}

		cfg->connector = connector;

		return true;
	}

	if (dyn_cfg_get(cmd, "max-recoveries-interleaved", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0) {
			cf_warning(AS_XDR, "invalid 'max-recoveries-interleaved' %s", v);
			return false;
		}

		cfg->max_recoveries_interleaved = v_u32;
		return true;
	}

	if (dyn_cfg_get(cmd, "max-used-service-threads", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 || v_u32 > MAX_SERVICE_THREADS) {
			cf_warning(AS_XDR, "invalid 'max-used-service-threads' %s", v);
			return false;
		}

		cfg->max_used_service_threads = v_u32;
		return true;
	}

	if (dyn_cfg_get(cmd, "period-ms", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 ||
				v_u32 < AS_XDR_MIN_PERIOD_MS || v_u32 > AS_XDR_MAX_PERIOD_MS) {
			cf_warning(AS_XDR, "invalid 'period-ms' %s", v);
			return false;
		}

		cfg->period_us = v_u32 * 1000;
		return true;
	}

	if (dyn_cfg_get(cmd, "tls-name", v, &v_len)) {
		if (warn_if_connected(dc_name, cmd)) {
			return false;
		}

		char* name = NULL;
		cf_tls_spec* spec = NULL;

		if (strcmp(v, "null") != 0) { // tls-name "null" removes TLS setup
			name = cf_strdup(v);
		}

		if (name != NULL && (spec = cfg_link_tls("xdr", &name)) == NULL) {
			cf_warning(AS_XDR, "failed to set up using 'tls-name' %s", v);
			cf_free(name);
			return false;
		}

		if (cfg->tls_our_name != NULL) {
			cf_free(cfg->tls_our_name);
		}

		cfg->tls_our_name = name;
		cfg->tls_spec = spec;

		return true;
	}

	if (dyn_cfg_get(cmd, "use-alternate-access-address", v, &v_len)) {
		if (warn_if_connected(dc_name, cmd)) {
			return false;
		}

		return dyn_cfg_bool(v, &cfg->use_alternate_access_address);
	}

	cf_warning(AS_XDR, "bad DC config parameter in command %s", cmd);
	return false;
}

// set-config:context=xdr;dc=dcname;namespace=nsname;action=add/remove
// set-config:context=xdr;dc=dcname;namespace=nsname;variable=value
// set-config:context=xdr;dc=dcname;namespace=nsname;variable=value;action=add/remove
static bool
set_config_dc_ns(const char* cmd, const char* dc_name, as_namespace* ns)
{
	as_xdr_dc_cfg* dc_cfg = as_dc_manager_get_cfg(dc_name);

	if (dc_cfg == NULL) {
		cf_warning(AS_XDR, "unknown DC %s", dc_name);
		return false;
	}

	as_xdr_dc_ns_cfg* dc_ns_cfg = dc_cfg->ns_cfgs[ns->ix];

	action_t action = parse_action(cmd);

	if (action == ACTION_ADD) {
		char r[12];
		int r_len = sizeof(r);

		uint32_t rewind = 0;

		if (dyn_cfg_get(cmd, "rewind", r, &r_len)) {
			if (strcmp(r, "all") == 0) {
				rewind = UINT32_MAX;
			}
			else if (cf_str_atoi_seconds(r, &rewind) != 0) {
				cf_warning(AS_XDR, "'rewind' must be 'all' or an unsigned number with time unit (s, m, h, or d)");
				return false;
			}
		}

		return as_dc_manager_add_ns(dc_name, ns, rewind);
	}

	if (action == ACTION_REMOVE) {
		return as_dc_manager_remove_ns(dc_name, ns);
	}

	//------------------------------------------------------
	// No configs which use 'action' after this.
	//

	if (action != ACTION_INVALID) {
		cf_warning(AS_XDR, "invalid action in command %s", cmd);
		return false;
	}

	char v[1024];
	int v_len = sizeof(v);
	uint32_t v_u32;

	if (dyn_cfg_get(cmd, "bin-policy", v, &v_len)) {
		if (ns->single_bin) {
			cf_warning(AS_XDR, "can't set 'bin-policy' for single-bin namespace");
			return false;
		}

		as_xdr_bin_policy policy;

		if (strcmp(v, "all") == 0) {
			policy = XDR_BIN_POLICY_ALL;
		}
		else if (strcmp(v, "no-bins") == 0) {
			policy = XDR_BIN_POLICY_NO_BINS;
		}
		else if (strcmp(v, "only-changed") == 0) {
			policy = XDR_BIN_POLICY_ONLY_CHANGED;
		}
		else if (strcmp(v, "changed-and-specified") == 0) {
			policy = XDR_BIN_POLICY_CHANGED_AND_SPECIFIED;
		}
		else if (strcmp(v, "changed-or-specified") == 0) {
			policy = XDR_BIN_POLICY_CHANGED_OR_SPECIFIED;
		}
		else {
			cf_warning(AS_XDR, "invalid 'bin-policy' %s", v);
			return false;
		}

		if (policy == XDR_BIN_POLICY_NO_BINS && ! dc_cfg->connector) {
			cf_warning(AS_XDR, "can't set '%s' unless 'connector' is true", v);
			return false;
		}

		if (policy == XDR_BIN_POLICY_ALL && dc_ns_cfg->ship_bin_luts) {
			cf_warning(AS_XDR, "can't set 'all' with 'ship-bin-luts' true");
			return false;
		}

		if (policy != XDR_BIN_POLICY_ALL &&
				dc_ns_cfg->write_policy == XDR_WRITE_POLICY_REPLACE) {
			cf_warning(AS_XDR, "can't set '%s' with write policy 'replace'", v);
			return false;
		}

		dc_ns_cfg->bin_policy = policy;
		as_dc_manager_update_ns_ships_changed_bins(dc_name, ns);

		return true;
	}

	if (dyn_cfg_get(cmd, "compression-level", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 || v_u32 < 1 || v_u32 > 9) {
			cf_warning(AS_XDR, "invalid 'compression-level' %s", v);
			return false;
		}

		dc_ns_cfg->compression_level = v_u32;
		return true;
	}

	if (dyn_cfg_get(cmd, "compression-threshold", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 ||
				v_u32 < AS_XDR_MIN_COMPRESSION_THRESHOLD) {
			cf_warning(AS_XDR, "invalid 'compression-threshold' %s", v);
			return false;
		}

		dc_ns_cfg->compression_threshold = v_u32;
		return true;
	}

	if (dyn_cfg_get(cmd, "delay-ms", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 || v_u32 > AS_XDR_MAX_HOT_KEY_MS) {
			cf_warning(AS_XDR, "invalid 'delay-ms' %s", v);
			return false;
		}

		if (v_u32 > dc_ns_cfg->hot_key_ms) {
			cf_warning(AS_XDR, "'delay-ms' %u must be <= 'hot-key-ms' %u",
					v_u32, dc_ns_cfg->hot_key_ms);
			return false;
		}

		dc_ns_cfg->delay_ms = v_u32;
		return true;
	}

	if (dyn_cfg_get(cmd, "enable-compression", v, &v_len)) {
		return dyn_cfg_bool(v, &dc_ns_cfg->compression_enabled);
	}

	if (dyn_cfg_get(cmd, "forward", v, &v_len)) {
		return dyn_cfg_bool(v, &dc_ns_cfg->forward);
	}

	if (dyn_cfg_get(cmd, "hot-key-ms", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 || v_u32 > AS_XDR_MAX_HOT_KEY_MS) {
			cf_warning(AS_XDR, "invalid 'hot-key-ms' %s", v);
			return false;
		}

		if (v_u32 < dc_ns_cfg->delay_ms) {
			cf_warning(AS_XDR, "'hot-key-ms' %u must be >= 'delay-ms' %u",
					v_u32, dc_ns_cfg->delay_ms);
			return false;
		}

		dc_ns_cfg->hot_key_ms = v_u32;
		return true;
	}

	if (dyn_cfg_get(cmd, "ignore-bin", v, &v_len)) {
		return as_dc_manager_update_ns_bins(dc_name, ns, v, false);
	}

	if (dyn_cfg_get(cmd, "ignore-expunges", v, &v_len)) {
		if (! dyn_cfg_bool(v, &dc_ns_cfg->ignore_expunges)) {
			return false;
		}

		as_dc_manager_update_ns_ships_client_drops(dc_name, ns);
		return true;
	}

	if (dyn_cfg_get(cmd, "ignore-set", v, &v_len)) {
		return as_dc_manager_update_ns_sets(dc_name, ns, v, false);
	}

	if (dyn_cfg_get(cmd, "max-throughput", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 || v_u32 % 100 != 0) {
			cf_warning(AS_XDR, "invalid 'max-throughput' %s", v);
			return false;
		}

		dc_ns_cfg->max_throughput = v_u32;
		return true;
	}

	if (dyn_cfg_get(cmd, "remote-namespace", v, &v_len)) {
		if (warn_if_connected(dc_name, cmd)) {
			return false;
		}

		return as_dc_manager_update_ns_remote_namespace(dc_name, ns, v);
	}

	if (dyn_cfg_get(cmd, "sc-replication-wait-ms", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 ||
				v_u32 < AS_XDR_MIN_SC_REPLICATION_WAIT_MS ||
				v_u32 > AS_XDR_MAX_SC_REPLICATION_WAIT_MS) {
			cf_warning(AS_XDR, "invalid 'sc-replication-wait-ms' %s", v);
			return false;
		}

		dc_ns_cfg->sc_replication_wait_ms = v_u32;
		return true;
	}

	if (dyn_cfg_get(cmd, "ship-bin", v, &v_len)) {
		return as_dc_manager_update_ns_bins(dc_name, ns, v, true);
	}

	if (dyn_cfg_get(cmd, "ship-bin-luts", v, &v_len)) {
		bool val;

		if (! dyn_cfg_bool(v, &val)) {
			return false;
		}

		if (val && g_config.xdr_cfg.src_id == 0) {
			cf_warning(AS_XDR, "can't set 'ship-bin-luts' true if xdr context 'src-id' is 0");
			return false;
		}

		if (val && dc_cfg->connector) {
			cf_warning(AS_XDR, "can't set 'ship-bin-luts' true if 'connector' is true");
			return false;
		}

		if (val && dc_ns_cfg->bin_policy == XDR_BIN_POLICY_ALL) {
			cf_warning(AS_XDR, "can't set 'ship-bin-luts' true if bin policy is 'all'");
			return false;
		}

		dc_ns_cfg->ship_bin_luts = val;
		as_dc_manager_update_ns_ships_bin_luts(dc_name, ns);
		return true;
	}

	if (dyn_cfg_get(cmd, "ship-nsup-deletes", v, &v_len)) {
		if (! dyn_cfg_bool(v, &dc_ns_cfg->ship_nsup_deletes)) {
			return false;
		}

		as_dc_manager_update_ns_ships_nsup_drops(dc_name, ns);
		return true;
	}

	if (dyn_cfg_get(cmd, "ship-only-specified-sets", v, &v_len)) {
		return dyn_cfg_bool(v, &dc_ns_cfg->ship_only_specified_sets);
	}

	if (dyn_cfg_get(cmd, "ship-set", v, &v_len)) {
		return as_dc_manager_update_ns_sets(dc_name, ns, v, true);
	}

	if (dyn_cfg_get(cmd, "transaction-queue-limit", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 || (v_u32 & (v_u32 - 1)) != 0 ||
				v_u32 < AS_XDR_MIN_TRANSACTION_QUEUE_LIMIT ||
				v_u32 > AS_XDR_MAX_TRANSACTION_QUEUE_LIMIT) {
			cf_warning(AS_XDR, "invalid 'transaction-queue-limit' %s", v);
			return false;
		}

		dc_ns_cfg->transaction_queue_limit = v_u32;
		return true;
	}

	if (dyn_cfg_get(cmd, "write-policy", v, &v_len)) {
		if (strcmp(v, "auto") == 0) {
			dc_ns_cfg->write_policy = XDR_WRITE_POLICY_AUTO;
		}
		else if (strcmp(v, "update") == 0) {
			dc_ns_cfg->write_policy = XDR_WRITE_POLICY_UPDATE;
		}
		else if (strcmp(v, "replace") == 0) {
			if (dc_ns_cfg->bin_policy != XDR_BIN_POLICY_ALL) {
				cf_warning(AS_XDR, "can't set 'replace' if bin policy is not 'all'");
				return false;
			}

			dc_ns_cfg->write_policy = XDR_WRITE_POLICY_REPLACE;
		}
		else {
			cf_warning(AS_XDR, "invalid 'write-policy' %s", v);
			return false;
		}

		return true;
	}

	cf_warning(AS_XDR, "bad namespace config parameter in command %s", cmd);
	return false;
}

static bool
add_seed(const char* dc_name, const char* tls_our_name, char* buf)
{
	char* host = NULL;
	char* port = NULL;
	char* tls_name = NULL;

	if (! parse_endpoint(buf, &host, &port, &tls_name)) {
		cf_warning(AS_XDR, "bad seed");
		return false;
	}

	if (tls_our_name != NULL && tls_name == NULL) {
		cf_warning(AS_XDR, "missing TLS name");
		return false;
	}

	if (tls_our_name == NULL && tls_name != NULL) {
		cf_warning(AS_XDR, "unexpected TLS name");
		return false;
	}

	if (! as_dc_manager_add_seed(dc_name, host, port, tls_name)) {
		cf_warning(AS_XDR, "can't add seed");
		return false;
	}

	return true;
}

static bool
remove_seed(const char* dc_name, char* buf)
{
	char* host = NULL;
	char* port = NULL;
	char* tls_name = NULL;

	if (! parse_endpoint(buf, &host, &port, &tls_name)) {
		cf_warning(AS_XDR, "bad seed");
		return false;
	}

	if (tls_name != NULL) {
		cf_warning(AS_XDR, "unexpected TLS name");
		return false;
	}

	if (! as_dc_manager_remove_seed(dc_name, host, port)) {
		cf_warning(AS_XDR, "can't remove seed");
		return false;
	}

	return true;
}

// TODO - should be a non-XDR generic helper.
static bool
parse_endpoint(char* begin, char** host_r, char** port_r, char** tls_name_r)
{
	char* host = begin;
	char* search_port = begin;

	if (*host == '[') { // ipv6
		host++;

		char* host_end = strchr(host, ']');

		if (host_end == NULL) {
			return false;
		}

		*host_end = 0;
		search_port = host_end + 1;
	}

	char* colon = strchr(search_port, ':');

	if (colon == NULL) {
		return false;
	}

	*colon = 0; // null terminate host

	*host_r = host;
	*port_r = colon + 1;

	colon = strchr(*port_r, ':');

	if (colon == NULL) { // tls_name is optional
		*tls_name_r = NULL;
	}
	else {
		*colon = 0; // null terminate port
		*tls_name_r = colon + 1;
	}

	return true;
}


//==========================================================
// Local helpers - parameter parsing.
//

static bool
dyn_cfg_get(const char* cmd, const char* param_name, char* v, int* v_len)
{
	int rv = as_info_parameter_get(cmd, param_name, v, v_len);

	switch (rv) {
	case 0:
		if (*v_len == 0) {
			cf_warning(AS_XDR, "missing '%s' value", param_name);
			return false;
		}
		return true;
	case -1:
		return false;
	case -2:
		cf_warning(AS_XDR, "'%s' value too long", param_name);
		return false;
	default:
		cf_crash(AS_XDR, "unexpected rv parsing command");
		return false;
	}
}

static bool
dyn_cfg_bool(const char* input, bool* field_r)
{
	if (strcasecmp(input, "true") == 0) {
		*field_r = true;
		return true;
	}

	if (strcasecmp(input, "false") == 0) {
		*field_r = false;
		return true;
	}

	cf_warning(AS_XDR, "value must be true or false not %s", input);

	return false;
}

static bool
extract_namespace(const char* cmd, as_namespace** ns_r)
{
	char ns_name[AS_ID_NAMESPACE_SZ];
	int ns_name_len = sizeof(ns_name);

	int rv = as_info_parameter_get(cmd, "namespace", ns_name, &ns_name_len);

	if (rv == -1) {
		*ns_r = NULL;
		return true; // no namespace parameter
	}

	if (rv == -2) {
		cf_warning(AS_XDR, "'namespace' value too long");
		return false;
	}

	if (ns_name_len == 0) {
		cf_warning(AS_XDR, "missing 'namespace' value");
		return false;
	}

	as_namespace* ns = as_namespace_get_byname(ns_name);

	if (ns == NULL) {
		cf_warning(AS_XDR, "unknown 'namespace' %s", ns_name);
		return false;
	}

	*ns_r = ns;

	return true;
}

static action_t
parse_action(const char* cmd)
{
	char action[32];
	int action_len = sizeof(action);

	if (! dyn_cfg_get(cmd, "action", action, &action_len)) {
		return ACTION_INVALID;
	}

	if (strcmp(action, "remove") == 0) {
		return ACTION_REMOVE;
	}

	if (strcmp(action, "add") == 0) {
		return ACTION_ADD;
	}

	if (strcmp(action, "create") == 0) {
		return ACTION_CREATE;
	}

	if (strcmp(action, "delete") == 0) {
		return ACTION_DELETE;
	}

	cf_warning(AS_XDR, "invalid 'action' %s", action);
	return ACTION_INVALID;
}
