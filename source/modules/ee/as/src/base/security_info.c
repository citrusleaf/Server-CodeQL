/*
 * security_info.c
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cf_str.h"
#include "dynbuf.h"
#include "log.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/security_config.h"
#include "base/security_ee.h"
#include "base/thr_info.h"

#include "warnings.h"


//==========================================================
// Forward declarations.
//

static bool parse_param(const char* cmd, const char* param_name, char* v, int* v_len);
static bool parse_bool(const char* input, bool* field);
static bool parse_report(const char* input, uint32_t sink, uint32_t* field);
static bool parse_report_data_op(const char* cmd, const char* input, uint32_t sink);


//==========================================================
// Public API.
//

void
as_security_get_config(cf_dyn_buf* db)
{
	as_sec_config* cfg = &g_config.sec_cfg;

	if (! cfg->security_configured) {
		// FIXME - empty or error? Not quite like XDR was in 5.6- ...
		// Don't warn - used by tools to detect if security is configured.
//		cf_dyn_buf_append_string(db, "ERROR::security-not-configured");
		return;
	}

	// 'security' scope.

	info_append_bool(db, "enable-quotas", cfg->quotas_enabled);
	info_append_bool(db, "enable-security", true);
	info_append_uint32(db, "privilege-refresh-period",
			cfg->privilege_refresh_period);
	info_append_uint32(db, "session-ttl", cfg->session_ttl);
	info_append_uint32(db, "tps-weight", cfg->tps_weight);

	// 'ldap' scope.

	if (cfg->ldap_configured) {
		info_append_bool(db, "ldap.disable-tls", cfg->ldap_tls_disabled);
		info_append_uint32(db, "ldap.login-threads", cfg->n_ldap_login_threads);
		info_append_uint32(db, "ldap.polling-period", cfg->ldap_polling_period);
		info_append_string_safe(db, "ldap.query-base-dn",
				cfg->ldap_query_base_dn);
		info_append_string_safe(db, "ldap.query-user-dn",
				cfg->ldap_query_user_dn);
		info_append_string_safe(db, "ldap.query-user-password-file",
				cfg->ldap_query_user_password_file);
		info_append_string_safe(db, "ldap.role-query-base-dn",
				cfg->ldap_role_query_base_dn);

		for (int i = 0; i < MAX_ROLE_QUERY_PATTERNS; i++) {
			if (! cfg->ldap_role_query_patterns[i]) {
				break;
			}

			info_append_string(db, "ldap.role-query-pattern",
					cfg->ldap_role_query_patterns[i]);
		}

		info_append_bool(db, "ldap.role-query-search-ou",
				cfg->ldap_role_query_search_ou);
		info_append_string_safe(db, "ldap.server", cfg->ldap_server);
		info_append_string_safe(db, "ldap.tls-ca-file", cfg->ldap_tls_ca_file);

		as_sec_ldap_evp_md m = cfg->ldap_token_hash_method;

		info_append_string_safe(db, "ldap.token-hash-method",
				(m == AS_LDAP_EVP_SHA_256 ? "sha-256" :
						(m == AS_LDAP_EVP_SHA_256 ? "sha-512" : "illegal")));

		info_append_string_safe(db, "ldap.user-dn-pattern",
				cfg->ldap_user_dn_pattern);
		info_append_string_safe(db, "ldap.user-query-pattern",
				cfg->ldap_user_query_pattern);
	}

	// 'log' scope.

	info_append_bool(db, "log.report-authentication",
			(cfg->report.authentication & AS_SEC_SINK_LOG) != 0);

	as_security_get_data_op_scopes(AS_SEC_SINK_LOG, db);
	as_security_get_data_op_roles(AS_SEC_SINK_LOG, db);
	as_security_get_data_op_users(AS_SEC_SINK_LOG, db);

	info_append_bool(db, "log.report-sys-admin",
			(cfg->report.sys_admin & AS_SEC_SINK_LOG) != 0);
	info_append_bool(db, "log.report-user-admin",
			(cfg->report.user_admin & AS_SEC_SINK_LOG) != 0);
	info_append_bool(db, "log.report-violation",
			(cfg->report.violation & AS_SEC_SINK_LOG) != 0);

	// 'syslog' scope.

	info_append_int(db, "syslog.local", cfg->syslog_local);
	info_append_bool(db, "syslog.report-authentication",
			(cfg->report.authentication & AS_SEC_SINK_SYSLOG) != 0);

	as_security_get_data_op_scopes(AS_SEC_SINK_SYSLOG, db);
	as_security_get_data_op_roles(AS_SEC_SINK_SYSLOG, db);
	as_security_get_data_op_users(AS_SEC_SINK_SYSLOG, db);

	info_append_bool(db, "syslog.report-sys-admin",
			(cfg->report.sys_admin & AS_SEC_SINK_SYSLOG) != 0);
	info_append_bool(db, "syslog.report-user-admin",
			(cfg->report.user_admin & AS_SEC_SINK_SYSLOG) != 0);
	info_append_bool(db, "syslog.report-violation",
			(cfg->report.violation & AS_SEC_SINK_SYSLOG) != 0);
}

bool
as_security_set_config(const char* cmd)
{
	as_sec_config* cfg = &g_config.sec_cfg;

	if (! cfg->security_configured) {
		cf_warning(AS_SECURITY, "security not configured");
		return false;
	}

	char v[1024];
	int v_len = sizeof(v);
	uint32_t v_u32;

	if (parse_param(cmd, "privilege-refresh-period", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 ||
				v_u32 < PRIVILEGE_REFRESH_PERIOD_MIN ||
				v_u32 > PRIVILEGE_REFRESH_PERIOD_MAX) {
			cf_warning(AS_SECURITY, "invalid 'privilege-refresh-period' %s", v);
			return false;
		}

		cfg->privilege_refresh_period = v_u32;
		return true;
	}

	if (parse_param(cmd, "session-ttl", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 ||
				v_u32 < SECURITY_SESSION_TTL_MIN ||
				v_u32 > SECURITY_SESSION_TTL_MAX) {
			cf_warning(AS_SECURITY, "invalid 'session-ttl' %s", v);
			return false;
		}

		cfg->session_ttl = v_u32;
		return true;
	}

	if (parse_param(cmd, "tps-weight", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 ||
				v_u32 < TPS_WEIGHT_MIN || v_u32 > TPS_WEIGHT_MAX) {
			cf_warning(AS_SECURITY, "invalid 'tps-weight' %s", v);
			return false;
		}

		cfg->tps_weight = v_u32;
		return true;
	}

	if (parse_param(cmd, "ldap.polling-period", v, &v_len)) {
		if (cf_str_atoi_u32(v, &v_u32) != 0 ||
				v_u32 > LDAP_POLLING_PERIOD_MAX) {
			cf_warning(AS_SECURITY, "invalid 'ldap.polling-period' %s", v);
			return false;
		}

		cfg->ldap_polling_period = v_u32;
		return true;
	}

	if (parse_param(cmd, "log.report-authentication", v, &v_len)) {
		return parse_report(v, AS_SEC_SINK_LOG, &cfg->report.authentication);
	}

	if (parse_param(cmd, "log.report-data-op", v, &v_len)) {
		return parse_report_data_op(cmd, v, AS_SEC_SINK_LOG);
	}

	if (parse_param(cmd, "log.report-sys-admin", v, &v_len)) {
		return parse_report(v, AS_SEC_SINK_LOG, &cfg->report.sys_admin);
	}

	if (parse_param(cmd, "log.report-user-admin", v, &v_len)) {
		return parse_report(v, AS_SEC_SINK_LOG, &cfg->report.user_admin);
	}

	if (parse_param(cmd, "log.report-violation", v, &v_len)) {
		return parse_report(v, AS_SEC_SINK_LOG, &cfg->report.violation);
	}

	if (parse_param(cmd, "syslog.report-authentication", v, &v_len)) {
		return parse_report(v, AS_SEC_SINK_SYSLOG, &cfg->report.authentication);
	}

	if (parse_param(cmd, "syslog.report-data-op", v, &v_len)) {
		return parse_report_data_op(cmd, v, AS_SEC_SINK_SYSLOG);
	}

	if (parse_param(cmd, "syslog.report-sys-admin", v, &v_len)) {
		return parse_report(v, AS_SEC_SINK_SYSLOG, &cfg->report.sys_admin);
	}

	if (parse_param(cmd, "syslog.report-user-admin", v, &v_len)) {
		return parse_report(v, AS_SEC_SINK_SYSLOG, &cfg->report.user_admin);
	}

	if (parse_param(cmd, "syslog.report-violation", v, &v_len)) {
		return parse_report(v, AS_SEC_SINK_SYSLOG, &cfg->report.violation);
	}

	cf_warning(AS_SECURITY, "bad security config parameter in command %s", cmd);

	return false;
}


//==========================================================
// Local helpers.
//

static bool
parse_param(const char* cmd, const char* param_name, char* v, int* v_len)
{
	int rv = as_info_parameter_get(cmd, param_name, v, v_len);

	switch (rv) {
	case 0:
		if (*v_len == 0) {
			cf_warning(AS_SECURITY, "missing '%s' value", param_name);
			return false;
		}
		return true;
	case -1:
		return false;
	case -2:
		cf_warning(AS_SECURITY, "'%s' value too long", param_name);
		return false;
	default:
		cf_crash(AS_SECURITY, "unexpected rv parsing command");
		return false;
	}
}

static bool
parse_bool(const char* input, bool* field)
{
	if (strcasecmp(input, "true") == 0) {
		*field = true;
		return true;
	}

	if (strcasecmp(input, "false") == 0) {
		*field = false;
		return true;
	}

	cf_warning(AS_SECURITY, "value must be true or false not %s", input);

	return false;
}

static bool
parse_report(const char* input, uint32_t sink, uint32_t* field)
{
	bool enable;

	if (! parse_bool(input, &enable)) {
		return false;
	}

	if (enable) {
		*field |= sink;
	}
	else {
		*field &= ~sink;
	}

	return true;
}

static bool
parse_report_data_op(const char* cmd, const char* input, uint32_t sink)
{
	bool enable;

	if (! parse_bool(input, &enable)) {
		return false;
	}

	char role[MAX_ROLE_NAME_SIZE];
	int role_len = sizeof(role);

	if (parse_param(cmd, "role", role, &role_len)) {
		return as_security_adjust_log_role(sink, role, enable);
	}

	char user[MAX_USER_SIZE];
	int user_len = sizeof(user);

	if (parse_param(cmd, "user", user, &user_len)) {
		return as_security_adjust_log_user(sink, user, enable);
	}

	char ns_name[AS_ID_NAMESPACE_SZ];
	int ns_name_len = sizeof(ns_name);

	if (parse_param(cmd, "namespace", ns_name, &ns_name_len)) {
		as_namespace* ns = as_namespace_get_byname(ns_name);

		if (ns == NULL) {
			cf_warning(AS_SECURITY, "unknown 'namespace' %s", ns_name);
			return false;
		}

		char set_name[AS_SET_NAME_MAX_SIZE];
		int set_name_len = sizeof(set_name);

		int rv = as_info_parameter_get(cmd, "set", set_name, &set_name_len);

		if (rv == -2) {
			cf_warning(AS_SECURITY, "'set' value too long");
			return false;
		}

		if (set_name_len == 0) { // rv must be 0 if set_name_len is 0
			cf_warning(AS_SECURITY, "missing 'set' value");
			return false;
		}

		return as_security_adjust_log_scope(sink, ns, rv == 0 ? set_name : NULL,
				enable);
	}

	cf_warning(AS_SECURITY, "bad or missing report-data-op parameter");

	return false;
}
