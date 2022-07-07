/*
 * ldap_ee.c
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "base/ldap_ee.h"

#include <ctype.h>
#include <ldap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_queue.h"

#include "cf_mutex.h"
#include "cf_thread.h"
#include "fetch.h"
#include "log.h"

#include "base/cfg.h"
#include "base/proto.h"
#include "base/security_ee.h"
#include "base/session_token.h"
#include "base/transaction.h"
#include "fabric/exchange.h"


//==========================================================
// Typedefs & constants.
//

typedef struct login_req_s {
	as_file_handle* fd_h;
	char* user;
	char* clear_pw;
	uint32_t user_len;
	uint32_t clear_pw_len;
} login_req;

typedef struct pattern_info_s {
	const char* pos;
	const char* val;
	size_t len;
} pattern_info;

#define PATTERN_DELIMITER '$'
#define PATTERN_TOK_UN "${un}"
#define PATTERN_TOK_DN "${dn}"
#define PATTERN_TOK_LEN 5

COMPILER_ASSERT(sizeof(PATTERN_TOK_UN) - 1 == PATTERN_TOK_LEN);
COMPILER_ASSERT(sizeof(PATTERN_TOK_DN) - 1 == PATTERN_TOK_LEN);


//==========================================================
// Forward declarations.
//

static void* run_login(void* arg);

static void* run_polling(void* arg);

static uint8_t serv_setup(LDAP** pp_ld);
static uint8_t serv_setup_query_user(LDAP** pp_ld);
static uint8_t serv_bind_query_user(LDAP* ld);
static uint8_t serv_authenticate(LDAP* ld, const char* user, bool user_is_dn, const char* clear_pw, uint32_t clear_pw_len);
static uint8_t serv_authenticate_user(LDAP* ld, const char* user, const char* clear_pw, uint32_t clear_pw_len);
static uint8_t serv_authenticate_user_dn(LDAP* ld, const char* user, const char* clear_pw, uint32_t clear_pw_len);
static uint8_t serv_get_user_dn(LDAP* ld, const char* user, char** pp_user_dn);
static uint8_t serv_check_user_exists(LDAP** pp_ld, const char* user);
static uint8_t serv_query_roles(LDAP** pp_ld, const char* user, char** pp_roles, uint32_t* p_num_roles);

static void add_ou_roles_from_dn(const char* user_dn, char** pp_roles, uint32_t* num_roles);
static char* apply_ldap_pattern(const char* pattern, const char* user, const char* dn);
static char* escape_user_dn(char* dn);


//==========================================================
// Globals.
//

static cf_queue g_login_q;

// Limit calls to LDAP server - not a const thanks to OpenLDAP API.
static struct timeval g_timeout = { .tv_sec = 20, .tv_usec = 50000 };


//==========================================================
// Inlines & macros.
//

static inline bool
is_principal()
{
	return g_config.self_node == as_exchange_principal();
}


//==========================================================
// Public API - enterprise only.
//

void
as_ldap_config_check()
{
	if (! g_config.sec_cfg.ldap_tls_disabled &&
			! g_config.sec_cfg.ldap_tls_ca_file) {
		cf_crash_nostack(AS_SECURITY, "ldap tls-ca-file not configured");
	}

	if (! g_config.sec_cfg.ldap_query_base_dn) {
		cf_crash_nostack(AS_SECURITY, "ldap query-base-dn not configured");
	}

	if (g_config.sec_cfg.ldap_query_user_dn) {
		if (! g_config.sec_cfg.ldap_query_user_password_file) {
			cf_crash_nostack(AS_SECURITY, "ldap query-user-dn configured but query-user-password-file not configured");
		}
	}
	else if (g_config.sec_cfg.ldap_query_user_password_file) {
		cf_crash_nostack(AS_SECURITY, "ldap query-user-password-file configured but query-user-dn not configured");
	}

	if (! g_config.sec_cfg.ldap_role_query_patterns[0]) {
		cf_crash_nostack(AS_SECURITY, "ldap role-query-pattern not configured");
	}

	if (! g_config.sec_cfg.ldap_server) {
		cf_crash_nostack(AS_SECURITY, "ldap server not configured");
	}

	if (! (g_config.sec_cfg.ldap_user_dn_pattern ||
			g_config.sec_cfg.ldap_user_query_pattern)) {
		cf_crash_nostack(AS_SECURITY, "ldap user-dn-pattern or user-query-pattern must be configured");
	}

	const char* file_path = g_config.sec_cfg.ldap_query_user_password_file;

	if (file_path != NULL && ! cf_fetch_validate_string(file_path)) {
		cf_crash_nostack(AS_SECURITY, "can't read ldap query-user-password-file");
	}
}

void
as_ldap_init()
{
	cf_queue_init(&g_login_q, sizeof(login_req), 64, true);

	for (uint32_t i = 0; i < g_config.sec_cfg.n_ldap_login_threads; i++) {
		cf_thread_create_detached(run_login, NULL);
	}

	cf_thread_create_detached(run_polling, NULL);
}

int
as_ldap_login(as_file_handle* fd_h, const char* p_user, uint32_t user_len,
		const char* p_clear_pw, uint32_t clear_pw_len)
{
	if (! g_config.sec_cfg.ldap_configured) {
		return AS_SEC_ERR_LDAP_NOT_CONFIGURED;
	}

	login_req req = {
			.fd_h = fd_h,
			.user = cf_malloc(user_len + 1),
			.clear_pw = cf_malloc(clear_pw_len + 1),
			.user_len = user_len,
			.clear_pw_len = clear_pw_len
	};

	// Null-terminate here, since calls that talk to LDAP server require it.

	memcpy(req.user, p_user, user_len);
	req.user[user_len] = 0;

	memcpy(req.clear_pw, p_clear_pw, clear_pw_len);
	req.clear_pw[clear_pw_len] = 0;

	if (cf_queue_push(&g_login_q, &req) != CF_QUEUE_OK) {
		cf_crash(AS_SECURITY, "failed push to login queue");
	}

	return AS_OK;
}


//==========================================================
// Local helpers - login.
//

static void*
run_login(void* arg)
{
	while (true) {
		login_req req;

		if (cf_queue_pop(&g_login_q, &req, CF_QUEUE_FOREVER) != CF_QUEUE_OK) {
			cf_crash(AS_SECURITY, "failed login queue pop");
		}

		LDAP* ld = NULL;
		uint8_t result = serv_setup(&ld);

		if (result != AS_OK) {
			as_security_login_failed(req.fd_h, result, req.user, req.user_len);
			cf_free(req.user);
			cf_free(req.clear_pw);
			continue;
		}

		if ((result = serv_authenticate_user(ld, req.user, req.clear_pw,
				req.clear_pw_len)) != AS_OK) {
			as_security_login_failed(req.fd_h, result, req.user, req.user_len);

			if (ld != NULL) {
				ldap_unbind_ext_s(ld, NULL, NULL);
			}

			cf_free(req.user);
			cf_free(req.clear_pw);
			continue;
		}

		char* roles = NULL;
		uint32_t num_roles = 0;

		if ((result = serv_query_roles(&ld, req.user, &roles, &num_roles)) !=
				AS_OK) {
			as_security_login_failed(req.fd_h, result, req.user, req.user_len);

			if (ld != NULL) {
				ldap_unbind_ext_s(ld, NULL, NULL);
			}

			cf_free(req.user);
			cf_free(req.clear_pw);
			continue;
		}

		if (ld != NULL) {
			ldap_unbind_ext_s(ld, NULL, NULL);
		}

		if (! as_security_ip_addr_ok(req.fd_h, roles, num_roles)) {
			as_security_login_failed(req.fd_h, AS_SEC_ERR_NOT_WHITELISTED,
					req.user, req.user_len);

			if (roles != NULL) {
				cf_free(roles);
			}

			cf_free(req.user);
			cf_free(req.clear_pw);
			continue;
		}

		uint32_t token_size = 0;
		uint8_t* token = as_session_token_generate(req.user, req.user_len,
				&token_size);

		as_security_new_session(req.fd_h, req.user, req.user_len, roles,
				num_roles);

		as_security_login_succeeded(req.fd_h, req.user, req.user_len, roles,
				num_roles, token, token_size, g_config.sec_cfg.session_ttl);

		cf_free(token);

		if (roles != NULL) {
			cf_free(roles);
		}

		cf_free(req.user);
		cf_free(req.clear_pw);
	}

	return NULL;
}


//==========================================================
// Local helpers - polling for roles.
//

static void*
run_polling(void* arg)
{
	uint64_t last_time = cf_get_seconds();
	LDAP* ld = NULL;

	while (true) {
		sleep(1); // wake up every second to check

		uint64_t period = (uint64_t)g_config.sec_cfg.ldap_polling_period;
		uint64_t curr_time = cf_get_seconds();

		if (period == 0 || curr_time - last_time < period) {
			continue;
		}

		last_time = curr_time;
		char* users = NULL;
		uint32_t num_users = 0;

		if (is_principal()) {
			if ((users = as_security_get_external_users(&num_users)) == NULL) {
				continue;
			}

			if (ld == NULL && serv_setup_query_user(&ld) != AS_OK) {
				continue;
			}
		}
		else {
			if (ld != NULL) {
				ldap_unbind_ext_s(ld, NULL, NULL);
				ld = NULL;
			}

			continue;
		}

		cf_detail(AS_SECURITY, "polling ldap server for %u users' roles ...",
				num_users);

		char* user = users;
		char* end = users + (num_users * MAX_USER_SIZE);

		while (is_principal() && user < end && ld != NULL) {
			uint8_t result = serv_check_user_exists(&ld, user);

			if (result == AS_OK) {
				char* roles = NULL;
				uint32_t num_roles = 0;

				result = serv_query_roles(&ld, user, &roles, &num_roles);

				if (ld == NULL) {
					break; // handle reconnect at next ldap_setup()
				}

				if (result == AS_OK) {
					as_security_update_roles(user, strlen(user), roles,
							num_roles);
					// Becomes role-less user if there are no roles.

					if (roles != NULL) {
						cf_free(roles);
					}
				}
			}
			else if (result == AS_SEC_ERR_USER) {
				as_security_drop_external_user(user, strlen(user));
			}

			if (ld == NULL) {
				break; // handle reconnect at next ldap_setup()
			}
			// if err just skip this user for this round.

			user += MAX_USER_SIZE; // next user
		}

		cf_detail(AS_SECURITY, "... done polling for roles%s",
				is_principal() ? "" : " (no longer principal)");

		cf_free(users);
	}

	return NULL;
}


//==========================================================
// Local helpers - communicate with LDAP server.
//

static uint8_t
serv_setup(LDAP** pp_ld)
{
	char* hostfs = g_config.sec_cfg.ldap_server;

	*pp_ld = NULL;

	// We don't know why, but apparently libldap_r is not good enough to solve
	// all issues. Without this lock, we connect to the LDAP server but it very
	// occasionally fails the TLS handshake.
	static cf_mutex init_lock = CF_MUTEX_INIT;

	cf_mutex_lock(&init_lock);

	int rc = ldap_initialize(pp_ld, hostfs);

	cf_mutex_unlock(&init_lock);

	if (rc != LDAP_SUCCESS || *pp_ld == NULL) {
		cf_warning(AS_SECURITY, "couldn't initialize ldap: %s err %d (%s)",
				hostfs, rc, ldap_err2string(rc));

		if (*pp_ld != NULL) {
			ldap_unbind_ext_s(*pp_ld, NULL, NULL);
		}

		*pp_ld = NULL;
		return AS_SEC_ERR_LDAP_SETUP;
	}

	const int version = LDAP_VERSION3; // force version 3 since default is 2
	const int log_level = 0; // set to -1 to log all

	if ((rc = ldap_set_option(*pp_ld, LDAP_OPT_PROTOCOL_VERSION, &version)) !=
			LDAP_OPT_SUCCESS) {
		cf_warning(AS_SECURITY, "couldn't set protocol version %d (%s)", rc,
				ldap_err2string(rc));
		ldap_unbind_ext_s(*pp_ld, NULL, NULL);
		*pp_ld = NULL;
		return AS_SEC_ERR_LDAP_SETUP;
	}

	if ((rc = ldap_set_option(*pp_ld, LDAP_OPT_TIMEOUT, &g_timeout)) !=
			LDAP_OPT_SUCCESS) {
		cf_warning(AS_SECURITY, "couldn't set timeout %d (%s)", rc,
				ldap_err2string(rc));
		ldap_unbind_ext_s(*pp_ld, NULL, NULL);
		*pp_ld = NULL;
		return AS_SEC_ERR_LDAP_SETUP;
	}

	if ((rc = ldap_set_option(*pp_ld, LDAP_OPT_NETWORK_TIMEOUT, &g_timeout)) !=
			LDAP_OPT_SUCCESS) {
		cf_warning(AS_SECURITY, "couldn't set network timeout %d (%s)", rc,
				ldap_err2string(rc));
		ldap_unbind_ext_s(*pp_ld, NULL, NULL);
		*pp_ld = NULL;
		return AS_SEC_ERR_LDAP_SETUP;
	}

	if ((rc = ldap_set_option(*pp_ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF)) !=
			LDAP_OPT_SUCCESS) {
		cf_warning(AS_SECURITY, "couldn't set referrals %d (%s)", rc,
				ldap_err2string(rc));
		ldap_unbind_ext_s(*pp_ld, NULL, NULL);
		*pp_ld = NULL;
		return AS_SEC_ERR_LDAP_SETUP;
	}

	if ((rc = ldap_set_option(*pp_ld, LDAP_OPT_DEBUG_LEVEL, &log_level)) !=
			LDAP_OPT_SUCCESS) {
		cf_warning(AS_SECURITY, "couldn't set debug level %d (%s)", rc,
				ldap_err2string(rc));
		ldap_unbind_ext_s(*pp_ld, NULL, NULL);
		*pp_ld = NULL;
		return AS_SEC_ERR_LDAP_SETUP;
	}

	if ((rc = ldap_set_option(*pp_ld, LDAP_OPT_RESTART, LDAP_OPT_ON)) !=
			LDAP_OPT_SUCCESS) {
		cf_warning(AS_SECURITY, "couldn't set restart %d (%s)", rc,
				ldap_err2string(rc));
		ldap_unbind_ext_s(*pp_ld, NULL, NULL);
		*pp_ld = NULL;
		return AS_SEC_ERR_LDAP_SETUP;
	}

	if (! g_config.sec_cfg.ldap_tls_disabled) {
		// Set ca-file globally once, lazily. OpenLDAP pre-2.4 doesn't support
		// setting on handle.
		static bool ca_file_set = false;
		static cf_mutex opt_lock = CF_MUTEX_INIT;

		if (! ca_file_set) {
			cf_mutex_lock(&opt_lock);

			if (! ca_file_set &&
					(rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE,
							g_config.sec_cfg.ldap_tls_ca_file)) !=
									LDAP_OPT_SUCCESS) {
				cf_mutex_unlock(&opt_lock);

				cf_warning(AS_SECURITY, "couldn't set tls cacertfile %d (%s)",
						rc, ldap_err2string(rc));
				ldap_unbind_ext_s(*pp_ld, NULL, NULL);
				*pp_ld = NULL;
				return AS_SEC_ERR_LDAP_SETUP;
			}

			ca_file_set = true;
			cf_mutex_unlock(&opt_lock);
		}

		// If server URL starts with "ldaps:", no need to start TLS.
		static const char LDAPS_PREFIX[] = "ldaps:";

		if (strncasecmp(hostfs, LDAPS_PREFIX, sizeof(LDAPS_PREFIX) - 1) != 0 &&
				(rc = ldap_start_tls_s(*pp_ld, NULL, NULL)) != LDAP_SUCCESS) {
			cf_warning(AS_SECURITY, "couldn't start tls: %s err %d (%s)",
					hostfs, rc, ldap_err2string(rc));
			ldap_unbind_ext_s(*pp_ld, NULL, NULL);
			*pp_ld = NULL;
			return AS_SEC_ERR_LDAP_TLS_SETUP;
		}
	}

	return AS_OK;
}

static uint8_t
serv_setup_query_user(LDAP** pp_ld)
{
	uint8_t as_rc = serv_setup(pp_ld);

	if (as_rc != AS_OK) {
		cf_warning(AS_SECURITY, "ldap setup failed");
		return as_rc;
	}

	// If bind fails, act as if ldap_setup() failed - don't set ld.
	if ((as_rc = serv_bind_query_user(*pp_ld)) != AS_OK && *pp_ld != NULL) {
		ldap_unbind_ext_s(*pp_ld, NULL, NULL);
		*pp_ld = NULL;
	}

	return as_rc;
}

static uint8_t
serv_bind_query_user(LDAP* ld)
{
	const char* dn = g_config.sec_cfg.ldap_query_user_dn;

	if (dn == NULL) {
		return AS_OK;
	}

	char* pw = cf_fetch_string(g_config.sec_cfg.ldap_query_user_password_file);

	if (pw == NULL) {
		cf_warning(AS_SECURITY, "can't read ldap query-user-password-file");
		return AS_SEC_ERR_LDAP_AUTHENTICATION;
	}

	uint8_t as_rc = serv_authenticate_user_dn(ld, dn, pw, strlen(pw));

	cf_free(pw);

	if (as_rc != AS_OK) {
		cf_warning(AS_SECURITY, "couldn't authenticate trusted aerospike user");
	}

	return as_rc;
}

// If caller passes null ld, will use self-contained ldap connection.
static uint8_t
serv_authenticate(LDAP* ld, const char* user, bool user_is_dn,
		const char* clear_pw, uint32_t clear_pw_len)
{
	uint8_t as_rc = AS_OK;
	bool teardown_ld = false;

	if (ld == NULL) {
		if ((as_rc = serv_setup(&ld)) != AS_OK) {
			cf_warning(AS_SECURITY, "ldap setup failed");
			return as_rc;
		}

		teardown_ld = true;
	}

	char* bind_dn = NULL;

	if (! user_is_dn &&
		! (serv_bind_query_user(ld) == AS_OK &&
				serv_get_user_dn(ld, user, &bind_dn) == AS_OK)) {
		cf_warning(AS_SECURITY, "could not get dn for user %s", user);
		as_rc = AS_SEC_ERR_LDAP_AUTHENTICATION;
	}
	else {
		struct berval creds = {
				.bv_val = (char*)clear_pw,
				.bv_len = clear_pw_len
		};

		cf_detail(AS_SECURITY, "binding to ldap using dn %s",
				user_is_dn ? user : bind_dn);

		int rc = ldap_sasl_bind_s(ld, user_is_dn ? user : bind_dn,
				LDAP_SASL_SIMPLE, &creds, NULL, NULL, NULL);

		if (rc != LDAP_SUCCESS) {
			cf_warning(AS_SECURITY, "error binding to ldap for user %s: %d (%s)",
					user, rc, ldap_err2string(rc));
			as_rc = AS_SEC_ERR_LDAP_AUTHENTICATION;
		}
	}

	if (bind_dn != NULL) {
		cf_free(bind_dn);
	}

	if (teardown_ld && ld != NULL) {
		int rc = ldap_unbind_ext_s(ld, NULL, NULL);

		if (rc != LDAP_SUCCESS) {
			cf_warning(AS_SECURITY, "error unbinding ldap %d (%s)", rc,
					ldap_err2string(rc));
			as_rc = AS_SEC_ERR_LDAP_AUTHENTICATION;
		}
	}

	return as_rc;
}

static uint8_t
serv_authenticate_user(LDAP* ld, const char* user, const char* clear_pw,
		uint32_t clear_pw_len)
{
	return serv_authenticate(ld, user, false, clear_pw, clear_pw_len);
}

static uint8_t
serv_authenticate_user_dn(LDAP* ld, const char* user, const char* clear_pw,
		uint32_t clear_pw_len)
{
	return serv_authenticate(ld, user, true, clear_pw, clear_pw_len);
}

// Caller must cf_free pp_user_dn on success.
static uint8_t
serv_get_user_dn(LDAP* ld, const char* user, char** pp_user_dn)
{
	if (g_config.sec_cfg.ldap_user_dn_pattern != NULL) {
		*pp_user_dn = apply_ldap_pattern(g_config.sec_cfg.ldap_user_dn_pattern,
				user, ""); // wipe dn if it is in bind_dn_pattern (!)
		return AS_OK;
	}
	// else - must query ldap to get cn of the user entry.

	char* query = apply_ldap_pattern(g_config.sec_cfg.ldap_user_query_pattern,
			user, ""); // wipe dn if it is in user entry pattern for some reason

	cf_detail(AS_SECURITY, "querying for user dn using %s", query);

	char* attrs[2] = { "cn" };
	int msg_id;
	int rc = ldap_search_ext(ld, g_config.sec_cfg.ldap_query_base_dn,
			LDAP_SCOPE_SUB, query, attrs, 0, NULL, NULL, &g_timeout,
			LDAP_NO_LIMIT, &msg_id);

	cf_free(query);

	if (rc != LDAP_SUCCESS) {
		cf_warning(AS_SECURITY, "cannot get dn for user %s: %d (%s)", user, rc,
				ldap_err2string(rc));
		return AS_SEC_ERR_LDAP_QUERY;
	}

	LDAPMessage* msg = NULL;
	// Note - this result code is different than the rest of result codes, see
	// man ldap_result for more info.
	int rs_rc = ldap_result(ld, msg_id, LDAP_MSG_ALL, &g_timeout, &msg);

	if (rs_rc <= 0) {
		cf_warning(AS_SECURITY, "cannot get dn for user %s: %d", user, rs_rc);
		ldap_msgfree(msg);
		return AS_SEC_ERR_LDAP_QUERY;
	}

	// Note: this entry chain is freed when msg is freed.
	LDAPMessage* entry = ldap_first_entry(ld, msg);
	int entries_count = ldap_count_entries(ld, entry);

	if (entry == NULL || entries_count == 0) {
		cf_warning(AS_SECURITY, "query for user %s dn got no entries", user);
		ldap_msgfree(msg);
		return AS_SEC_ERR_USER;
	}

	if (entries_count != 1) {
		cf_warning(AS_SECURITY, "attempted to get dn for user %s but user_entry_pattern returned %d entries",
				user, entries_count);
		ldap_msgfree(msg);
		return AS_SEC_ERR_LDAP_QUERY;
	}

	char* dn = ldap_get_dn(ld, entry);

	if (dn == NULL) {
		cf_warning(AS_SECURITY, "could not get dn from user entry");
		ldap_msgfree(msg);
		return AS_SEC_ERR_LDAP_QUERY;
	}

	*pp_user_dn = cf_strdup(dn);
	ldap_memfree(dn);

	ldap_msgfree(msg);

	return AS_OK;
}

static uint8_t
serv_check_user_exists(LDAP** pp_ld, const char* user)
{
	// If ldap_get_user_dn() needs to query ldap to get user's dn, it can tell
	// us right away if the user does not exist. However, if it is successful
	// the dn still must be validated.

	char* user_dn;
	uint8_t as_rc = serv_get_user_dn(*pp_ld, user, &user_dn);

	if (as_rc != AS_OK) {
		if (as_rc != AS_SEC_ERR_USER) {
			cf_warning(AS_SECURITY, "failed getting dn for user %s", user);
		}

		// Connection errors can be opaque, so unbind on any error to reset
		// connection on next go round.
		if (*pp_ld != NULL) {
			ldap_unbind_ext_s(*pp_ld, NULL, NULL);
			*pp_ld = NULL;
		}

		return as_rc;
	}

	int msg_id;
	int rc = ldap_search_ext(*pp_ld, user_dn, LDAP_SCOPE_BASE, NULL, NULL, 0,
			NULL, NULL, &g_timeout, LDAP_NO_LIMIT, &msg_id);
	LDAPMessage* msg = NULL;

	if (rc == LDAP_SUCCESS) {
		int rs_rc = ldap_result(*pp_ld, msg_id, LDAP_MSG_ALL, &g_timeout, &msg);

		if (rs_rc > 0) {
			// Note - entry chain is freed when msg is freed.
			LDAPMessage* entry = ldap_first_entry(*pp_ld, msg);
			int entries_count = ldap_count_entries(*pp_ld, entry);

			// Query should have returned exactly one result. User not found
			// would result in zero entries. There should not be multiple users.
			if (entries_count == 1) {
				as_rc = AS_OK;
			}
			else if (entries_count == 0) {
				as_rc = AS_SEC_ERR_USER;
			}
			else {
				cf_warning(AS_SECURITY, "search for user %s got %d entries",
						user_dn, entries_count);
				as_rc = AS_SEC_ERR_LDAP_QUERY;
			}
		}
		else {
			cf_warning(AS_SECURITY, "unknown error %d getting user results",
					as_rc);
			as_rc = AS_SEC_ERR_LDAP_QUERY;
		}
	}
	else if (rc == LDAP_NO_SUCH_OBJECT) {
		as_rc = AS_SEC_ERR_USER;
	}
	else if (rc == LDAP_CONNECT_ERROR || rc == LDAP_SERVER_DOWN ||
			rc == LDAP_TIMEOUT) {
		cf_warning(AS_SECURITY, "search for user - resetting connection");
		ldap_unbind_ext_s(*pp_ld, NULL, NULL);
		*pp_ld = NULL;
		as_rc = AS_SEC_ERR_LDAP_QUERY;
	}
	else {
		cf_warning(AS_SECURITY, "error searching for user %s: %d (%s)", user_dn,
				rc, ldap_err2string(rc));
		as_rc = AS_SEC_ERR_LDAP_QUERY;
	}

	ldap_msgfree(msg);
	cf_free(user_dn);

	return as_rc;
}

// Caller must free returned roles, if pointer is not null.
static uint8_t
serv_query_roles(LDAP** pp_ld, const char* user, char** pp_roles,
		uint32_t* p_num_roles)
{
	char* roles = NULL;
	uint32_t num_roles = 0;

	char* user_dn;
	uint8_t as_rc = serv_get_user_dn(*pp_ld, user, &user_dn);

	// Below we check for connection failures before returning error, but
	// don't have to here because no pattern will be successful.
	if (as_rc != AS_OK) {
		if (*pp_ld != NULL) {
			ldap_unbind_ext_s(*pp_ld, NULL, NULL);
			*pp_ld = NULL;
		}

		return as_rc;
	}

	if (g_config.sec_cfg.ldap_role_query_search_ou) {
		add_ou_roles_from_dn(user_dn, &roles, &num_roles);
	}

	cf_detail(AS_SECURITY, "querying roles for user %s dn %s", user, user_dn);

	user_dn = escape_user_dn(user_dn);

	const char* pattern;

	for (int i = 0;
			(pattern = g_config.sec_cfg.ldap_role_query_patterns[i]) != NULL;
			++i) {
		char* query = apply_ldap_pattern(pattern, user, user_dn);

		cf_detail(AS_SECURITY, "%s: using the role query %s", user, query);

		const char* base_dn = g_config.sec_cfg.ldap_role_query_base_dn != NULL ?
				g_config.sec_cfg.ldap_role_query_base_dn :
				g_config.sec_cfg.ldap_query_base_dn;
		char* attrs[2] = { "cn" };
		int msg_id;
		int rc = ldap_search_ext(*pp_ld, base_dn,
				LDAP_SCOPE_SUB, query, attrs, 0, NULL, NULL, &g_timeout,
				LDAP_NO_LIMIT, &msg_id);

		cf_free(query);

		if (rc != LDAP_SUCCESS) {
			cf_warning(AS_SECURITY, "can't get roles for user %s: %d (%s)",
					user, rc, ldap_err2string(rc));

			// It seems that if the server goes down, ldap will not attempt a
			// reconnect using the same handle. So we have to treat server down
			// the same as a connection error.
			if (rc == LDAP_CONNECT_ERROR || rc == LDAP_SERVER_DOWN ||
					rc == LDAP_TIMEOUT) {
				cf_warning(AS_SECURITY, "query roles - resetting connection");

				if (roles != NULL) {
					cf_free(roles);
				}

				ldap_unbind_ext_s(*pp_ld, NULL, NULL);
				*pp_ld = NULL;
				cf_free(user_dn);
				return AS_SEC_ERR_LDAP_QUERY;
			}

			continue; // roles query failed - try next pattern
		}
		// else - roles query "succeeded" with this pattern ...

		LDAPMessage* msg = NULL;
		// Note - this result code is different than the rest of result codes,
		// see man ldap_result for more info.
		int rs_rc = ldap_result(*pp_ld, msg_id, LDAP_MSG_ALL, &g_timeout, &msg);

		if (rs_rc <= 0) {
			cf_warning(AS_SECURITY, "cannot get role for user %s: %d", user,
					rs_rc);

			if (roles != NULL) {
				cf_free(roles);
			}

			cf_free(user_dn);
			ldap_msgfree(msg);
			return AS_SEC_ERR_LDAP_QUERY;
		}

		// Note: this entry chain is freed when msg is freed.
		LDAPMessage* entry = ldap_first_entry(*pp_ld, msg);
		int entries_count = ldap_count_entries(*pp_ld, entry);

		cf_detail(AS_SECURITY, "%s: found %d roles", user, entries_count);

		if (entries_count == 0) {
			// Only free outermost message in chain (even if zero count).
			ldap_msgfree(msg);
			continue; // no roles - try next pattern
		}
		// else - ... and we found roles for the user.

		roles = cf_realloc(roles,
				(num_roles + ldap_count_entries(*pp_ld, entry)) *
						MAX_ROLE_NAME_SIZE);

		while (entry != NULL) {
			BerElement* ber;
			// Only getting "cn", so only one attribute and only one val.
			char* attr = ldap_first_attribute(*pp_ld, entry, &ber);
			BerValue** vals = ldap_get_values_len(*pp_ld, entry, attr);

			if (vals[0]->bv_len < MAX_ROLE_NAME_SIZE &&
					as_security_add_aerospike_role(
							roles + (num_roles * MAX_ROLE_NAME_SIZE),
							vals[0]->bv_val, (uint32_t)vals[0]->bv_len)) {
				++num_roles;

				cf_detail(AS_SECURITY, "%s: found aerospike role %.*s", user,
						(int)vals[0]->bv_len, vals[0]->bv_val);
			}
			else {
				cf_detail(AS_SECURITY, "%s: NON-aerospike role %.*s", user,
						(int)vals[0]->bv_len, vals[0]->bv_val);
			}

			ber_free(ber, 0);
			ldap_value_free_len(vals);
			ldap_memfree(attr);

			entry = ldap_next_entry(*pp_ld, entry);
		}

		ldap_msgfree(msg);
	}

	cf_free(user_dn);

	// Don't return allocated roles if number of Aerospike roles is 0.
	if (num_roles == 0 && roles != NULL) {
		cf_free(roles);
		roles = NULL;
	}

	*pp_roles = roles;
	*p_num_roles = num_roles;

	return AS_OK;
}


//==========================================================
// Local helpers - generic.
//

static void
add_ou_roles_from_dn(const char* user_dn, char** pp_roles,
		uint32_t* p_num_roles)
{
	LDAPDN dn = NULL;
	int rc = ldap_str2dn(user_dn, &dn, LDAP_DN_FORMAT_LDAPV3);

	if (rc == LDAP_SUCCESS) {
		LDAPRDN rdn = NULL;
		char* roles = NULL;
		uint32_t num_roles = 0;

		for (int i = 0; (rdn = dn[i]) != NULL; ++i) {
			LDAPAVA *attr = rdn[0];

			if (attr != NULL && attr->la_value.bv_len < MAX_ROLE_NAME_SIZE &&
					strncasecmp("OU", attr->la_attr.bv_val,
							attr->la_attr.bv_len) == 0) {
				roles = cf_realloc(roles,
						((num_roles + 1) * MAX_ROLE_NAME_SIZE));

				if (as_security_add_aerospike_role(
						roles + (num_roles * MAX_ROLE_NAME_SIZE),
						attr->la_value.bv_val,
						(uint32_t)attr->la_value.bv_len)) {
					++num_roles;
				}
			}
		}

		*pp_roles = roles;
		*p_num_roles = num_roles;
	}
	else {
		cf_warning(AS_SECURITY, "error parsing %s for roles: %d (%s)", user_dn,
				rc, ldap_err2string(rc));
	}

	if (dn != NULL) {
		ldap_dnfree(dn);
	}
}

// Takes an ldap pattern from config and replaces tokens with user name or
// user's dn depending on token value. If stripping symbol is desired, supply
// empty string as parameter.
//
// Caller must cf_free returned value.
static char*
apply_ldap_pattern(const char* pattern, const char* user, const char* dn)
{
	uint8_t num_dns = 0;
	uint8_t num_uns = 0;
	pattern_info infos[7 + 1]; // up to 7 subs plus a null

	size_t pattern_len = strlen(pattern);
	size_t un_len = strlen(user);
	size_t dn_len = strlen(dn);

	uint8_t num_patterns = 0;
	const char* current_pos = pattern;

	// Collect substitution patterns in pattern string.
	while ((current_pos = strchr(current_pos, PATTERN_DELIMITER)) != NULL &&
			num_dns < 7) {
		if (memcmp(current_pos, PATTERN_TOK_UN, PATTERN_TOK_LEN) == 0) {
			infos[num_patterns].val = user;
			infos[num_patterns].len = un_len;
			++num_uns;
		}
		else if (memcmp(current_pos, PATTERN_TOK_DN, PATTERN_TOK_LEN) == 0) {
			infos[num_patterns].val = dn;
			infos[num_patterns].len = dn_len;
			++num_dns;
		}
		else {
			++current_pos; // must have just been a delimiter char but no tok
			continue;
		}

		infos[num_patterns].pos = current_pos;
		current_pos += PATTERN_TOK_LEN;
		++num_patterns;
	}

	size_t applied_len = pattern_len - (PATTERN_TOK_LEN * num_patterns) +
			(un_len * num_uns + dn_len * num_dns);
	char* applied = cf_malloc(applied_len + 1);
	char* dest = applied;

	current_pos = pattern;

	// Build string with replacements.
	for (int i = 0; i < num_patterns; ++i) {
		size_t len = infos[i].pos - current_pos;

		memcpy(dest, current_pos, len);
		current_pos += len + PATTERN_TOK_LEN;
		dest += len;
		memcpy(dest, infos[i].val, infos[i].len);
		dest += infos[i].len;
	}

	// Add rest of string after last substitution (and terminate).
	memcpy(dest, current_pos, pattern + pattern_len - current_pos);
	applied[applied_len] = '\0';

	return applied;
}

// Allocated dn is replaced by the returned value.
static char*
escape_user_dn(char* dn)
{
	char* escaped = cf_malloc(3 * strlen(dn) + 1);
	const char* from = dn;
	char* to = escaped;
	bool is_modified = false;

	while (*from != '\0') {
		if (strchr("*()\\/ ", *from) == NULL ||
				// Don't escape backslash if it's already escaping something.
				(*from == '\\' && isxdigit(*(from + 1)) != 0 &&
						isxdigit(*(from + 2)) != 0)) {
			*to++ = *from++;
		}
		else {
			*to++ = '\\';
			sprintf(to, "%02x", (uint8_t)*from);
			to += 2;
			from++;
			is_modified = true;
		}
	}

	*to = '\0';

	cf_free(dn);

	if (is_modified) {
		cf_detail(AS_SECURITY, "modified dn to %s", escaped);
	}

	return escaped;
}
