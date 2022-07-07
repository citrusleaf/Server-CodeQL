/*
 * security.c
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

#include "base/security.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syslog.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_byte_order.h"

#include "bits.h"
#include "cf_mutex.h"
#include "dynbuf.h"
#include "fips_ee.h"
#include "log.h"
#include "rchash.h"
#include "socket.h"
#include "tls_ee.h"
#include "vector.h"

#include "base/batch.h"
#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/ldap_ee.h"
#include "base/proto.h"
#include "base/rate_quota.h"
#include "base/security_book.h"
#include "base/security_config.h"
#include "base/security_ee.h"
#include "base/security_role.h"
#include "base/security_user.h"
#include "base/session_token.h"
#include "base/smd.h"
#include "base/thr_info.h"
#include "base/transaction.h"


//==========================================================
// Typedefs & constants.
//

// Security filter information per socket.
typedef struct as_sec_filter_s {
	cf_mutex		lock;
	bool			addr_ok;				// no whitelist or whitelisted
	qinfo*			p_qinfo;				// contains quota information
	uinfo*			p_uinfo;				// contains permissions on this socket
	uint32_t		user_len;				// user name length (doubles as flag)
	char			user[MAX_USER_SIZE];	// user authenticated on this socket
} as_sec_filter;

// Must correspond to predefined role arrays below.
#define NUM_ROLES 10

// Predefined role indexes.
#define ROLE_USER_ADMIN		0
#define ROLE_SYS_ADMIN		1 // the only one currently used!
#define ROLE_DATA_ADMIN		2
#define ROLE_UDF_ADMIN		3
#define ROLE_SINDEX_ADMIN	4
#define ROLE_READ			5
#define ROLE_READ_WRITE		6
#define ROLE_READ_WRITE_UDF	7
#define ROLE_WRITE			8
#define ROLE_TRUNCATE		9

// Predefined roles' names.
const char* ROLES[] = {
		"user-admin",
		"sys-admin",
		"data-admin",
		"udf-admin",
		"sindex-admin",
		"read",
		"read-write",
		"read-write-udf",
		"write",
		"truncate"
};

// Convenient permission sets.
#define DATA_ADMIN_PERMS	(PERM_UDF_ADMIN | PERM_SINDEX_ADMIN | PERM_QUERY_ADMIN | PERM_TRUNCATE | PERM_EVICT_ADMIN)
#define OPS_ADMIN_PERMS		(PERM_SET_CONFIG | PERM_LOGGING_CTRL | PERM_SERVICE_CTRL | PERM_XDR_SET_FILTER)
#define READ_PERMS			(PERM_READ | PERM_QUERY)
#define WRITE_PERMS			(PERM_WRITE | PERM_DELETE | PERM_OPS_QUERY)
#define UDF_PERMS			(PERM_UDF_APPLY | PERM_UDF_QUERY)

// Predefined roles' permissions.
const uint64_t ROLE_PERMS[] = {
		PERM_USER_ADMIN,
		DATA_ADMIN_PERMS | OPS_ADMIN_PERMS,
		DATA_ADMIN_PERMS,
		PERM_UDF_ADMIN,
		PERM_SINDEX_ADMIN,
		READ_PERMS,
		READ_PERMS | WRITE_PERMS,
		READ_PERMS | WRITE_PERMS | UDF_PERMS,
		WRITE_PERMS,
		PERM_TRUNCATE
};

// Predefined roles' permission codes.
const uint64_t ROLE_PERM_CODES[] = {
		AS_SEC_PERM_CODE_USER_ADMIN,
		AS_SEC_PERM_CODE_SYS_ADMIN,
		AS_SEC_PERM_CODE_DATA_ADMIN,
		AS_SEC_PERM_CODE_UDF_ADMIN,
		AS_SEC_PERM_CODE_SINDEX_ADMIN,
		AS_SEC_PERM_CODE_READ,
		AS_SEC_PERM_CODE_READ_WRITE,
		AS_SEC_PERM_CODE_READ_WRITE_UDF,
		AS_SEC_PERM_CODE_WRITE,
		AS_SEC_PERM_CODE_TRUNCATE
};

// Initial super-user.
const char SMD_SUPER_USER[] = "admin|P";
const char SMD_SUPER_PASSWORD[] = "$2a$10$7EqJtq98hPqEX7fNZaFWoO1mVO/4MLpGzsqojz6E9Gef6iXDjXdDa";
const char SMD_SUPER_ROLE[] = "admin|R|user-admin";

// Sanity-check clear passwords.
#define MAX_CLEAR_PASSWORD_LEN 256

// This means leave the quota alone.
#define NO_QUOTA ((uint32_t)-1)

// System metadata key format tokens.
#define TOK_PASSWORD	('P')
#define TOK_ROLE		('R')
#define TOK_PRIV		('V')
#define TOK_WHITELIST	('W')
#define TOK_READ_QUOTA	('E')
#define TOK_WRITE_QUOTA	('I')

// Syslog local facility map.
const int SYSLOG_FACILITIES[] = {
		LOG_LOCAL0,
		LOG_LOCAL1,
		LOG_LOCAL2,
		LOG_LOCAL3,
		LOG_LOCAL4,
		LOG_LOCAL5,
		LOG_LOCAL6,
		LOG_LOCAL7
};

// Move a privilege's definition from incoming client message to SMD.
typedef struct priv_def_s {
	uint8_t	perm_code;
	char ns_name[AS_ID_NAMESPACE_SZ];
	char set_name[AS_SET_NAME_MAX_SIZE];
} priv_def;

// rchash helper, for reduce loop to collect and count external users.
typedef struct udata_external_users_s {
	char* names;
	uint32_t num_names;
	uint32_t capacity;
} udata_external_users;

// rchash helper, for reduce loop to collect keys.
typedef struct udata_key_s {
	const char** pp_key;
} udata_key;

// rchash helper, for reduce loop to collect and sort keys.
typedef struct udata_sort_key_s {
	const char** pp_key;
	uint32_t num_keys;
} udata_sort_key;

// Maximum size of a pre-packed privilege.
#define PACKED_PRIV_MAX_SIZE (1 + AS_ID_NAMESPACE_SZ + AS_SET_NAME_MAX_SIZE)

// Used for tracking users' open connections.
typedef struct user_conn_s {
	char user[MAX_USER_SIZE];
	uint32_t n_conns;
} user_conn;

// Used for tracking users' open connections.
typedef struct conn_tracker_s {
	cf_mutex lock;
	uint32_t n_users;
	user_conn* uconns;
} conn_tracker;

// Used for lists of roles and users which are audited.
typedef struct name_list_s {
	cf_mutex lock;
	uint32_t max_name_sz;
	uint32_t n_names;
	char* names;
} name_list;

// Maximum size of a privilege to log.
#define LOG_PRIV_MAX_SIZE (3 + 1 + AS_ID_NAMESPACE_SZ + AS_SET_NAME_MAX_SIZE + 1)

// Maximum size of a log filter scope string.
#define LOG_FILTER_SCOPE_MAX_SIZE (AS_ID_NAMESPACE_SZ + AS_SET_NAME_MAX_SIZE)

// Log filter row size.
#define LOG_FILTER_NUM_SETS (1 + AS_SET_MAX_COUNT)

// Size of a log filter scopes block.
#define LOG_FILTER_SCOPES_SIZE (LOG_FILTER_SCOPE_MAX_SIZE * LOG_FILTER_NUM_SETS * 256)

// Limit a data op's key string for logging.
#define MAX_KEY_STR_SIZE 1024
#define MAX_KEY_STR_LEN (MAX_KEY_STR_SIZE - 3) // type, |, and null-terminator

// Security 'audit trail' detail prefixes.
static const char ERR_TAG[] = "<parse error>";
static const char USER_TAG[] = "user=";
static const char ROLES_TAG[] = "roles=";
static const char ROLE_TAG[] = "role=";
static const char PRIVS_TAG[] = "privs=";
static const char WHITELIST_TAG[] = "whitelist=";
static const char READ_QUOTA_TAG[] = "read-quota=";
static const char WRITE_QUOTA_TAG[] = "write-quota=";


//==========================================================
// Globals.
//

// Number of namespaces.
uint32_t g_num_namespaces = 0;

// Time of last security refresh.
static uint64_t g_last_refresh = 0;

// Security roles cache.
static cf_rchash* g_roles = NULL;

// Security user-info cache.
static cf_rchash* g_users = NULL;

// Don't answer queries if cache keys might be changing.
static cf_mutex g_query_roles_lock = CF_MUTEX_INIT;
static cf_mutex g_query_users_lock = CF_MUTEX_INIT;

// Session users can be created via LDAP or SMD.
static cf_mutex g_session_users_lock = CF_MUTEX_INIT;

// Total number of whitelists across all roles.
static uint32_t g_n_whitelists = 0;

// User connection tracker.
static conn_tracker g_conn_tracker = { .lock = CF_MUTEX_INIT };

// Data transaction log filters.

static char* g_log_filter_scopes = NULL;
static uint32_t g_num_log_filter_scopes = 0;
static bool* g_log_filter = NULL;

static char* g_syslog_filter_scopes = NULL;
static uint32_t g_num_syslog_filter_scopes = 0;
static bool* g_syslog_filter = NULL;

static uint32_t g_log_filter_size = 0;

static name_list g_log_filter_roles = {
		.lock = CF_MUTEX_INIT,
		.max_name_sz = MAX_ROLE_NAME_SIZE
};
static name_list g_log_filter_users = {
		.lock = CF_MUTEX_INIT,
		.max_name_sz = MAX_USER_SIZE
};

static name_list g_syslog_filter_roles = {
		.lock = CF_MUTEX_INIT,
		.max_name_sz = MAX_ROLE_NAME_SIZE
};
static name_list g_syslog_filter_users = {
		.lock = CF_MUTEX_INIT,
		.max_name_sz = MAX_USER_SIZE
};


//==========================================================
// Forward declarations.
//

void adjust_roles_in_smd(const uinfo* p_uinfo, const char* p_user, uint32_t user_len, const char* roles, uint32_t num_roles);
int collect_external_users_cb(const void* p_key, void* p_value, void* udata);

static inline uint8_t admin_permission_check(const as_file_handle* fd_h);
uint8_t permission_check(const as_file_handle* fd_h, uint32_t ns_ix, uint16_t set_id, as_sec_perm perm);
uint8_t quota_and_permission_check(const as_transaction* tr, const as_file_handle* fd_h, uint32_t ns_ix, uint16_t set_id, as_sec_perm perm);
as_sec_perm write_op_perm(as_transaction* tr);

void handle_req_msg(as_file_handle* fd_h, as_sec_msg* p_req_msg, uint64_t size);
bool req_msg_get_fields(as_sec_msg* p_msg, uint64_t size, as_sec_msg_field* req_fields[]);
bool send_resp_to_client(as_file_handle* fd_h, const uint8_t* p_resp, size_t resp_size, bool done);
void send_result_msg(as_file_handle* fd_h, uint8_t result);
void send_resp_token(as_file_handle* fd_h, const uint8_t* token, uint32_t token_size, uint32_t ttl);
bool send_resp_bb(as_file_handle* fd_h, cf_buf_builder* p_bb);

void cmd_login(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);

void cmd_authenticate(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);

void cmd_create_user(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_drop_user(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_set_password(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_change_password(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_grant_roles(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_revoke_roles(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_query_users(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);

void cmd_create_role(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_delete_role(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_add_privs(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_delete_privs(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_set_whitelist(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_set_quotas(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void cmd_query_roles(as_file_handle* fd_h, as_sec_msg_field* req_fields[]);

cf_buf_builder* resp_bb_create();
void resp_bb_pack_sec_msg(cf_buf_builder** pp_bb, uint8_t result, uint8_t n_fields);
void resp_bb_pack_string_msg_field(cf_buf_builder** pp_bb, uint8_t id, const char* p_val, uint32_t len);
void resp_bb_pack_uint32_msg_field(cf_buf_builder** pp_bb, uint8_t id, uint32_t val);
uint8_t* resp_bb_reserve_roles_msg_field(cf_buf_builder** pp_bb, uint32_t n_roles, uint32_t role_len_sum);
uint8_t* pack_role_name(uint8_t* p_write, const char* p_role, uint32_t role_len);
void resp_bb_pack_whitelist_msg_field(cf_buf_builder** pp_bb, const char* whitelist);
uint32_t prepack_priv(const priv_code* p_priv, uint8_t* p_packed_priv);
uint8_t* resp_bb_reserve_privs_msg_field(cf_buf_builder** pp_bb, uint32_t n_privs, uint32_t priv_size_sum);
uint8_t* pack_priv(uint8_t* p_write, const uint8_t* p_packed_priv, uint32_t packed_priv_size);
void resp_bb_pack_rw_info_msg_field(cf_buf_builder** pp_bb, uint8_t id, uint32_t quota, uint32_t tps, uint32_t rps, uint32_t n_rps_zero);

bool is_valid_field_id(uint8_t id);
uint32_t msg_field_value_size(const as_sec_msg_field* p_field);
bool msg_field_uint32_value(as_sec_msg_field* p_field, uint32_t* p_value);
void req_msg_field_swap(as_sec_msg_field* p_field);
void resp_msg_field_swap(as_sec_msg_field* p_field);

static inline bool is_global_scope_perm_code(uint32_t perm_code);
static inline bool is_valid_perm_code(uint32_t perm_code);
uint8_t parse_privs(const uint8_t* p_privs, uint32_t privs_size, priv_def** pp_privs, uint32_t* p_num_privs);
uint8_t parse_roles(const uint8_t* p_roles, uint32_t roles_size, char** pp_roles, uint32_t* p_num_roles);

uint8_t login(as_file_handle* fd_h, const char* p_user, uint32_t user_len, const uint8_t* p_cred, uint32_t cred_size, const char* p_clear_pw, uint32_t clear_pw_len);

uint8_t authenticate(const char* ukey, uint32_t user_len, const uint8_t* p_tok, uint32_t tok_size, uinfo** pp_uinfo);

uint8_t create_user(const char* p_user, uint32_t user_len, const char* p_password, uint32_t password_len, const uint8_t* p_roles, uint32_t roles_size);
uint8_t drop_user(const char* p_user, uint32_t user_len);
uint8_t set_password(const char* p_user, uint32_t user_len, const char* p_password, uint32_t password_len);
uint8_t change_password(const char* p_user, uint32_t user_len, const char* p_old_password, uint32_t old_password_len, const char* p_password, uint32_t password_len);
uint8_t grant_roles(const char* p_user, uint32_t user_len, const uint8_t* p_roles, uint32_t roles_size);
uint8_t revoke_roles(const char* p_user, uint32_t user_len, const uint8_t* p_roles, uint32_t roles_size);
uint8_t query_users(const char* p_user, uint32_t user_len, cf_buf_builder** pp_bb);
void query_user(const char* ukey, uint32_t user_len, const uinfo* p_uinfo, cf_buf_builder** pp_bb);

uint8_t create_role(const char* p_role, uint32_t role_len, const uint8_t* p_privs, uint32_t privs_size, const char* p_whitelist, uint32_t whitelist_len, uint32_t read_quota, uint32_t write_quota);
uint8_t delete_role(const char* p_role, uint32_t role_len);
int revoke_role_reduce_fn(const void* p_key, void* p_value, void* udata);
uint8_t add_privs(const char* p_role, uint32_t role_len, const uint8_t* p_privs, uint32_t privs_size);
uint8_t delete_privs(const char* p_role, uint32_t role_len, const uint8_t* p_privs, uint32_t privs_size);
uint8_t set_whitelist(const char* p_role, uint32_t role_len, const char* p_whitelist, uint32_t whitelist_len);
uint8_t set_quotas(const char* p_role, uint32_t role_len, uint32_t read_quota, uint32_t write_quota);
uint8_t query_roles(const char* p_role, uint32_t role_len, cf_buf_builder** pp_bb);
void query_role(const char* p_role, uint32_t role_len, const rinfo* p_rinfo, cf_buf_builder** pp_bb);
int packed_priv_cmp(const uint8_t* p_packed_priv1, const uint8_t* p_packed_priv2);

void smd_add_password(const char* p_user, uint32_t user_len, const char* p_password, uint32_t password_len);
void smd_add_role(const char* p_user, uint32_t user_len, const char* role);
void smd_delete_password(const char* p_user, uint32_t user_len);
void smd_delete_role(const char* p_user, uint32_t user_len, const char* role);

void smd_add_priv(const char* p_role, uint32_t role_len, const priv_def* p_priv);
void smd_delete_priv(const char* p_role, uint32_t role_len, const priv_def* p_priv);
void priv_code_to_def(const priv_code* p_priv_code, priv_def* p_priv_def);
void smd_add_whitelist(const char* p_role, uint32_t role_len, const char* p_whitelist, uint32_t whitelist_len);
void smd_delete_whitelist(const char* p_role, uint32_t role_len);
void smd_add_quota(const char* p_role, uint32_t role_len, char quota_tok, uint32_t tps_quota);
void smd_delete_quota(const char* p_role, uint32_t role_len, char quota_tok);

void sec_smd_dummy_accept_cb(const cf_vector* items, as_smd_accept_type accept_type);
void sec_smd_accept_cb(const cf_vector* items, as_smd_accept_type accept_type);

void action_user_cache_delete(const as_smd_item* p_item);
void action_user_cache_set(const as_smd_item* p_item, bool is_startup);
void act_add_password(const char* p_user, uint32_t user_len, const char* password);
void act_add_role(const char* p_user, uint32_t user_len, const char* role);
void act_delete_password(const char* p_user, uint32_t user_len);
void act_delete_role(const char* p_user, uint32_t user_len, const char* role);
void act_hold_role(const char* p_user, uint32_t user_len, const char* role);
void activate_held_roles();

void action_role_cache_delete(const as_smd_item* p_item);
void action_role_cache_set(const as_smd_item* p_item, bool is_startup);
void act_add_priv(const char* p_role, uint32_t role_len, const char* smd_priv);
void act_delete_priv(const char* p_role, uint32_t role_len, const char* smd_priv);
void act_hold_priv(const char* p_role, uint32_t role_len, const char* smd_priv);
void activate_held_privs();
bool get_priv(const char* smd_priv, priv_code* p_priv, bool create_set);
void act_add_whitelist(const char* p_role, uint32_t role_len, const char* whitelist);
void act_delete_whitelist(const char* p_role, uint32_t role_len);
void act_add_quota(const char* p_role, uint32_t role_len, char quota_tok, const char* quota_str);
void act_delete_quota(const char* p_role, uint32_t role_len, char quota_tok);

int collect_keys_reduce_fn(const void* p_key, void* p_value, void* udata);
int collect_sort_keys_reduce_fn(const void* p_key, void* p_value, void* udata);

static inline bool uinfo_is_user_admin(const uinfo* p_uinfo);
void user_info_update_grow_role(const char* rkey, const book* p_rbook, uint32_t rbook_size);
void user_info_update_shrink_role(const char* rkey);
void quota_info_update(const char* rkey);

bool is_predefined_role(const char* role);
void role_cache_init();
bool role_in_parsed_list(const char* role, const char* roles, uint32_t num_roles);

static void conn_tracker_insert(const char* user);
static void conn_tracker_remove(const char* user);
static void conn_tracker_update_n_conns(const char* user, int32_t delta);
static uint32_t conn_tracker_get_n_conns(const char* user);
static uint32_t conn_tracker_find_lockless(const char* user, bool* found);

static bool name_list_insert(name_list* nl, const char* name);
static bool name_list_remove(name_list* nl, const char* name);
static bool name_list_find(name_list* nl, const char* name);
static inline bool name_list_is_empty(const name_list* nl);
static void name_list_info(name_list* nl, const char* tag, cf_dyn_buf* db);
static uint32_t name_list_find_lockless(name_list* nl, const char* name, bool* found);

char* add_log_scope(char* log_filter_scopes, uint32_t s, const char* ns_name, const char* set_name);
bool* create_log_filter(char* log_filter_scopes, uint32_t num_scopes);
void init_log_filters();
void get_data_op_scopes(bool* log_filter, const char* tag, cf_dyn_buf* db);
bool adjust_log_filter(bool* log_filter, as_namespace* ns, const char* set_name, bool enable);
void log_login_failure(const as_file_handle* fd_h, uint8_t result, const char* p_user, uint32_t user_len);
void log_login_success(const as_file_handle* fd_h, const char* p_user, uint32_t user_len, const char* roles, uint32_t num_roles);
void log_auth_failure(const as_file_handle* fd_h, uint8_t result, as_sec_msg_field* req_fields[]);
void log_auth_success(const as_file_handle* fd_h, as_sec_msg_field* req_fields[]);
void log_data_op(const as_file_handle* fd_h, uint32_t ns_ix, uint16_t set_id, as_sec_perm perm, const char* detail);
void log_user_admin(const as_file_handle* fd_h, uint8_t result, const char* cmd, as_sec_msg_field* req_fields[]);
bool msg_digest_str(as_transaction* tr, char* d_str);
bool msg_key_str(as_transaction* tr, char* key_str);
uint16_t msg_set(as_transaction* tr, as_namespace* ns, char* msg_set_name);
static inline const char* perm_code_tag(uint32_t perm_code);
static inline const char* perm_tag(as_sec_perm perm);
static inline const char* result_tag(uint8_t result);
void login_log(uint32_t sinks, const as_file_handle* fd_h, uint8_t result, const char* p_user, uint32_t user_len, const char* roles, uint32_t num_roles);
void sec_msg_log(uint32_t sinks, const as_file_handle* fd_h, uint8_t result, const char* cmd, as_sec_msg_field* req_fields[]);
char* sec_msg_log_parse_privs(const uint8_t* p_privs, uint32_t privs_size, uint32_t* p_len);
char* sec_msg_log_parse_roles(const uint8_t* p_roles, uint32_t roles_size, uint32_t* p_len);
void sec_log(uint32_t sinks, uint8_t result, const char* client, const char* user, const char* action, const char* detail);


//==========================================================
// Public API.
//

//------------------------------------------------
// Initialize the security subsystem.
//
void
as_security_init(void)
{
	// Act like a stub if security is not configured.
	if (! g_config.sec_cfg.security_configured) {
		// ... But don't impede other nodes with security configured.
		as_smd_module_load(AS_SMD_MODULE_SECURITY, sec_smd_dummy_accept_cb,
				NULL, NULL);
		return;
	}

	as_session_token_init();

	g_num_namespaces = g_config.n_namespaces;
	g_log_filter_size = g_num_namespaces * LOG_FILTER_NUM_SETS;

	set_max_priv_book_size();
	init_log_filters();

	// Create the roles cache.
	g_roles = cf_rchash_create(cf_rchash_fn_zstr, NULL, MAX_ROLE_NAME_SIZE,
			1024);

	// Add the predefined roles to the roles cache.
	role_cache_init();

	// Create the user-info cache.
	g_users = cf_rchash_create(cf_rchash_fn_zstr, NULL, MAX_USER_SIZE, 1024);

	if (g_config.sec_cfg.quotas_enabled) {
		as_quotas_init();
	}

	// Set up the default (admin) user, to be added if it never existed.
	cf_vector_define(default_user, sizeof(as_smd_item*), 2, 0);

	const as_smd_item default_user_password = {
			.key = (char*)SMD_SUPER_USER,
			.value = (char*)SMD_SUPER_PASSWORD
	};

	const as_smd_item default_user_role = {
			.key = (char*)SMD_SUPER_ROLE,
			.value = (char*)""
	};

	cf_vector_append_ptr(&default_user, &default_user_password);
	cf_vector_append_ptr(&default_user, &default_user_role);

	as_smd_module_load(AS_SMD_MODULE_SECURITY, sec_smd_accept_cb, NULL,
			&default_user);

	if (g_config.sec_cfg.syslog_local != AS_SYSLOG_NONE) {
		openlog(NULL, LOG_NDELAY,
				SYSLOG_FACILITIES[g_config.sec_cfg.syslog_local]);
	}

	if (g_config.sec_cfg.ldap_configured) {
		as_ldap_init();
	}
}

//------------------------------------------------
// Check that a socket is authenticated.
//
uint8_t
as_security_check_auth(const as_file_handle* fd_h)
{
	// Act like a stub if security is not configured.
	if (! g_config.sec_cfg.security_configured) {
		return AS_OK;
	}

	if (! fd_h) {
		// As things are now, this means it's a telnet connection.
		return AS_SEC_ERR_NOT_AUTHENTICATED;
	}

	return permission_check(fd_h, NO_NS_IX, INVALID_SET_ID, PERM_NONE);
}

//------------------------------------------------
// Check that an info command requiring the
// specified permission is permitted.
//
uint8_t
as_security_check_info_cmd(const as_file_handle* fd_h, const char* cmd,
		const char* params, as_sec_perm perm)
{
	// Act like a stub if security is not configured.
	if (! g_config.sec_cfg.security_configured) {
		return AS_OK;
	}

	if (! fd_h) {
		// As things are now, this means it's a telnet connection.
		return AS_SEC_ERR_NOT_AUTHENTICATED;
	}

	// Info commands that could be scoped by namespace and set might need these
	// extracted and passed to the permission check. For now only truncate
	// commands need this. Hack to accomplish the desired functionality, and
	// worry about how to do it right later.

	char ns_name[AS_ID_NAMESPACE_SZ];
	int ns_name_len = (int)sizeof(ns_name);

	char set_name[AS_SET_NAME_MAX_SIZE];
	int set_name_len = (int)sizeof(set_name);

	ns_name[0] = '\0';
	set_name[0] = '\0';

	// Note - commands with bad/missing parameters may fail by permission check
	// when they would otherwise have failed "normally" - tough.

	if (strcmp(cmd, "truncate") == 0 ||
			strcmp(cmd, "truncate-undo") == 0) {
		as_info_parameter_get(params, "namespace", ns_name, &ns_name_len);
		as_info_parameter_get(params, "set", set_name, &set_name_len);
	}
	else if (strcmp(cmd, "truncate-namespace") == 0 ||
			strcmp(cmd, "truncate-namespace-undo") == 0) {
		as_info_parameter_get(params, "namespace", ns_name, &ns_name_len);
	}

	// Note - with security enabled, truncate commands will now fail if the
	// command goes to a node that does not have the namespace in question.

	uint32_t ns_ix = NO_NS_IX;
	uint16_t set_id = INVALID_SET_ID;

	if (ns_name[0] != '\0') {
		as_namespace* ns = as_namespace_get_byname(ns_name);

		if (ns != NULL) {
			ns_ix = ns->ix;

			if (set_name[0] != '\0') {
				set_id = as_namespace_get_set_id(ns, set_name);
			}
		}
	}

	return permission_check(fd_h, ns_ix, set_id, perm);
}

//------------------------------------------------
// Check that a data transaction requiring the
// specified permission is permitted.
//
bool
as_security_check_data_op(as_transaction* tr, as_namespace* ns,
		as_sec_perm perm)
{
	// Act like a stub if security is not configured.
	if (! g_config.sec_cfg.security_configured) {
		return true;
	}

	uint32_t ns_ix = ns->ix;
	char set_name[AS_SET_NAME_MAX_SIZE];

	*set_name = 0;
	uint16_t set_id = msg_set(tr, ns, set_name);

	char key_str[MAX_KEY_STR_SIZE];
	char detail[2048];

	if (msg_key_str(tr, key_str) || msg_digest_str(tr, key_str)) {
		sprintf(detail, "{%s|%s} [%s]", ns->name, set_name, key_str);
	}
	else {
		sprintf(detail, "{%s|%s}", ns->name, set_name);
	}

	// If PERM_WRITE and PERM_READ are both set, can't be delete or UDF.
	if (perm == PERM_WRITE) {
		perm = write_op_perm(tr);
	}

	as_file_handle* fd_h = tr->origin == FROM_BATCH ?
			as_batch_get_fd_h(tr->from.batch_shared) : tr->from.proto_fd_h;

	uint8_t result = quota_and_permission_check(tr, fd_h, ns_ix, set_id, perm);

	if (result != AS_OK) {
		if (result != AS_SEC_ERR_QUOTA_EXCEEDED) {
			as_security_log(fd_h, result, perm, NULL, detail);
		}
		// else - logged (less often!) from rate_quota.c background thread.

		tr->result_code = (int)result;
		return false;
	}

	log_data_op(fd_h, ns_ix, set_id, perm, detail);

	return true;
}

//------------------------------------------------
// Check that a multi-record transaction with
// specified rps is allowed.
//
int
as_security_check_rps(as_file_handle* fd_h, uint32_t rps, as_sec_perm perm,
		bool is_write, void** udata)
{
	if (! g_config.sec_cfg.quotas_enabled) {
		return AS_OK;
	}

	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);

	if (p_filter->p_uinfo == NULL) {
		cf_mutex_unlock(&p_filter->lock);
		as_security_log(fd_h, AS_SEC_ERR_NOT_AUTHENTICATED, perm, NULL, NULL);
		return AS_SEC_ERR_NOT_AUTHENTICATED;
	}

	qinfo* p_qinfo = p_filter->p_qinfo;

	cf_assert(p_qinfo != NULL, AS_SECURITY, "null qinfo");

	cf_mutex_lock(&p_qinfo->rps_lock);

	if (is_write) {
		uint32_t quota = as_load_uint32(&p_qinfo->write_quota);

		if (quota != 0 && (rps == 0 ||
				p_qinfo->write_tps + p_qinfo->write_rps + rps > quota)) {
			cf_mutex_unlock(&p_qinfo->rps_lock);
			cf_mutex_unlock(&p_filter->lock);

			char tag[64];

			sprintf(tag, "rps=%u,write-quota=%u", rps, quota);
			as_security_log(fd_h, AS_SEC_ERR_QUOTA_EXCEEDED, perm, NULL, tag);

			return AS_SEC_ERR_QUOTA_EXCEEDED;
		}

		if (rps == 0) {
			p_qinfo->n_write_rps_zero++;
		}
		else {
			p_qinfo->write_rps += rps;
		}
	}
	else {
		uint32_t quota = as_load_uint32(&p_qinfo->read_quota);

		if (quota != 0 && (rps == 0 ||
				p_qinfo->read_tps + p_qinfo->read_rps + rps > quota)) {
			cf_mutex_unlock(&p_qinfo->rps_lock);
			cf_mutex_unlock(&p_filter->lock);

			char tag[64];

			sprintf(tag, "rps=%u,read-quota=%u", rps, quota);
			as_security_log(fd_h, AS_SEC_ERR_QUOTA_EXCEEDED, perm, NULL, tag);

			return AS_SEC_ERR_QUOTA_EXCEEDED;
		}

		if (rps == 0) {
			p_qinfo->n_read_rps_zero++;
		}
		else {
			p_qinfo->read_rps += rps;
		}
	}

	cf_mutex_unlock(&p_qinfo->rps_lock);

	cf_rc_reserve(p_qinfo);
	// Reference will be released in as_security_done_rps().

	*udata = p_qinfo;

	cf_mutex_unlock(&p_filter->lock);

	return AS_OK;
}

//------------------------------------------------
// A multi-record transaction with specified rps
// is done - account appropriately.
//
void
as_security_done_rps(void* udata, uint32_t rps, bool is_write)
{
	qinfo* p_qinfo = (qinfo*)udata;

	cf_mutex_lock(&p_qinfo->rps_lock);

	if (is_write) {
		if (rps == 0) {
			p_qinfo->n_write_rps_zero--;
		}
		else {
			p_qinfo->write_rps -= rps;
		}
	}
	else {
		if (rps == 0) {
			p_qinfo->n_read_rps_zero--;
		}
		else {
			p_qinfo->read_rps -= rps;
		}
	}

	cf_mutex_unlock(&p_qinfo->rps_lock);

	cf_rc_releaseandfree(p_qinfo);
}

//------------------------------------------------
// Create a socket's security filter.
//
void*
as_security_filter_create(void)
{
	// Act like a stub if security is not configured.
	if (! g_config.sec_cfg.security_configured) {
		return NULL;
	}

	as_sec_filter* p_filter = (as_sec_filter*)cf_malloc(sizeof(as_sec_filter));

	cf_mutex_init(&p_filter->lock);
	p_filter->addr_ok = false;
	p_filter->p_qinfo = NULL;
	p_filter->p_uinfo = NULL;
	p_filter->user_len = 0;

	// This ensures the user is null-terminated and padded for use as hash key.
	memset(p_filter->user, 0, MAX_USER_SIZE);

	return (void*)p_filter;
}

//------------------------------------------------
// Destroy a socket's security filter.
//
void
as_security_filter_destroy(void* pv_filter)
{
	// Act like a stub if security is not configured.
	if (! g_config.sec_cfg.security_configured) {
		return;
	}

	as_sec_filter* p_filter = (as_sec_filter*)pv_filter;

	if (p_filter->p_qinfo) {
		cf_rc_releaseandfree(p_filter->p_qinfo);
	}

	if (p_filter->p_uinfo) {
		cf_rc_releaseandfree(p_filter->p_uinfo);
	}

	if (p_filter->user_len != 0) {
		conn_tracker_update_n_conns(p_filter->user, -1);
	}

	cf_mutex_destroy(&p_filter->lock);
	cf_free(p_filter);
}

//------------------------------------------------
// Non-security protocol transactions call this to
// log to the security 'audit trail'.
//
void
as_security_log(const as_file_handle* fd_h, uint8_t result, as_sec_perm perm,
		const char* action, const char* detail)
{
	// Act like a stub if security is not configured.
	if (! g_config.sec_cfg.security_configured) {
		return;
	}

	switch (result) {
	case AS_OK:
		// Note - authentication and user-admin actions are handled elsewhere.
		if ((perm & ROLE_PERMS[ROLE_SYS_ADMIN]) != 0 &&
				g_config.sec_cfg.report.sys_admin != 0) {
			as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

			cf_mutex_lock(&p_filter->lock);
			sec_log(g_config.sec_cfg.report.sys_admin, result, fd_h->client,
					p_filter->user, action ? action : perm_tag(perm), detail);
			cf_mutex_unlock(&p_filter->lock);
		}
		break;
	case AS_SEC_ERR_NOT_AUTHENTICATED:
		// Here fd_h may not be valid. Either way there'll be no user.
		if (g_config.sec_cfg.report.violation != 0) {
			sec_log(g_config.sec_cfg.report.violation, result,
					fd_h ? fd_h->client : "<unknown>", NULL,
					action ? action : perm_tag(perm), detail);
		}
		break;
	case AS_SEC_ERR_ROLE_VIOLATION:
	case AS_SEC_ERR_NOT_WHITELISTED:
	case AS_SEC_ERR_QUOTA_EXCEEDED: // only scans & queries get here
		if (g_config.sec_cfg.report.violation != 0) {
			as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

			cf_mutex_lock(&p_filter->lock);
			sec_log(g_config.sec_cfg.report.violation, result, fd_h->client,
					p_filter->user, action ? action : perm_tag(perm), detail);
			cf_mutex_unlock(&p_filter->lock);
		}
		break;
	default:
		// Should never get here.
		cf_warning(AS_SECURITY, "security log - result %u", result);
		break;
	}
}

//------------------------------------------------
// The file reaper thread calls this to determine
// if we should refresh sockets' authentication.
//
bool
as_security_should_refresh(void)
{
	// Act like a stub if security is not configured.
	if (! g_config.sec_cfg.security_configured) {
		return false;
	}

	uint64_t now = cf_get_seconds();

	if (g_last_refresh == 0) {
		g_last_refresh = now;
		return false;
	}

	if (now - g_last_refresh <
			(uint64_t)g_config.sec_cfg.privilege_refresh_period) {
		return false;
	}

	g_last_refresh = now;

	return true;
}

//------------------------------------------------
// The file reaper thread calls this periodically
// to refresh a socket's authentication.
//
void
as_security_refresh(as_file_handle* fd_h)
{
	cf_assert(g_config.sec_cfg.security_configured, AS_SECURITY,
			"called as_security_refresh() with security not configured");

	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);

	if (p_filter->p_uinfo == NULL) {
		cf_mutex_unlock(&p_filter->lock);
		return;
	}

	cf_rc_releaseandfree(p_filter->p_uinfo);
	p_filter->p_uinfo = NULL;

	if (cf_rchash_get(g_users, p_filter->user, (void**)&p_filter->p_uinfo) ==
			CF_RCHASH_OK) {
		p_filter->addr_ok = as_security_ip_addr_ok(fd_h,
				uinfo_roles(p_filter->p_uinfo),
				uinfo_num_roles(p_filter->p_uinfo));
		// Note - we keep the ref count on p_filter->p_uinfo.
	}
	else {
		cf_warning(AS_SECURITY, "refresh permissions - user not found");

		p_filter->addr_ok = false;
		p_filter->user_len = 0;
		memset(p_filter->user, 0, MAX_USER_SIZE);

		if (g_config.sec_cfg.quotas_enabled && p_filter->p_qinfo != NULL) {
			cf_rc_releaseandfree(p_filter->p_qinfo);
			p_filter->p_qinfo = NULL;
		}
	}

	cf_mutex_unlock(&p_filter->lock);
}

//------------------------------------------------
// Security protocol transaction entry point.
//
void
as_security_transact(as_transaction *tr)
{
	// Act like a stub if security is not configured.
	if (! g_config.sec_cfg.security_configured) {
		// We don't need the request, since we're ignoring it.
		cf_free(tr->msgp);
		tr->msgp = NULL;

		send_result_msg(tr->from.proto_fd_h, AS_SEC_ERR_NOT_CONFIGURED);
		return;
	}

	as_proto* p_req_proto = &tr->msgp->proto;

	// For now trust there's only one security message per request proto body.
	handle_req_msg(tr->from.proto_fd_h, (as_sec_msg*)p_req_proto->body,
			p_req_proto->sz);

	// We're now done with the request proto buffer.
	cf_free(tr->msgp);
	tr->msgp = NULL;
}


//==========================================================
// Public API - security configuration.
//

//------------------------------------------------
// Add a scope for logging successful data
// transactions to the security 'audit trail'.
//
void
as_security_config_log_scope(uint32_t sink, const char* ns_name,
		const char* set_name)
{
	if (sink == AS_SEC_SINK_LOG) {
		g_config.sec_cfg.report.data_op |= AS_SEC_SINK_LOG;
		g_log_filter_scopes = add_log_scope(g_log_filter_scopes,
				g_num_log_filter_scopes++, ns_name, set_name);
	}

	if (sink == AS_SEC_SINK_SYSLOG) {
		g_config.sec_cfg.report.data_op |= AS_SEC_SINK_SYSLOG;
		g_syslog_filter_scopes = add_log_scope(g_syslog_filter_scopes,
				g_num_syslog_filter_scopes++, ns_name, set_name);
	}
}

//------------------------------------------------
// Add a role for logging successful data
// transactions to the security 'audit trail'.
//
void
as_security_config_log_role(uint32_t sink, const char* role)
{
	if (sink == AS_SEC_SINK_LOG) {
		g_config.sec_cfg.report.data_op |= AS_SEC_SINK_LOG;

		if (! name_list_insert(&g_log_filter_roles, role)) {
			cf_crash_nostack(AS_SECURITY, "security cfg - bad role %s", role);
		}
	}

	if (sink == AS_SEC_SINK_SYSLOG) {
		g_config.sec_cfg.report.data_op |= AS_SEC_SINK_SYSLOG;

		if (! name_list_insert(&g_syslog_filter_roles, role)) {
			cf_crash_nostack(AS_SECURITY, "security cfg - bad role %s", role);
		}
	}
}

//------------------------------------------------
// Add a user for logging successful data
// transactions to the security 'audit trail'.
//
void
as_security_config_log_user(uint32_t sink, const char* user)
{
	if (sink == AS_SEC_SINK_LOG) {
		g_config.sec_cfg.report.data_op |= AS_SEC_SINK_LOG;

		if (! name_list_insert(&g_log_filter_users, user)) {
			cf_crash_nostack(AS_SECURITY, "security cfg - bad user %s", user);
		}
	}

	if (sink == AS_SEC_SINK_SYSLOG) {
		g_config.sec_cfg.report.data_op |= AS_SEC_SINK_SYSLOG;

		if (! name_list_insert(&g_syslog_filter_users, user)) {
			cf_crash_nostack(AS_SECURITY, "security cfg - bad user %s", user);
		}
	}
}


//==========================================================
// Public API - enterprise only.
//

//------------------------------------------------
// Security configuration consistency checks.
//
void
as_security_cfg_post_process()
{
	if (g_config.sec_cfg.ldap_configured) {
		as_ldap_config_check();
	}

	char* p_read = g_log_filter_scopes;

	for (uint32_t s = 0; s < g_num_log_filter_scopes; s++) {
		if (! as_namespace_get_byname(p_read)) {
			cf_crash_nostack(AS_SECURITY,
					"security config - invalid namespace %s", p_read);
		}

		p_read += LOG_FILTER_SCOPE_MAX_SIZE;
	}

	p_read = g_syslog_filter_scopes;

	for (uint32_t s = 0; s < g_num_syslog_filter_scopes; s++) {
		if (! as_namespace_get_byname(p_read)) {
			cf_crash_nostack(AS_SECURITY,
					"security config - invalid namespace %s", p_read);
		}

		p_read += LOG_FILTER_SCOPE_MAX_SIZE;
	}
}

//------------------------------------------------
// On 'get-config', return data-op logged scopes.
//
void
as_security_get_data_op_scopes(uint32_t sinks, cf_dyn_buf* db)
{
	if ((sinks & AS_SEC_SINK_LOG) != 0 &&
			(g_config.sec_cfg.report.data_op & AS_SEC_SINK_LOG) != 0) {
		get_data_op_scopes(g_log_filter, "log.report-data-op", db);
	}

	if ((sinks & AS_SEC_SINK_SYSLOG) != 0 &&
			(g_config.sec_cfg.report.data_op & AS_SEC_SINK_SYSLOG) != 0) {
		get_data_op_scopes(g_syslog_filter, "syslog.report-data-op", db);
	}
}

//------------------------------------------------
// On 'get-config', return data-op logged roles.
//
void
as_security_get_data_op_roles(uint32_t sinks, cf_dyn_buf* db)
{
	if ((sinks & AS_SEC_SINK_LOG) != 0 &&
			(g_config.sec_cfg.report.data_op & AS_SEC_SINK_LOG) != 0) {
		name_list_info(&g_log_filter_roles, "log.report-data-op-role", db);
	}

	if ((sinks & AS_SEC_SINK_SYSLOG) != 0 &&
			(g_config.sec_cfg.report.data_op & AS_SEC_SINK_SYSLOG) != 0) {
		name_list_info(&g_syslog_filter_roles, "syslog.report-data-op-role",
				db);
	}
}

//------------------------------------------------
// On 'get-config', return data-op logged users.
//
void
as_security_get_data_op_users(uint32_t sinks, cf_dyn_buf* db)
{
	if ((sinks & AS_SEC_SINK_LOG) != 0 &&
			(g_config.sec_cfg.report.data_op & AS_SEC_SINK_LOG) != 0) {
		name_list_info(&g_log_filter_users, "log.report-data-op-user", db);
	}

	if ((sinks & AS_SEC_SINK_SYSLOG) != 0 &&
			(g_config.sec_cfg.report.data_op & AS_SEC_SINK_SYSLOG) != 0) {
		name_list_info(&g_syslog_filter_users, "syslog.report-data-op-user",
				db);
	}
}

//------------------------------------------------
// Dynamically configure a scope for logging
// successful data transactions to the security
// 'audit trail'.
//
bool
as_security_adjust_log_scope(uint32_t sink, as_namespace* ns,
		const char* set_name, bool enable)
{
	if (sink == AS_SEC_SINK_LOG) {
		if (g_log_filter == NULL) { // first filter added dynamically
			g_log_filter = cf_calloc(1, g_log_filter_size);
		}

		if (enable) {
			g_config.sec_cfg.report.data_op |= AS_SEC_SINK_LOG;
		}

		if (! adjust_log_filter(g_log_filter, ns, set_name, enable)) {
			return false;
		}

		if (! enable && cf_memeq(g_log_filter, 0, g_log_filter_size) &&
				name_list_is_empty(&g_log_filter_roles) &&
				name_list_is_empty(&g_log_filter_users)) {
			g_config.sec_cfg.report.data_op &= ~AS_SEC_SINK_LOG;
		}

		return true;
	}

	if (sink == AS_SEC_SINK_SYSLOG) {
		if (g_syslog_filter == NULL) { // first filter added dynamically
			g_syslog_filter = cf_calloc(1, g_log_filter_size);
		}

		if (enable) {
			g_config.sec_cfg.report.data_op |= AS_SEC_SINK_SYSLOG;
		}

		if (! adjust_log_filter(g_syslog_filter, ns, set_name, enable)) {
			return false;
		}

		if (! enable && cf_memeq(g_syslog_filter, 0, g_log_filter_size) &&
				name_list_is_empty(&g_syslog_filter_roles) &&
				name_list_is_empty(&g_syslog_filter_users)) {
			g_config.sec_cfg.report.data_op &= ~AS_SEC_SINK_SYSLOG;
		}

		return true;
	}

	// Should be impossible to get here.
	return false;
}

//------------------------------------------------
// Dynamically configure a role for which we log
// successful data transactions to the security
// 'audit trail'.
//
bool
as_security_adjust_log_role(uint32_t sink, const char* role, bool enable)
{
	if (sink == AS_SEC_SINK_LOG) {
		if (enable) {
			g_config.sec_cfg.report.data_op |= AS_SEC_SINK_LOG;

			if (! name_list_insert(&g_log_filter_roles, role)) {
				return false;
			}
		}
		else {
			if (! name_list_remove(&g_log_filter_roles, role)) {
				return false;
			}

			if ((g_log_filter == NULL ||
					cf_memeq(g_log_filter, 0, g_log_filter_size)) &&
					name_list_is_empty(&g_log_filter_roles) &&
					name_list_is_empty(&g_log_filter_users)) {
				g_config.sec_cfg.report.data_op &= ~AS_SEC_SINK_LOG;
			}
		}

		return true;
	}

	if (sink == AS_SEC_SINK_SYSLOG) {
		if (enable) {
			g_config.sec_cfg.report.data_op |= AS_SEC_SINK_SYSLOG;

			if (! name_list_insert(&g_syslog_filter_roles, role)) {
				return false;
			}
		}
		else {
			if (! name_list_remove(&g_syslog_filter_roles, role)) {
				return false;
			}

			if ((g_syslog_filter == NULL ||
					cf_memeq(g_syslog_filter, 0, g_log_filter_size)) &&
					name_list_is_empty(&g_syslog_filter_roles) &&
					name_list_is_empty(&g_syslog_filter_users)) {
				g_config.sec_cfg.report.data_op &= ~AS_SEC_SINK_SYSLOG;
			}
		}

		return true;
	}

	// Should be impossible to get here.
	return false;
}


//------------------------------------------------
// Dynamically configure a user for which we log
// successful data transactions to the security
// 'audit trail'.
//
bool
as_security_adjust_log_user(uint32_t sink, const char* user, bool enable)
{
	if (sink == AS_SEC_SINK_LOG) {
		if (enable) {
			g_config.sec_cfg.report.data_op |= AS_SEC_SINK_LOG;

			if (! name_list_insert(&g_log_filter_users, user)) {
				return false;
			}
		}
		else {
			if (! name_list_remove(&g_log_filter_users, user)) {
				return false;
			}

			if ((g_log_filter == NULL ||
					cf_memeq(g_log_filter, 0, g_log_filter_size)) &&
					name_list_is_empty(&g_log_filter_roles) &&
					name_list_is_empty(&g_log_filter_users)) {
				g_config.sec_cfg.report.data_op &= ~AS_SEC_SINK_LOG;
			}
		}

		return true;
	}

	if (sink == AS_SEC_SINK_SYSLOG) {
		if (enable) {
			g_config.sec_cfg.report.data_op |= AS_SEC_SINK_SYSLOG;

			if (! name_list_insert(&g_syslog_filter_users, user)) {
				return false;
			}
		}
		else {
			if (! name_list_remove(&g_syslog_filter_users, user)) {
				return false;
			}

			if ((g_syslog_filter == NULL ||
					cf_memeq(g_syslog_filter, 0, g_log_filter_size)) &&
					name_list_is_empty(&g_syslog_filter_roles) &&
					name_list_is_empty(&g_syslog_filter_users)) {
				g_config.sec_cfg.report.data_op &= ~AS_SEC_SINK_SYSLOG;
			}
		}

		return true;
	}

	// Should be impossible to get here.
	return false;
}

//------------------------------------------------
// Log a quota violation.
//
void
as_security_log_quota_violation(const char* user, uint32_t quota, bool is_write)
{
	if (g_config.sec_cfg.report.violation != 0) {
		char tag[16];

		sprintf(tag, "quota=%u", quota);

		sec_log(g_config.sec_cfg.report.violation, AS_SEC_ERR_QUOTA_EXCEEDED,
				"<n/a>", user, is_write ? "write" : "read", tag);
	}
}

//------------------------------------------------
// Send a login nack security message to client.
//
void
as_security_login_failed(as_file_handle* fd_h, uint8_t result,
		const char* p_user, uint32_t user_len)
{
	log_login_failure(fd_h, result, p_user, user_len);
	send_result_msg(fd_h, result);
}

//------------------------------------------------
// Send a response with session token to client.
//
void
as_security_login_succeeded(as_file_handle* fd_h, const char* p_user,
		uint32_t user_len, const char* roles, uint32_t num_roles,
		const uint8_t* token, uint32_t token_size, uint32_t ttl)
{
	log_login_success(fd_h, p_user, user_len, roles, num_roles);
	send_resp_token(fd_h, token, token_size, ttl);
}

//------------------------------------------------
// Is this socket ok by whitelists on these roles?
// Note - also called internally.
//
bool
as_security_ip_addr_ok(as_file_handle* fd_h, const char* roles,
		uint32_t num_roles)
{
	if (g_n_whitelists == 0 || num_roles == 0) {
		return true;
	}

	bool result = true; // we're ok if no role has a whitelist

	cf_sock_addr sa;
	const char* role = roles;

	for (uint32_t r = 0; r < num_roles; r++) {
		rinfo* p_rinfo;

		if (cf_rchash_get(g_roles, role, (void**)&p_rinfo) == CF_RCHASH_OK) {
			// If any role has a whitelist, addr must be on one of these lists.
			if (rinfo_has_whitelist(p_rinfo)) {
				if (result) {
					result = false;

					// Lazily, to spare users with no whitelists.
					if (cf_socket_remote_name(&fd_h->sock, &sa) < 0) {
						cf_ip_addr_set_any(&sa.addr);
					}
				}

				if (rinfo_whitelist_contains(p_rinfo, &sa.addr)) {
					cf_rc_releaseandfree(p_rinfo);
					return true;
				}
			}

			cf_rc_releaseandfree(p_rinfo);
		}

		role = role + MAX_ROLE_NAME_SIZE;
	}

	return result;
}

//------------------------------------------------
// On successful login, start a fresh session for
// an external user. May create a new user. Also
// authenticates the login socket.
//
void
as_security_new_session(as_file_handle* fd_h, const char* p_user,
		uint32_t user_len, const char* roles, uint32_t num_roles)
{
	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	qinfo* p_qinfo = NULL;
	uinfo* p_uinfo = NULL;

	cf_mutex_lock(&g_session_users_lock);

	if (g_config.sec_cfg.quotas_enabled) {
		if (cf_rchash_get(g_quotas, ukey, (void**)&p_qinfo) != CF_RCHASH_OK) {
			p_qinfo = qinfo_new_session(roles, num_roles);

			// Filter copy needs a ref count. (Reserve before hash insertion in
			// case of concurrent delete, unlikely as that may be.)
			cf_rc_reserve((void*)p_qinfo);

			cf_rchash_put(g_quotas, ukey, (void*)p_qinfo);
		}
		// else - Keep the reference for the filter copy, which was released at
		// the beginning of this login.
	}

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) == CF_RCHASH_OK) {
		adjust_roles_in_smd(p_uinfo, p_user, user_len, roles, num_roles);
		cf_rc_releaseandfree(p_uinfo);
	}
	else {
		// Creates new user.
		smd_add_password(p_user, user_len, NULL, 0);
		adjust_roles_in_smd(NULL, p_user, user_len, roles, num_roles);

		conn_tracker_insert(ukey);
	}

	uinfo* p_new_uinfo = uinfo_new_session(roles, num_roles);

	// Filter copy needs a ref count. (Reserve before hash insertion in case of
	// concurrent delete, unlikely as that may be.)
	cf_rc_reserve((void*)p_new_uinfo);

	cf_rchash_put(g_users, ukey, (void*)p_new_uinfo);

	conn_tracker_update_n_conns(ukey, 1);

	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);
	p_filter->addr_ok = true;
	p_filter->p_qinfo = p_qinfo;
	p_filter->p_uinfo = p_new_uinfo;
	p_filter->user_len = user_len;
	memcpy(p_filter->user, p_user, user_len);
	cf_mutex_unlock(&p_filter->lock);

	cf_mutex_unlock(&g_session_users_lock);
}

//------------------------------------------------
// Return a list of external users, i.e. users
// without a password. Caller must free returned
// pointer.
//
char*
as_security_get_external_users(uint32_t* p_num_external_users)
{
	uint32_t num_users = cf_rchash_get_size(g_users);

	if (num_users == 0) {
		*p_num_external_users = 0;
		return NULL;
	}

	udata_external_users external_users = {
			.names = cf_malloc(num_users * MAX_USER_SIZE),
			.num_names = 0,
			.capacity = num_users
	};

	cf_rchash_reduce(g_users, collect_external_users_cb,
			(void*)&external_users);

	if (external_users.num_names == 0) {
		cf_free(external_users.names);
		*p_num_external_users = 0;
		return NULL;
	}

	*p_num_external_users = external_users.num_names;

	return external_users.names;
}

//------------------------------------------------
// Remove an external user from the system.
//
void
as_security_drop_external_user(const char* p_user, uint32_t user_len)
{
	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uinfo* p_uinfo = NULL;

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) != CF_RCHASH_OK) {
		// Removed user while polling for roles?
		return;
	}

	smd_delete_password(p_user, user_len);

	// Just to clean these out of the system metadata...
	uint32_t num_uinfo_roles = uinfo_num_roles(p_uinfo);
	const char* uinfo_role = uinfo_roles(p_uinfo);

	for (uint32_t n = 0; n < num_uinfo_roles; n++) {
		smd_delete_role(p_user, user_len, uinfo_role);
		uinfo_role = uinfo_next_role(uinfo_role);
	}

	cf_rc_releaseandfree(p_uinfo);
}

//------------------------------------------------
// Update an external user's roles.
//
void
as_security_update_roles(const char* p_user, uint32_t user_len,
		const char* roles, uint32_t num_roles)
{
	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uinfo* p_uinfo = NULL;

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) != CF_RCHASH_OK) {
		// Removed user while polling for roles?
		return;
	}

	adjust_roles_in_smd(p_uinfo, p_user, user_len, roles, num_roles);

	cf_rc_releaseandfree(p_uinfo);
}

//------------------------------------------------
// Utility function to add a role to a list.
// Returns true if role is a current Aerospike
// role, false if not.
//
bool
as_security_add_aerospike_role(char* dest, const char* p_role,
		uint32_t role_len)
{
	// Use dest directly as rkey.
	memset(dest, 0, MAX_ROLE_NAME_SIZE);
	memcpy(dest, p_role, role_len);

	// Yes, predefined roles are in the hash.
	return cf_rchash_get(g_roles, dest, NULL) == CF_RCHASH_OK;
}


//==========================================================
// LDAP API helpers.
//

//------------------------------------------------
// Check differences between old and new roles,
// issue appropriate SMD set and delete commands
// to move to new roles.
//
void
adjust_roles_in_smd(const uinfo* p_uinfo, const char* p_user, uint32_t user_len,
		const char* roles, uint32_t num_roles)
{
	// If creating a new user, add all roles via SMD.
	if (! p_uinfo) {
		if (! roles) {
			return;
		}

		const char* role = roles;
		const char* end = roles + (num_roles * MAX_ROLE_NAME_SIZE);

		while (role < end) {
			smd_add_role(p_user, user_len, role);
			role += MAX_ROLE_NAME_SIZE;
		}

		return;
	}
	// else - user existed, apply differences between new and existing roles.

	uint32_t num_uinfo_roles = uinfo_num_roles(p_uinfo);
	const char* uinfo_role = uinfo_roles(p_uinfo);

	// Handle user with no roles - remove all via SMD, leaving role-less user.
	if (! roles) {
		for (uint32_t n = 0; n < num_uinfo_roles; n++) {
			smd_delete_role(p_user, user_len, uinfo_role);
			uinfo_role = uinfo_next_role(uinfo_role);
		}

		return;
	}
	// else - user has at least one role - make changes if necessary.

	// If new role is not in uinfo, add it via SMD.

	const char* role = roles;
	const char* end = roles + (num_roles * MAX_ROLE_NAME_SIZE);

	while (role < end) {
		if (! uinfo_has_role(p_uinfo, role)) {
			smd_add_role(p_user, user_len, role);
		}

		role += MAX_ROLE_NAME_SIZE;
	}

	// If uinfo has role that is not in new roles, remove it via SMD.

	for (uint32_t n = 0; n < num_uinfo_roles; n++) {
		role = roles;

		while (role < end) {
			if (strcmp(uinfo_role, role) == 0) {
				break;
			}

			role += MAX_ROLE_NAME_SIZE;
		}

		if (role == end) {
			smd_delete_role(p_user, user_len, uinfo_role);
		}

		uinfo_role = uinfo_next_role(uinfo_role);
	}
}

//------------------------------------------------
// Accumulate list of external users.
//
int
collect_external_users_cb(const void* p_key, void* p_value, void* udata)
{
	udata_external_users* external_users = (udata_external_users*)udata;
	uinfo* p_uinfo = (uinfo*)p_value;

	if (! uinfo_password_is_empty(p_uinfo)) {
		return CF_RCHASH_OK; // internal user
	}

	if (external_users->num_names == external_users->capacity) {
		external_users->capacity += 16;
		external_users->names = cf_realloc(external_users->names,
				external_users->capacity * MAX_USER_SIZE);
	}

	char* at = external_users->names +
			(external_users->num_names * MAX_USER_SIZE);

	strcpy(at, (const char*)p_key);
	external_users->num_names++;

	return CF_RCHASH_OK;
}


//==========================================================
// Security check helpers.
//

//------------------------------------------------
// Check that a user-admin transaction is
// permitted on the socket.
//
static inline uint8_t
admin_permission_check(const as_file_handle* fd_h)
{
	return permission_check(fd_h, NO_NS_IX, INVALID_SET_ID, PERM_USER_ADMIN);
}

//------------------------------------------------
// Check that a transaction requiring the
// specified permission is permitted on the
// socket.
//
uint8_t
permission_check(const as_file_handle* fd_h, uint32_t ns_ix, uint16_t set_id,
		as_sec_perm perm)
{
	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);

	if (p_filter->p_uinfo == NULL) {
		cf_mutex_unlock(&p_filter->lock);
		return AS_SEC_ERR_NOT_AUTHENTICATED;
	}

	if (! p_filter->addr_ok) {
		cf_mutex_unlock(&p_filter->lock);
		return AS_SEC_ERR_NOT_WHITELISTED;
	}

	// Note that perm PERM_NONE gives result AS_OK.
	bool allow_op = book_allows_op(uinfo_book(p_filter->p_uinfo), ns_ix, set_id,
			perm);

	uint8_t result = allow_op ? AS_OK : AS_SEC_ERR_ROLE_VIOLATION;

	cf_mutex_unlock(&p_filter->lock);
	return result;
}

//------------------------------------------------
// Check that a transaction subject to quotas is
// currently permitted on the socket.
//
uint8_t
quota_and_permission_check(const as_transaction* tr, const as_file_handle* fd_h,
		uint32_t ns_ix, uint16_t set_id, as_sec_perm perm)
{
	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);

	if (p_filter->p_uinfo == NULL) {
		cf_mutex_unlock(&p_filter->lock);
		return AS_SEC_ERR_NOT_AUTHENTICATED;
	}

	if (g_config.sec_cfg.quotas_enabled) {
		cf_assert(p_filter->p_qinfo != NULL, AS_SECURITY, "null qinfo");

		if ((tr->msgp->msg.info2 & AS_MSG_INFO2_WRITE) != 0) {
			as_incr_uint64(&p_filter->p_qinfo->write_tr_total);

			if (p_filter->p_qinfo->write_quota_exceeded) {
				cf_mutex_unlock(&p_filter->lock);
				return AS_SEC_ERR_QUOTA_EXCEEDED;
			}
		}
		else {
			as_incr_uint64(&p_filter->p_qinfo->read_tr_total);

			if (p_filter->p_qinfo->read_quota_exceeded) {
				cf_mutex_unlock(&p_filter->lock);
				return AS_SEC_ERR_QUOTA_EXCEEDED;
			}
		}
	}

	if (! p_filter->addr_ok) {
		cf_mutex_unlock(&p_filter->lock);
		return AS_SEC_ERR_NOT_WHITELISTED;
	}

	// Note that perm PERM_NONE gives result AS_OK.
	bool allow_op = book_allows_op(uinfo_book(p_filter->p_uinfo), ns_ix, set_id,
			perm);

	uint8_t result = allow_op ? AS_OK : AS_SEC_ERR_ROLE_VIOLATION;

	cf_mutex_unlock(&p_filter->lock);
	return result;
}

//------------------------------------------------
// Determine if an op flagged as a write is really
// a write, or a record UDF.
//
as_sec_perm
write_op_perm(as_transaction* tr)
{
	as_msg* m = &tr->msgp->msg;
	as_msg_field *f = as_transaction_is_udf(tr) ?
			as_msg_field_get(m, AS_MSG_FIELD_TYPE_UDF_FILENAME) : NULL;

	if (! f || as_msg_field_get_value_sz(f) == 0) {
		// It's not a UDF - so it must be a regular write or delete.
		return (m->info2 & AS_MSG_INFO2_DELETE) == 0 ? PERM_WRITE : PERM_DELETE;
	}

	// It's a UDF apply.
	return PERM_UDF_APPLY;
}


//==========================================================
// Request high-level helpers.
//

//------------------------------------------------
// Handle request's security message.
//
void
handle_req_msg(as_file_handle* fd_h, as_sec_msg* p_req_msg, uint64_t size)
{
	if (size < sizeof(as_sec_msg)) {
		cf_warning(AS_SECURITY, "security proto body size %lu", size);
		send_result_msg(fd_h, AS_ERR_UNKNOWN);
		return;
	}

	if (p_req_msg->scheme != AS_SEC_MSG_SCHEME) {
		cf_warning(AS_SECURITY, "security message scheme %u not supported",
				p_req_msg->scheme);
		send_result_msg(fd_h, AS_SEC_ERR_SCHEME);
		return;
	}

	as_sec_msg_field* req_fields[AS_SEC_FIELD_LAST_PLUS_1] = { NULL };

	if (! req_msg_get_fields(p_req_msg, size, req_fields)) {
		cf_warning(AS_SECURITY, "bad security proto body, size %lu", size);
		send_result_msg(fd_h, AS_SEC_ERR_FIELD);
		return;
	}

	switch (p_req_msg->command) {
	case AS_SEC_CMD_LOGIN:
		cmd_login(fd_h, req_fields);
		break;
	case AS_SEC_CMD_AUTHENTICATE:
		cmd_authenticate(fd_h, req_fields);
		break;
	case AS_SEC_CMD_CREATE_USER:
		cmd_create_user(fd_h, req_fields);
		break;
	case AS_SEC_CMD_DROP_USER:
		cmd_drop_user(fd_h, req_fields);
		break;
	case AS_SEC_CMD_SET_PASSWORD:
		cmd_set_password(fd_h, req_fields);
		break;
	case AS_SEC_CMD_CHANGE_PASSWORD:
		cmd_change_password(fd_h, req_fields);
		break;
	case AS_SEC_CMD_GRANT_ROLES:
		cmd_grant_roles(fd_h, req_fields);
		break;
	case AS_SEC_CMD_REVOKE_ROLES:
		cmd_revoke_roles(fd_h, req_fields);
		break;
	case AS_SEC_CMD_QUERY_USERS:
		cmd_query_users(fd_h, req_fields);
		break;
	case AS_SEC_CMD_CREATE_ROLE:
		cmd_create_role(fd_h, req_fields);
		break;
	case AS_SEC_CMD_DELETE_ROLE:
		cmd_delete_role(fd_h, req_fields);
		break;
	case AS_SEC_CMD_ADD_PRIVS:
		cmd_add_privs(fd_h, req_fields);
		break;
	case AS_SEC_CMD_DELETE_PRIVS:
		cmd_delete_privs(fd_h, req_fields);
		break;
	case AS_SEC_CMD_SET_WHITELIST:
		cmd_set_whitelist(fd_h, req_fields);
		break;
	case AS_SEC_CMD_SET_QUOTAS:
		cmd_set_quotas(fd_h, req_fields);
		break;
	case AS_SEC_CMD_QUERY_ROLES:
		cmd_query_roles(fd_h, req_fields);
		break;
	default:
		cf_warning(AS_SECURITY, "unknown security message command %u",
				p_req_msg->command);
		send_result_msg(fd_h, AS_SEC_ERR_COMMAND);
		return;
	}
}

//------------------------------------------------
// Sweep through security message to verify all
// fields' sizes, swap sizes to host byte order,
// and store pointers to recognized fields.
//
bool
req_msg_get_fields(as_sec_msg* p_msg, uint64_t size,
		as_sec_msg_field* req_fields[])
{
	uint8_t* p_end = (uint8_t*)p_msg + size;
	uint8_t* p_read = p_msg->fields;

	while (p_read < p_end) {
		if (p_read + sizeof(as_sec_msg_field) > p_end) {
			cf_warning(AS_SECURITY, "incomplete security message field");
			return false;
		}

		as_sec_msg_field* p_field = (as_sec_msg_field*)p_read;

		req_msg_field_swap(p_field);

		uint32_t value_size = msg_field_value_size(p_field);

		p_read = p_field->value + value_size;

		if (p_read > p_end) {
			cf_warning(AS_SECURITY, "incomplete security message field value");
			return false;
		}

		if (is_valid_field_id(p_field->id)) {
			req_fields[p_field->id] = p_field;
		}
		else {
			cf_debug(AS_SECURITY, "skipping message field, id %u", p_field->id);
		}
	}

	return true;
}


//==========================================================
// Response high-level helpers.
//

//------------------------------------------------
// Send a complete response to client.
//
bool
send_resp_to_client(as_file_handle* fd_h, const uint8_t* p_resp,
		size_t resp_size, bool done)
{
	cf_socket* sock = &fd_h->sock;

	if (cf_socket_send_all(sock, p_resp, resp_size, MSG_NOSIGNAL,
			CF_SOCKET_TIMEOUT) < 0) {
		cf_warning(AS_SECURITY, "fd %d send failed, errno %d", CSFD(sock),
				errno);
		as_end_of_transaction_force_close(fd_h);
		return false;
	}

	if (done) {
		as_end_of_transaction_ok(fd_h);
	}

	return true;
}

//------------------------------------------------
// Send an ack/nack security message to client.
//
void
send_result_msg(as_file_handle* fd_h, uint8_t result)
{
	// Set up a simple response with a single as_sec_msg that has no fields.
	size_t resp_size = sizeof(as_proto) + sizeof(as_sec_msg);
	uint8_t resp[resp_size];

	// Fill out the as_proto fields.
	as_proto* p_resp_proto = (as_proto*)resp;

	p_resp_proto->version = PROTO_VERSION;
	p_resp_proto->type = PROTO_TYPE_SECURITY;
	p_resp_proto->sz = sizeof(as_sec_msg);

	// Switch to network byte order.
	as_proto_swap(p_resp_proto);

	uint8_t* p_proto_body = resp + sizeof(as_proto);

	memset((void*)p_proto_body, 0, sizeof(as_sec_msg));

	// Fill out the relevant as_sec_msg fields.
	as_sec_msg* p_sec_msg = (as_sec_msg*)p_proto_body;

	p_sec_msg->scheme = AS_SEC_MSG_SCHEME;
	p_sec_msg->result = result;

	// Send the complete response to the client.
	send_resp_to_client(fd_h, resp, resp_size, true);
}

//------------------------------------------------
// Send a response with session token to client.
// Optionally include the configured session TTL.
//
void
send_resp_token(as_file_handle* fd_h, const uint8_t* token, uint32_t token_size,
		uint32_t ttl)
{
	// Set up a response with an as_sec_msg that has one or two fields.
	uint8_t n_fields = 1;
	size_t proto_body_size = sizeof(as_sec_msg) + sizeof(as_sec_msg_field) +
			token_size;

	if (ttl != 0) {
		n_fields++;
		proto_body_size += sizeof(as_sec_msg_field) + sizeof(uint32_t);
	}

	size_t resp_size = sizeof(as_proto) + proto_body_size;
	uint8_t resp[resp_size];

	// Fill out the as_proto fields.
	as_proto* p_resp_proto = (as_proto*)resp;

	p_resp_proto->version = PROTO_VERSION;
	p_resp_proto->type = PROTO_TYPE_SECURITY;
	p_resp_proto->sz = proto_body_size;

	// Switch to network byte order.
	as_proto_swap(p_resp_proto);

	uint8_t* p_proto_body = resp + sizeof(as_proto);

	memset(p_proto_body, 0, sizeof(as_sec_msg));

	// Fill out the relevant as_sec_msg fields.
	as_sec_msg* p_sec_msg = (as_sec_msg*)p_proto_body;

	p_sec_msg->scheme = AS_SEC_MSG_SCHEME;
	p_sec_msg->result = AS_OK;
	p_sec_msg->n_fields = n_fields;

	// Fill out the session token message field.
	as_sec_msg_field* pf_token = (as_sec_msg_field*)(p_sec_msg + 1);

	pf_token->size = 1 + token_size;
	pf_token->id = AS_SEC_FIELD_SESSION_TOKEN;
	memcpy(pf_token->value, token, token_size);

	// Switch to network byte order.
	resp_msg_field_swap(pf_token);

	if (ttl != 0) {
		// Fill out the session ttl message field.
		as_sec_msg_field* pf_ttl = (as_sec_msg_field*)
				((uint8_t*)pf_token + sizeof(as_sec_msg_field) + token_size);

		pf_ttl->size = 1 + sizeof(uint32_t);
		pf_ttl->id = AS_SEC_FIELD_SESSION_TTL;
		*(uint32_t*)pf_ttl->value = cf_swap_to_be32(ttl);

		// Switch to network byte order.
		resp_msg_field_swap(pf_ttl);
	}

	// Send the complete response to the client.
	send_resp_to_client(fd_h, resp, resp_size, true);
}

//------------------------------------------------
// Send a cf_buf_builder response containing
// one or more security messages to client.
//
bool
send_resp_bb(as_file_handle* fd_h, cf_buf_builder* p_bb)
{
	// Fill out the as_proto fields.
	as_proto* p_resp_proto = (as_proto*)p_bb->buf;

	p_resp_proto->version = PROTO_VERSION;
	p_resp_proto->type = PROTO_TYPE_SECURITY;
	p_resp_proto->sz = p_bb->used_sz - sizeof(as_proto);

	// Switch to network byte order.
	as_proto_swap(p_resp_proto);

	// Send the complete response to the client.
	return send_resp_to_client(fd_h, p_bb->buf, p_bb->used_sz, false);
}


//==========================================================
// Security commands - login.
//

//------------------------------------------------
// Handle 'login' command.
//
void
cmd_login(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);

	// To re-use authenticated socket for login, strip authentication. If login
	// succeeds, socket will be re-authenticated.
	if (p_filter->p_uinfo != NULL) {
		p_filter->addr_ok = false;

		if (g_config.sec_cfg.quotas_enabled) {
			cf_assert(p_filter->p_qinfo != NULL, AS_SECURITY, "null qinfo");
			cf_rc_releaseandfree(p_filter->p_qinfo);
			p_filter->p_qinfo = NULL;
		}

		conn_tracker_update_n_conns(p_filter->user, -1);

		cf_rc_releaseandfree(p_filter->p_uinfo);
		p_filter->p_uinfo = NULL;
		p_filter->user_len = 0;
		memset(p_filter->user, 0, MAX_USER_SIZE);
	}

	cf_mutex_unlock(&p_filter->lock);

	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];
	as_sec_msg_field* pf_cred = req_fields[AS_SEC_FIELD_CREDENTIAL];
	as_sec_msg_field* pf_clear_pw = req_fields[AS_SEC_FIELD_CLEAR_PASSWORD];

	uint32_t user_len;
	const char* p_user;
	char tls_user[MAX_USER_SIZE];

	if (pf_user) {
		user_len = msg_field_value_size(pf_user);
		p_user = (const char*)pf_user->value;

		if (! pf_cred && ! pf_clear_pw) {
			log_login_failure(fd_h, AS_SEC_ERR_CREDENTIAL, p_user, user_len);
			send_result_msg(fd_h, AS_SEC_ERR_CREDENTIAL);
			return;
		}
	}
	else { // PKI authentication ...
		user_len = sizeof(tls_user);
		p_user = tls_user;

		if (! tls_get_peer_name(&fd_h->sock, tls_user, &user_len)) {
			log_login_failure(fd_h, AS_SEC_ERR_USER, NULL, 0);
			send_result_msg(fd_h, AS_SEC_ERR_USER);
			return;
		}

		if (pf_cred || pf_clear_pw) {
			log_login_failure(fd_h, AS_SEC_ERR_CREDENTIAL, p_user, user_len);
			send_result_msg(fd_h, AS_SEC_ERR_CREDENTIAL);
			return;
		}
	}

	if (g_fips && pf_cred && ! pf_clear_pw) {
		// For now FIPS mode won't allow internal login mode.
		log_login_failure(fd_h, AS_SEC_ERR_CREDENTIAL, p_user, user_len);
		send_result_msg(fd_h, AS_SEC_ERR_CREDENTIAL);
		return;
	}

	uint32_t cred_size = 0;
	const uint8_t* p_cred = NULL;

	if (pf_cred) {
		cred_size = msg_field_value_size(pf_cred);
		p_cred = (const uint8_t*)pf_cred->value;
	}

	uint32_t clear_pw_len = 0;
	const char* p_clear_pw = NULL;

	if (pf_clear_pw) {
		clear_pw_len = msg_field_value_size(pf_clear_pw);
		p_clear_pw = (const char*)pf_clear_pw->value;
	}

	uint8_t result = login(fd_h,
			p_user, user_len,
			p_cred, cred_size,
			p_clear_pw, clear_pw_len);

	if (result != AS_OK) {
		log_login_failure(fd_h, result, p_user, user_len);
		send_result_msg(fd_h, result);
	}
	// else - either handed off for LDAP login or sent "local" session token.
}


//==========================================================
// Security commands - authentication.
//

//------------------------------------------------
// Handle 'authenticate' command. We expect one of
// these as the first transaction on every socket,
// then never again on the socket.
//
void
cmd_authenticate(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);

	if (p_filter->p_uinfo != NULL) {
		cf_mutex_unlock(&p_filter->lock);
		// Not bothering to log this.
		send_result_msg(fd_h, AS_SEC_ERR_STATE);
		return;
	}

	cf_mutex_unlock(&p_filter->lock);

	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];

	uint32_t user_len;
	const char* p_user;
	char tls_user[MAX_USER_SIZE];

	if (pf_user) {
		user_len = msg_field_value_size(pf_user);
		p_user = (const char*)pf_user->value;
	}
	else { // PKI authentication ...
		user_len = sizeof(tls_user);
		p_user = tls_user;

		if (! tls_get_peer_name(&fd_h->sock, tls_user, &user_len)) {
			log_auth_failure(fd_h, AS_SEC_ERR_USER, req_fields);
			send_result_msg(fd_h, AS_SEC_ERR_USER);
			return;
		}
	}

	as_sec_msg_field* pf_tok = req_fields[AS_SEC_FIELD_SESSION_TOKEN];

	if (! pf_tok) {
		log_auth_failure(fd_h, AS_SEC_ERR_CREDENTIAL, req_fields);
		send_result_msg(fd_h, AS_SEC_ERR_CREDENTIAL);
		return;
	}

	if (user_len == 0 || user_len >= MAX_USER_SIZE) {
		log_auth_failure(fd_h, AS_SEC_ERR_USER, req_fields);
		send_result_msg(fd_h, AS_SEC_ERR_USER);
		return;
	}

	uint32_t tok_size = msg_field_value_size(pf_tok);

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uinfo* p_uinfo = NULL;

	uint8_t result = authenticate(ukey, user_len, pf_tok->value, tok_size,
			&p_uinfo);

	if (result == AS_OK) {
		if (! as_security_ip_addr_ok(fd_h, uinfo_roles(p_uinfo),
				uinfo_num_roles(p_uinfo))) {
			cf_rc_releaseandfree(p_uinfo);
			log_auth_failure(fd_h, AS_SEC_ERR_NOT_WHITELISTED, req_fields);
			send_result_msg(fd_h, AS_SEC_ERR_NOT_WHITELISTED);
			return;
		}

		qinfo* p_qinfo = NULL;

		if (g_config.sec_cfg.quotas_enabled) {
			cf_rchash_get(g_quotas, ukey, (void**)&p_qinfo);
			cf_assert(p_qinfo != NULL, AS_SECURITY, "null qinfo");

			// Note that we keep the ref count on p_qinfo for filter.
		}

		conn_tracker_update_n_conns(ukey, 1);

		cf_mutex_lock(&p_filter->lock);
		p_filter->addr_ok = true;
		p_filter->p_qinfo = p_qinfo;
		p_filter->p_uinfo = p_uinfo;
		p_filter->user_len = user_len;
		memcpy(p_filter->user, p_user, user_len);
		cf_mutex_unlock(&p_filter->lock);

		log_auth_success(fd_h, req_fields);
	}
	else {
		log_auth_failure(fd_h, result, req_fields);
	}

	send_result_msg(fd_h, result);
}


//==========================================================
// Security commands - modify/query user info.
//

//------------------------------------------------
// Handle 'create-user' command. Requires user-
// admin permission on the socket.
//
void
cmd_create_user(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "create user", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];
	as_sec_msg_field* pf_password = req_fields[AS_SEC_FIELD_PASSWORD];
	as_sec_msg_field* pf_roles = req_fields[AS_SEC_FIELD_ROLES];

	if (! pf_user) {
		send_result_msg(fd_h, AS_SEC_ERR_USER);
		return;
	}

	if (! pf_password) {
		send_result_msg(fd_h, AS_SEC_ERR_PASSWORD);
		return;
	}

	if (! pf_roles) {
		send_result_msg(fd_h, AS_SEC_ERR_ROLE);
		return;
	}

	uint32_t user_len = msg_field_value_size(pf_user);
	uint32_t password_len = msg_field_value_size(pf_password);
	uint32_t roles_size = msg_field_value_size(pf_roles);

	send_result_msg(fd_h, create_user(
			(const char*)pf_user->value, user_len,
			(const char*)pf_password->value, password_len,
			pf_roles->value, roles_size));
}

//------------------------------------------------
// Handle 'drop-user' command. Requires user-
// admin permission on the socket.
//
void
cmd_drop_user(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "drop user", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];

	if (! pf_user) {
		send_result_msg(fd_h, AS_SEC_ERR_USER);
		return;
	}

	uint32_t user_len = msg_field_value_size(pf_user);

	send_result_msg(fd_h, drop_user(
			(const char*)pf_user->value, user_len));
}

//------------------------------------------------
// Handle 'set-password' command. Requires user-
// admin permission on the socket.
//
void
cmd_set_password(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "set password", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];
	as_sec_msg_field* pf_password = req_fields[AS_SEC_FIELD_PASSWORD];

	if (! pf_user) {
		send_result_msg(fd_h, AS_SEC_ERR_USER);
		return;
	}

	if (! pf_password) {
		send_result_msg(fd_h, AS_SEC_ERR_PASSWORD);
		return;
	}

	uint32_t user_len = msg_field_value_size(pf_user);
	uint32_t password_len = msg_field_value_size(pf_password);

	send_result_msg(fd_h, set_password(
			(const char*)pf_user->value, user_len,
			(const char*)pf_password->value, password_len));
}

//------------------------------------------------
// Handle 'change-password' command. Socket need
// not be authenticated, since this may change an
// expired password.
//
void
cmd_change_password(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];
	as_sec_msg_field* pf_old_password = req_fields[AS_SEC_FIELD_OLD_PASSWORD];
	as_sec_msg_field* pf_password = req_fields[AS_SEC_FIELD_PASSWORD];

	// Note - OK means operation attempt is allowed - it's not the result of the
	// operation itself.
	log_user_admin(fd_h, AS_OK, "change password", req_fields);

	if (! pf_user) {
		send_result_msg(fd_h, AS_SEC_ERR_USER);
		return;
	}

	if (! (pf_old_password && pf_password)) {
		send_result_msg(fd_h, AS_SEC_ERR_PASSWORD);
		return;
	}

	uint32_t user_len = msg_field_value_size(pf_user);
	uint32_t old_password_len = msg_field_value_size(pf_old_password);
	uint32_t password_len = msg_field_value_size(pf_password);

	send_result_msg(fd_h, change_password(
			(const char*)pf_user->value, user_len,
			(const char*)pf_old_password->value, old_password_len,
			(const char*)pf_password->value, password_len));
}

//------------------------------------------------
// Handle 'grant-roles' command. Requires user-
// admin permission on the socket.
//
void
cmd_grant_roles(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "grant roles", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];
	as_sec_msg_field* pf_roles = req_fields[AS_SEC_FIELD_ROLES];

	if (! pf_user) {
		send_result_msg(fd_h, AS_SEC_ERR_USER);
		return;
	}

	if (! pf_roles) {
		send_result_msg(fd_h, AS_SEC_ERR_ROLE);
		return;
	}

	uint32_t user_len = msg_field_value_size(pf_user);
	uint32_t roles_size = msg_field_value_size(pf_roles);

	send_result_msg(fd_h, grant_roles(
			(const char*)pf_user->value, user_len,
			pf_roles->value, roles_size));
}

//------------------------------------------------
// Handle 'revoke-roles' command. Requires user-
// admin permission on the socket.
//
void
cmd_revoke_roles(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "revoke roles", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];
	as_sec_msg_field* pf_roles = req_fields[AS_SEC_FIELD_ROLES];

	if (! pf_user) {
		send_result_msg(fd_h, AS_SEC_ERR_USER);
		return;
	}

	if (! pf_roles) {
		send_result_msg(fd_h, AS_SEC_ERR_ROLE);
		return;
	}

	uint32_t user_len = msg_field_value_size(pf_user);
	uint32_t roles_size = msg_field_value_size(pf_roles);

	send_result_msg(fd_h, revoke_roles(
			(const char*)pf_user->value, user_len,
			pf_roles->value, roles_size));
}

//------------------------------------------------
// Handle 'query-users' command. Requires user-
// admin permission on the socket, or that user is
// querying self.
//
void
cmd_query_users(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);

	if (p_filter->p_uinfo == NULL) {
		cf_mutex_unlock(&p_filter->lock);
		log_user_admin(fd_h, AS_SEC_ERR_NOT_AUTHENTICATED, "query users",
				req_fields);
		send_result_msg(fd_h, AS_SEC_ERR_NOT_AUTHENTICATED);
		return;
	}

	cf_mutex_unlock(&p_filter->lock);

	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];

	const char* p_user = NULL;
	uint32_t user_len = 0;

	// User field is optional - no user means do all.
	if (pf_user) {
		p_user = (const char*)pf_user->value;
		user_len = msg_field_value_size(pf_user);
	}

	cf_mutex_lock(&p_filter->lock);

	// If socket's & message's users don't match, and not admin, disallow.
	if (! (p_filter->user_len == user_len &&
			memcmp(p_filter->user, p_user, user_len) == 0)
		&&
			! uinfo_is_user_admin(p_filter->p_uinfo)) {
		cf_mutex_unlock(&p_filter->lock);
		log_user_admin(fd_h, AS_SEC_ERR_ROLE_VIOLATION, "query users",
				req_fields);
		send_result_msg(fd_h, AS_SEC_ERR_ROLE_VIOLATION);
		return;
	}

	cf_mutex_unlock(&p_filter->lock);

	log_user_admin(fd_h, AS_OK, "query users", req_fields);

	cf_buf_builder* p_bb = resp_bb_create();
	uint8_t result = query_users(p_user, user_len, &p_bb);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
	}
	else {
		// TODO - break up response into reasonable size proto messages.
		if (send_resp_bb(fd_h, p_bb)) {
			send_result_msg(fd_h, AS_SEC_OK_LAST);
		}
	}

	cf_buf_builder_free(p_bb);
}


//==========================================================
// Security commands - modify/query role info.
//

//------------------------------------------------
// Handle 'create-role' command. Requires user-
// admin permission on the socket.
//
void
cmd_create_role(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "create role", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_role = req_fields[AS_SEC_FIELD_ROLE];
	as_sec_msg_field* pf_privs = req_fields[AS_SEC_FIELD_PRIVS];
	as_sec_msg_field* pf_whitelist = req_fields[AS_SEC_FIELD_WHITELIST];
	as_sec_msg_field* pf_read_quota = req_fields[AS_SEC_FIELD_READ_QUOTA];
	as_sec_msg_field* pf_write_quota = req_fields[AS_SEC_FIELD_WRITE_QUOTA];

	if (! pf_role) {
		send_result_msg(fd_h, AS_SEC_ERR_ROLE);
		return;
	}

	if (! pf_privs && ! pf_whitelist && ! pf_read_quota && ! pf_write_quota) {
		send_result_msg(fd_h, AS_SEC_ERR_PRIVILEGE); // adequate error code
		return;
	}

	if ((pf_read_quota || pf_write_quota) &&
			! g_config.sec_cfg.quotas_enabled) {
		send_result_msg(fd_h, AS_SEC_ERR_QUOTAS_NOT_ENABLED);
		return;
	}

	uint32_t role_len = msg_field_value_size(pf_role);

	uint8_t* p_privs = NULL;
	uint32_t privs_len = 0;

	if (pf_privs) {
		p_privs = pf_privs->value;
		privs_len = msg_field_value_size(pf_privs);
	}

	const char* p_whitelist = NULL;
	uint32_t whitelist_len = 0;

	if (pf_whitelist) {
		p_whitelist = (const char*)pf_whitelist->value;
		whitelist_len = msg_field_value_size(pf_whitelist);
	}

	uint32_t read_quota = NO_QUOTA;

	if (pf_read_quota &&
			! msg_field_uint32_value(pf_read_quota, &read_quota)) {
		send_result_msg(fd_h, AS_SEC_ERR_QUOTA);
		return;
	}

	uint32_t write_quota = NO_QUOTA;

	if (pf_write_quota &&
			! msg_field_uint32_value(pf_write_quota, &write_quota)) {
		send_result_msg(fd_h, AS_SEC_ERR_QUOTA);
		return;
	}

	send_result_msg(fd_h, create_role(
			(const char*)pf_role->value, role_len,
			p_privs, privs_len,
			p_whitelist, whitelist_len,
			read_quota, write_quota));
}

//------------------------------------------------
// Handle 'delete-role' command. Requires user-
// admin permission on the socket.
//
void
cmd_delete_role(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "delete role", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_role = req_fields[AS_SEC_FIELD_ROLE];

	if (! pf_role) {
		send_result_msg(fd_h, AS_SEC_ERR_ROLE);
		return;
	}

	uint32_t role_len = msg_field_value_size(pf_role);

	send_result_msg(fd_h, delete_role(
			(const char*)pf_role->value, role_len));
}

//------------------------------------------------
// Handle 'add-privs' command. Requires user-admin
// permission on the socket.
//
void
cmd_add_privs(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "add privs", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_role = req_fields[AS_SEC_FIELD_ROLE];
	as_sec_msg_field* pf_privs = req_fields[AS_SEC_FIELD_PRIVS];

	if (! pf_role) {
		send_result_msg(fd_h, AS_SEC_ERR_ROLE);
		return;
	}

	if (! pf_privs) {
		send_result_msg(fd_h, AS_SEC_ERR_PRIVILEGE);
		return;
	}

	uint32_t role_len = msg_field_value_size(pf_role);
	uint32_t privs_len = msg_field_value_size(pf_privs);

	send_result_msg(fd_h, add_privs(
			(const char*)pf_role->value, role_len,
			pf_privs->value, privs_len));
}

//------------------------------------------------
// Handle 'delete-privs' command. Requires user-
// admin permission on the socket.
//
void
cmd_delete_privs(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "delete privs", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_role = req_fields[AS_SEC_FIELD_ROLE];
	as_sec_msg_field* pf_privs = req_fields[AS_SEC_FIELD_PRIVS];

	if (! pf_role) {
		send_result_msg(fd_h, AS_SEC_ERR_ROLE);
		return;
	}

	if (! pf_privs) {
		send_result_msg(fd_h, AS_SEC_ERR_PRIVILEGE);
		return;
	}

	uint32_t role_len = msg_field_value_size(pf_role);
	uint32_t privs_len = msg_field_value_size(pf_privs);

	send_result_msg(fd_h, delete_privs(
			(const char*)pf_role->value, role_len,
			pf_privs->value, privs_len));
}

//------------------------------------------------
// Handle 'set-whitelist' command. Requires
// user-admin permission on the socket.
//
void
cmd_set_whitelist(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = admin_permission_check(fd_h);

	log_user_admin(fd_h, result, "set whitelist", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_role = req_fields[AS_SEC_FIELD_ROLE];
	as_sec_msg_field* pf_whitelist = req_fields[AS_SEC_FIELD_WHITELIST];

	if (! pf_role) {
		send_result_msg(fd_h, AS_SEC_ERR_ROLE);
		return;
	}

	uint32_t role_len = msg_field_value_size(pf_role);

	const char* p_whitelist = NULL;
	uint32_t whitelist_len = 0;

	if (pf_whitelist) {
		p_whitelist = (const char*)pf_whitelist->value;
		whitelist_len = msg_field_value_size(pf_whitelist);
	}
	// else - remove whitelist from role.

	send_result_msg(fd_h, set_whitelist(
			(const char*)pf_role->value, role_len,
			p_whitelist, whitelist_len));
}

//------------------------------------------------
// Handle 'set-quota' command. Requires user-admin
// permission on the socket.
//
void
cmd_set_quotas(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	uint8_t result = permission_check(fd_h, 0, 0, PERM_USER_ADMIN);

	log_user_admin(fd_h, result, "set quotas", req_fields);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
		return;
	}

	as_sec_msg_field* pf_role = req_fields[AS_SEC_FIELD_ROLE];
	as_sec_msg_field* pf_read_quota = req_fields[AS_SEC_FIELD_READ_QUOTA];
	as_sec_msg_field* pf_write_quota = req_fields[AS_SEC_FIELD_WRITE_QUOTA];

	if (! pf_role) {
		send_result_msg(fd_h, AS_SEC_ERR_ROLE);
		return;
	}

	if (! pf_read_quota && ! pf_write_quota) {
		send_result_msg(fd_h, AS_SEC_ERR_QUOTA);
		return;
	}

	if (! g_config.sec_cfg.quotas_enabled) {
		send_result_msg(fd_h, AS_SEC_ERR_QUOTAS_NOT_ENABLED);
		return;
	}

	uint32_t role_len = msg_field_value_size(pf_role);

	uint32_t read_quota = NO_QUOTA;

	if (pf_read_quota &&
			! msg_field_uint32_value(pf_read_quota, &read_quota)) {
		send_result_msg(fd_h, AS_SEC_ERR_QUOTA);
		return;
	}

	uint32_t write_quota = NO_QUOTA;

	if (pf_write_quota &&
			! msg_field_uint32_value(pf_write_quota, &write_quota)) {
		send_result_msg(fd_h, AS_SEC_ERR_QUOTA);
		return;
	}

	send_result_msg(fd_h, set_quotas(
			(const char*)pf_role->value, role_len, read_quota, write_quota));
}

//------------------------------------------------
// Handle 'query-roles' command. Requires user-
// admin permission on the socket, or that user
// has been granted role.
//
void
cmd_query_roles(as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);

	if (p_filter->p_uinfo == NULL) {
		cf_mutex_unlock(&p_filter->lock);
		log_user_admin(fd_h, AS_SEC_ERR_NOT_AUTHENTICATED, "query roles",
				req_fields);
		send_result_msg(fd_h, AS_SEC_ERR_NOT_AUTHENTICATED);
		return;
	}

	cf_mutex_unlock(&p_filter->lock);

	as_sec_msg_field* pf_role = req_fields[AS_SEC_FIELD_ROLE];

	const char* p_role = NULL;
	uint32_t role_len = 0;

	// Role field is optional - no role means do all.
	if (pf_role) {
		p_role = (const char*)pf_role->value;
		role_len = msg_field_value_size(pf_role);
	}

	cf_mutex_lock(&p_filter->lock);

	bool user_is_admin = uinfo_is_user_admin(p_filter->p_uinfo);
	bool user_has_role = false;

	if (p_role && ! user_is_admin) {
		char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

		memcpy(rkey, p_role, role_len);

		user_has_role = uinfo_has_role(p_filter->p_uinfo, rkey);
	}

	// If socket's user doesn't own role, and not admin, disallow.
	if (! (user_is_admin || user_has_role)) {
		cf_mutex_unlock(&p_filter->lock);
		log_user_admin(fd_h, AS_SEC_ERR_ROLE_VIOLATION, "query roles",
				req_fields);
		send_result_msg(fd_h, AS_SEC_ERR_ROLE_VIOLATION);
		return;
	}

	cf_mutex_unlock(&p_filter->lock);

	log_user_admin(fd_h, AS_OK, "query roles", req_fields);

	cf_buf_builder* p_bb = resp_bb_create();
	uint8_t result = query_roles(p_role, role_len, &p_bb);

	if (result != AS_OK) {
		send_result_msg(fd_h, result);
	}
	else {
		// TODO - break up response into reasonable size proto messages.
		if (send_resp_bb(fd_h, p_bb)) {
			send_result_msg(fd_h, AS_SEC_OK_LAST);
		}
	}

	cf_buf_builder_free(p_bb);
}


//==========================================================
// Response packing, using cf_buf_builder.
//

//------------------------------------------------
// Create a cf_buf_builder response.
//
cf_buf_builder*
resp_bb_create()
{
	cf_buf_builder* p_bb = cf_buf_builder_create(8 * 1024);

	cf_buf_builder_reserve(&p_bb, (int)sizeof(as_proto), NULL);

	return p_bb;
}

//------------------------------------------------
// Add an as_sec_msg to a cf_buf_builder response.
//
void
resp_bb_pack_sec_msg(cf_buf_builder** pp_bb, uint8_t result, uint8_t n_fields)
{
	as_sec_msg* p_sec_msg = NULL;

	cf_buf_builder_reserve(pp_bb, (int)sizeof(as_sec_msg),
			(uint8_t**)&p_sec_msg);

	memset((void*)p_sec_msg, 0, sizeof(as_sec_msg));

	p_sec_msg->scheme = AS_SEC_MSG_SCHEME;
	p_sec_msg->result = result;
	p_sec_msg->n_fields = n_fields;
}

//------------------------------------------------
// Add a single string as_sec_msg_field to a
// cf_buf_builder response.
//
void
resp_bb_pack_string_msg_field(cf_buf_builder** pp_bb, uint8_t id,
		const char* p_val, uint32_t len)
{
	uint32_t field_size = 1 + len;
	int pack_size = (int)(sizeof(uint32_t) + field_size);
	as_sec_msg_field* p_field = NULL;

	cf_buf_builder_reserve(pp_bb, pack_size, (uint8_t**)&p_field);

	p_field->size = field_size;
	p_field->id = id;
	memcpy(p_field->value, p_val, len);

	resp_msg_field_swap(p_field);
}

//------------------------------------------------
// Add a uint32_t as_sec_msg_field to a
// cf_buf_builder response.
//
void
resp_bb_pack_uint32_msg_field(cf_buf_builder** pp_bb, uint8_t id, uint32_t val)
{
	uint32_t field_size = 1 + sizeof(uint32_t);
	int pack_size = (int)(sizeof(uint32_t) + field_size);
	as_sec_msg_field* p_field = NULL;

	cf_buf_builder_reserve(pp_bb, pack_size, (uint8_t**)&p_field);

	p_field->size = field_size;
	p_field->id = id;
	*(uint32_t*)p_field->value = cf_swap_to_be32(val);

	resp_msg_field_swap(p_field);
}

//------------------------------------------------
// Add a roles list as_sec_msg_field to a
// cf_buf_builder response, and return a pointer
// where role names can be added.
//
uint8_t*
resp_bb_reserve_roles_msg_field(cf_buf_builder** pp_bb, uint32_t n_roles,
		uint32_t role_len_sum)
{
	uint32_t field_size = 1 + 1 + n_roles + role_len_sum;
	int pack_size = (int)(sizeof(uint32_t) + field_size);
	as_sec_msg_field* p_field = NULL;

	cf_buf_builder_reserve(pp_bb, pack_size, (uint8_t**)&p_field);

	p_field->size = field_size;
	p_field->id = AS_SEC_FIELD_ROLES;
	p_field->value[0] = (uint8_t)n_roles;

	resp_msg_field_swap(p_field);

	return p_field->value + 1;
}

//------------------------------------------------
// Add a role name.
//
uint8_t*
pack_role_name(uint8_t* p_write, const char* p_role, uint32_t role_len)
{
	*p_write++ = (uint8_t)role_len;
	memcpy(p_write, p_role, role_len);

	return p_write + role_len;
}

//------------------------------------------------
// Add a whitelist as_sec_msg_field to a
// cf_buf_builder response.
//
void
resp_bb_pack_whitelist_msg_field(cf_buf_builder** pp_bb, const char* whitelist)
{
	uint32_t whitelist_len = (uint32_t)strlen(whitelist);
	uint32_t field_size = 1 + whitelist_len;
	int pack_size = (int)(sizeof(uint32_t) + field_size);
	as_sec_msg_field* p_field = NULL;

	cf_buf_builder_reserve(pp_bb, pack_size, (uint8_t**)&p_field);

	p_field->size = field_size;
	p_field->id = AS_SEC_FIELD_WHITELIST;
	memcpy(p_field->value, whitelist, whitelist_len);

	resp_msg_field_swap(p_field);
}

//------------------------------------------------
// Pack a privilege (component of a privileges
// as_sec_msg_field) into specified buffer and
// return the packed size.
//
uint32_t
prepack_priv(const priv_code* p_priv, uint8_t* p_packed_priv)
{
	uint8_t* p_write = p_packed_priv;

	*p_write++ = p_priv->perm_code;

	if (is_global_scope_perm_code(p_priv->perm_code)) {
		return 1;
	}

	if (p_priv->ns_ix == NO_NS_IX) {
		*p_write++ = 0;
		*p_write++ = 0;
		return 3;
	}

	as_namespace* ns = g_config.namespaces[p_priv->ns_ix];
	uint8_t ns_len = (uint8_t)strlen(ns->name);

	*p_write++ = ns_len;
	memcpy(p_write, ns->name, ns_len);
	p_write += ns_len;

	if (p_priv->set_id == INVALID_SET_ID) {
		*p_write++ = 0;
		return (uint32_t)(p_write - p_packed_priv);
	}

	const char* set_name = as_namespace_get_set_name(ns, p_priv->set_id);
	uint8_t set_name_len = (uint8_t)strlen(set_name);

	*p_write++ = set_name_len;
	memcpy(p_write, set_name, set_name_len);
	p_write += set_name_len;

	return (uint32_t)(p_write - p_packed_priv);
}

//------------------------------------------------
// Add a privileges as_sec_msg_field to a
// cf_buf_builder response, and return a pointer
// where privileges can be added.
//
uint8_t*
resp_bb_reserve_privs_msg_field(cf_buf_builder** pp_bb, uint32_t n_privs,
		uint32_t priv_size_sum)
{
	uint32_t field_size = 1 + 1 + priv_size_sum;
	int pack_size = (int)(sizeof(uint32_t) + field_size);
	as_sec_msg_field* p_field = NULL;

	cf_buf_builder_reserve(pp_bb, pack_size, (uint8_t**)&p_field);

	p_field->size = field_size;
	p_field->id = AS_SEC_FIELD_PRIVS;
	p_field->value[0] = (uint8_t)n_privs;

	resp_msg_field_swap(p_field);

	return p_field->value + 1;
}

//------------------------------------------------
// Add a (pre-packed) privilege.
//
uint8_t*
pack_priv(uint8_t* p_write, const uint8_t* p_packed_priv,
		uint32_t packed_priv_size)
{
	memcpy(p_write, p_packed_priv, packed_priv_size);

	return p_write + packed_priv_size;
}

//------------------------------------------------
// Add a read/write info as_sec_msg_field to a
// cf_buf_builder response.
//
void
resp_bb_pack_rw_info_msg_field(cf_buf_builder** pp_bb, uint8_t id,
		uint32_t quota, uint32_t tps, uint32_t rps, uint32_t n_rps_zero)
{
	uint32_t field_size = 1 + 1 + (4 * sizeof(uint32_t));
	int pack_size = (int)(sizeof(uint32_t) + field_size);
	as_sec_msg_field* p_field = NULL;

	cf_buf_builder_reserve(pp_bb, pack_size, (uint8_t**)&p_field);

	p_field->size = field_size;
	p_field->id = id;

	uint8_t* at = p_field->value;

	*at++ = 4;

	uint32_t* at_uint32 = (uint32_t*)at;

	*at_uint32++ = cf_swap_to_be32(quota);
	*at_uint32++ = cf_swap_to_be32(tps);
	*at_uint32++ = cf_swap_to_be32(rps);
	*at_uint32   = cf_swap_to_be32(n_rps_zero);

	resp_msg_field_swap(p_field);
}


//==========================================================
// Generic security message field helpers.
//

//------------------------------------------------
// Validate security message field ID.
//
bool
is_valid_field_id(uint8_t id)
{
	return id < AS_SEC_FIELD_LAST_PLUS_1;
}

//------------------------------------------------
// Get security message field value size. Must
// already have swapped to host byte order.
//
uint32_t
msg_field_value_size(const as_sec_msg_field* p_field)
{
	return p_field->size - 1;
}

//------------------------------------------------
// Get security message field uint32_t value,
// swapped to host byte order. Must already have
// swapped size to host byte order.
//
bool
msg_field_uint32_value(as_sec_msg_field* p_field, uint32_t* p_value)
{
	if (msg_field_value_size(p_field) != 4) {
		return false;
	}

	*p_value = cf_swap_from_be32(*(uint32_t*)p_field->value);

	return true;
}

//------------------------------------------------
// Swap security message field members (size) to
// host byte order. Used early on request message.
//
void
req_msg_field_swap(as_sec_msg_field* p_field)
{
	p_field->size = cf_swap_from_be32(p_field->size);
}

//------------------------------------------------
// Swap security message field members (size) to
// network byte order. Used just before sending
// response message.
//
void
resp_msg_field_swap(as_sec_msg_field* p_field)
{
	p_field->size = cf_swap_to_be32(p_field->size);
}


//==========================================================
// Structured message field parsing.
//

//------------------------------------------------
// Is specified permission code mandatory global
// scope?
//
static inline bool
is_global_scope_perm_code(uint32_t perm_code)
{
	return perm_code < AS_SEC_PERM_CODE_LAST_GLOBAL_PLUS_1;
}

//------------------------------------------------
// Is specified permission code valid?
//
static inline bool
is_valid_perm_code(uint32_t perm_code)
{
	return perm_code < AS_SEC_PERM_CODE_LAST_GLOBAL_PLUS_1 ||
			(perm_code >= AS_SEC_PERM_CODE_FIRST_NON_GLOBAL &&
					perm_code < AS_SEC_PERM_CODE_LAST_PLUS_1);
}

//------------------------------------------------
// Parse a security message privileges list to
// collect priv_codes.
//
uint8_t
parse_privs(const uint8_t* p_privs, uint32_t privs_size, priv_def** pp_privs,
		uint32_t* p_num_privs)
{
	if (privs_size == 0) {
		cf_warning(AS_SECURITY, "parse privs - field size 0");
		return AS_SEC_ERR_FIELD;
	}

	const uint8_t* p_read = p_privs;
	const uint8_t* p_end = p_privs + privs_size;

	uint32_t num_privs = (uint32_t)*p_read++;

	if (num_privs == 0) {
		cf_warning(AS_SECURITY, "parse privs - no privs");
		return AS_SEC_ERR_PRIVILEGE;
	}

	priv_def* privs = cf_malloc(num_privs * sizeof(priv_def));

	for (uint32_t j = 0; j < num_privs; j++) {
		if (p_read >= p_end) {
			cf_warning(AS_SECURITY, "parse privs - incomplete");
			cf_free(privs);
			return AS_SEC_ERR_FIELD;
		}

		priv_def* p_priv_def = &privs[j];
		uint8_t m = *p_read++;

		if (! is_valid_perm_code(m)) {
			cf_warning(AS_SECURITY, "parse privs - invalid perm code %u", m);
			cf_free(privs);
			return AS_SEC_ERR_PRIVILEGE;
		}

		p_priv_def->perm_code = m;

		if (is_global_scope_perm_code(p_priv_def->perm_code)) {
			// Mandatory global scope - no namespace or set in wire protocol.
			p_priv_def->ns_name[0] = 0;
			p_priv_def->set_name[0] = 0;

			continue;
		}

		if (p_read >= p_end) {
			cf_warning(AS_SECURITY, "parse privs - incomplete");
			cf_free(privs);
			return AS_SEC_ERR_FIELD;
		}

		uint32_t ns_len = (uint32_t)*p_read++;
		const char* p_ns = (const char*)p_read;

		p_read += ns_len;

		if (p_read >= p_end) {
			cf_warning(AS_SECURITY, "parse privs - incomplete");
			cf_free(privs);
			return AS_SEC_ERR_FIELD;
		}

		uint32_t set_len = (uint32_t)*p_read++;
		const char* p_set = (const char*)p_read;

		p_read += set_len;

		if (p_read > p_end) {
			cf_warning(AS_SECURITY, "parse privs - incomplete");
			cf_free(privs);
			return AS_SEC_ERR_FIELD;
		}

		if (ns_len == 0) {
			if (set_len != 0) {
				cf_warning(AS_SECURITY, "parse privs - extraneous set");
				cf_free(privs);
				return AS_SEC_ERR_PRIVILEGE;
			}

			// Global scope - no namespace or set.
			p_priv_def->ns_name[0] = 0;
			p_priv_def->set_name[0] = 0;

			continue;
		}

		if (ns_len >= AS_ID_NAMESPACE_SZ) {
			cf_warning(AS_SECURITY, "parse privs - invalid ns name");
			cf_free(privs);
			return AS_ERR_NAMESPACE;
		}

		memcpy(p_priv_def->ns_name, p_ns, ns_len);
		p_priv_def->ns_name[ns_len] = 0;

		if (set_len == 0) {
			// Namespace scope - no set.
			p_priv_def->set_name[0] = 0;

			continue;
		}

		if (set_len >= AS_SET_NAME_MAX_SIZE) {
			cf_warning(AS_SECURITY, "parse privs - invalid set name");
			cf_free(privs);
			return AS_SEC_ERR_PRIVILEGE;
		}

		memcpy(p_priv_def->set_name, p_set, set_len);
		p_priv_def->set_name[set_len] = 0;
	}

	if (p_read != p_end) {
		cf_warning(AS_SECURITY, "parse privs - extraneous bytes");
		cf_free(privs);
		return AS_SEC_ERR_FIELD;
	}

	*pp_privs = privs;
	*p_num_privs = num_privs;

	return AS_OK;
}

//------------------------------------------------
// Parse a security message role list to collect
// roles, returned as an allocated block of null-
// terminated (but not padded) role names.
//
uint8_t
parse_roles(const uint8_t* p_roles, uint32_t roles_size, char** pp_roles,
		uint32_t* p_num_roles)
{
	if (roles_size == 0) {
		cf_warning(AS_SECURITY, "parse roles - field size 0");
		return AS_SEC_ERR_FIELD;
	}

	const uint8_t* p_read = p_roles;
	const uint8_t* p_end = p_roles + roles_size;

	uint32_t num_roles = (uint32_t)*p_read++;

	if (num_roles == 0) {
		if (p_read != p_end) {
			cf_warning(AS_SECURITY, "parse roles - extraneous bytes");
			return AS_SEC_ERR_FIELD;
		}

		return AS_OK;
	}

	char* roles = cf_malloc(num_roles * MAX_ROLE_NAME_SIZE);
	char* role = roles;

	for (uint32_t j = 0; j < num_roles; j++) {
		if (p_read >= p_end) {
			cf_warning(AS_SECURITY, "parse roles - incomplete");
			cf_free(roles);
			return AS_SEC_ERR_FIELD;
		}

		uint32_t role_len = (uint32_t)*p_read++;
		const char* p_role = (const char*)p_read;

		p_read += role_len;

		if (p_read > p_end) {
			cf_warning(AS_SECURITY, "parse roles - incomplete");
			cf_free(roles);
			return AS_SEC_ERR_FIELD;
		}

		if (role_len >= MAX_ROLE_NAME_SIZE) {
			cf_warning(AS_SECURITY, "parse roles - bad role len %u", role_len);
			cf_free(roles);
			return AS_SEC_ERR_ROLE;
		}

		memcpy(role, p_role, role_len);
		role[role_len] = 0;
		role += MAX_ROLE_NAME_SIZE;
	}

	if (p_read != p_end) {
		cf_warning(AS_SECURITY, "parse roles - extraneous bytes");
		cf_free(roles);
		return AS_SEC_ERR_FIELD;
	}

	*pp_roles = roles;
	*p_num_roles = num_roles;

	return AS_OK;
}


//==========================================================
// Command helpers - login.
//

//------------------------------------------------
// Check user credentials. If ok, return session
// token. Handles both internal and external
// users. For external users, token is returned
// asynchronously, after authentication by
// external server.
//
uint8_t
login(as_file_handle* fd_h, const char* p_user, uint32_t user_len,
		const uint8_t* p_cred, uint32_t cred_size, const char* p_clear_pw,
		uint32_t clear_pw_len)
{
	if (user_len == 0 || user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "login - bad user len %u", user_len);
		return AS_SEC_ERR_USER;
	}

	if (p_cred && cred_size != PASSWORD_LEN) {
		cf_warning(AS_SECURITY, "login - bad cred size %u", cred_size);
		return AS_SEC_ERR_CREDENTIAL;
	}

	if (p_clear_pw &&
			(clear_pw_len == 0 || clear_pw_len > MAX_CLEAR_PASSWORD_LEN)) {
		cf_warning(AS_SECURITY, "login - bad clear password len %u",
				clear_pw_len);
		return AS_SEC_ERR_PASSWORD;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uinfo* p_uinfo = NULL;

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) != CF_RCHASH_OK) {
		if (p_clear_pw) {
			return as_ldap_login(fd_h, p_user, user_len, p_clear_pw,
					clear_pw_len);
		}

		cf_warning(AS_SECURITY, "login - internal user not found");
		return AS_SEC_ERR_USER;
	}

	// User with no password - external user.
	if (p_clear_pw) {
		if (! uinfo_password_is_empty(p_uinfo)) {
			cf_warning(AS_SECURITY, "login - internal user but external mode");
			cf_rc_releaseandfree(p_uinfo);
			return AS_SEC_ERR_USER;
		}

		cf_rc_releaseandfree(p_uinfo);
		return as_ldap_login(fd_h, p_user, user_len, p_clear_pw, clear_pw_len);
	}

	// Internal user with password - credential must match.
	if (uinfo_password_is_empty(p_uinfo) || (p_cred &&
			memcmp(uinfo_password(p_uinfo), p_cred, PASSWORD_LEN) != 0)) {
		cf_warning(AS_SECURITY, "login - internal user credential mismatch");
		cf_rc_releaseandfree(p_uinfo);
		return AS_SEC_ERR_CREDENTIAL;
	}

	// Internal user with matching password hash - respond with token.

	if (! as_security_ip_addr_ok(fd_h, uinfo_roles(p_uinfo),
			uinfo_num_roles(p_uinfo))) {
		cf_warning(AS_SECURITY, "login - internal user not whitelisted");
		cf_rc_releaseandfree(p_uinfo);
		return AS_SEC_ERR_NOT_WHITELISTED;
	}

	qinfo* p_qinfo = NULL;

	if (g_config.sec_cfg.quotas_enabled) {
		cf_rchash_get(g_quotas, ukey, (void**)&p_qinfo);
		cf_assert(p_qinfo != NULL, AS_SECURITY, "null qinfo");

		// Note that we keep the ref count on p_qinfo for filter.
	}

	conn_tracker_update_n_conns(ukey, 1);

	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);
	p_filter->addr_ok = true;
	p_filter->p_qinfo = p_qinfo;
	p_filter->p_uinfo = p_uinfo;
	p_filter->user_len = user_len;
	memcpy(p_filter->user, p_user, user_len);
	cf_mutex_unlock(&p_filter->lock);

	// Note that we keep the ref count on p_uinfo.

	// Internal login success. (Exclude roles - not part of this transaction.)
	log_login_success(fd_h, p_user, user_len, NULL, 0);

	// Create token and respond.

	uint32_t token_size = 0;
	uint8_t* token = as_session_token_generate(p_user, user_len, &token_size);

	send_resp_token(fd_h, token, token_size, g_config.sec_cfg.session_ttl);
	cf_free(token);

	return AS_OK;
}


//==========================================================
// Command helpers - authentication.
//

//------------------------------------------------
// Validate session token and return uinfo.
//
uint8_t
authenticate(const char* ukey, uint32_t user_len, const uint8_t* p_tok,
		uint32_t tok_size, uinfo** pp_uinfo)
{
	uinfo* p_uinfo = NULL;

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "authenticate-session - user not found");
		return AS_SEC_ERR_USER;
	}

	uint8_t result = as_session_token_is_valid(ukey, user_len, p_tok, tok_size);

	// TODO - roll into general error handler below when development is done?
	if (result == AS_SEC_ERR_EXPIRED_SESSION) {
		cf_warning(AS_SECURITY, "authenticate-session - expired token");
		cf_rc_releaseandfree(p_uinfo);
		return AS_SEC_ERR_EXPIRED_SESSION;
	}

	if (result != AS_OK) {
		cf_warning(AS_SECURITY, "authenticate-session - invalid token");
		cf_rc_releaseandfree(p_uinfo);
		return result;
	}

	// Note that we keep the ref count on p_uinfo.
	*pp_uinfo = p_uinfo;

	return AS_OK;
}


//==========================================================
// Command helpers - modify/query user info.
//

//------------------------------------------------
// Add a unique user.
//
uint8_t
create_user(const char* p_user, uint32_t user_len, const char* p_password,
		uint32_t password_len, const uint8_t* p_roles, uint32_t roles_size)
{
	if (user_len == 0 || user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "create user - bad user len %u", user_len);
		return AS_SEC_ERR_USER;
	}

	// In scheme 0, password == credential of known size.
	if (password_len != PASSWORD_LEN) {
		cf_warning(AS_SECURITY, "create user - bad password len %u",
				password_len);
		return AS_SEC_ERR_PASSWORD;
	}

	char* roles = NULL;
	uint32_t num_roles = 0;
	uint8_t result = parse_roles(p_roles, roles_size, &roles, &num_roles);

	if (result != AS_OK) {
		cf_warning(AS_SECURITY, "create user - bad roles");
		return result;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	if (cf_rchash_get(g_users, ukey, NULL) == CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "create user - user already exists");

		if (roles) {
			cf_free(roles);
		}

		return AS_SEC_ERR_USER_EXISTS;
	}

	smd_add_password(p_user, user_len, p_password, password_len);

	char* role = roles;

	for (uint32_t n = 0; n < num_roles; n++) {
		smd_add_role(p_user, user_len, role);
		role += MAX_ROLE_NAME_SIZE;
	}

	if (roles) {
		cf_free(roles);
	}

	return AS_OK;
}

//------------------------------------------------
// Delete a user.
//
uint8_t
drop_user(const char* p_user, uint32_t user_len)
{
	if (user_len == 0 || user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "drop user - bad user len %u", user_len);
		return AS_SEC_ERR_USER;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uinfo* p_uinfo = NULL;

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "drop user - user not found");
		return AS_SEC_ERR_USER;
	}

	smd_delete_password(p_user, user_len);

	uint32_t num_roles = uinfo_num_roles(p_uinfo);
	const char* role = uinfo_roles(p_uinfo);

	// Just to clean these out of the system metadata...
	for (uint32_t n = 0; n < num_roles; n++) {
		smd_delete_role(p_user, user_len, role);
		role = uinfo_next_role(role);
	}

	cf_rc_releaseandfree(p_uinfo);

	return AS_OK;
}

//------------------------------------------------
// Set a user's password.
//
uint8_t
set_password(const char* p_user, uint32_t user_len, const char* p_password,
		uint32_t password_len)
{
	if (user_len == 0 || user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "set password - bad user len %u", user_len);
		return AS_SEC_ERR_USER;
	}

	// In scheme 0, password == credential of known size.
	if (password_len != PASSWORD_LEN) {
		cf_warning(AS_SECURITY, "set password - bad password len %u",
				password_len);
		return AS_SEC_ERR_PASSWORD;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	if (cf_rchash_get(g_users, ukey, NULL) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "set password - user not found");
		return AS_SEC_ERR_USER;
	}

	smd_add_password(p_user, user_len, p_password, password_len);

	return AS_OK;
}

//------------------------------------------------
// Change a user's password.
//
uint8_t
change_password(const char* p_user, uint32_t user_len,
		const char* p_old_password, uint32_t old_password_len,
		const char* p_password, uint32_t password_len)
{
	if (user_len == 0 || user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "change password - bad user len %u", user_len);
		return AS_SEC_ERR_USER;
	}

	// In scheme 0, password == credential of known size.
	if (old_password_len != PASSWORD_LEN) {
		cf_warning(AS_SECURITY, "change password - bad old password len %u",
				old_password_len);
		return AS_SEC_ERR_PASSWORD;
	}

	// In scheme 0, password == credential of known size.
	if (password_len != PASSWORD_LEN) {
		cf_warning(AS_SECURITY, "change password - bad password len %u",
				password_len);
		return AS_SEC_ERR_PASSWORD;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uinfo* p_uinfo = NULL;

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "change password - user not found");
		return AS_SEC_ERR_USER;
	}

	// In scheme 0, password == credential.
	if (uinfo_password_is_empty(p_uinfo) ||
			memcmp(uinfo_password(p_uinfo), p_old_password,
					PASSWORD_LEN) != 0) {
		cf_warning(AS_SECURITY, "change password - old password mismatch");
		cf_rc_releaseandfree(p_uinfo);
		return AS_SEC_ERR_PASSWORD;
	}

	cf_rc_releaseandfree(p_uinfo);
	smd_add_password(p_user, user_len, p_password, password_len);

	return AS_OK;
}

//------------------------------------------------
// Grant (more) roles to a user.
//
uint8_t
grant_roles(const char* p_user, uint32_t user_len, const uint8_t* p_roles,
		uint32_t roles_size)
{
	if (user_len == 0 || user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "grant roles - bad user len %u", user_len);
		return AS_SEC_ERR_USER;
	}

	char* roles = NULL;
	uint32_t num_roles = 0;
	uint8_t result = parse_roles(p_roles, roles_size, &roles, &num_roles);

	if (result != AS_OK) {
		cf_warning(AS_SECURITY, "grant roles - bad roles");
		return result;
	}

	if (num_roles == 0) {
		cf_warning(AS_SECURITY, "grant roles - no roles");
		return AS_SEC_ERR_ROLE;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	if (cf_rchash_get(g_users, ukey, NULL) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "grant roles - user not found");
		cf_free(roles);
		return AS_SEC_ERR_USER;
	}

	char* role = roles;

	for (uint32_t n = 0; n < num_roles; n++) {
		smd_add_role(p_user, user_len, role);
		role += MAX_ROLE_NAME_SIZE;
	}

	cf_free(roles);

	return AS_OK;
}

//------------------------------------------------
// Remove roles from a user.
//
uint8_t
revoke_roles(const char* p_user, uint32_t user_len, const uint8_t* p_roles,
		uint32_t roles_size)
{
	if (user_len == 0 || user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "revoke roles - bad user len %u", user_len);
		return AS_SEC_ERR_USER;
	}

	char* roles = NULL;
	uint32_t num_roles = 0;
	uint8_t result = parse_roles(p_roles, roles_size, &roles, &num_roles);

	if (result != AS_OK) {
		cf_warning(AS_SECURITY, "revoke roles - bad roles");
		return result;
	}

	if (num_roles == 0) {
		cf_warning(AS_SECURITY, "revoke roles - no roles");
		return AS_SEC_ERR_ROLE;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	if (cf_rchash_get(g_users, ukey, NULL) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "revoke roles - user not found");
		cf_free(roles);
		return AS_SEC_ERR_USER;
	}

	char* role = roles;

	for (uint32_t n = 0; n < num_roles; n++) {
		smd_delete_role(p_user, user_len, role);
		role += MAX_ROLE_NAME_SIZE;
	}

	cf_free(roles);

	return AS_OK;
}

//------------------------------------------------
// Pack one or many security messages, each with
// user & roles fields into the cf_buf_builder.
//
uint8_t
query_users(const char* p_user, uint32_t user_len, cf_buf_builder** pp_bb)
{
	if (! p_user) {
		// Query all users.
		cf_mutex_lock(&g_query_users_lock);

		uint32_t num_users = cf_rchash_get_size(g_users);
		const char* ukeys[num_users];
		udata_sort_key ukey;

		ukey.pp_key = ukeys;
		ukey.num_keys = 0;

		cf_rchash_reduce(g_users, collect_sort_keys_reduce_fn, (void*)&ukey);

		for (uint32_t i = 0; i < num_users; i++) {
			uinfo* p_uinfo = NULL;

			if (cf_rchash_get(g_users, ukeys[i], (void**)&p_uinfo) !=
					CF_RCHASH_OK) {
				cf_crash(AS_SECURITY, "query users failed - user not found");
			}

			query_user(ukeys[i], strlen(ukeys[i]), p_uinfo, pp_bb);
			cf_rc_releaseandfree(p_uinfo);
		}

		cf_mutex_unlock(&g_query_users_lock);
		return AS_OK;
	}

	if (user_len == 0 || user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "query users - bad user len %u", user_len);
		return AS_SEC_ERR_USER;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uinfo* p_uinfo = NULL;

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "query users - user not found");
		return AS_SEC_ERR_USER;
	}

	query_user(ukey, user_len, p_uinfo, pp_bb);
	cf_rc_releaseandfree(p_uinfo);

	return AS_OK;
}

//------------------------------------------------
// Pack one security message with user & roles
// fields into the cf_buf_builder.
//
void
query_user(const char* ukey, uint32_t user_len, const uinfo* p_uinfo,
		cf_buf_builder** pp_bb)
{
	uint8_t n_fields = 3 + (g_config.sec_cfg.quotas_enabled ? 2 : 0);

	resp_bb_pack_sec_msg(pp_bb, AS_OK, n_fields);
	resp_bb_pack_string_msg_field(pp_bb, AS_SEC_FIELD_USER, ukey, user_len);

	uint32_t num_roles = uinfo_num_roles(p_uinfo);
	const char* roles = uinfo_roles(p_uinfo);
	const char* role = roles;

	// Alphabetically sort the role names.
	const char* sorted_roles[num_roles];
	int num_sorted_roles = 0;

	for (uint32_t n = 0; n < num_roles; n++) {
		int s;

		for (s = 0; s < num_sorted_roles; s++) {
			if (strcmp(role, sorted_roles[s]) < 0) {
				break;
			}
		}

		for (int j = num_sorted_roles - 1; j >= s; j--) {
			sorted_roles[j + 1] = sorted_roles[j];
		}

		sorted_roles[s] = role;
		num_sorted_roles++;

		role = uinfo_next_role(role);
	}

	uint32_t role_lens[num_roles];
	uint32_t role_len_sum = 0;

	for (uint32_t n = 0; n < num_roles; n++) {
		role_lens[n] = strlen(sorted_roles[n]);
		role_len_sum += role_lens[n];
	}

	uint8_t* p_write = resp_bb_reserve_roles_msg_field(pp_bb, num_roles,
			role_len_sum);

	for (uint32_t n = 0; n < num_roles; n++) {
		p_write = pack_role_name(p_write, sorted_roles[n], role_lens[n]);
	}

	resp_bb_pack_uint32_msg_field(pp_bb, AS_SEC_FIELD_CONNECTIONS,
			conn_tracker_get_n_conns(ukey));

	if (g_config.sec_cfg.quotas_enabled) {
		qinfo* p_qinfo = NULL;

		cf_rchash_get(g_quotas, ukey, (void**)&p_qinfo);
		cf_assert(p_qinfo != NULL, AS_SECURITY, "null qinfo");

		resp_bb_pack_rw_info_msg_field(pp_bb, AS_SEC_FIELD_READ_INFO,
				p_qinfo->read_quota, p_qinfo->read_tps, p_qinfo->read_rps,
				p_qinfo->n_read_rps_zero);

		resp_bb_pack_rw_info_msg_field(pp_bb, AS_SEC_FIELD_WRITE_INFO,
				p_qinfo->write_quota, p_qinfo->write_tps, p_qinfo->write_rps,
				p_qinfo->n_write_rps_zero);
	}
}


//==========================================================
// Command helpers - modify/query role info.
//

//------------------------------------------------
// Add a unique role.
//
uint8_t
create_role(const char* p_role, uint32_t role_len, const uint8_t* p_privs,
		uint32_t privs_size, const char* p_whitelist, uint32_t whitelist_len,
		uint32_t read_quota, uint32_t write_quota)
{
	if (role_len == 0 || role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "create role - bad role len %u", role_len);
		return AS_SEC_ERR_ROLE;
	}

	if (read_quota == 0 || write_quota == 0) {
		cf_warning(AS_SECURITY, "create role - quota is 0");
		return AS_SEC_ERR_QUOTA;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "create role - role predefined");
		return AS_SEC_ERR_ROLE_EXISTS;
	}

	if (cf_rchash_get(g_roles, rkey, NULL) == CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "create role - role already exists");
		return AS_SEC_ERR_ROLE_EXISTS;
	}

	priv_def* privs = NULL;
	uint32_t n_privs = 0;

	if (p_privs != NULL) {
		uint8_t result = parse_privs(p_privs, privs_size, &privs, &n_privs);

		if (result != AS_OK) {
			cf_warning(AS_SECURITY, "create role - bad privs");
			return result;
		}
	}

	if (p_whitelist != NULL &&
			! ip_net_list_validate_string(p_whitelist, whitelist_len)) {
		cf_warning(AS_SECURITY, "create role - bad whitelist");
		return AS_SEC_ERR_WHITELIST;
	}

	for (uint32_t j = 0; j < n_privs; j++) {
		smd_add_priv(p_role, role_len, &privs[j]);
	}

	if (p_whitelist != NULL) {
		smd_add_whitelist(p_role, role_len, p_whitelist, whitelist_len);
	}

	if (read_quota != NO_QUOTA) {
		smd_add_quota(p_role, role_len, TOK_READ_QUOTA, read_quota);
	}

	if (write_quota != NO_QUOTA) {
		smd_add_quota(p_role, role_len, TOK_WRITE_QUOTA, write_quota);
	}

	cf_free(privs);

	return AS_OK;
}

//------------------------------------------------
// Delete a role.
//
uint8_t
delete_role(const char* p_role, uint32_t role_len)
{
	if (role_len == 0 || role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "delete role - bad role len %u", role_len);
		return AS_SEC_ERR_ROLE;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "delete role - role predefined");
		return AS_SEC_ERR_ROLE;
	}

	rinfo* p_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "delete role - role not found");
		return AS_SEC_ERR_ROLE;
	}

	cf_rchash_reduce(g_users, revoke_role_reduce_fn, (void*)rkey);

	uint32_t num_cur_privs = rinfo_num_privs(p_rinfo);
	const priv_code* cur_privs = rinfo_privs(p_rinfo);

	for (uint32_t k = 0; k < num_cur_privs; k++) {
		priv_def def;

		priv_code_to_def(&cur_privs[k], &def);
		smd_delete_priv(p_role, role_len, &def);
	}

	if (rinfo_has_whitelist(p_rinfo)) {
		smd_delete_whitelist(p_role, role_len);
	}

	if (rinfo_get_read_quota(p_rinfo) != 0) {
		smd_delete_quota(p_role, role_len, TOK_READ_QUOTA);
	}

	if (rinfo_get_write_quota(p_rinfo) != 0) {
		smd_delete_quota(p_role, role_len, TOK_WRITE_QUOTA);
	}

	cf_rc_releaseandfree(p_rinfo);

	return AS_OK;
}

//------------------------------------------------
// Revoke a deleted role from all users.
//
int
revoke_role_reduce_fn(const void* p_key, void* p_value, void* udata)
{
	const char* user = (const char*)p_key;
	const char* role = (const char*)udata;

	if (uinfo_has_role((uinfo*)p_value, role)) {
		smd_delete_role(user, strlen(user), role);
	}

	return CF_RCHASH_OK;
}

//------------------------------------------------
// Add (more) privileges to a role.
//
uint8_t
add_privs(const char* p_role, uint32_t role_len, const uint8_t* p_privs,
		uint32_t privs_size)
{
	if (role_len == 0 || role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "add privs - bad role len %u", role_len);
		return AS_SEC_ERR_ROLE;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "add privs - role predefined");
		return AS_SEC_ERR_ROLE;
	}

	if (cf_rchash_get(g_roles, rkey, NULL) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "add privs - role not found");
		return AS_SEC_ERR_ROLE;
	}

	priv_def* privs = NULL;
	uint32_t n_privs = 0;
	uint8_t result = parse_privs(p_privs, privs_size, &privs, &n_privs);

	if (result != AS_OK) {
		cf_warning(AS_SECURITY, "add privs - bad privs");
		return result;
	}

	for (uint32_t j = 0; j < n_privs; j++) {
		smd_add_priv(p_role, role_len, &privs[j]);
	}

	cf_free(privs);

	return AS_OK;
}

//------------------------------------------------
// Remove privileges from a role. Note - can
// delete role.
//
uint8_t
delete_privs(const char* p_role, uint32_t role_len, const uint8_t* p_privs,
		uint32_t privs_size)
{
	if (role_len == 0 || role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "delete privs - bad role len %u", role_len);
		return AS_SEC_ERR_ROLE;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "delete privs - role predefined");
		return AS_SEC_ERR_ROLE;
	}

	if (cf_rchash_get(g_roles, rkey, NULL) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "delete privs - role not found");
		return AS_SEC_ERR_ROLE;
	}

	priv_def* privs = NULL;
	uint32_t n_privs = 0;
	uint8_t result = parse_privs(p_privs, privs_size, &privs, &n_privs);

	if (result != AS_OK) {
		cf_warning(AS_SECURITY, "delete privs - bad privs");
		return result;
	}

	for (uint32_t j = 0; j < n_privs; j++) {
		smd_delete_priv(p_role, role_len, &privs[j]);
	}

	cf_free(privs);

	return AS_OK;
}

//------------------------------------------------
// Set or remove the whitelist for a role.
//
uint8_t
set_whitelist(const char* p_role, uint32_t role_len, const char* p_whitelist,
		uint32_t whitelist_len)
{
	if (role_len == 0 || role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "set whitelist - bad role len %u", role_len);
		return AS_SEC_ERR_ROLE;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "set whitelist - role predefined");
		return AS_SEC_ERR_ROLE;
	}

	if (cf_rchash_get(g_roles, rkey, NULL) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "set whitelist - role not found");
		return AS_SEC_ERR_ROLE;
	}

	if (p_whitelist != NULL) {
		if (! ip_net_list_validate_string(p_whitelist, whitelist_len)) {
			cf_warning(AS_SECURITY, "set whitelist - bad whitelist");
			return AS_SEC_ERR_WHITELIST;
		}

		smd_add_whitelist(p_role, role_len, p_whitelist, whitelist_len);
	}
	else {
		smd_delete_whitelist(p_role, role_len);
	}

	return AS_OK;
}

//------------------------------------------------
// Set or remove quotas for a role.
//
uint8_t
set_quotas(const char* p_role, uint32_t role_len, uint32_t read_quota,
		uint32_t write_quota)
{
	if (role_len == 0 || role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "set quotas - bad role len %u", role_len);
		return AS_SEC_ERR_ROLE;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "set quotas - role predefined");
		return AS_SEC_ERR_ROLE;
	}

	if (cf_rchash_get(g_roles, rkey, NULL) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "set quotas - role not found");
		return AS_SEC_ERR_ROLE;
	}

	if (read_quota == 0) {
		smd_delete_quota(p_role, role_len, TOK_READ_QUOTA);
	}
	else if (read_quota != NO_QUOTA) {
		smd_add_quota(p_role, role_len, TOK_READ_QUOTA, read_quota);
	}

	if (write_quota == 0) {
		smd_delete_quota(p_role, role_len, TOK_WRITE_QUOTA);
	}
	else if (write_quota != NO_QUOTA) {
		smd_add_quota(p_role, role_len, TOK_WRITE_QUOTA, write_quota);
	}

	return AS_OK;
}

//------------------------------------------------
// Pack one or many security messages, each with
// role & privileges fields into the
// cf_buf_builder.
//
uint8_t
query_roles(const char* p_role, uint32_t role_len, cf_buf_builder** pp_bb)
{
	if (! p_role) {
		// Query all roles.
		cf_mutex_lock(&g_query_roles_lock);

		uint32_t num_roles = cf_rchash_get_size(g_roles);
		const char* rkeys[num_roles];
		udata_sort_key rkey;

		rkey.pp_key = rkeys;
		rkey.num_keys = 0;

		cf_rchash_reduce(g_roles, collect_sort_keys_reduce_fn, (void*)&rkey);

		for (uint32_t i = 0; i < num_roles; i++) {
			rinfo* p_rinfo = NULL;

			// Note - it's ok to query predefined roles.

			if (cf_rchash_get(g_roles, rkeys[i], (void**)&p_rinfo) !=
					CF_RCHASH_OK) {
				cf_crash(AS_SECURITY, "query roles failed - role not found");
			}

			query_role(rkeys[i], strlen(rkeys[i]), p_rinfo, pp_bb);
			cf_rc_releaseandfree(p_rinfo);
		}

		cf_mutex_unlock(&g_query_roles_lock);
		return AS_OK;
	}

	if (role_len == 0 || role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "query roles - bad role len %u", role_len);
		return AS_SEC_ERR_ROLE;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	// Note - it's ok to query predefined roles.

	rinfo* p_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "query roles - role not found");
		return AS_SEC_ERR_ROLE;
	}

	query_role(p_role, role_len, p_rinfo, pp_bb);
	cf_rc_releaseandfree(p_rinfo);

	return AS_OK;
}

//------------------------------------------------
// Pack one security message with role &
// privileges fields into the cf_buf_builder.
//
void
query_role(const char* p_role, uint32_t role_len, const rinfo* p_rinfo,
		cf_buf_builder** pp_bb)
{
	bool has_whitelist = rinfo_has_whitelist(p_rinfo);
	uint32_t read_quota = rinfo_get_read_quota(p_rinfo);
	uint32_t write_quota = rinfo_get_write_quota(p_rinfo);
	uint32_t num_privs = rinfo_num_privs(p_rinfo);

	uint8_t n_fields = 1 + (has_whitelist ? 1 : 0) + (read_quota != 0 ? 1 : 0) +
			(write_quota != 0 ? 1 : 0) + (num_privs != 0 ? 1 : 0);

	resp_bb_pack_sec_msg(pp_bb, AS_OK, n_fields);
	resp_bb_pack_string_msg_field(pp_bb, AS_SEC_FIELD_ROLE, p_role, role_len);

	if (has_whitelist) {
		char whitelist[2048];

		rinfo_get_whitelist(p_rinfo, whitelist, sizeof(whitelist));
		resp_bb_pack_whitelist_msg_field(pp_bb, whitelist);
	}

	if (read_quota != 0) {
		resp_bb_pack_uint32_msg_field(pp_bb, AS_SEC_FIELD_READ_QUOTA,
				read_quota);
	}

	if (write_quota != 0) {
		resp_bb_pack_uint32_msg_field(pp_bb, AS_SEC_FIELD_WRITE_QUOTA,
				write_quota);
	}

	if (num_privs == 0) {
		return;
	}

	const priv_code* privs = rinfo_privs(p_rinfo);

	uint8_t packed_privs[num_privs * PACKED_PRIV_MAX_SIZE];
	uint8_t* p_packed_priv = packed_privs;
	uint32_t packed_priv_sizes[num_privs];
	uint32_t packed_priv_size_sum = 0;

	for (uint32_t i = 0; i < num_privs; i++) {
		packed_priv_sizes[i] = prepack_priv(&privs[i], p_packed_priv);
		packed_priv_size_sum += packed_priv_sizes[i];
		p_packed_priv += PACKED_PRIV_MAX_SIZE;
	}

	uint8_t* p_write = resp_bb_reserve_privs_msg_field(pp_bb, num_privs,
			packed_priv_size_sum);

	// Sort the packed privs into canonical order.
	uint8_t* sorted_packed_privs[num_privs];
	uint32_t sorted_sizes[num_privs];
	int num_sorted = 0;

	p_packed_priv = packed_privs;

	for (uint32_t i = 0; i < num_privs; i++) {
		int s;

		for (s = 0; s < num_sorted; s++) {
			if (packed_priv_cmp(p_packed_priv, sorted_packed_privs[s]) < 0) {
				break;
			}
		}

		for (int j = num_sorted - 1; j >= s; j--) {
			sorted_packed_privs[j + 1] = sorted_packed_privs[j];
			sorted_sizes[j + 1] = sorted_sizes[j];
		}

		sorted_packed_privs[s] = p_packed_priv;
		sorted_sizes[s] = packed_priv_sizes[i];
		num_sorted++;

		p_packed_priv += PACKED_PRIV_MAX_SIZE;
	}

	for (uint32_t i = 0; i < num_privs; i++) {
		p_write = pack_priv(p_write, sorted_packed_privs[i], sorted_sizes[i]);
		p_packed_priv += PACKED_PRIV_MAX_SIZE;
	}
}

//------------------------------------------------
// Compare two packed privileges for ordering.
//
int
packed_priv_cmp(const uint8_t* p_packed_priv1, const uint8_t* p_packed_priv2)
{
	int perm_diff = (int)*p_packed_priv1 - (int)*p_packed_priv2;

	if (perm_diff != 0) {
		return perm_diff;
	}

	p_packed_priv1++;
	p_packed_priv2++;

	if (*p_packed_priv1 == 0 || *p_packed_priv2 == 0) {
		return (int)*p_packed_priv1 - (int)*p_packed_priv2;
	}

	uint32_t ns1_len = (uint32_t)*p_packed_priv1++;
	uint32_t ns2_len = (uint32_t)*p_packed_priv2++;
	uint32_t min_ns_len = ns1_len < ns2_len ? ns1_len : ns2_len;

	int ns_cmp = strncmp((const char*)p_packed_priv1,
			(const char*)p_packed_priv2, min_ns_len);

	if (ns_cmp != 0) {
		return ns_cmp;
	}

	int ns_len_diff = (int)ns1_len - (int)ns2_len;

	if (ns_len_diff != 0) {
		return ns_len_diff;
	}

	p_packed_priv1 += ns1_len;
	p_packed_priv2 += ns2_len;

	uint32_t set1_len = (uint32_t)*p_packed_priv1++;
	uint32_t set2_len = (uint32_t)*p_packed_priv2++;
	uint32_t min_set_len = set1_len < set2_len ? set1_len : set2_len;

	int set_cmp = strncmp((const char*)p_packed_priv1,
			(const char*)p_packed_priv2, min_set_len);

	if (set_cmp != 0) {
		return set_cmp;
	}

	return (int)set1_len - (int)set2_len;
}


//==========================================================
// System metadata input utilities - user info.
//

//------------------------------------------------
// Add a user's password item to SMD.
//
void
smd_add_password(const char* p_user, uint32_t user_len, const char* p_password,
		uint32_t password_len)
{
	char smd_key[user_len + 1 + 1 + 1];

	memcpy(smd_key, p_user, user_len);

	char* p_write = smd_key + user_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_PASSWORD;
	*p_write = 0;

	char smd_value[password_len + 1];

	if (p_password) {
		memcpy(smd_value, p_password, password_len);
	}

	smd_value[password_len] = 0;

	as_smd_set_and_forget(AS_SMD_MODULE_SECURITY, smd_key, smd_value);
}

//------------------------------------------------
// Add a user's role item to SMD.
//
void
smd_add_role(const char* p_user, uint32_t user_len, const char* role)
{
	char smd_key[user_len + 1 + 1 + 1 + MAX_ROLE_NAME_SIZE];

	memcpy(smd_key, p_user, user_len);

	char* p_write = smd_key + user_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_ROLE;
	*p_write++ = TOK_DELIMITER;
	strcpy(p_write, role);

	// For now, roles have no SMD value.
	as_smd_set_and_forget(AS_SMD_MODULE_SECURITY, smd_key, "");
}

//------------------------------------------------
// Delete a user's password item from SMD - will
// cause user-info cache to delete user.
//
void
smd_delete_password(const char* p_user, uint32_t user_len)
{
	char smd_key[user_len + 1 + 1 + 1];

	memcpy(smd_key, p_user, user_len);

	char* p_write = smd_key + user_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_PASSWORD;
	*p_write = 0;

	as_smd_delete_and_forget(AS_SMD_MODULE_SECURITY, smd_key);
}

//------------------------------------------------
// Delete a user's role item from SMD.
//
void
smd_delete_role(const char* p_user, uint32_t user_len, const char* role)
{
	char smd_key[user_len + 1 + 1 + 1 + MAX_ROLE_NAME_SIZE];

	memcpy(smd_key, p_user, user_len);

	char* p_write = smd_key + user_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_ROLE;
	*p_write++ = TOK_DELIMITER;
	strcpy(p_write, role);

	as_smd_delete_and_forget(AS_SMD_MODULE_SECURITY, smd_key);
}


//==========================================================
// System metadata input utilities - user-defined role info.
//

//------------------------------------------------
// Add a role's privilege item to SMD.
//
void
smd_add_priv(const char* p_role, uint32_t role_len, const priv_def* p_priv)
{
	const uint32_t smd_priv_max_size =
			3 + 1 + (AS_ID_NAMESPACE_SZ - 1) + 1 + AS_SET_NAME_MAX_SIZE;
	char smd_key[1 + 1 + 1 + role_len + 1 + 1 + 1 + smd_priv_max_size + 1];
	char* p_write = smd_key;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_ROLE;
	*p_write++ = TOK_DELIMITER;

	memcpy(p_write, p_role, role_len);
	p_write += role_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_PRIV;
	*p_write++ = TOK_DELIMITER;

	sprintf(p_write, "%u%c%s%c%s",
			p_priv->perm_code, TOK_DELIMITER,
			p_priv->ns_name, TOK_DELIMITER,
			p_priv->set_name);

	// For now, privileges have no SMD value.
	as_smd_set_and_forget(AS_SMD_MODULE_SECURITY, smd_key, "");
}

//------------------------------------------------
// Delete a role's privilege item from SMD.
//
void
smd_delete_priv(const char* p_role, uint32_t role_len, const priv_def* p_priv)
{
	const uint32_t smd_priv_max_size =
			3 + 1 + (AS_ID_NAMESPACE_SZ - 1) + 1 + AS_SET_NAME_MAX_SIZE;
	char smd_key[1 + 1 + 1 + role_len + 1 + 1 + 1 + smd_priv_max_size + 1];
	char* p_write = smd_key;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_ROLE;
	*p_write++ = TOK_DELIMITER;

	memcpy(p_write, p_role, role_len);
	p_write += role_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_PRIV;
	*p_write++ = TOK_DELIMITER;

	sprintf(p_write, "%u%c%s%c%s",
			p_priv->perm_code, TOK_DELIMITER,
			p_priv->ns_name, TOK_DELIMITER,
			p_priv->set_name);

	as_smd_delete_and_forget(AS_SMD_MODULE_SECURITY, smd_key);
}

//------------------------------------------------
// Convert a priv_code to a priv_def for SMD.
// Assume success since for codes in cache, their
// corresponding namespaces and sets should exist.
//
void
priv_code_to_def(const priv_code* p_priv_code, priv_def* p_priv_def)
{
	p_priv_def->perm_code = p_priv_code->perm_code;
	p_priv_def->ns_name[0] = 0;
	p_priv_def->set_name[0] = 0;

	as_namespace* ns = NULL;

	if (p_priv_code->ns_ix != NO_NS_IX) {
		ns = g_config.namespaces[p_priv_code->ns_ix];
		strcpy(p_priv_def->ns_name, ns->name);
	}

	if (p_priv_code->set_id != INVALID_SET_ID) {
		// Assumes ns_ix was also valid, i.e. ns not null.
		strcpy(p_priv_def->set_name,
				as_namespace_get_set_name(ns, p_priv_code->set_id));
	}
}

// ------------------------------------------------
// Change (or add) a role's whitelist item to SMD.
//
void
smd_add_whitelist(const char* p_role, uint32_t role_len, const char* p_whitelist,
		uint32_t whitelist_len)
{
	char smd_key[1 + 1 + 1 + role_len + 1 + 1 + 1 + 1];
	char* p_write = smd_key;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_ROLE;
	*p_write++ = TOK_DELIMITER;

	memcpy(p_write, p_role, role_len);
	p_write += role_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_WHITELIST;
	*p_write = '\0';

	char smd_value[whitelist_len + 1];

	memcpy(smd_value, p_whitelist, whitelist_len);
	smd_value[whitelist_len] = '\0';

	as_smd_set_and_forget(AS_SMD_MODULE_SECURITY, smd_key, smd_value);
}

//------------------------------------------------
// Removes a role's whitelist item from SMD.
//
void
smd_delete_whitelist(const char* p_role, uint32_t role_len)
{
	char smd_key[1 + 1 + 1 + role_len + 1 + 1 + 1 + 1];
	char* p_write = smd_key;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_ROLE;
	*p_write++ = TOK_DELIMITER;

	memcpy(p_write, p_role, role_len);
	p_write += role_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_WHITELIST;
	*p_write = '\0';

	as_smd_delete_and_forget(AS_SMD_MODULE_SECURITY, smd_key);
}

// ------------------------------------------------
// Change (or add) a role's quota item to SMD.
//
void
smd_add_quota(const char* p_role, uint32_t role_len, char quota_tok,
		uint32_t tps_quota)
{
	char smd_key[1 + 1 + 1 + role_len + 1 + 1 + 1 + 1];
	char* p_write = smd_key;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_ROLE;
	*p_write++ = TOK_DELIMITER;

	memcpy(p_write, p_role, role_len);
	p_write += role_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = quota_tok;
	*p_write = '\0';

	char smd_value[10 + 1];

	sprintf(smd_value, "%u", tps_quota);

	as_smd_set_and_forget(AS_SMD_MODULE_SECURITY, smd_key, smd_value);
}

//------------------------------------------------
// Removes a role's quota item from SMD.
//
void
smd_delete_quota(const char* p_role, uint32_t role_len, char quota_tok)
{
	char smd_key[1 + 1 + 1 + role_len + 1 + 1 + 1 + 1];
	char* p_write = smd_key;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = TOK_ROLE;
	*p_write++ = TOK_DELIMITER;

	memcpy(p_write, p_role, role_len);
	p_write += role_len;

	*p_write++ = TOK_DELIMITER;
	*p_write++ = quota_tok;
	*p_write = '\0';

	as_smd_delete_and_forget(AS_SMD_MODULE_SECURITY, smd_key);
}


//==========================================================
// System metadata callback implementations.
//

//------------------------------------------------
// The dummy 'accept' callback that allows SMD
// participation when security is disabled.
//
void
sec_smd_dummy_accept_cb(const cf_vector* items, as_smd_accept_type accept_type)
{
	(void)items;
	(void)accept_type;
}

//------------------------------------------------
// The 'accept' callback that gets all runtime
// modifications.
//
void
sec_smd_accept_cb(const cf_vector* items, as_smd_accept_type accept_type)
{
	bool is_startup = accept_type == AS_SMD_ACCEPT_OPT_START;

	for (uint32_t i = 0; i < cf_vector_size(items); i++) {
		const as_smd_item* p_item = cf_vector_get_ptr(items, i);
		bool is_user_info = *p_item->key != TOK_DELIMITER;

		if (p_item->value != NULL) {
			if (is_user_info) {
				action_user_cache_set(p_item, is_startup);
			}
			else {
				action_role_cache_set(p_item, is_startup);
			}
		}
		else {
			if (is_user_info) {
				action_user_cache_delete(p_item);
			}
			else {
				action_role_cache_delete(p_item);
			}
		}
	}

	if (is_startup) {
		// Calculate all roles' permission books from held privs.
		activate_held_privs();

		// Calculate all users' permission books from held roles.
		activate_held_roles();
	}
}


//==========================================================
// System metadata to user-info cache utilities.
//

//------------------------------------------------
// Apply SMD 'delete' action to user-info cache.
//
void
action_user_cache_delete(const as_smd_item* p_item)
{
	const char* p_user = p_item->key;
	const char* p_tok = strchr(p_user, TOK_DELIMITER);

	if (! p_tok) {
		cf_warning(AS_SECURITY, "smd DELETE - user key has no delimiter");
		return;
	}

	uint32_t user_len = (uint32_t)(p_tok - p_user);

	p_tok++;
	// Now p_tok points to ID token.

	switch (*p_tok++) {
	case TOK_PASSWORD:
		if (*p_tok == 0) {
			act_delete_password(p_user, user_len);
		}
		else {
			cf_warning(AS_SECURITY,
					"smd DELETE - user key has bad password token");
		}
		break;
	case TOK_ROLE:
		if (*p_tok++ == TOK_DELIMITER) {
			act_delete_role(p_user, user_len, p_tok);
		}
		else {
			cf_warning(AS_SECURITY, "smd DELETE - user key has bad role token");
		}
		break;
	default:
		cf_warning(AS_SECURITY, "smd DELETE - user key has unknown token");
		break;
	}
}

//------------------------------------------------
// Apply SMD 'set' action to user-info cache.
//
void
action_user_cache_set(const as_smd_item* p_item, bool is_startup)
{
	const char* p_user = p_item->key;
	const char* p_tok = strchr(p_user, TOK_DELIMITER);

	if (! p_tok) {
		cf_warning(AS_SECURITY, "smd SET - user key has no delimiter");
		return;
	}

	uint32_t user_len = (uint32_t)(p_tok - p_user);

	p_tok++;
	// Now p_tok points to ID token.

	switch (*p_tok++) {
	case TOK_PASSWORD:
		if (*p_tok == 0) {
			act_add_password(p_user, user_len, p_item->value);
		}
		else {
			cf_warning(AS_SECURITY,
					"smd SET - user key has bad password token");
		}
		break;
	case TOK_ROLE:
		if (*p_tok++ == TOK_DELIMITER) {
			if (is_startup) {
				act_hold_role(p_user, user_len, p_tok);
			}
			else {
				act_add_role(p_user, user_len, p_tok);
			}
		}
		else {
			cf_warning(AS_SECURITY, "smd SET - user key has bad role token");
		}
		break;
	default:
		cf_warning(AS_SECURITY, "smd SET - key has unknown token");
		break;
	}
}

//------------------------------------------------
// Update a password in user-info cache - may
// create user.
//
void
act_add_password(const char* p_user, uint32_t user_len, const char* password)
{
	if (user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "add password failed - bad user");
		return;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	// External users have empty passwords.
	if (*password != 0 && strlen(password) != PASSWORD_LEN) {
		cf_warning(AS_SECURITY, "add password failed - bad password");
		return;
	}

	uinfo* p_uinfo = NULL;
	uinfo* p_new_uinfo = NULL;

	cf_mutex_lock(&g_session_users_lock);

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) == CF_RCHASH_OK) {
		if (uinfo_password_matches(p_uinfo, password)) {
			cf_debug(AS_SECURITY, "add password - no change");
			cf_rc_releaseandfree(p_uinfo);
			cf_mutex_unlock(&g_session_users_lock);
			return;
		}

		p_new_uinfo = uinfo_replace_password(p_uinfo, password);
		cf_rc_releaseandfree(p_uinfo);
	}
	else {
		p_new_uinfo = uinfo_new_password(password);
		// Creates new user.

		if (g_config.sec_cfg.quotas_enabled) {
			cf_rchash_put(g_quotas, ukey, (void*)qinfo_new_empty());
		}

		conn_tracker_insert(ukey);
	}

	cf_mutex_lock(&g_query_users_lock);
	cf_rchash_put(g_users, ukey, (void*)p_new_uinfo);
	cf_mutex_unlock(&g_query_users_lock);
	cf_mutex_unlock(&g_session_users_lock);
}

//------------------------------------------------
// Grant a role in user-info cache - may create
// user.
//
void
act_add_role(const char* p_user, uint32_t user_len, const char* role)
{
	if (user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "add role failed - bad user");
		return;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uint32_t role_len = strlen(role);

	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "add role failed - bad role %s", role);
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, role, role_len);

	uinfo* p_uinfo = NULL;
	uinfo* p_new_uinfo = NULL;

	cf_mutex_lock(&g_session_users_lock);

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) == CF_RCHASH_OK) {
		if (uinfo_has_role(p_uinfo, rkey)) {
			cf_debug(AS_SECURITY, "add role - role already in user");
			cf_rc_releaseandfree(p_uinfo);
			cf_mutex_unlock(&g_session_users_lock);
			return;
		}

		p_new_uinfo = uinfo_replace_add_role(p_uinfo, rkey);
		cf_rc_releaseandfree(p_uinfo);

		if (g_config.sec_cfg.quotas_enabled) {
			qinfo* p_qinfo = NULL;

			cf_rchash_get(g_quotas, ukey, (void**)&p_qinfo);
			cf_assert(p_qinfo != NULL, AS_SECURITY, "null qinfo");

			qinfo_adjust_add_role(p_qinfo, rkey);

			cf_rc_releaseandfree(p_qinfo);
		}
	}
	else {
		p_new_uinfo = uinfo_new_add_role(rkey);
		// Creates new user.

		if (g_config.sec_cfg.quotas_enabled) {
			cf_rchash_put(g_quotas, ukey, (void*)qinfo_new_add_role(rkey));
		}

		conn_tracker_insert(ukey);
	}

	cf_mutex_lock(&g_query_users_lock);
	cf_rchash_put(g_users, ukey, (void*)p_new_uinfo);
	cf_mutex_unlock(&g_query_users_lock);
	cf_mutex_unlock(&g_session_users_lock);
}

//------------------------------------------------
// Remove a user from user-info cache - caused by
// deleting password in SMD.
//
void
act_delete_password(const char* p_user, uint32_t user_len)
{
	if (user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "delete password failed - bad user");
		return;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	cf_mutex_lock(&g_query_users_lock);

	if (cf_rchash_delete(g_users, ukey) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "delete password failed - user not found");
	}

	if (g_config.sec_cfg.quotas_enabled &&
			cf_rchash_delete(g_quotas, ukey) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "delete password failed - qinfo not found");
	}

	conn_tracker_remove(ukey);

	cf_mutex_unlock(&g_query_users_lock);
}

//------------------------------------------------
// Revoke a role in user-info cache.
//
void
act_delete_role(const char* p_user, uint32_t user_len, const char* role)
{
	if (user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "delete role failed - bad user");
		return;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uint32_t role_len = strlen(role);

	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "delete role failed - bad role %s", role);
		return;
	}

	uinfo* p_uinfo = NULL;

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) != CF_RCHASH_OK) {
		// This is normal when dropping a user.
		cf_debug(AS_SECURITY, "delete role failed - user not found");
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, role, role_len);

	if (! uinfo_has_role(p_uinfo, rkey)) {
		cf_warning(AS_SECURITY, "delete role - role not in user");
		cf_rc_releaseandfree(p_uinfo);
		return;
	}

	uinfo* p_new_uinfo = uinfo_replace_delete_role(p_uinfo, rkey);

	cf_rc_releaseandfree(p_uinfo);

	cf_rchash_put(g_users, ukey, (void*)p_new_uinfo);

	if (g_config.sec_cfg.quotas_enabled) {
		qinfo* p_qinfo = NULL;

		cf_rchash_get(g_quotas, ukey, (void**)&p_qinfo);
		cf_assert(p_qinfo != NULL, AS_SECURITY, "null qinfo");

		qinfo_adjust_reset_roles(p_qinfo, uinfo_roles(p_new_uinfo),
				uinfo_num_roles(p_new_uinfo));

		cf_rc_releaseandfree(p_qinfo);
	}
}

//------------------------------------------------
// Grant a role in user-info cache, but don't
// generate the permissions book. May create
// user. Used only at startup.
//
void
act_hold_role(const char* p_user, uint32_t user_len, const char* role)
{
	if (user_len >= MAX_USER_SIZE) {
		cf_warning(AS_SECURITY, "hold role failed - bad user");
		return;
	}

	char ukey[MAX_USER_SIZE] = { 0 };

	memcpy(ukey, p_user, user_len);

	uint32_t role_len = strlen(role);

	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "hold role failed - bad role %s", role);
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, role, role_len);

	uinfo* p_uinfo = NULL;
	uinfo* p_new_uinfo = NULL;

	if (cf_rchash_get(g_users, ukey, (void**)&p_uinfo) == CF_RCHASH_OK) {
		if (uinfo_has_role(p_uinfo, rkey)) {
			cf_warning(AS_SECURITY, "hold role - role already in user");
			cf_rc_releaseandfree(p_uinfo);
			return;
		}

		p_new_uinfo = uinfo_replace_add_role_only(p_uinfo, rkey);
		cf_rc_releaseandfree(p_uinfo);
	}
	else {
		p_new_uinfo = uinfo_new_add_role_only(rkey);
		// Creates new user.

		if (g_config.sec_cfg.quotas_enabled) {
			cf_rchash_put(g_quotas, ukey, (void*)qinfo_new_empty());
		}

		conn_tracker_insert(ukey);
	}

	cf_rchash_put(g_users, ukey, (void*)p_new_uinfo);
}

//------------------------------------------------
// Generate user's permissions book from list of
// roles. Used only at startup.
//
void
activate_held_roles()
{
	uint32_t num_users = cf_rchash_get_size(g_users);
	const char* ukeys[num_users];
	udata_key ukey;

	ukey.pp_key = ukeys;

	cf_rchash_reduce(g_users, collect_keys_reduce_fn, (void*)&ukey);

	for (uint32_t i = 0; i < num_users; i++) {
		uinfo* p_uinfo = NULL;

		if (cf_rchash_get(g_users, ukeys[i], (void**)&p_uinfo) !=
				CF_RCHASH_OK) {
			cf_crash(AS_SECURITY, "activate roles failed - user not found");
		}

		uinfo* p_new_uinfo = uinfo_generate_book(p_uinfo);

		cf_rc_releaseandfree(p_uinfo);

		cf_rchash_put(g_users, ukeys[i], (void*)p_new_uinfo);

		if (g_config.sec_cfg.quotas_enabled) {
			qinfo* p_qinfo = NULL;

			cf_rchash_get(g_quotas, ukeys[i], (void**)&p_qinfo);
			cf_assert(p_qinfo != NULL, AS_SECURITY, "null qinfo");

			qinfo_adjust_reset_roles(p_qinfo, uinfo_roles(p_new_uinfo),
					uinfo_num_roles(p_new_uinfo));

			cf_rc_releaseandfree(p_qinfo);
		}
	}
}


//==========================================================
// System metadata to role cache utilities.
//

//------------------------------------------------
// Apply SMD 'delete' action to role cache.
//
void
action_role_cache_delete(const as_smd_item* p_item)
{
	const char* p_tok = p_item->key + 1;

	if (! (*p_tok++ == TOK_ROLE && *p_tok++ == TOK_DELIMITER)) {
		cf_warning(AS_SECURITY, "smd DELETE - unknown key format");
		return;
	}

	const char* p_role = p_tok;

	p_tok = strchr(p_role, TOK_DELIMITER);

	if (! p_tok) {
		cf_warning(AS_SECURITY, "smd DELETE - role key is missing delimiter");
		return;
	}

	uint32_t role_len = (uint32_t)(p_tok - p_role);

	p_tok++;
	// Now p_tok points to ID token.

	switch (*p_tok++) {
	case TOK_PRIV:
		if (*p_tok++ == TOK_DELIMITER) {
			act_delete_priv(p_role, role_len, p_tok);
		}
		else {
			cf_warning(AS_SECURITY, "smd DELETE - role key has bad priv token");
		}
		break;
	case TOK_WHITELIST:
		if (*p_tok == 0) {
			act_delete_whitelist(p_role, role_len);
		}
		else {
			cf_warning(AS_SECURITY,
					"smd DELETE - role key has bad whitelist token");
		}
		break;
	case TOK_READ_QUOTA:
	case TOK_WRITE_QUOTA:
		if (g_config.sec_cfg.quotas_enabled) {
			if (*p_tok == 0) {
				act_delete_quota(p_role, role_len, *(p_tok - 1));
			}
			else {
				cf_warning(AS_SECURITY,
						"smd DELETE - role key has bad quota token");
			}
		}
		break;
	default:
		cf_warning(AS_SECURITY, "smd DELETE - role key has unknown token");
		break;
	}
}

//------------------------------------------------
// Apply SMD 'set' action to role cache.
//
void
action_role_cache_set(const as_smd_item* p_item, bool is_startup)
{
	const char* p_tok = p_item->key + 1;

	if (! (*p_tok++ == TOK_ROLE && *p_tok++ == TOK_DELIMITER)) {
		cf_warning(AS_SECURITY, "smd SET - unknown key format");
		return;
	}

	const char* p_role = p_tok;

	p_tok = strchr(p_role, TOK_DELIMITER);

	if (! p_tok) {
		cf_warning(AS_SECURITY, "smd SET - role key is missing delimiter");
		return;
	}

	uint32_t role_len = (uint32_t)(p_tok - p_role);

	p_tok++;
	// Now p_tok points to priv token.

	switch (*p_tok++) {
	case TOK_PRIV:
		if (*p_tok++ == TOK_DELIMITER) {
			if (is_startup) {
				act_hold_priv(p_role, role_len, p_tok);
			}
			else {
				act_add_priv(p_role, role_len, p_tok);
			}
		}
		else {
			cf_warning(AS_SECURITY, "smd SET - role key has bad priv token");
		}
		break;
	case TOK_WHITELIST:
		if (*p_tok == 0) {
			act_add_whitelist(p_role, role_len, p_item->value);
		}
		else {
			cf_warning(AS_SECURITY,
					"smd SET - role key has bad whitelist token");
		}
		break;
	case TOK_READ_QUOTA:
	case TOK_WRITE_QUOTA:
		if (g_config.sec_cfg.quotas_enabled) {
			if (*p_tok == 0) {
				act_add_quota(p_role, role_len, *(p_tok - 1), p_item->value);
			}
			else {
				cf_warning(AS_SECURITY,
						"smd SET - role key has bad quota token");
			}
		}
		break;
	default:
		cf_warning(AS_SECURITY, "smd SET - role key has unknown token");
		break;
	}
}

//------------------------------------------------
// Add a privilege in role-info cache - may create
// role.
//
void
act_add_priv(const char* p_role, uint32_t role_len, const char* smd_priv)
{
	priv_code priv;

	if (! get_priv(smd_priv, &priv, true)) {
		cf_warning(AS_SECURITY, "add priv failed - bad priv");
		return;
	}

	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "add priv failed - bad role");
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "add priv failed - role predefined");
		return;
	}

	rinfo* p_rinfo = NULL;
	rinfo* p_new_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) == CF_RCHASH_OK) {
		if (rinfo_has_priv(p_rinfo, &priv)) {
			cf_debug(AS_SECURITY, "add priv - priv already in role");
			cf_rc_releaseandfree(p_rinfo);
			return;
		}

		p_new_rinfo = rinfo_replace_add_priv(p_rinfo, &priv);
		cf_rc_releaseandfree(p_rinfo);
	}
	else {
		p_new_rinfo = rinfo_new_add_priv(&priv);
		// Creates new role.
	}

	cf_mutex_lock(&g_query_roles_lock);
	cf_rchash_put(g_roles, rkey, (void*)p_new_rinfo);
	cf_mutex_unlock(&g_query_roles_lock);

	user_info_update_grow_role(rkey, rinfo_book(p_new_rinfo),
			rinfo_book_size(p_new_rinfo));
}

//------------------------------------------------
// Remove a privilege from role-info cache - may
// delete role.
//
void
act_delete_priv(const char* p_role, uint32_t role_len, const char* smd_priv)
{
	priv_code priv;

	if (! get_priv(smd_priv, &priv, false)) {
		cf_warning(AS_SECURITY, "delete priv failed - bad priv");
		return;
	}

	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "delete priv failed - bad role");
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "delete priv failed - role predefined");
		return;
	}

	rinfo* p_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "delete priv failed - role not found");
		return;
	}

	if (! rinfo_has_priv(p_rinfo, &priv)) {
		cf_warning(AS_SECURITY, "delete priv - priv not in role");
		cf_rc_releaseandfree(p_rinfo);
		return;
	}

	if (rinfo_num_privs(p_rinfo) == 1 && ! rinfo_has_whitelist(p_rinfo) &&
			rinfo_get_read_quota(p_rinfo) == 0 &&
			rinfo_get_write_quota(p_rinfo) == 0) {
		cf_info(AS_SECURITY, "delete priv - deleting empty role");
		cf_rc_releaseandfree(p_rinfo);

		cf_mutex_lock(&g_query_roles_lock);

		if (cf_rchash_delete(g_roles, rkey) != CF_RCHASH_OK) {
			cf_crash(AS_SECURITY, "delete priv - role not found");
		}

		cf_mutex_unlock(&g_query_roles_lock);

		user_info_update_shrink_role(rkey);
		return;
	}

	rinfo* p_new_rinfo = rinfo_replace_delete_priv(p_rinfo, &priv);

	cf_rc_releaseandfree(p_rinfo);

	cf_mutex_lock(&g_query_roles_lock);
	cf_rchash_put(g_roles, rkey, (void*)p_new_rinfo);
	cf_mutex_unlock(&g_query_roles_lock);

	user_info_update_shrink_role(rkey);
}

//------------------------------------------------
// Add a privilege in role-info cache, but don't
// generate the permissions book. May create
// role. Used only at startup.
//
void
act_hold_priv(const char* p_role, uint32_t role_len, const char* smd_priv)
{
	priv_code priv;

	if (! get_priv(smd_priv, &priv, true)) {
		cf_warning(AS_SECURITY, "hold priv failed - bad priv");
		return;
	}

	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "hold priv failed - bad role");
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	rinfo* p_rinfo = NULL;
	rinfo* p_new_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) == CF_RCHASH_OK) {
		if (rinfo_has_priv(p_rinfo, &priv)) {
			cf_warning(AS_SECURITY, "hold priv - priv already in role");
			cf_rc_releaseandfree(p_rinfo);
			return;
		}

		p_new_rinfo = rinfo_replace_add_priv_only(p_rinfo, &priv);
		cf_rc_releaseandfree(p_rinfo);
	}
	else {
		p_new_rinfo = rinfo_new_add_priv_only(&priv);
		// Creates new role.
	}

	cf_rchash_put(g_roles, rkey, (void*)p_new_rinfo);
}

//------------------------------------------------
// Generate role's permissions book from list of
// privileges. Used only at startup.
//
void
activate_held_privs()
{
	uint32_t num_roles = cf_rchash_get_size(g_roles);
	const char* rkeys[num_roles];
	udata_key rkey;

	rkey.pp_key = rkeys;

	cf_rchash_reduce(g_roles, collect_keys_reduce_fn, (void*)&rkey);

	for (uint32_t i = 0; i < num_roles; i++) {
		rinfo* p_rinfo = NULL;

		if (cf_rchash_get(g_roles, rkeys[i], (void**)&p_rinfo) !=
				CF_RCHASH_OK) {
			cf_crash(AS_SECURITY, "activate privs failed - role not found");
		}

		rinfo* p_new_rinfo = rinfo_generate_book(p_rinfo);

		cf_rc_releaseandfree(p_rinfo);

		cf_rchash_put(g_roles, rkeys[i], (void*)p_new_rinfo);
	}
}

//------------------------------------------------
// Convert SMD format to priv_code.
//
bool
get_priv(const char* smd_priv, priv_code* p_priv, bool create_set)
{
	char* p_read = NULL;
	uint32_t i = (uint32_t)strtol(smd_priv, &p_read, 10);

	if (! (is_valid_perm_code(i) && *p_read++ == TOK_DELIMITER)) {
		cf_warning(AS_SECURITY, "get priv %s - invalid perm code", smd_priv);
		return false;
	}

	p_priv->perm_code = i;

	char* p_tok = strchr(p_read, TOK_DELIMITER);

	if (! p_tok) {
		cf_warning(AS_SECURITY, "get priv %s - missing delimiter", smd_priv);
		return false;
	}

	uint32_t ns_len = (uint32_t)(p_tok - p_read);
	char* set_name = p_tok + 1;

	if (ns_len == 0) {
		// Global scope - no namespace, and so no set.
		p_priv->ns_ix = NO_NS_IX;
		p_priv->set_id = INVALID_SET_ID;

		if (*set_name != 0) {
			cf_warning(AS_SECURITY, "get priv %s - extraneous set", smd_priv);
			return false;
		}

		return true;
	}

	as_namespace* ns = as_namespace_get_bybuf((uint8_t*)p_read, ns_len);

	if (! ns) {
		cf_warning(AS_SECURITY, "get priv %s - invalid ns", smd_priv);
		return false;
	}

	p_priv->ns_ix = ns->ix;

	if (*set_name == 0) {
		// Namespace scope - no set.
		p_priv->set_id = INVALID_SET_ID;

		return true;
	}

	uint16_t set_id;

	if (create_set) {
		set_id = as_namespace_get_create_set_id(ns, set_name);

		if (set_id == INVALID_SET_ID) {
			cf_warning(AS_SECURITY, "get priv %s - can't create set", smd_priv);
			return false;
		}
	}
	else {
		set_id = as_namespace_get_set_id(ns, set_name);

		if (set_id == INVALID_SET_ID) {
			cf_warning(AS_SECURITY, "get priv %s - invalid set", smd_priv);
			return false;
		}
	}

	p_priv->set_id = set_id;

	return true;
}

//------------------------------------------------
// Add a whitelist to role-info cache - may create
// role.
//
void
act_add_whitelist(const char* p_role, uint32_t role_len, const char* whitelist)
{
	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "add whitelist failed - bad role");
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "add whitelist failed - role predefined");
		return;
	}

	rinfo* p_rinfo = NULL;
	rinfo* p_new_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) == CF_RCHASH_OK) {
		p_new_rinfo = rinfo_replace_set_whitelist(p_rinfo, whitelist);
		cf_rc_releaseandfree(p_rinfo);
	}
	else {
		p_new_rinfo = rinfo_new_add_whitelist(whitelist);
		// Creates new role.
	}

	if (p_new_rinfo == NULL) {
		cf_warning(AS_SECURITY, "add whitelist failed - bad whitelist");
		return;
	}

	g_n_whitelists++;

	cf_mutex_lock(&g_query_roles_lock);
	cf_rchash_put(g_roles, rkey, (void*)p_new_rinfo);
	cf_mutex_unlock(&g_query_roles_lock);
}

//------------------------------------------------
// Delete a whitelist from role-info cache - may
// delete role.
//
void
act_delete_whitelist(const char* p_role, uint32_t role_len)
{
	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "delete whitelist failed - bad role");
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "delete whitelist failed - role predefined");
		return;
	}

	rinfo* p_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "delete whitelist failed - role not found");
		return;
	}

	if (! rinfo_has_whitelist(p_rinfo)) {
		cf_warning(AS_SECURITY, "delete whitelist failed - no list in role");
		return;
	}

	g_n_whitelists--;

	if (rinfo_num_privs(p_rinfo) == 0 && rinfo_get_read_quota(p_rinfo) == 0 &&
			rinfo_get_write_quota(p_rinfo) == 0) {
		cf_info(AS_SECURITY, "delete whitelist - deleting empty role");
		cf_rc_releaseandfree(p_rinfo);

		cf_mutex_lock(&g_query_roles_lock);

		if (cf_rchash_delete(g_roles, rkey) != CF_RCHASH_OK) {
			cf_crash(AS_SECURITY, "delete whitelist - role not found");
		}

		cf_mutex_unlock(&g_query_roles_lock);
		return;
	}

	rinfo* p_new_rinfo = rinfo_replace_set_whitelist(p_rinfo, NULL);

	cf_rc_releaseandfree(p_rinfo);

	cf_mutex_lock(&g_query_roles_lock);
	cf_rchash_put(g_roles, rkey, (void*)p_new_rinfo);
	cf_mutex_unlock(&g_query_roles_lock);
}

//------------------------------------------------
// Add a quota to role-info cache - may create
// role.
//
void
act_add_quota(const char* p_role, uint32_t role_len, char quota_tok,
		const char* quota_str)
{
	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "add quota failed - bad role");
		return;
	}

	uint64_t quota = strtoul(quota_str, NULL, 0);

	if (quota == 0 || quota >= (uint64_t)NO_QUOTA) {
		cf_warning(AS_SECURITY, "add quota failed - bad quota value %s",
				quota_str);
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "add quota failed - role predefined");
		return;
	}

	bool is_write = quota_tok == TOK_WRITE_QUOTA;

	rinfo* p_rinfo = NULL;
	rinfo* p_new_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) == CF_RCHASH_OK) {
		p_new_rinfo = rinfo_replace_set_quota(p_rinfo, quota, is_write);
		cf_rc_releaseandfree(p_rinfo);
	}
	else {
		p_new_rinfo = rinfo_new_add_quota(quota, is_write);
		// Creates new role.
	}

	cf_mutex_lock(&g_query_roles_lock);
	cf_rchash_put(g_roles, rkey, (void*)p_new_rinfo);
	cf_mutex_unlock(&g_query_roles_lock);

	quota_info_update(rkey);
}

//------------------------------------------------
// Delete a quota from role-info cache - may
// delete role.
//
void
act_delete_quota(const char* p_role, uint32_t role_len, char quota_tok)
{
	if (role_len >= MAX_ROLE_NAME_SIZE) {
		cf_warning(AS_SECURITY, "delete quota failed - bad role");
		return;
	}

	char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

	memcpy(rkey, p_role, role_len);

	if (is_predefined_role(rkey)) {
		cf_warning(AS_SECURITY, "delete quota failed - role predefined");
		return;
	}

	rinfo* p_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) != CF_RCHASH_OK) {
		cf_warning(AS_SECURITY, "delete quota failed - role not found");
		return;
	}

	uint32_t read_quota = rinfo_get_read_quota(p_rinfo);
	uint32_t write_quota = rinfo_get_write_quota(p_rinfo);

	bool is_write = quota_tok == TOK_WRITE_QUOTA;

	if ((is_write && write_quota == 0) || (! is_write && read_quota == 0)) {
		cf_warning(AS_SECURITY, "delete quota failed - quota not in role");
		return;
	}

	bool other_quota_is_zero = is_write ? read_quota == 0 : write_quota == 0;

	if (rinfo_num_privs(p_rinfo) == 0 && ! rinfo_has_whitelist(p_rinfo) &&
			other_quota_is_zero) {
		cf_info(AS_SECURITY, "delete quota - deleting empty role");
		cf_rc_releaseandfree(p_rinfo);

		cf_mutex_lock(&g_query_roles_lock);

		if (cf_rchash_delete(g_roles, rkey) != CF_RCHASH_OK) {
			cf_crash(AS_SECURITY, "delete quota - role not found");
		}

		cf_mutex_unlock(&g_query_roles_lock);

		quota_info_update(rkey);
		return;
	}

	rinfo* p_new_rinfo = rinfo_replace_set_quota(p_rinfo, 0, is_write);

	cf_rc_releaseandfree(p_rinfo);

	cf_mutex_lock(&g_query_roles_lock);
	cf_rchash_put(g_roles, rkey, (void*)p_new_rinfo);
	cf_mutex_unlock(&g_query_roles_lock);

	quota_info_update(rkey);
}


//==========================================================
// Generic rchash helper utilities.
//

//------------------------------------------------
// Add each rchash's key pointer to the list.
//
int
collect_keys_reduce_fn(const void* p_key, void* p_value, void* udata)
{
	udata_key* p_udata_key = (udata_key*)udata;

	*p_udata_key->pp_key++ = (const char*)p_key;

	return CF_RCHASH_OK;
}

//------------------------------------------------
// Add each rchash's key pointer to the
// alphabetically sorted list.
//
int
collect_sort_keys_reduce_fn(const void* p_key, void* p_value, void* udata)
{
	udata_sort_key* p_udata_key = (udata_sort_key*)udata;
	int num_keys = (int)p_udata_key->num_keys;
	int k;

	for (k = 0; k < num_keys; k++) {
		if (strcmp((const char*)p_key, p_udata_key->pp_key[k]) < 0) {
			break;
		}
	}

	for (int j = num_keys - 1; j >= k; j--) {
		p_udata_key->pp_key[j + 1] = p_udata_key->pp_key[j];
	}

	p_udata_key->pp_key[k] = (const char*)p_key;
	p_udata_key->num_keys++;

	return CF_RCHASH_OK;
}


//==========================================================
// Generic user-info cache utilities.
//

//------------------------------------------------
// Does user have admin permission?
//
static inline bool
uinfo_is_user_admin(const uinfo* p_uinfo)
{
	return book_allows_op(uinfo_book(p_uinfo), 0, 0, PERM_USER_ADMIN);
}

//------------------------------------------------
// Update a user's info on increasing privileges
// of a role.
//
void
user_info_update_grow_role(const char* rkey, const book* p_rbook,
		uint32_t rbook_size)
{
	uint32_t num_users = cf_rchash_get_size(g_users);
	const char* ukeys[num_users];
	udata_key ukey;

	ukey.pp_key = ukeys;

	cf_rchash_reduce(g_users, collect_keys_reduce_fn, (void*)&ukey);

	for (uint32_t i = 0; i < num_users; i++) {
		uinfo* p_uinfo = NULL;

		if (cf_rchash_get(g_users, ukeys[i], (void**)&p_uinfo) !=
				CF_RCHASH_OK) {
			cf_crash(AS_SECURITY, "role expanded failed - user not found");
		}

		if (! uinfo_has_role(p_uinfo, rkey)) {
			cf_rc_releaseandfree(p_uinfo);
			continue;
		}

		uinfo* p_new_uinfo =
				uinfo_replace_grow_role(p_uinfo, rkey, p_rbook, rbook_size);

		cf_rc_releaseandfree(p_uinfo);

		cf_rchash_put(g_users, ukeys[i], (void*)p_new_uinfo);
	}
}

//------------------------------------------------
// Update a user's info on decreasing privileges
// of a role.
//
void
user_info_update_shrink_role(const char* rkey)
{
	uint32_t num_users = cf_rchash_get_size(g_users);
	const char* ukeys[num_users];
	udata_key ukey;

	ukey.pp_key = ukeys;

	cf_rchash_reduce(g_users, collect_keys_reduce_fn, (void*)&ukey);

	for (uint32_t i = 0; i < num_users; i++) {
		uinfo* p_uinfo = NULL;

		if (cf_rchash_get(g_users, ukeys[i], (void**)&p_uinfo) !=
				CF_RCHASH_OK) {
			cf_crash(AS_SECURITY, "role shrunk failed - user not found");
		}

		if (! uinfo_has_role(p_uinfo, rkey)) {
			cf_rc_releaseandfree(p_uinfo);
			continue;
		}

		uinfo* p_new_uinfo = uinfo_replace_shrink_role(p_uinfo, rkey);

		cf_rc_releaseandfree(p_uinfo);

		cf_rchash_put(g_users, ukeys[i], (void*)p_new_uinfo);
	}
}

//------------------------------------------------
// Update a user's quota info on adding or
// removing a quota to/from a role.
//
void
quota_info_update(const char* rkey)
{
	uint32_t num_users = cf_rchash_get_size(g_users);
	const char* ukeys[num_users];
	udata_key ukey;

	ukey.pp_key = ukeys;

	cf_rchash_reduce(g_users, collect_keys_reduce_fn, (void*)&ukey);

	for (uint32_t i = 0; i < num_users; i++) {
		uinfo* p_uinfo = NULL;

		if (cf_rchash_get(g_users, ukeys[i], (void**)&p_uinfo) !=
				CF_RCHASH_OK) {
			cf_crash(AS_SECURITY, "quota add failed - user not found");
		}

		if (! uinfo_has_role(p_uinfo, rkey)) {
			cf_rc_releaseandfree(p_uinfo);
			continue;
		}

		qinfo* p_qinfo = NULL;

		cf_rchash_get(g_quotas, ukeys[i], (void**)&p_qinfo);
		cf_assert(p_qinfo != NULL, AS_SECURITY, "null qinfo");

		qinfo_adjust_reset_roles(p_qinfo, uinfo_roles(p_uinfo),
				uinfo_num_roles(p_uinfo));

		cf_rc_releaseandfree(p_uinfo);
	}
}


//==========================================================
// Intra-security role cache utilities.
//

//------------------------------------------------
// Get specified role's quotas.
//
void
role_quotas(const char* rkey, uint32_t* read_quota, uint32_t* write_quota)
{
	rinfo* p_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) == CF_RCHASH_OK) {
		*read_quota = rinfo_get_read_quota(p_rinfo);
		*write_quota = rinfo_get_write_quota(p_rinfo);

		cf_rc_releaseandfree(p_rinfo);
	}
}

//------------------------------------------------
// Get specified role's permission book info.
//
const book*
role_book(const char* rkey, uint32_t* p_book_size)
{
	rinfo* p_rinfo = NULL;

	if (cf_rchash_get(g_roles, rkey, (void**)&p_rinfo) == CF_RCHASH_OK) {
		// It's ok, this won't free it - only called from SMD thread.
		cf_rc_releaseandfree(p_rinfo);

		*p_book_size = rinfo_book_size(p_rinfo);

		return rinfo_book(p_rinfo);
	}

	*p_book_size = 0;

	return NULL;
}


//==========================================================
// Generic role cache utilities.
//

//------------------------------------------------
// Is specified role predefined?
//
bool
is_predefined_role(const char* role)
{
	for (uint32_t i = 0; i < NUM_ROLES; i++) {
		if (strcmp(role, ROLES[i]) == 0) {
			return true;
		}
	}

	return false;
}

//------------------------------------------------
// Add the predefined roles to the roles cache.
//
void
role_cache_init()
{
	for (uint32_t i = 0; i < NUM_ROLES; i++) {
		char rkey[MAX_ROLE_NAME_SIZE] = { 0 };

		strcpy(rkey, ROLES[i]);

		priv_code priv;

		priv.ns_ix = NO_NS_IX;
		priv.set_id = INVALID_SET_ID;
		priv.perm_code = ROLE_PERM_CODES[i];

		rinfo* p_rinfo = rinfo_new_add_priv_only(&priv);

		cf_rchash_put(g_roles, rkey, (void*)p_rinfo);
	}
}

//------------------------------------------------
// Is specified role in role list parsed from
// wire protocol message?
//
bool
role_in_parsed_list(const char* role, const char* roles, uint32_t num_roles)
{
	for (uint32_t i = 0; i < num_roles; i++) {
		if (strcmp(role, roles) == 0) {
			return true;
		}

		roles += MAX_ROLE_NAME_SIZE;
	}

	return false;
}


//==========================================================
// Mini-class - conn_list.
//

static void
conn_tracker_insert(const char* user)
{
	conn_tracker* ct = &g_conn_tracker;

	cf_mutex_lock(&ct->lock);

	bool found;
	uint32_t i = conn_tracker_find_lockless(user, &found);

	if (found) {
		// FIXME - cf_crash instead?
		cf_warning(AS_SECURITY, "%s already specified", user);
		cf_mutex_unlock(&ct->lock);
		return;
	}

	ct->uconns = cf_realloc(ct->uconns, (ct->n_users + 1) * sizeof(user_conn));

	user_conn* match = ct->uconns + i;
	user_conn* end = ct->uconns + ct->n_users;

	if (match < end) {
		memmove(match + 1, match, (uint8_t*)end - (uint8_t*)match);
	}

	strcpy(match->user, user);
	match->n_conns = 0;

	ct->n_users++;

	cf_mutex_unlock(&ct->lock);
}

static void
conn_tracker_remove(const char* user)
{
	conn_tracker* ct = &g_conn_tracker;

	cf_mutex_lock(&ct->lock);

	bool found;
	uint32_t i = conn_tracker_find_lockless(user, &found);

	if (! found) {
		cf_warning(AS_SECURITY, "%s not found", user);
		cf_mutex_unlock(&ct->lock);
		return;
	}

	user_conn* match = ct->uconns + i;
	user_conn* next = match + 1;
	user_conn* end = ct->uconns + ct->n_users;

	if (next < end) {
		memmove(match, next, (uint8_t*)end - (uint8_t*)next);
	}

	ct->n_users--;

	cf_mutex_unlock(&ct->lock);
}

static void
conn_tracker_update_n_conns(const char* user, int32_t delta)
{
	conn_tracker* ct = &g_conn_tracker;

	cf_mutex_lock(&ct->lock);

	bool found;
	uint32_t i = conn_tracker_find_lockless(user, &found);

	if (found) {
		ct->uconns[i].n_conns += delta;
	}

	cf_mutex_unlock(&ct->lock);
}

static uint32_t
conn_tracker_get_n_conns(const char* user)
{
	conn_tracker* ct = &g_conn_tracker;

	cf_mutex_lock(&ct->lock);

	bool found;
	uint32_t i = conn_tracker_find_lockless(user, &found);
	uint32_t n_conns = found ? ct->uconns[i].n_conns : 0;

	cf_mutex_unlock(&ct->lock);

	return n_conns;
}

static uint32_t
conn_tracker_find_lockless(const char* user, bool* found)
{
	conn_tracker* ct = &g_conn_tracker;

	int lo = 0;
	int hi = (int)ct->n_users - 1;
	int i = 0;

	while (lo <= hi) {
		i = (lo + hi) / 2;

		int result = strcmp(user, ct->uconns[i].user);

		if (result > 0) { // user > i
			lo = ++i;
		}
		else if (result < 0) { // user < i
			hi = i - 1;
		}
		else { // match - i is the index of the matched item
			*found = true;
			return (uint32_t)i;
		}
	}

	// No match, i is insertion point.
	*found = false;
	return (uint32_t)i;
}


//==========================================================
// Mini-class - name_list.
//

static bool
name_list_insert(name_list* nl, const char* name)
{
	if (*name == 0 || strlen(name) >= nl->max_name_sz) {
		return false; // can't (yet) happen dynamically - startup caller warns
	}

	cf_mutex_lock(&nl->lock);

	bool found;
	uint32_t i = name_list_find_lockless(nl, name, &found);

	if (found) {
		cf_warning(AS_SECURITY, "%s already specified", name);
		cf_mutex_unlock(&nl->lock);
		return false;
	}

	nl->names = cf_realloc(nl->names, (nl->n_names + 1) * nl->max_name_sz);

	char* match = nl->names + (i * nl->max_name_sz);
	char* end = nl->names + (nl->n_names * nl->max_name_sz);

	if (match < end) {
		memmove(match + nl->max_name_sz, match, end - match);
	}

	strcpy(match, name);
	nl->n_names++;

	cf_mutex_unlock(&nl->lock);
	return true;
}

static bool
name_list_remove(name_list* nl, const char* name)
{
	if (nl->n_names == 0) {
		cf_warning(AS_SECURITY, "nothing to remove");
		return false;
	}

	cf_mutex_lock(&nl->lock);

	bool found;
	uint32_t i = name_list_find_lockless(nl, name, &found);

	if (! found) {
		cf_warning(AS_SECURITY, "%s not found", name);
		cf_mutex_unlock(&nl->lock);
		return false;
	}

	char* match = nl->names + (i * nl->max_name_sz);
	char* next = match + nl->max_name_sz;
	char* end = nl->names + (nl->n_names * nl->max_name_sz);

	if (next < end) {
		memmove(match, next, end - next);
	}

	nl->n_names--;

	cf_mutex_unlock(&nl->lock);
	return true;
}

static bool
name_list_find(name_list* nl, const char* name)
{
	if (nl->n_names == 0) {
		return false;
	}

	cf_mutex_lock(&nl->lock);

	bool found;

	name_list_find_lockless(nl, name, &found);

	cf_mutex_unlock(&nl->lock);
	return found;
}

static inline bool
name_list_is_empty(const name_list* nl)
{
	return nl->n_names == 0;
}

static void
name_list_info(name_list* nl, const char* tag, cf_dyn_buf* db)
{
	if (nl->n_names == 0) {
		return;
	}

	cf_mutex_lock(&nl->lock);

	char* name = nl->names;
	char* end = nl->names + (nl->n_names * nl->max_name_sz);
	uint32_t ix = 0;

	while (name < end) {
		info_append_indexed_string(db, tag, ix++, NULL, name);
		name += nl->max_name_sz;
	}

	cf_mutex_unlock(&nl->lock);
}

static uint32_t
name_list_find_lockless(name_list* nl, const char* name, bool* found)
{
	int lo = 0;
	int hi = (int)nl->n_names - 1;
	int i = 0;

	while (lo <= hi) {
		i = (lo + hi) / 2;

		int result = strcmp(name, nl->names + (i * nl->max_name_sz));

		if (result > 0) { // name > i
			lo = ++i;
		}
		else if (result < 0) { // name < i
			hi = i - 1;
		}
		else { // match - i is the index of the matched item
			*found = true;
			return (uint32_t)i;
		}
	}

	// No match, i is insertion point.
	*found = false;
	return (uint32_t)i;
}


//==========================================================
// Logging utilities.
//

//------------------------------------------------
// Add a data transaction log filter scope.
//
char*
add_log_scope(char* log_filter_scopes, uint32_t s, const char* ns_name,
		const char* set_name)
{
	if (! log_filter_scopes) {
		// Avoid reallocation - this is big, but we won't keep it long.
		log_filter_scopes = cf_malloc(LOG_FILTER_SCOPES_SIZE);
	}

	if (*ns_name == 0) {
		cf_crash_nostack(AS_SECURITY,
				"security cfg - missing log filter namespace");
	}

	if (strlen(ns_name) >= AS_ID_NAMESPACE_SZ) {
		cf_crash_nostack(AS_SECURITY,
				"security cfg - invalid log filter namespace %s", ns_name);
	}

	if (strlen(set_name) >= AS_SET_NAME_MAX_SIZE) {
		cf_crash_nostack(AS_SECURITY,
				"security cfg - invalid log filter set %s", set_name);
	}

	char* p_write = &log_filter_scopes[s * LOG_FILTER_SCOPE_MAX_SIZE];

	strcpy(p_write, ns_name);
	strcpy(p_write + AS_ID_NAMESPACE_SZ, set_name);

	return log_filter_scopes;
}

//------------------------------------------------
// Set up a data transaction log filter.
//
bool*
create_log_filter(char* log_filter_scopes, uint32_t num_scopes)
{
	bool* log_filter = cf_calloc(1, g_log_filter_size);

	char* p_read = log_filter_scopes;

	for (uint32_t s = 0; s < num_scopes; s++) {
		as_namespace* ns = as_namespace_get_byname(p_read);

		if (! ns) {
			cf_crash(AS_SECURITY, "security init - invalid namespace %s",
					p_read);
		}

		uint32_t ns_ix = ns->ix;

		const char* set_name = p_read + AS_ID_NAMESPACE_SZ;
		uint16_t set_id = 0;

		if (*set_name) {
			set_id = as_namespace_get_create_set_id(ns, set_name);

			if (set_id == 0) {
				cf_crash(AS_SECURITY, "security init - get/create set %s",
						set_name);
			}
		}

		if (set_id == 0) {
			// No set name means log everything in the namespace.

			uint32_t start = ns_ix * LOG_FILTER_NUM_SETS;
			uint32_t end = start + LOG_FILTER_NUM_SETS;

			for (uint32_t i = start; i < end; i++) {
				log_filter[i] = true;
			}
		}
		else {
			log_filter[(ns_ix * LOG_FILTER_NUM_SETS) + set_id] = true;
		}

		p_read += LOG_FILTER_SCOPE_MAX_SIZE;
	}

	cf_free(log_filter_scopes);

	return log_filter;
}

//------------------------------------------------
// Set up the data transaction log filters.
//
void
init_log_filters()
{
	if (g_log_filter_scopes != NULL) {
		g_log_filter = create_log_filter(g_log_filter_scopes,
				g_num_log_filter_scopes);
	}

	if (g_syslog_filter_scopes != NULL) {
		g_syslog_filter = create_log_filter(g_syslog_filter_scopes,
				g_num_syslog_filter_scopes);
	}
}

//------------------------------------------------
// Construct scope strings from log filters.
//
void
get_data_op_scopes(bool* log_filter, const char* tag, cf_dyn_buf* db)
{
	if (log_filter == NULL) {
		return;
	}

	uint32_t ix = 0;

	for (uint32_t ns_ix = 0; ns_ix < g_num_namespaces; ns_ix++) {
		as_namespace* ns = g_config.namespaces[ns_ix];

		bool* row = &log_filter[ns_ix * LOG_FILTER_NUM_SETS];

		if (row[0]) {
			info_append_indexed_string(db, tag, ix++, NULL, ns->name);
			continue;
		}

		char scope[AS_ID_NAMESPACE_SZ + AS_SET_NAME_MAX_SIZE];
		size_t ns_name_len = strlen(ns->name);
		char* at = scope + ns_name_len;

		strcpy(scope, ns->name);
		*at++ = '|';

		for (uint32_t set_id = 1; set_id < LOG_FILTER_NUM_SETS; set_id++) {
			if (row[set_id]) {
				strcpy(at, as_namespace_get_set_name(ns, set_id));
				info_append_indexed_string(db, tag, ix++, NULL, scope);
			}
		}
	}
}

//------------------------------------------------
// Adjust the data transaction log filters.
//
bool
adjust_log_filter(bool* log_filter, as_namespace* ns, const char* set_name,
		bool enable)
{
	uint32_t start = ns->ix * LOG_FILTER_NUM_SETS;

	if (enable) {
		if (set_name == NULL) {
			if (log_filter[start]) {
				return true;
			}

			uint32_t end = start + LOG_FILTER_NUM_SETS;

			for (uint32_t i = start; i < end; i++) {
				log_filter[i] = true;
			}
		}
		else {
			if (log_filter[start]) {
				cf_info(AS_SECURITY, "whole namespace %s already enabled",
						ns->name);
				return true;
			}

			uint16_t set_id = as_namespace_get_create_set_id(ns, set_name);

			if (set_id == 0) {
				cf_warning(AS_SECURITY, "failed create set %s", set_name);
				return false;
			}

			log_filter[start + set_id] = true;
		}
	}
	else {
		if (set_name == NULL) {
			bool already_disabled = ! log_filter[start];

			if (already_disabled) {
				cf_info(AS_SECURITY, "whole namespace %s already disabled",
						ns->name);
			}

			uint32_t end = start + LOG_FILTER_NUM_SETS;

			for (uint32_t i = start; i < end; i++) {
				if (already_disabled && log_filter[i]) { // never true at start
					cf_info(AS_SECURITY, "... disabling set %s",
							as_namespace_get_set_name(ns, i - start));
				}

				log_filter[i] = false;
			}
		}
		else {
			// Don't allow "log everything except this set" functionality since
			// we can't currently specify this via config file.
			if (log_filter[start]) {
				cf_warning(AS_SECURITY, "whole namespace %s enabled", ns->name);
				return false;
			}

			uint16_t set_id = as_namespace_get_set_id(ns, set_name);

			if (set_id == 0) {
				cf_warning(AS_SECURITY, "unknown set %s", set_name);
				return false;
			}

			log_filter[start + set_id] = false;
		}
	}

	return true;
}

//------------------------------------------------
// Log login failures.
//
void
log_login_failure(const as_file_handle* fd_h, uint8_t result,
		const char* p_user, uint32_t user_len)
{
	if (g_config.sec_cfg.report.violation != 0) {
		login_log(g_config.sec_cfg.report.violation, fd_h,
				result, p_user, user_len, NULL, 0);
	}
}

//------------------------------------------------
// Log login successes.
//
void
log_login_success(const as_file_handle* fd_h, const char* p_user,
		uint32_t user_len, const char* roles, uint32_t num_roles)
{
	if (g_config.sec_cfg.report.authentication != 0) {
		login_log(g_config.sec_cfg.report.authentication, fd_h, AS_OK, p_user,
				user_len, roles, num_roles);
	}
}

//------------------------------------------------
// Log authentication failures.
//
void
log_auth_failure(const as_file_handle* fd_h, uint8_t result,
		as_sec_msg_field* req_fields[])
{
	if (g_config.sec_cfg.report.violation != 0) {
		sec_msg_log(g_config.sec_cfg.report.violation, fd_h, result,
				"authentication", req_fields);
	}
}

//------------------------------------------------
// Log authentication successes.
//
void
log_auth_success(const as_file_handle* fd_h, as_sec_msg_field* req_fields[])
{
	if (g_config.sec_cfg.report.authentication != 0) {
		sec_msg_log(g_config.sec_cfg.report.authentication, fd_h, AS_OK,
				"authentication", req_fields);
	}
}

//------------------------------------------------
// Successful data transactions call this to log
// to the security 'audit trail'.
//
void
log_data_op(const as_file_handle* fd_h, uint32_t ns_ix, uint16_t set_id,
		as_sec_perm perm, const char* detail)
{
	if (g_config.sec_cfg.report.data_op == 0) {
		return;
	}

	uint32_t sinks = 0;
	uint32_t filter_index = (ns_ix * LOG_FILTER_NUM_SETS) + set_id;

	if (g_log_filter != NULL) {
		sinks |= g_log_filter[filter_index] ? AS_SEC_SINK_LOG : 0;
	}

	if (g_syslog_filter != NULL) {
		sinks |= g_syslog_filter[filter_index] ? AS_SEC_SINK_SYSLOG : 0;
	}

	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);

	if ((sinks & AS_SEC_SINK_LOG) == 0 &&
			name_list_find(&g_log_filter_users, p_filter->user)) {
		sinks |= AS_SEC_SINK_LOG;
	}

	if ((sinks & AS_SEC_SINK_LOG) == 0 &&
			! name_list_is_empty(&g_log_filter_roles)) {
		uint32_t n_roles = uinfo_num_roles(p_filter->p_uinfo);
		const char* role = uinfo_roles(p_filter->p_uinfo);

		for (uint32_t n = 0; n < n_roles; n++) {
			if (name_list_find(&g_log_filter_roles, role)) {
				sinks |= AS_SEC_SINK_LOG;
				break;
			}

			role = uinfo_next_role(role);
		}
	}

	if ((sinks & AS_SEC_SINK_SYSLOG) == 0 &&
			name_list_find(&g_syslog_filter_users, p_filter->user)) {
		sinks |= AS_SEC_SINK_SYSLOG;
	}

	if ((sinks & AS_SEC_SINK_SYSLOG) == 0 &&
			! name_list_is_empty(&g_syslog_filter_roles)) {
		uint32_t n_roles = uinfo_num_roles(p_filter->p_uinfo);
		const char* role = uinfo_roles(p_filter->p_uinfo);

		for (uint32_t n = 0; n < n_roles; n++) {
			if (name_list_find(&g_syslog_filter_roles, role)) {
				sinks |= AS_SEC_SINK_SYSLOG;
				break;
			}

			role = uinfo_next_role(role);
		}
	}

	if (sinks == 0) {
		cf_mutex_unlock(&p_filter->lock);
		return;
	}

	sec_log(sinks, AS_OK, fd_h->client, p_filter->user, perm_tag(perm), detail);

	cf_mutex_unlock(&p_filter->lock);
}

//------------------------------------------------
// Log attempted user-admin commands.
//
void
log_user_admin(const as_file_handle* fd_h, uint8_t result, const char* cmd,
		as_sec_msg_field* req_fields[])
{
	switch (result) {
	case AS_OK:
		if (g_config.sec_cfg.report.user_admin != 0) {
			sec_msg_log(g_config.sec_cfg.report.user_admin, fd_h, result, cmd,
					req_fields);
		}
		break;
	case AS_SEC_ERR_NOT_AUTHENTICATED:
		// Here we know fd_h is valid but will have no user - fall through.
	case AS_SEC_ERR_ROLE_VIOLATION:
		if (g_config.sec_cfg.report.violation != 0) {
			sec_msg_log(g_config.sec_cfg.report.violation, fd_h, result, cmd,
					req_fields);
		}
		break;
	default:
		// Should never get here.
		cf_warning(AS_SECURITY, "log user-admin - result %u", result);
		break;
	}
}

//------------------------------------------------
// Get digest's string representation for logging.
//
bool
msg_digest_str(as_transaction* tr, char* d_str)
{
	if (as_transaction_is_query(tr)) {
		return false;
	}
	// else - single-record tr always has digest at this point.

	*d_str++ = 'D';
	*d_str++ = '|';

	const uint8_t* from_bytes = (const uint8_t*)&tr->keyd;
	const uint8_t* p_end = from_bytes + sizeof(cf_digest);

	while (from_bytes < p_end) {
		d_str += sprintf(d_str, "%02x", *from_bytes++);
	}

	*d_str = 0;

	return true;
}

//------------------------------------------------
// Get key's string representation for logging.
//
bool
msg_key_str(as_transaction* tr, char* key_str)
{
	if (! as_transaction_has_key(tr)) {
		return false;
	}

	as_msg_field* f = as_msg_field_get(&tr->msgp->msg, AS_MSG_FIELD_TYPE_KEY);
	size_t flat_key_size = as_msg_field_get_value_sz(f);

	if (flat_key_size == 0) {
		cf_warning(AS_SECURITY, "msg flat key size is 0");
		return false;
	}

	const uint8_t* flat_key = (const uint8_t*)f->data;
	uint8_t type = *flat_key;
	const uint8_t* key = flat_key + 1;

	switch (type) {
		case AS_PARTICLE_TYPE_INTEGER:
			if (flat_key_size != 1 + sizeof(uint64_t)) {
				cf_warning(AS_SECURITY, "bad msg integer key flat size %zu",
						flat_key_size);
				return false;
			}
			// Flat integer keys are in big-endian order.
			sprintf(key_str, "I|%lu", cf_swap_from_be64(*(uint64_t*)key));
			return true;
		case AS_PARTICLE_TYPE_STRING:
		{
			*key_str++ = 'S';
			*key_str++ = '|';

			uint32_t len = flat_key_size - 1;

			if (len > MAX_KEY_STR_LEN) {
				len = MAX_KEY_STR_LEN;
			}

			memcpy(key_str, key, len);
			key_str[len] = 0;

			return true;
		}
		case AS_PARTICLE_TYPE_BLOB:
			*key_str++ = 'B';
			break;
		default:
			*key_str++ = '?';
			break;
	}

	*key_str++ = '|';

	uint32_t key_size = flat_key_size - 1;

	if (key_size == 0) {
		cf_warning(AS_SECURITY, "msg key size is 0");
		*key_str = 0;
		return true;
	}

	if (key_size > MAX_KEY_STR_LEN / 3) {
		key_size = MAX_KEY_STR_LEN / 3;
	}

	const uint8_t* p_end = key + key_size;

	while (key < p_end) {
		key_str += sprintf(key_str, "%02x ", *key++);
	}

	*(key_str - 1) = 0;

	return true;
}

//------------------------------------------------
// Get set name and ID for logging.
//
uint16_t
msg_set(as_transaction* tr, as_namespace* ns, char* msg_set_name)
{
	as_msg_field* f = as_transaction_has_set(tr) ?
			as_msg_field_get(&tr->msgp->msg, AS_MSG_FIELD_TYPE_SET) : NULL;

	if (! f || as_msg_field_get_value_sz(f) == 0) {
		return INVALID_SET_ID;
	}

	size_t msg_set_name_len = as_msg_field_get_value_sz(f);

	if (msg_set_name_len >= AS_SET_NAME_MAX_SIZE) {
		cf_warning(AS_SECURITY, "security check - set name too long");
		msg_set_name_len = AS_SET_NAME_MAX_SIZE - 1;
	}

	memcpy((void*)msg_set_name, (const void*)f->data, msg_set_name_len);
	msg_set_name[msg_set_name_len] = 0;

	// Note: we don't assign an ID if this is the first transaction in this set.
	// We'll return 0, and the security check will only pass with namespace or
	// global scoped permissions. (If a set-scoped permission was granted, it
	// would have assigned this set's ID.)

	return as_namespace_get_set_id(ns, msg_set_name);
}

//------------------------------------------------
// Convert perm codes to strings for logging.
//
static inline const char*
perm_code_tag(uint32_t perm_code)
{
	switch (perm_code) {
	case AS_SEC_PERM_CODE_USER_ADMIN:
		return "u";
	case AS_SEC_PERM_CODE_SYS_ADMIN:
		return "s";
	case AS_SEC_PERM_CODE_DATA_ADMIN:
		return "d";
	case AS_SEC_PERM_CODE_UDF_ADMIN:
		return "fa";
	case AS_SEC_PERM_CODE_SINDEX_ADMIN:
		return "ia";
	case AS_SEC_PERM_CODE_READ:
		return "r";
	case AS_SEC_PERM_CODE_READ_WRITE:
		return "rw";
	case AS_SEC_PERM_CODE_READ_WRITE_UDF:
		return "rwf";
	case AS_SEC_PERM_CODE_WRITE:
		return "w";
	case AS_SEC_PERM_CODE_TRUNCATE:
		return "t";
	default:
		// Should never get here.
		return "?";
	}
}

//------------------------------------------------
// Convert relevant perms to action strings. We
// expect only data transactions via thr_tsvc.c to
// need this conversion.
//
static inline const char*
perm_tag(as_sec_perm perm)
{
	switch ((uint64_t)perm) {
	case PERM_NONE:
		// TODO - try harder in thr_tsvc.c to identify transaction type?
		return "data transaction";
	case PERM_READ:
		return "read";
	case PERM_QUERY:
		return "query";
	case PERM_WRITE:
		return "write";
	// Note - typecast in switch - some compilers allow only enum members.
	case PERM_WRITE | PERM_READ:
		return "write + read";
	case PERM_DELETE:
		return "delete";
	case PERM_UDF_APPLY:
		return "udf apply";
	case PERM_UDF_QUERY:
		return "udf query";
	case PERM_OPS_QUERY:
		return "ops query";
	default:
		// Should never get here.
		return "<unexpected action>";
	}
}

//------------------------------------------------
// Convert relevant results to strings.
//
static inline const char*
result_tag(uint8_t result)
{
	switch (result) {
	case AS_OK:
		return "permitted";
	case AS_SEC_ERR_NOT_AUTHENTICATED:
		return "not authenticated";
	case AS_SEC_ERR_ROLE_VIOLATION:
		return "role violation";
	case AS_SEC_ERR_NOT_WHITELISTED:
		return "not whitelisted";
	case AS_SEC_ERR_QUOTA_EXCEEDED:
		return "quota exceeded";
	// The following cases only occur when authentication fails.
	case AS_SEC_ERR_USER:
		return "authentication failed (user)";
	case AS_SEC_ERR_CREDENTIAL:
		return "authentication failed (credential)";
	case AS_SEC_ERR_PASSWORD:
		return "authentication failed (password)";
	case AS_SEC_ERR_EXPIRED_SESSION:
		return "authentication failed (session expired)";
	// When LDAP authentication fails.
	case AS_SEC_ERR_LDAP_NOT_CONFIGURED:
		return "LDAP not configured";
	case AS_SEC_ERR_LDAP_SETUP:
		return "LDAP setup failed";
	case AS_SEC_ERR_LDAP_TLS_SETUP:
		return "LDAP TLS setup failed";
	case AS_SEC_ERR_LDAP_AUTHENTICATION:
		return "LDAP authentication failed";
	case AS_SEC_ERR_LDAP_QUERY:
		return "LDAP role query failed";
	default:
		// Should never get here.
		return "<unexpected result>";
	}
}

//------------------------------------------------
// Log login results.
//
void
login_log(uint32_t sinks, const as_file_handle* fd_h, uint8_t result,
		const char* p_user, uint32_t user_len, const char* roles,
		uint32_t num_roles)
{
	cf_dyn_buf_define_size(db, 2048);

	cf_dyn_buf_append_buf(&db, (uint8_t*)USER_TAG, sizeof(USER_TAG) - 1);
	cf_dyn_buf_append_buf(&db, (uint8_t*)p_user, user_len);

	if (roles) {
		cf_dyn_buf_append_char(&db, ';');
		cf_dyn_buf_append_buf(&db, (uint8_t*)ROLES_TAG, sizeof(ROLES_TAG) - 1);

		const char* role = roles;
		const char* end = roles + (num_roles * MAX_ROLE_NAME_SIZE);

		while (role < end) {
			cf_dyn_buf_append_string(&db, role);
			cf_dyn_buf_append_char(&db, ',');
			role += MAX_ROLE_NAME_SIZE;
		}

		cf_dyn_buf_chomp(&db);
	}

	cf_dyn_buf_append_char(&db, 0);

	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);
	sec_log(sinks, result, fd_h->client, p_filter->user, "login",
			(const char*)db.buf);
	cf_mutex_unlock(&p_filter->lock);

	cf_dyn_buf_free(&db);
}

//------------------------------------------------
// Log security message content.
//
void
sec_msg_log(uint32_t sinks, const as_file_handle* fd_h, uint8_t result,
		const char* cmd, as_sec_msg_field* req_fields[])
{
	cf_dyn_buf_define_size(db, 2048);

	as_sec_msg_field* pf_user = req_fields[AS_SEC_FIELD_USER];
	as_sec_msg_field* pf_roles = req_fields[AS_SEC_FIELD_ROLES];
	as_sec_msg_field* pf_role = req_fields[AS_SEC_FIELD_ROLE];
	as_sec_msg_field* pf_privs = req_fields[AS_SEC_FIELD_PRIVS];
	as_sec_msg_field* pf_whitelist = req_fields[AS_SEC_FIELD_WHITELIST];
	as_sec_msg_field* pf_read_quota = req_fields[AS_SEC_FIELD_READ_QUOTA];
	as_sec_msg_field* pf_write_quota = req_fields[AS_SEC_FIELD_WRITE_QUOTA];

	if (pf_user != NULL) {
		cf_dyn_buf_append_buf(&db, (uint8_t*)USER_TAG, sizeof(USER_TAG) - 1);
		cf_dyn_buf_append_buf(&db, pf_user->value,
				msg_field_value_size(pf_user));
		cf_dyn_buf_append_char(&db, ';');
	}

	if (pf_roles != NULL) {
		cf_dyn_buf_append_buf(&db, (uint8_t*)ROLES_TAG, sizeof(ROLES_TAG) - 1);

		uint32_t roles_len = 0;
		char* roles = sec_msg_log_parse_roles(pf_roles->value,
				msg_field_value_size(pf_roles), &roles_len);

		if (roles != NULL) {
			cf_dyn_buf_append_buf(&db, (uint8_t*)roles, roles_len);
			cf_free(roles);
		}
		else {
			cf_dyn_buf_append_buf(&db, (uint8_t*)ERR_TAG, sizeof(ERR_TAG) - 1);
		}

		cf_dyn_buf_append_char(&db, ';');
	}

	if (pf_role != NULL) {
		cf_dyn_buf_append_buf(&db, (uint8_t*)ROLE_TAG, sizeof(ROLE_TAG) - 1);
		cf_dyn_buf_append_buf(&db, pf_role->value,
				msg_field_value_size(pf_role));
		cf_dyn_buf_append_char(&db, ';');
	}

	if (pf_privs != NULL) {
		cf_dyn_buf_append_buf(&db, (uint8_t*)PRIVS_TAG, sizeof(PRIVS_TAG) - 1);

		uint32_t privs_len = 0;
		char* privs = sec_msg_log_parse_privs(pf_privs->value,
				msg_field_value_size(pf_privs), &privs_len);

		if (privs != NULL) {
			cf_dyn_buf_append_buf(&db, (uint8_t*)privs, privs_len);
			cf_free(privs);
		}
		else {
			cf_dyn_buf_append_buf(&db, (uint8_t*)ERR_TAG, sizeof(ERR_TAG) - 1);
		}

		cf_dyn_buf_append_char(&db, ';');
	}

	if (pf_whitelist != NULL) {
		cf_dyn_buf_append_buf(&db, (uint8_t*)WHITELIST_TAG,
				sizeof(WHITELIST_TAG) - 1);
		cf_dyn_buf_append_buf(&db, pf_whitelist->value,
				msg_field_value_size(pf_whitelist));
		cf_dyn_buf_append_char(&db, ';');
	}

	if (pf_read_quota != NULL) {
		cf_dyn_buf_append_buf(&db, (uint8_t*)READ_QUOTA_TAG,
				sizeof(READ_QUOTA_TAG) - 1);

		uint32_t value;

		if (msg_field_uint32_value(pf_read_quota, &value)) {
			cf_dyn_buf_append_uint32(&db, value);
		}
		else {
			cf_dyn_buf_append_buf(&db, (uint8_t*)ERR_TAG, sizeof(ERR_TAG) - 1);
		}

		cf_dyn_buf_append_char(&db, ';');
	}

	if (pf_write_quota != NULL) {
		cf_dyn_buf_append_buf(&db, (uint8_t*)WRITE_QUOTA_TAG,
				sizeof(WRITE_QUOTA_TAG) - 1);

		uint32_t value;

		if (msg_field_uint32_value(pf_write_quota, &value)) {
			cf_dyn_buf_append_uint32(&db, value);
		}
		else {
			cf_dyn_buf_append_buf(&db, (uint8_t*)ERR_TAG, sizeof(ERR_TAG) - 1);
		}

		cf_dyn_buf_append_char(&db, ';');
	}

	cf_dyn_buf_chomp_char(&db, ';');
	cf_dyn_buf_append_char(&db, 0);

	as_sec_filter* p_filter = (as_sec_filter*)fd_h->security_filter;

	cf_mutex_lock(&p_filter->lock);
	sec_log(sinks, result, fd_h->client, p_filter->user, cmd,
			(const char*)db.buf);
	cf_mutex_unlock(&p_filter->lock);

	cf_dyn_buf_free(&db);
}

//------------------------------------------------
// Parse a as_sec_msg privileges field and return
// a string representation to log.
//
char*
sec_msg_log_parse_privs(const uint8_t* p_privs, uint32_t privs_size,
		uint32_t* p_len)
{
	if (privs_size == 0) {
		cf_warning(AS_SECURITY, "log parse privs - field size 0");
		return NULL;
	}

	const uint8_t* p_read = p_privs;
	const uint8_t* p_end = p_privs + privs_size;

	uint32_t num_privs = (uint32_t)*p_read++;

	if (num_privs == 0) {
		cf_warning(AS_SECURITY, "log parse privs - no privs");
		return NULL;
	}

	char* log_privs = cf_malloc(num_privs * LOG_PRIV_MAX_SIZE);
	char* p_write = log_privs;

	for (uint32_t j = 0; j < num_privs; j++) {
		if (j != 0) {
			*p_write++ = ',';
		}

		if (p_read >= p_end) {
			cf_warning(AS_SECURITY, "log parse privs - incomplete");
			cf_free(log_privs);
			return NULL;
		}

		uint32_t m = (uint32_t)*p_read++;

		if (! is_valid_perm_code(m)) {
			cf_warning(AS_SECURITY, "log parse privs - invalid perm code");
			cf_free(log_privs);
			return NULL;
		}

		p_write += sprintf(p_write, "%s", perm_code_tag(m));

		if (is_global_scope_perm_code(m)) {
			// Mandatory global scope - no namespace or set in wire protocol.
			continue;
		}

		if (p_read >= p_end) {
			cf_warning(AS_SECURITY, "log parse privs - incomplete");
			cf_free(log_privs);
			return NULL;
		}

		uint32_t ns_len = (uint32_t)*p_read++;
		const char* p_ns = (const char*)p_read;

		p_read += ns_len;

		if (p_read >= p_end) {
			cf_warning(AS_SECURITY, "log parse privs - incomplete");
			cf_free(log_privs);
			return NULL;
		}

		uint32_t set_len = (uint32_t)*p_read++;
		const char* p_set = (const char*)p_read;

		p_read += set_len;

		if (p_read > p_end) {
			cf_warning(AS_SECURITY, "log parse privs - incomplete");
			cf_free(log_privs);
			return NULL;
		}

		*p_write++ = '{';

		if (ns_len == 0) {
			if (set_len != 0) {
				cf_warning(AS_SECURITY, "log parse privs - extraneous set");
				cf_free(log_privs);
				return NULL;
			}

			// Global scope - no namespace or set.
			*p_write++ = '}';
			continue;
		}

		as_namespace* ns = as_namespace_get_bybuf((uint8_t*)p_ns, ns_len);

		if (! ns) {
			cf_warning(AS_SECURITY, "log parse privs - invalid ns");
		}

		memcpy(p_write, p_ns, ns_len);
		p_write += ns_len;

		if (set_len == 0) {
			// Namespace scope - no set.
			*p_write++ = '}';
			continue;
		}

		*p_write++ = '|';
		memcpy(p_write, p_set, set_len);
		p_write += set_len;
		*p_write++ = '}';
	}

	*p_len = (uint32_t)(p_write - log_privs);

	return log_privs;
}

//------------------------------------------------
// Parse a as_sec_msg roles field and return
// a string representation to log.
//
char*
sec_msg_log_parse_roles(const uint8_t* p_roles, uint32_t roles_size,
		uint32_t* p_len)
{
	if (roles_size == 0) {
		cf_warning(AS_SECURITY, "log parse roles - field size 0");
		return NULL;
	}

	const uint8_t* p_read = p_roles;
	const uint8_t* p_end = p_roles + roles_size;

	uint32_t num_roles = (uint32_t)*p_read++;

	if (num_roles == 0) {
		if (p_read != p_end) {
			cf_warning(AS_SECURITY, "log parse roles - extraneous bytes");
			return NULL;
		}

		static const char NO_ROLES_TAG[] = "<none>";

		*p_len = sizeof(NO_ROLES_TAG) - 1;

		return cf_strdup(NO_ROLES_TAG);
	}

	char* log_roles = cf_malloc(num_roles * MAX_ROLE_NAME_SIZE);
	char* p_write = log_roles;

	for (uint32_t j = 0; j < num_roles; j++) {
		if (j != 0) {
			*p_write++ = ',';
		}

		if (p_read >= p_end) {
			cf_warning(AS_SECURITY, "log parse roles - incomplete");
			cf_free(log_roles);
			return NULL;
		}

		uint32_t role_len = (uint32_t)*p_read++;
		const char* p_role = (const char*)p_read;

		p_read += role_len;

		if (p_read > p_end) {
			cf_warning(AS_SECURITY, "log parse roles - incomplete");
			cf_free(log_roles);
			return NULL;
		}

		if (role_len >= MAX_ROLE_NAME_SIZE) {
			cf_warning(AS_SECURITY, "log parse roles - bad role len");
		}

		memcpy(p_write, p_role, role_len);
		p_write += role_len;
	}

	*p_len = (uint32_t)(p_write - log_roles);

	return log_roles;
}

//------------------------------------------------
// Log to all specified sinks.
//
void
sec_log(uint32_t sinks, uint8_t result, const char* client, const char* user,
		const char* action, const char* detail)
{
	if (! (user && *user != 0)) {
		user = "<none>";
	}

	if (! (action && *action != 0)) {
		action = "<none>";
	}

	if (! (detail && *detail != 0)) {
		detail = "<none>";
	}

	static const char SEC_LOG_FMT[] =
		"%s | client: %s | authenticated user: %s | action: %s | detail: %s";

	if ((sinks & AS_SEC_SINK_LOG) != 0) {
		cf_info(AS_AUDIT, (char*)SEC_LOG_FMT, result_tag(result), client, user,
				action, detail);
	}

	if ((sinks & AS_SEC_SINK_SYSLOG) != 0) {
		syslog(LOG_INFO, SEC_LOG_FMT, result_tag(result), client, user, action,
				detail);
	}
}
