/*
 * security_ee.h
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
// Includes.
//

#include <stdbool.h>
#include <stdint.h>

#include "dynbuf.h"


//==========================================================
// Forward declarations.
//

struct as_file_handle_s;
struct as_namespace_s;
struct book_s;


//==========================================================
// Typedefs & constants.
//

// Security message commands.
#define AS_SEC_CMD_AUTHENTICATE		0
#define AS_SEC_CMD_CREATE_USER		1
#define AS_SEC_CMD_DROP_USER		2
#define AS_SEC_CMD_SET_PASSWORD		3
#define AS_SEC_CMD_CHANGE_PASSWORD	4
#define AS_SEC_CMD_GRANT_ROLES		5
#define AS_SEC_CMD_REVOKE_ROLES		6
#define AS_SEC_CMD_UNUSED_7			7
#define AS_SEC_CMD_UNUSED_8			8
#define AS_SEC_CMD_QUERY_USERS		9
#define AS_SEC_CMD_CREATE_ROLE		10
#define AS_SEC_CMD_DELETE_ROLE		11
#define AS_SEC_CMD_ADD_PRIVS		12
#define AS_SEC_CMD_DELETE_PRIVS		13
#define AS_SEC_CMD_SET_WHITELIST	14
#define AS_SEC_CMD_SET_QUOTAS		15
#define AS_SEC_CMD_QUERY_ROLES		16
#define AS_SEC_CMD_UNUSED_17		17
#define AS_SEC_CMD_UNUSED_18		18
#define AS_SEC_CMD_UNUSED_19		19
#define AS_SEC_CMD_LOGIN			20

// Security message field IDs.
#define AS_SEC_FIELD_USER			0
#define AS_SEC_FIELD_PASSWORD		1
#define AS_SEC_FIELD_OLD_PASSWORD	2
#define AS_SEC_FIELD_CREDENTIAL		3
#define AS_SEC_FIELD_CLEAR_PASSWORD	4
#define AS_SEC_FIELD_SESSION_TOKEN	5
#define AS_SEC_FIELD_SESSION_TTL	6
#define AS_SEC_FIELD_ROLES			10
#define AS_SEC_FIELD_ROLE			11
#define AS_SEC_FIELD_PRIVS			12
#define AS_SEC_FIELD_WHITELIST		13
#define AS_SEC_FIELD_READ_QUOTA		14
#define AS_SEC_FIELD_WRITE_QUOTA	15
#define AS_SEC_FIELD_READ_INFO		16
#define AS_SEC_FIELD_WRITE_INFO		17
#define AS_SEC_FIELD_CONNECTIONS	18
#define AS_SEC_FIELD_LAST_PLUS_1	19 // for the field pointer array

// A message field has a size and an ID-value pair - just like as_msg_field.
typedef struct as_sec_msg_field_s {
	uint32_t	size;		// size of id plus value
	uint8_t		id;			// the field's ID
	uint8_t		value[];	// the field's value
} __attribute__((__packed__)) as_sec_msg_field;

// Includes null-terminator, so max length is really 63.
#define MAX_USER_SIZE 64

// In the user-info cache passwords are not null-terminated.
#define PASSWORD_LEN 60

// Includes null-terminator, so max length is really 63.
#define MAX_ROLE_NAME_SIZE 64

// Permission codes used in wire protocol, SMD, and priv_code.
#define AS_SEC_PERM_CODE_USER_ADMIN				0
#define AS_SEC_PERM_CODE_SYS_ADMIN				1
#define AS_SEC_PERM_CODE_DATA_ADMIN				2
#define AS_SEC_PERM_CODE_UDF_ADMIN				3
#define AS_SEC_PERM_CODE_SINDEX_ADMIN			4
#define AS_SEC_PERM_CODE_LAST_GLOBAL_PLUS_1		5
#define AS_SEC_PERM_CODE_FIRST_NON_GLOBAL		10
#define AS_SEC_PERM_CODE_READ					10
#define AS_SEC_PERM_CODE_READ_WRITE				11
#define AS_SEC_PERM_CODE_READ_WRITE_UDF			12
#define AS_SEC_PERM_CODE_WRITE					13
#define AS_SEC_PERM_CODE_TRUNCATE				14
#define AS_SEC_PERM_CODE_LAST_PLUS_1			15

// Intra-security globals.
extern uint32_t g_num_namespaces;
extern const uint64_t ROLE_PERMS[];

// Privilege info structure used in role cache, and as wire protocol and SMD
// intermediary.
typedef struct priv_code_s {
	uint32_t	perm_code:8;
	uint32_t	ns_ix:8;
	uint32_t	set_id:16;
} priv_code;


//==========================================================
// Public API.
//

static inline bool
priv_eq(const priv_code* p_priv1, const priv_code* p_priv2)
{
	return p_priv1->perm_code == p_priv2->perm_code &&
			p_priv1->ns_ix == p_priv2->ns_ix &&
			p_priv1->set_id == p_priv2->set_id;
}

void role_quotas(const char* rkey, uint32_t* read_quota, uint32_t* write_quota);
const struct book_s* role_book(const char* rkey, uint32_t* p_book_size);

void as_security_cfg_post_process(void);
void as_security_get_data_op_scopes(uint32_t sinks, cf_dyn_buf* db);
void as_security_get_data_op_roles(uint32_t sinks, cf_dyn_buf* db);
void as_security_get_data_op_users(uint32_t sinks, cf_dyn_buf* db);
bool as_security_adjust_log_scope(uint32_t sink, struct as_namespace_s* ns, const char* set_name, bool enable);
bool as_security_adjust_log_role(uint32_t sink, const char* role, bool enable);
bool as_security_adjust_log_user(uint32_t sink, const char* user, bool enable);
void as_security_log_quota_violation(const char* user, uint32_t quota, bool is_write);

// API for external authentication modules (so far, only LDAP).
void as_security_login_failed(struct as_file_handle_s* fd_h, uint8_t result, const char* p_user, uint32_t user_len);
void as_security_login_succeeded(struct as_file_handle_s* fd_h, const char* p_user, uint32_t user_len, const char* roles, uint32_t num_roles, const uint8_t* token, uint32_t token_size, uint32_t ttl);
bool as_security_ip_addr_ok(struct as_file_handle_s* fd_h, const char* roles, uint32_t num_roles);
void as_security_new_session(struct as_file_handle_s* fd_h, const char* p_user, uint32_t user_len, const char* roles, uint32_t num_roles);
char* as_security_get_external_users(uint32_t* p_num_external_users);
void as_security_drop_external_user(const char* p_user, uint32_t user_len);
void as_security_update_roles(const char* p_user, uint32_t user_len, const char* roles, uint32_t num_roles);
bool as_security_add_aerospike_role(char* dest, const char* p_role, uint32_t role_len);
