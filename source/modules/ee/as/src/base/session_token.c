/*
 * session_token.c
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

#include "base/session_token.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_random.h"

#include "log.h"

#include "base/cfg.h"
#include "base/proto.h"
#include "base/security_config.h"


//==========================================================
// Typedefs & constants.
//

typedef const EVP_MD* (*md_method)(void);

// Must be synchronized with as_sec_ldap_evp_md enum!
const md_method EVP_METHODS[] = {
		EVP_sha256,
		EVP_sha512
};

COMPILER_ASSERT(sizeof(EVP_METHODS) / sizeof(md_method) == AS_LDAP_NUM_EVP_MDS);

const uint8_t SESSION_TOKEN_DELIMETER = '|';


//==========================================================
// Globals.
//

uint64_t g_hmac_key;


//==========================================================
// Public API - enterprise only.
//

void
as_session_token_init()
{
	g_hmac_key = cf_get_rand64();
}

// Caller must free returned token.
uint8_t*
as_session_token_generate(const char* p_user, uint32_t user_len,
		uint32_t* p_size)
{
	uint8_t d[user_len + 16 + 1]; // leave room for max hex and null terminator

	memcpy(d, p_user, user_len);

	uint8_t* timestamp = d + user_len;
	size_t timestamp_size = (size_t)sprintf((char*)timestamp, "%lx",
			cf_secs_since_clepoch());

	size_t d_size = user_len + timestamp_size;

	uint8_t md[EVP_MAX_MD_SIZE];
	uint32_t md_size;

	if (! HMAC(EVP_METHODS[g_config.sec_cfg.ldap_token_hash_method](),
			(const void*)&g_hmac_key, (int)sizeof(uint64_t),
			d, d_size,
			md, &md_size)) {
		cf_crash(AS_SECURITY, "unexpected - HMAC call failed");
	}

	size_t token_size = 1 + timestamp_size + 1 + md_size;
	uint8_t* token = cf_malloc(token_size);
	uint8_t* at = token;

	// For now there's only one type of token.
	*at++ = SESSION_TOKEN_TYPE_HMAC;

	memcpy(at, timestamp, timestamp_size);
	at += timestamp_size;

	*at++ = SESSION_TOKEN_DELIMETER;

	memcpy(at, md, md_size);

	*p_size = (uint32_t)token_size;

	return token;
}

uint8_t
as_session_token_is_valid(const char* p_user, uint32_t user_len,
		const uint8_t* p_cred, uint32_t cred_size)
{
	// For now there's only one type of token.
	if (cred_size == 0 || *p_cred != SESSION_TOKEN_TYPE_HMAC) {
		return AS_SEC_ERR_CREDENTIAL;
	}

	const uint8_t* timestamp = p_cred + 1;
	const uint8_t* at = timestamp;
	const uint8_t* end = p_cred + cred_size;

	while (at < end && *at != SESSION_TOKEN_DELIMETER) {
		at++;
	}

	if (at == end) {
		return AS_SEC_ERR_CREDENTIAL;
	}
	// else - at points at delimiter.

	size_t timestamp_size = at - timestamp;

	uint64_t session_gen_time = strtoul((const char*)timestamp, NULL, 16);

	if (session_gen_time > UINT32_MAX) {
		return AS_SEC_ERR_CREDENTIAL;
	}

	if (cf_secs_since_clepoch() >
			session_gen_time + g_config.sec_cfg.session_ttl) {
		return AS_SEC_ERR_EXPIRED_SESSION;
	}

	size_t d_size = user_len + timestamp_size;
	uint8_t d[d_size];

	memcpy(d, p_user, user_len);
	memcpy(d + user_len, timestamp, timestamp_size);

	uint8_t md[EVP_MAX_MD_SIZE];
	uint32_t md_size;

	if (! HMAC(EVP_METHODS[g_config.sec_cfg.ldap_token_hash_method](),
			(const void*)&g_hmac_key, (int)sizeof(uint64_t),
			d, d_size,
			md, &md_size)) {
		return AS_SEC_ERR_CREDENTIAL;
	}

	if ((uint32_t)(end - ++at) != md_size || memcmp(at, md, md_size) != 0) {
		return AS_SEC_ERR_CREDENTIAL;
	}

	return AS_OK;
}
