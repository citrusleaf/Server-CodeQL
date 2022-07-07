/*
 * session_token.h
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#pragma once

#include <stdint.h>

#define SESSION_TOKEN_TYPE_HMAC		'H'

void as_session_token_init();
uint8_t* as_session_token_generate(const char* p_user, uint32_t user_len, uint32_t* p_size);
uint8_t as_session_token_is_valid(const char* p_user, uint32_t user_len, const uint8_t* p_cred, uint32_t cred_size);
