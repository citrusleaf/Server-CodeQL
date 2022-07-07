/*
 * ldap_ee.h
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

struct as_file_handle_s;

void as_ldap_config_check();
void as_ldap_init();
int as_ldap_login(struct as_file_handle_s* fd_h, const char* p_user, uint32_t user_len, const char* p_clear_pw, uint32_t clear_pw_len);
