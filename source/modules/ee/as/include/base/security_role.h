/*
 * security_role.h
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "socket.h"

#include "base/security_book.h"
#include "base/security_ee.h"

// Generic ip_net_list API.
bool ip_net_list_validate_string(const char* ip_net_list_string, uint32_t len);

// Object containing a role's info - privileges list and permissions book.
typedef struct rinfo_s rinfo;

bool rinfo_has_whitelist(const rinfo* p_rinfo);
void rinfo_get_whitelist(const rinfo* p_rinfo, char* whitelist, uint32_t size);
bool rinfo_whitelist_contains(const rinfo* p_rinfo, const cf_ip_addr* addr);
uint32_t rinfo_get_read_quota(const rinfo* p_rinfo);
uint32_t rinfo_get_write_quota(const rinfo* p_rinfo);
bool rinfo_has_priv(const rinfo* p_rinfo, const priv_code* p_priv);
uint32_t rinfo_num_privs(const rinfo* p_rinfo);
const priv_code* rinfo_privs(const rinfo* p_rinfo);
const book* rinfo_book(const rinfo* p_rinfo);
uint32_t rinfo_book_size(const rinfo* p_rinfo);

rinfo* rinfo_new_add_whitelist(const char* whitelist);
rinfo* rinfo_replace_set_whitelist(const rinfo* p_old_rinfo, const char* whitelist);

rinfo* rinfo_new_add_quota(uint32_t quota, bool is_write);
rinfo* rinfo_replace_set_quota(const rinfo* p_old_rinfo, uint32_t quota, bool is_write);

rinfo* rinfo_new_add_priv(const priv_code* p_priv);
rinfo* rinfo_new_add_priv_only(const priv_code* p_priv);
rinfo* rinfo_replace_add_priv(const rinfo* p_old_rinfo, const priv_code* p_priv);
rinfo* rinfo_replace_add_priv_only(const rinfo* p_old_rinfo, const priv_code* p_priv);
rinfo* rinfo_replace_delete_priv(const rinfo* p_old_rinfo, const priv_code* p_priv);
rinfo* rinfo_generate_book(const rinfo* p_old_rinfo);

// For debugging only.
void dump_rinfo(const char* tag, const char* name, const rinfo* p_rinfo);
