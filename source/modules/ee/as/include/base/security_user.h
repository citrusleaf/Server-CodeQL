/*
 * security_user.h
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

#include "base/security_book.h"

// Object containing a user's info - password, roles list, and permissions book.
typedef struct uinfo_s uinfo;

const char* uinfo_password(const uinfo* p_uinfo);
bool uinfo_password_is_empty(const uinfo* p_uinfo);
bool uinfo_password_matches(const uinfo* p_uinfo, const char* password);
bool uinfo_has_role(const uinfo* p_uinfo, const char* role);
const char* uinfo_next_role(const char* role);
uint32_t uinfo_num_roles(const uinfo* p_uinfo);
const char* uinfo_roles(const uinfo* p_uinfo);
const book* uinfo_book(const uinfo* p_uinfo);

uinfo* uinfo_new_password(const char* p_password);
uinfo* uinfo_replace_password(const uinfo* p_old_uinfo, const char* p_password);
uinfo* uinfo_new_session(const char* roles, uint32_t num_roles);
uinfo* uinfo_new_add_role(const char* role);
uinfo* uinfo_new_add_role_only(const char* role);
uinfo* uinfo_replace_add_role(const uinfo* p_old_uinfo, const char* role);
uinfo* uinfo_replace_add_role_only(const uinfo* p_old_uinfo, const char* role);
uinfo* uinfo_replace_delete_role(const uinfo* p_old_uinfo, const char* role);
uinfo* uinfo_replace_grow_role(const uinfo* p_old_uinfo, const char* role, const book* p_role_book, uint32_t role_book_size);
uinfo* uinfo_replace_shrink_role(const uinfo* p_old_uinfo, const char* role);
uinfo* uinfo_generate_book(const uinfo* p_old_uinfo);

// For debugging only.
void dump_uinfo(const char* tag, const char* name, const uinfo* p_uinfo);
