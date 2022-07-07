/*
 * security_user.c
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

#include "base/security_user.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "citrusleaf/alloc.h"

#include "log.h"

#include "base/security_book.h"
#include "base/security_ee.h"
#include "base/security_role.h"


//==========================================================
// Typedefs & constants.
//

// Object containing a user's info - password, roles list, and permissions book.
struct uinfo_s {
	char		password[PASSWORD_LEN];
	uint32_t	num_roles;
	uint32_t	book_size;
	uint8_t		vdata[];
};


//==========================================================
// Forward declarations.
//

static inline uint32_t uinfo_size(const uinfo* p_uinfo);
static inline uint32_t uinfo_roles_size(const uinfo* p_uinfo);
uint8_t* write_role(uint8_t* p_write, const char* role);
uint8_t* write_roles(uint8_t* p_write, const char* roles, uint32_t num_roles);
static inline uint8_t* write_uinfo_roles(uint8_t* p_write, const uinfo* p_uinfo);
static void write_book(uint8_t* p_write, const book* p_book, uint32_t book_size);


//==========================================================
// Public API.
//

//------------------------------------------------
// Get the pointer to this user's password.
//
const char*
uinfo_password(const uinfo* p_uinfo)
{
	return (const char*)p_uinfo->password;
}

//------------------------------------------------
// Is user's password empty? (External user?)
//
bool
uinfo_password_is_empty(const uinfo* p_uinfo)
{
	return *p_uinfo->password == 0;
}

//------------------------------------------------
// Does user's password match this one?
//
bool
uinfo_password_matches(const uinfo* p_uinfo, const char* password)
{
	if (*password == 0) {
		return *p_uinfo->password == 0;
	}

	if (*p_uinfo->password == 0) {
		return *password == 0;
	}

	return memcmp(password, p_uinfo->password, PASSWORD_LEN) == 0;
}

//------------------------------------------------
// Is specified role in this user's list?
//
bool
uinfo_has_role(const uinfo* p_uinfo, const char* role)
{
	const char* roles = uinfo_roles(p_uinfo);

	for (uint32_t r = 0; r < p_uinfo->num_roles; r++) {
		if (strcmp(role, roles) == 0) {
			return true;
		}

		roles = uinfo_next_role(roles);
	}

	return false;
}

//------------------------------------------------
// Advance role pointer to point to the next role
// in a role list.
//
const char*
uinfo_next_role(const char* role)
{
	return role + MAX_ROLE_NAME_SIZE;
}

//------------------------------------------------
// Number of roles in this user's list.
//
uint32_t
uinfo_num_roles(const uinfo* p_uinfo)
{
	return p_uinfo->num_roles;
}

//------------------------------------------------
// Get the pointer to this user's role list.
//
const char*
uinfo_roles(const uinfo* p_uinfo)
{
	return (const char*)p_uinfo->vdata;
}

//------------------------------------------------
// Get the pointer to this user's book.
//
const book*
uinfo_book(const uinfo* p_uinfo)
{
	return p_uinfo->book_size != 0 ?
			(const book*)(uinfo_roles(p_uinfo) + uinfo_roles_size(p_uinfo)) :
			NULL;
}

//------------------------------------------------
// Create a uinfo object with only a password.
//
uinfo*
uinfo_new_password(const char* p_password)
{
	uint32_t new_size = (uint32_t)sizeof(uinfo);

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	// External users have empty passwords.
	if (*p_password == 0) {
		memset(p_new_uinfo->password, 0, PASSWORD_LEN);
	}
	else {
		memcpy(p_new_uinfo->password, p_password, PASSWORD_LEN);
	}

	p_new_uinfo->num_roles = 0;
	p_new_uinfo->book_size = 0;

	return p_new_uinfo;
}

//------------------------------------------------
// Create a uinfo object from an existing object,
// with only a different password.
//
uinfo*
uinfo_replace_password(const uinfo* p_old_uinfo, const char* p_password)
{
	uint32_t new_size = uinfo_size(p_old_uinfo);

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	// External users have empty passwords.
	if (*p_password == 0) {
		memset(p_new_uinfo->password, 0, PASSWORD_LEN);
	}
	else {
		memcpy(p_new_uinfo->password, p_password, PASSWORD_LEN);
	}

	p_new_uinfo->num_roles = p_old_uinfo->num_roles;
	p_new_uinfo->book_size = p_old_uinfo->book_size;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	p_write = write_uinfo_roles(p_write, p_old_uinfo);
	write_book(p_write, uinfo_book(p_old_uinfo), p_old_uinfo->book_size);

	return p_new_uinfo;
}

//------------------------------------------------
// Create a uinfo object with roles.
//
// Note - there's no uinfo_replace_session() for
// now, since there's nothing to transfer from the
// old uinfo when replacing it.
//
uinfo*
uinfo_new_session(const char* roles, uint32_t num_roles)
{
	uint32_t new_book_size = 0;
	book* p_new_book = NULL;
	bool free_book = false;

	// Note - roles and num_roles can be NULL and 0 respectively.

	const book* role_books[num_roles];
	uint32_t role_book_sizes[num_roles];
	uint32_t num_defined_roles = 0;

	const char* p_read_role = roles;

	for (uint32_t r = 0; r < num_roles; r++) {
		uint32_t role_book_size = 0;
		const book* p_role_book = role_book(p_read_role, &role_book_size);

		if (p_role_book) {
			role_books[num_defined_roles] = p_role_book;
			role_book_sizes[num_defined_roles] = role_book_size;
			num_defined_roles++;
		}

		p_read_role = uinfo_next_role(p_read_role);
	}

	if (num_defined_roles > 1) {
		p_new_book = book_merge(role_books, num_defined_roles, &new_book_size);
		free_book = true;
	}
	else if (num_defined_roles == 1) {
		p_new_book = (book*)role_books[0];
		new_book_size = role_book_sizes[0];
	}
	// else the book & size are NULL & 0 respectively

	uint32_t new_size =
			(uint32_t)sizeof(uinfo) +
			(num_roles * MAX_ROLE_NAME_SIZE) +
			new_book_size;

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	memset(p_new_uinfo->password, 0, PASSWORD_LEN);
	p_new_uinfo->num_roles = num_roles;
	p_new_uinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	p_write = write_roles(p_write, roles, num_roles);
	write_book(p_write, p_new_book, new_book_size);

	if (free_book) {
		cf_free(p_new_book);
	}

	return p_new_uinfo;
}

//------------------------------------------------
// Create a uinfo object with one role and its
// corresponding book.
//
uinfo*
uinfo_new_add_role(const char* role)
{
	uint32_t new_book_size = 0;
	const book* p_new_book = role_book(role, &new_book_size);

	uint32_t new_size =
			(uint32_t)sizeof(uinfo) +
			MAX_ROLE_NAME_SIZE +
			new_book_size;

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	memset(p_new_uinfo->password, 0, PASSWORD_LEN);
	p_new_uinfo->num_roles = 1;
	p_new_uinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	p_write = write_role(p_write, role);
	write_book(p_write, p_new_book, new_book_size);

	return p_new_uinfo;
}

//------------------------------------------------
// Create a uinfo object with one role but don't
// generate its book. (Currently used only at
// startup.)
//
uinfo*
uinfo_new_add_role_only(const char* role)
{
	uint32_t new_size =
			(uint32_t)sizeof(uinfo) +
			MAX_ROLE_NAME_SIZE;

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	memset(p_new_uinfo->password, 0, PASSWORD_LEN);
	p_new_uinfo->num_roles = 1;
	p_new_uinfo->book_size = 0;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	write_role(p_write, role);

	return p_new_uinfo;
}

//------------------------------------------------
// Create a uinfo object from an existing object,
// with a new role added.
//
uinfo*
uinfo_replace_add_role(const uinfo* p_old_uinfo, const char* role)
{
	uint32_t num_new_roles = p_old_uinfo->num_roles + 1;

	uint32_t new_book_size = 0;
	book* p_new_book = NULL;
	bool free_book = false;

	const book* p_old_book = uinfo_book(p_old_uinfo);

	uint32_t role_book_size = 0;
	const book* p_role_book = role_book(role, &role_book_size);

	if (p_old_book && p_role_book) {
		const book* books[2];

		books[0] = p_old_book;
		books[1] = p_role_book;

		p_new_book = book_merge(books, 2, &new_book_size);
		free_book = true;
	}
	else if (p_old_book) {
		p_new_book = (book*)p_old_book;
		new_book_size = p_old_uinfo->book_size;
	}
	else if (p_role_book) {
		p_new_book = (book*)p_role_book;
		new_book_size = role_book_size;
	}
	// else the book & size are NULL & 0 respectively

	uint32_t new_size =
			(uint32_t)sizeof(uinfo) +
			(num_new_roles * MAX_ROLE_NAME_SIZE) +
			new_book_size;

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	memcpy(p_new_uinfo->password, p_old_uinfo->password, PASSWORD_LEN);
	p_new_uinfo->num_roles = num_new_roles;
	p_new_uinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	p_write = write_uinfo_roles(p_write, p_old_uinfo);
	p_write = write_role(p_write, role);
	write_book(p_write, p_new_book, new_book_size);

	if (free_book) {
		cf_free(p_new_book);
	}

	return p_new_uinfo;
}

//------------------------------------------------
// Create a uinfo object from an existing object,
// with a new role added, but don't generate its
// book. (Currently used only at startup.)
//
uinfo*
uinfo_replace_add_role_only(const uinfo* p_old_uinfo, const char* role)
{
	if (p_old_uinfo->book_size != 0) {
		cf_crash(AS_SECURITY, "replace add role only - has book");
	}

	uint32_t num_new_roles = p_old_uinfo->num_roles + 1;

	uint32_t new_size =
			(uint32_t)sizeof(uinfo) +
			(num_new_roles * MAX_ROLE_NAME_SIZE);

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	memcpy(p_new_uinfo->password, p_old_uinfo->password, PASSWORD_LEN);
	p_new_uinfo->num_roles = num_new_roles;
	p_new_uinfo->book_size = 0;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	p_write = write_uinfo_roles(p_write, p_old_uinfo);
	write_role(p_write, role);

	return p_new_uinfo;
}

//------------------------------------------------
// Create a uinfo object from an existing object,
// with an existing role removed.
//
uinfo*
uinfo_replace_delete_role(const uinfo* p_old_uinfo, const char* role)
{
	uint32_t num_new_roles = p_old_uinfo->num_roles - 1; // can be 0
	uint32_t new_roles_size = num_new_roles * MAX_ROLE_NAME_SIZE;
	char new_roles[new_roles_size];

	if (num_new_roles != 0) {
		uint8_t* p_write_role = (uint8_t*)new_roles;
		const char* p_read_role = uinfo_roles(p_old_uinfo);

		for (uint32_t r = 0; r < p_old_uinfo->num_roles; r++) {
			if (strcmp(role, p_read_role) != 0) {
				p_write_role = write_role(p_write_role, p_read_role);
			}

			p_read_role = uinfo_next_role(p_read_role);
		}
	}

	uint32_t new_book_size = 0;
	book* p_new_book = NULL;
	bool free_book = false;

	const book* role_books[num_new_roles];
	uint32_t role_book_sizes[num_new_roles];
	uint32_t num_defined_roles = 0;

	const char* p_read_role = new_roles;

	for (uint32_t r = 0; r < num_new_roles; r++) {
		uint32_t role_book_size = 0;
		const book* p_role_book = role_book(p_read_role, &role_book_size);

		if (p_role_book) {
			role_books[num_defined_roles] = p_role_book;
			role_book_sizes[num_defined_roles] = role_book_size;
			num_defined_roles++;
		}

		p_read_role = uinfo_next_role(p_read_role);
	}

	if (num_defined_roles > 1) {
		p_new_book = book_merge(role_books, num_defined_roles, &new_book_size);
		free_book = true;
	}
	else if (num_defined_roles == 1) {
		p_new_book = (book*)role_books[0];
		new_book_size = role_book_sizes[0];
	}
	// else the book & size are NULL & 0 respectively

	uint32_t new_size =
			(uint32_t)sizeof(uinfo) +
			new_roles_size +
			new_book_size;

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	memcpy(p_new_uinfo->password, p_old_uinfo->password, PASSWORD_LEN);
	p_new_uinfo->num_roles = num_new_roles;
	p_new_uinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	p_write = write_roles(p_write, new_roles, num_new_roles);
	write_book(p_write, p_new_book, new_book_size);

	if (free_book) {
		cf_free(p_new_book);
	}

	return p_new_uinfo;
}

//------------------------------------------------
// Create a uinfo object from an existing object,
// with an existing role's privileges increased.
//
uinfo*
uinfo_replace_grow_role(const uinfo* p_old_uinfo, const char* role,
		const book* p_role_book, uint32_t role_book_size)
{
	uint32_t num_new_roles = p_old_uinfo->num_roles;

	uint32_t new_book_size = 0;
	book* p_new_book = NULL;
	bool free_book = false;

	const book* p_old_book = uinfo_book(p_old_uinfo);

	if (p_old_book) {
		const book* books[2];

		books[0] = p_old_book;
		books[1] = p_role_book;

		p_new_book = book_merge(books, 2, &new_book_size);
		free_book = true;
	}
	else {
		p_new_book = (book*)p_role_book;
		new_book_size = role_book_size;
	}

	uint32_t new_size =
			(uint32_t)sizeof(uinfo) +
			(num_new_roles * MAX_ROLE_NAME_SIZE) +
			new_book_size;

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	memcpy(p_new_uinfo->password, p_old_uinfo->password, PASSWORD_LEN);
	p_new_uinfo->num_roles = num_new_roles;
	p_new_uinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	p_write = write_uinfo_roles(p_write, p_old_uinfo);
	write_book(p_write, p_new_book, new_book_size);

	if (free_book) {
		cf_free(p_new_book);
	}

	return p_new_uinfo;
}

//------------------------------------------------
// Create a uinfo object from an existing object,
// with an existing role's privileges decreased.
//
uinfo*
uinfo_replace_shrink_role(const uinfo* p_old_uinfo, const char* role)
{
	uint32_t num_new_roles = p_old_uinfo->num_roles; // can't be 0

	uint32_t new_book_size = 0;
	book* p_new_book = NULL;
	bool free_book = false;

	const book* role_books[num_new_roles];
	uint32_t role_book_sizes[num_new_roles];
	uint32_t num_defined_roles = 0;

	const char* p_read_role = uinfo_roles(p_old_uinfo);

	for (uint32_t r = 0; r < p_old_uinfo->num_roles; r++) {
		uint32_t role_book_size = 0;
		const book* p_role_book = role_book(p_read_role, &role_book_size);

		if (p_role_book) {
			role_books[num_defined_roles] = p_role_book;
			role_book_sizes[num_defined_roles] = role_book_size;
			num_defined_roles++;
		}

		p_read_role = uinfo_next_role(p_read_role);
	}

	if (num_defined_roles > 1) {
		p_new_book = book_merge(role_books, num_defined_roles, &new_book_size);
		free_book = true;
	}
	else if (num_defined_roles == 1) {
		p_new_book = (book*)role_books[0];
		new_book_size = role_book_sizes[0];
	}
	// else the book & size are NULL & 0 respectively

	uint32_t new_size =
			(uint32_t)sizeof(uinfo) +
			(num_new_roles * MAX_ROLE_NAME_SIZE) +
			new_book_size;

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	memcpy(p_new_uinfo->password, p_old_uinfo->password, PASSWORD_LEN);
	p_new_uinfo->num_roles = num_new_roles;
	p_new_uinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	p_write = write_uinfo_roles(p_write, p_old_uinfo);
	write_book(p_write, p_new_book, new_book_size);

	if (free_book) {
		cf_free(p_new_book);
	}

	return p_new_uinfo;
}

//------------------------------------------------
// Generate this user's permissions book from its
// list of roles. (Currently used only at
// startup.)
//
uinfo*
uinfo_generate_book(const uinfo* p_old_uinfo)
{
	uint32_t num_new_roles = p_old_uinfo->num_roles; // can be 0

	uint32_t new_book_size = 0;
	book* p_new_book = NULL;
	bool free_book = false;

	const book* role_books[num_new_roles];
	uint32_t role_book_sizes[num_new_roles];
	uint32_t num_defined_roles = 0;

	const char* p_read_role = uinfo_roles(p_old_uinfo);

	for (uint32_t r = 0; r < p_old_uinfo->num_roles; r++) {
		uint32_t role_book_size = 0;
		const book* p_role_book = role_book(p_read_role, &role_book_size);

		if (p_role_book) {
			role_books[num_defined_roles] = p_role_book;
			role_book_sizes[num_defined_roles] = role_book_size;
			num_defined_roles++;
		}

		p_read_role = uinfo_next_role(p_read_role);
	}

	if (num_defined_roles > 1) {
		p_new_book = book_merge(role_books, num_defined_roles, &new_book_size);
		free_book = true;
	}
	else if (num_defined_roles == 1) {
		p_new_book = (book*)role_books[0];
		new_book_size = role_book_sizes[0];
	}
	// else the book & size are NULL & 0 respectively

	uint32_t new_size =
			(uint32_t)sizeof(uinfo) +
			(num_new_roles * MAX_ROLE_NAME_SIZE) +
			new_book_size;

	uinfo* p_new_uinfo = cf_rc_alloc(new_size);

	memcpy(p_new_uinfo->password, p_old_uinfo->password, PASSWORD_LEN);
	p_new_uinfo->num_roles = num_new_roles;
	p_new_uinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)uinfo_roles(p_new_uinfo);

	p_write = write_uinfo_roles(p_write, p_old_uinfo);
	write_book(p_write, p_new_book, new_book_size);

	if (free_book) {
		cf_free(p_new_book);
	}

	return p_new_uinfo;
}


//==========================================================
// Miscellaneous helpers.
//

//------------------------------------------------
// Size of this entire uinfo object.
//
static inline uint32_t
uinfo_size(const uinfo* p_uinfo)
{
	return sizeof(uinfo) + uinfo_roles_size(p_uinfo) + p_uinfo->book_size;
}

//------------------------------------------------
// Size of the roles list.
//
static inline uint32_t
uinfo_roles_size(const uinfo* p_uinfo)
{
	return p_uinfo->num_roles * MAX_ROLE_NAME_SIZE;
}

//------------------------------------------------
// Append a role to a buffer.
//
uint8_t*
write_role(uint8_t* p_write, const char* role)
{
	memcpy(p_write, role, MAX_ROLE_NAME_SIZE);

	return p_write + MAX_ROLE_NAME_SIZE;
}

//------------------------------------------------
// Append a list of roles to a buffer.
//
uint8_t*
write_roles(uint8_t* p_write, const char* roles, uint32_t num_roles)
{
	if (num_roles == 0) {
		return p_write;
	}

	uint32_t write_size = num_roles * MAX_ROLE_NAME_SIZE;

	memcpy(p_write, roles, write_size);

	return p_write + write_size;
}

//------------------------------------------------
// Append a uinfo's list of roles to a buffer.
//
static inline uint8_t*
write_uinfo_roles(uint8_t* p_write, const uinfo* p_uinfo)
{
	return write_roles(p_write, uinfo_roles(p_uinfo), p_uinfo->num_roles);
}

//------------------------------------------------
// Append a book to a buffer.
//
static void
write_book(uint8_t* p_write, const book* p_book, uint32_t book_size)
{
	if (book_size == 0) {
		return;
	}

	memcpy(p_write, p_book, book_size);
}


//==========================================================
// Public API - for debugging only.
//

#include <stdio.h>
#include "base/cfg.h"
#include "base/datamodel.h"

//------------------------------------------------
// Log the contents of this user.
//
void
dump_uinfo(const char* tag, const char* name, const uinfo* p_uinfo)
{
	cf_info(AS_SECURITY, "%s - user %s:", tag, name);

	if (! p_uinfo) {
		cf_info(AS_SECURITY, "<null uinfo>");
		return;
	}

	char password[PASSWORD_LEN + 1];

	strncpy(password, p_uinfo->password, PASSWORD_LEN);
	password[PASSWORD_LEN] = 0;

	cf_info(AS_SECURITY, " - password: %s", password);
	cf_info(AS_SECURITY, " - num-roles: %u", p_uinfo->num_roles);
	cf_info(AS_SECURITY, " - book-size: %u", p_uinfo->book_size);
	cf_info(AS_SECURITY, " roles:");

	const char* roles = uinfo_roles(p_uinfo);

	for (uint32_t r = 0; r < p_uinfo->num_roles; r++) {
		cf_info(AS_SECURITY, " - %s", roles);

		roles = uinfo_next_role(roles);
	}

	cf_info(AS_SECURITY, " book:");

	dump_book(uinfo_book(p_uinfo));
}
