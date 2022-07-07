/*
 * security_role.c
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

#include "base/security_role.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "citrusleaf/alloc.h"

#include "log.h"
#include "socket.h"

#include "base/security_book.h"
#include "base/security_ee.h"


//==========================================================
// Typedefs & constants.
//

#define MAX_IP_NETS 32

typedef struct ip_net_list_s {
	uint32_t n_nets;
	cf_ip_net nets[MAX_IP_NETS];
} ip_net_list;

#define NET_LIST_DELIMITER ','
#define NET_LIST_DELIMITERS ","

// Object containing a role's info - privileges list and permissions book.
struct rinfo_s {
	ip_net_list	whitelist;
	uint32_t	read_quota;
	uint32_t	write_quota;
	uint32_t	num_privs;
	uint32_t	book_size;
	uint8_t		vdata[];
};


//==========================================================
// Forward declarations.
//

void copy_rinfo_whitelist(rinfo* dest, const rinfo* src);
void copy_rinfo_vdata(rinfo* dest, const rinfo* src);
void set_rinfo_whitelist(rinfo* p_rinfo, const ip_net_list* list);
static inline uint32_t rinfo_privs_size(const rinfo* p_rinfo);
uint8_t* write_priv(uint8_t* p_write, const priv_code* p_priv);
uint8_t* write_privs(uint8_t* p_write, const priv_code* p_privs, uint32_t num_privs);
static inline uint8_t* write_rinfo_privs(uint8_t* p_write, const rinfo* p_rinfo);
static inline void write_book(uint8_t* p_write, const book* p_book, uint32_t book_size);

bool parse_list(char* list_string, ip_net_list* list);


//==========================================================
// Public API - ip_net_list.
//

bool
ip_net_list_validate_string(const char* ip_net_list_string, uint32_t len)
{
	char list_string[len + 1]; // tokenizable copy

	memcpy(list_string, ip_net_list_string, len);
	list_string[len] = '\0';

	ip_net_list dummy;

	return parse_list(list_string, &dummy);
}


//==========================================================
// Public API.
//

//------------------------------------------------
// Does this role have a whitelist?
//
bool
rinfo_has_whitelist(const rinfo* p_rinfo)
{
	return p_rinfo->whitelist.n_nets != 0;
}

//------------------------------------------------
// Get this role's whitelist (as string).
//
void
rinfo_get_whitelist(const rinfo* p_rinfo, char* whitelist, uint32_t size)
{
	cf_assert(p_rinfo->whitelist.n_nets != 0, AS_SECURITY, "empty whitelist");

	char* p_write = whitelist;

	for (uint32_t i = 0; i < p_rinfo->whitelist.n_nets; i++) {
		int32_t added = cf_ip_net_to_string(&p_rinfo->whitelist.nets[i],
				p_write, size);

		if (added < 0) {
			cf_warning(AS_SECURITY, "whitelist too long");
			whitelist[0] = '\0';
			return;
		}

		p_write += added;
		size -= added; // size must be at least 1 here

		*p_write++ = NET_LIST_DELIMITER;
		size--;
	}

	*(p_write - 1) = '\0';
}

//------------------------------------------------
// Does this role's whitelist contain IP addr?
//
bool
rinfo_whitelist_contains(const rinfo* p_rinfo, const cf_ip_addr* addr)
{
	for (uint32_t i = 0; i < p_rinfo->whitelist.n_nets; i++) {
		if (cf_ip_net_contains(&p_rinfo->whitelist.nets[i], addr)) {
			return true;
		}
	}

	return false;
}

//------------------------------------------------
// Get this role's read-quota.
//
uint32_t
rinfo_get_read_quota(const rinfo* p_rinfo)
{
	return p_rinfo->read_quota;
}

//------------------------------------------------
// Get this role's write-quota.
//
uint32_t
rinfo_get_write_quota(const rinfo* p_rinfo)
{
	return p_rinfo->write_quota;
}

//------------------------------------------------
// Is specified privilege in this role's list?
//
bool
rinfo_has_priv(const rinfo* p_rinfo, const priv_code* p_priv)
{
	const priv_code* privs = rinfo_privs(p_rinfo);

	for (uint32_t i = 0; i < p_rinfo->num_privs; i++) {
		if (priv_eq(p_priv, &privs[i])) {
			return true;
		}
	}

	return false;
}

//------------------------------------------------
// Number of privileges in this role's list.
//
uint32_t
rinfo_num_privs(const rinfo* p_rinfo)
{
	return p_rinfo->num_privs;
}

//------------------------------------------------
// Get the pointer to this role's privilege list.
//
const priv_code*
rinfo_privs(const rinfo* p_rinfo)
{
	return (const priv_code*)p_rinfo->vdata;
}

//------------------------------------------------
// Get the pointer to this role's book.
//
const book*
rinfo_book(const rinfo* p_rinfo)
{
	return p_rinfo->book_size != 0 ?
			(const book*)(p_rinfo->vdata + rinfo_privs_size(p_rinfo)) : NULL;
}

//------------------------------------------------
// Size of this role's book.
//
uint32_t
rinfo_book_size(const rinfo* p_rinfo)
{
	return p_rinfo->book_size;
}

//------------------------------------------------
// Create a rinfo object with a whitelist.
//
rinfo*
rinfo_new_add_whitelist(const char* whitelist)
{
	if (whitelist == NULL) {
		return NULL;
	}

	char list_string[strlen(whitelist) + 1]; // tokenizable copy

	strcpy(list_string, whitelist);

	ip_net_list list;

	if (! parse_list(list_string, &list)) {
		return NULL;
	}

	uint32_t new_size = sizeof(rinfo);

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	set_rinfo_whitelist(p_new_rinfo, &list);
	p_new_rinfo->read_quota = 0;
	p_new_rinfo->write_quota = 0;
	p_new_rinfo->num_privs = 0;
	p_new_rinfo->book_size = 0;

	return p_new_rinfo;
}

//------------------------------------------------
// Create a rinfo object from an existing object,
// with a new whitelist (or no whitelist).
//
rinfo*
rinfo_replace_set_whitelist(const rinfo* p_old_rinfo, const char* whitelist)
{
	ip_net_list list;

	if (whitelist != NULL) {
		char list_string[strlen(whitelist) + 1]; // tokenizable copy

		strcpy(list_string, whitelist);

		if (! parse_list(list_string, &list)) {
			return NULL;
		}
	}
	else {
		list.n_nets = 0;
	}

	uint32_t new_size =
			sizeof(rinfo) +
			rinfo_privs_size(p_old_rinfo) +
			p_old_rinfo->book_size;

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	set_rinfo_whitelist(p_new_rinfo, &list);
	p_new_rinfo->read_quota = p_old_rinfo->read_quota;
	p_new_rinfo->write_quota = p_old_rinfo->write_quota;
	p_new_rinfo->num_privs = p_old_rinfo->num_privs;
	p_new_rinfo->book_size = p_old_rinfo->book_size;
	copy_rinfo_vdata(p_new_rinfo, p_old_rinfo);

	return p_new_rinfo;
}

//------------------------------------------------
// Create a rinfo object with a quota.
//
rinfo*
rinfo_new_add_quota(uint32_t quota, bool is_write)
{
	// FIXME - fail if 0?

	uint32_t new_size = sizeof(rinfo);

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	p_new_rinfo->whitelist.n_nets = 0;
	p_new_rinfo->read_quota = is_write ? 0 : quota;
	p_new_rinfo->write_quota = is_write ? quota : 0;
	p_new_rinfo->num_privs = 0;
	p_new_rinfo->book_size = 0;

	return p_new_rinfo;
}

//------------------------------------------------
// Create a rinfo object from an existing object,
// with a new quota.
//
rinfo*
rinfo_replace_set_quota(const rinfo* p_old_rinfo, uint32_t quota, bool is_write)
{
	uint32_t new_size =
			sizeof(rinfo) +
			rinfo_privs_size(p_old_rinfo) +
			p_old_rinfo->book_size;

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	copy_rinfo_whitelist(p_new_rinfo, p_old_rinfo);
	p_new_rinfo->read_quota = is_write ? p_old_rinfo->read_quota : quota;
	p_new_rinfo->write_quota = is_write ? quota : p_old_rinfo->write_quota;
	p_new_rinfo->num_privs = p_old_rinfo->num_privs;
	p_new_rinfo->book_size = p_old_rinfo->book_size;
	copy_rinfo_vdata(p_new_rinfo, p_old_rinfo);

	return p_new_rinfo;
}

//------------------------------------------------
// Create a rinfo object with one privilege and
// its corresponding book.
//
rinfo*
rinfo_new_add_priv(const priv_code* p_priv)
{
	uint32_t new_book_size = priv_book_size(p_priv);

	uint32_t new_size =
			sizeof(rinfo) +
			sizeof(priv_code) +
			new_book_size;

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	p_new_rinfo->whitelist.n_nets = 0;
	p_new_rinfo->read_quota = 0;
	p_new_rinfo->write_quota = 0;
	p_new_rinfo->num_privs = 1;
	p_new_rinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)rinfo_privs(p_new_rinfo);

	p_write = write_priv(p_write, p_priv);
	book_init_priv((book*)p_write, new_book_size, p_priv);

	return p_new_rinfo;
}

//------------------------------------------------
// Create a rinfo object with one privilege but
// don't generate its book. (Currently used only
// at startup.)
//
rinfo*
rinfo_new_add_priv_only(const priv_code* p_priv)
{
	uint32_t new_size =
			sizeof(rinfo) +
			sizeof(priv_code);

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	p_new_rinfo->whitelist.n_nets = 0;
	p_new_rinfo->read_quota = 0;
	p_new_rinfo->write_quota = 0;
	p_new_rinfo->num_privs = 1;
	p_new_rinfo->book_size = 0;

	uint8_t* p_write = (uint8_t*)rinfo_privs(p_new_rinfo);

	write_priv(p_write, p_priv);

	return p_new_rinfo;
}

//------------------------------------------------
// Create a rinfo object from an existing object,
// with a new privilege added.
//
rinfo*
rinfo_replace_add_priv(const rinfo* p_old_rinfo, const priv_code* p_priv)
{
	uint32_t num_new_privs = p_old_rinfo->num_privs + 1;

	uint32_t new_book_size = 0;
	book* p_new_book = NULL;

	if (num_new_privs == 1) {
		new_book_size = priv_book_size(p_priv);
	}
	else {
		p_new_book = book_merge_priv(rinfo_book(p_old_rinfo), p_priv,
					&new_book_size);
	}

	uint32_t new_size =
			sizeof(rinfo) +
			(num_new_privs * sizeof(priv_code)) +
			new_book_size;

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	copy_rinfo_whitelist(p_new_rinfo, p_old_rinfo);
	p_new_rinfo->read_quota = p_old_rinfo->read_quota;
	p_new_rinfo->write_quota = p_old_rinfo->write_quota;
	p_new_rinfo->num_privs = num_new_privs;
	p_new_rinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)rinfo_privs(p_new_rinfo);

	if (num_new_privs == 1) {
		p_write = write_priv(p_write, p_priv);
		book_init_priv((book*)p_write, new_book_size, p_priv);
	}
	else {
		p_write = write_rinfo_privs(p_write, p_old_rinfo);
		p_write = write_priv(p_write, p_priv);
		write_book(p_write, p_new_book, new_book_size);

		cf_free(p_new_book);
	}

	return p_new_rinfo;
}

//------------------------------------------------
// Create a rinfo object from an existing object,
// with a new privilege added, but don't generate
// its book. (Currently used only at startup.)
//
rinfo*
rinfo_replace_add_priv_only(const rinfo* p_old_rinfo, const priv_code* p_priv)
{
	if (p_old_rinfo->book_size != 0) {
		cf_crash(AS_SECURITY, "replace add priv only - has book");
	}

	uint32_t num_new_privs = p_old_rinfo->num_privs + 1;

	uint32_t new_size =
			sizeof(rinfo) +
			(num_new_privs * sizeof(priv_code));

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	copy_rinfo_whitelist(p_new_rinfo, p_old_rinfo);
	p_new_rinfo->read_quota = p_old_rinfo->read_quota;
	p_new_rinfo->write_quota = p_old_rinfo->write_quota;
	p_new_rinfo->num_privs = num_new_privs;
	p_new_rinfo->book_size = 0;

	uint8_t* p_write = (uint8_t*)rinfo_privs(p_new_rinfo);

	if (num_new_privs > 1) {
		p_write = write_rinfo_privs(p_write, p_old_rinfo);
	}

	write_priv(p_write, p_priv);

	return p_new_rinfo;
}

//------------------------------------------------
// Create a rinfo object from an existing object,
// with an existing privilege removed.
//
rinfo*
rinfo_replace_delete_priv(const rinfo* p_old_rinfo, const priv_code* p_priv)
{
	uint32_t num_new_privs = p_old_rinfo->num_privs - 1;

	if (num_new_privs == 0) {
		rinfo* p_new_rinfo = cf_rc_alloc(sizeof(rinfo));

		copy_rinfo_whitelist(p_new_rinfo, p_old_rinfo);
		p_new_rinfo->read_quota = p_old_rinfo->read_quota;
		p_new_rinfo->write_quota = p_old_rinfo->write_quota;
		p_new_rinfo->num_privs = 0;
		p_new_rinfo->book_size = 0;

		return p_new_rinfo;
	}

	priv_code new_privs[num_new_privs];

	for (uint32_t i = 0, j = 0; i < p_old_rinfo->num_privs; i++) {
		const priv_code* old_privs = rinfo_privs(p_old_rinfo);

		if (! priv_eq(p_priv, &old_privs[i])) {
			new_privs[j++] = old_privs[i];
		}
	}

	uint32_t new_book_size = 0;
	book* p_new_book = book_merge_privs(new_privs, num_new_privs,
			&new_book_size);

	uint32_t new_size =
			sizeof(rinfo) +
			(num_new_privs * sizeof(priv_code)) +
			new_book_size;

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	copy_rinfo_whitelist(p_new_rinfo, p_old_rinfo);
	p_new_rinfo->read_quota = p_old_rinfo->read_quota;
	p_new_rinfo->write_quota = p_old_rinfo->write_quota;
	p_new_rinfo->num_privs = num_new_privs;
	p_new_rinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)rinfo_privs(p_new_rinfo);

	p_write = write_privs(p_write, new_privs, num_new_privs);
	write_book(p_write, p_new_book, new_book_size);

	cf_free(p_new_book);

	return p_new_rinfo;
}

//------------------------------------------------
// Generate this role's permissions book from its
// list of privileges. (Currently used only at
// startup.)
//
rinfo*
rinfo_generate_book(const rinfo* p_old_rinfo)
{
	if (p_old_rinfo->num_privs == 0) {
		rinfo* p_new_rinfo = cf_rc_alloc(sizeof(rinfo));

		copy_rinfo_whitelist(p_new_rinfo, p_old_rinfo);
		p_new_rinfo->read_quota = p_old_rinfo->read_quota;
		p_new_rinfo->write_quota = p_old_rinfo->write_quota;
		p_new_rinfo->num_privs = 0;
		p_new_rinfo->book_size = 0;

		return p_new_rinfo;
	}

	uint32_t new_book_size = 0;
	book* p_new_book = book_merge_privs(rinfo_privs(p_old_rinfo),
			p_old_rinfo->num_privs, &new_book_size);

	uint32_t new_size =
			sizeof(rinfo) +
			rinfo_privs_size(p_old_rinfo) +
			new_book_size;

	rinfo* p_new_rinfo = cf_rc_alloc(new_size);

	copy_rinfo_whitelist(p_new_rinfo, p_old_rinfo);
	p_new_rinfo->read_quota = p_old_rinfo->read_quota;
	p_new_rinfo->write_quota = p_old_rinfo->write_quota;
	p_new_rinfo->num_privs = p_old_rinfo->num_privs;
	p_new_rinfo->book_size = new_book_size;

	uint8_t* p_write = (uint8_t*)rinfo_privs(p_new_rinfo);

	p_write = write_rinfo_privs(p_write, p_old_rinfo);
	write_book(p_write, p_new_book, new_book_size);

	cf_free(p_new_book);

	return p_new_rinfo;
}


//==========================================================
// Miscellaneous helpers.
//

//------------------------------------------------
// Copy a rinfo's whitelist to another.
//
void
copy_rinfo_whitelist(rinfo* dest, const rinfo* src)
{
	uint32_t n_nets = src->whitelist.n_nets;

	dest->whitelist.n_nets = n_nets;

	for (uint32_t i = 0; i < n_nets; i++) {
		dest->whitelist.nets[i] = src->whitelist.nets[i];
	}
}

//------------------------------------------------
// Copy a rinfo's variable size data to another.
//
void
copy_rinfo_vdata(rinfo* dest, const rinfo* src)
{
	uint32_t size = rinfo_privs_size(src) + src->book_size;

	if (size != 0) {
		memcpy(dest->vdata, src->vdata, size);
	}
}

//------------------------------------------------
// Set a rinfo's whitelist.
//
void
set_rinfo_whitelist(rinfo* p_rinfo, const ip_net_list* list)
{
	uint32_t n_nets = list->n_nets;

	p_rinfo->whitelist.n_nets = n_nets;

	for (uint32_t i = 0; i < n_nets; i++) {
		p_rinfo->whitelist.nets[i] = list->nets[i];
	}
}

//------------------------------------------------
// Size of the privileges list.
//
static inline uint32_t
rinfo_privs_size(const rinfo* p_rinfo)
{
	return p_rinfo->num_privs * sizeof(priv_code);
}

//------------------------------------------------
// Append a privilege (priv_code) to a buffer.
//
uint8_t*
write_priv(uint8_t* p_write, const priv_code* p_priv)
{
	priv_code* p_write_priv_code = (priv_code*)p_write;

	*p_write_priv_code++ = *p_priv;

	return (uint8_t*)p_write_priv_code;
}

//------------------------------------------------
// Append a list of priv_codes to a buffer.
//
uint8_t*
write_privs(uint8_t* p_write, const priv_code* p_privs, uint32_t num_privs)
{
	if (num_privs == 0) {
		cf_crash(AS_SECURITY, "write privs - no privs");
	}

	uint32_t write_size = num_privs * sizeof(priv_code);

	memcpy(p_write, p_privs, write_size);

	return p_write + write_size;
}

//------------------------------------------------
// Append a rinfo's list of priv_codes to a
// buffer.
//
static inline uint8_t*
write_rinfo_privs(uint8_t* p_write, const rinfo* p_rinfo)
{
	return write_privs(p_write, rinfo_privs(p_rinfo), p_rinfo->num_privs);
}

//------------------------------------------------
// Append a book to a buffer.
//
static inline void
write_book(uint8_t* p_write, const book* p_book, uint32_t book_size)
{
	if (book_size == 0) {
		cf_crash(AS_SECURITY, "write book - no book");
	}

	memcpy(p_write, p_book, book_size);
}


//==========================================================
// ip_net_list helpers.
//

//------------------------------------------------
// Convert a string list to an ip_net_list.
//
bool
parse_list(char* list_string, ip_net_list* list)
{
	list->n_nets = 0;

	char* save_ptr = NULL;
	char* tok = strtok_r(list_string, NET_LIST_DELIMITERS, &save_ptr);

	while (tok != NULL) {
		if (list->n_nets == MAX_IP_NETS) {
			cf_warning(AS_SECURITY, "too many IP-nets in whitelist");
			return false;
		}

		if (cf_ip_net_from_string(tok, &list->nets[list->n_nets]) < 0) {
			cf_warning(AS_SECURITY, "invalid IP-net in whitelist");
			return false;
		}

		list->n_nets++;

		tok = strtok_r(NULL, NET_LIST_DELIMITERS, &save_ptr);
	}

	if (list->n_nets == 0) {
		cf_warning(AS_SECURITY, "empty whitelist");
		return false;
	}

	return true;
}


//==========================================================
// Public API - for debugging only.
//

#include <stdio.h>
#include "base/cfg.h"
#include "base/datamodel.h"

//------------------------------------------------
// Log the contents of this role.
//
void
dump_rinfo(const char* tag, const char* name, const rinfo* p_rinfo)
{
	cf_info(AS_SECURITY, "%s - role %s:", tag, name);

	if (! p_rinfo) {
		cf_info(AS_SECURITY, "<null rinfo>");
		return;
	}

	if (rinfo_has_whitelist(p_rinfo)) {
		char whitelist[2048];

		rinfo_get_whitelist(p_rinfo, whitelist, sizeof(whitelist));

		cf_info(AS_SECURITY, " - whitelist: %s", whitelist);
	}

	cf_info(AS_SECURITY, " - read-quota: %u", p_rinfo->read_quota);
	cf_info(AS_SECURITY, " - write-quota: %u", p_rinfo->write_quota);
	cf_info(AS_SECURITY, " - num-privs: %u", p_rinfo->num_privs);
	cf_info(AS_SECURITY, " - book-size: %u", p_rinfo->book_size);
	cf_info(AS_SECURITY, " privs:");

	if (p_rinfo->num_privs == 0) {
		return;
	}

	const priv_code* privs = rinfo_privs(p_rinfo);

	for (uint32_t i = 0; i < p_rinfo->num_privs; i++) {
		const priv_code* p_priv = &privs[i];

		char* ns_name = NULL;
		as_namespace* ns = NULL;
		char ns_ix_str[8];

		if (p_priv->ns_ix < g_num_namespaces) {
			ns = g_config.namespaces[p_priv->ns_ix];
			ns_name = ns->name;
		}
		else {
			if (p_priv->ns_ix == NO_NS_IX) {
				strcpy(ns_ix_str, "<none>");
			}
			else {
				sprintf(ns_ix_str, "<%u>", p_priv->ns_ix);
			}

			ns_name = ns_ix_str;
		}

		const char* set_name = ns ?
				as_namespace_get_set_name(ns,  p_priv->set_id) : NULL;
		char set_id_str[16];

		if (! set_name) {
			sprintf(set_id_str, "<%u>", p_priv->set_id);
			set_name = (const char*)set_id_str;
		}

		cf_info(AS_SECURITY, " - %u:%s:%s", p_priv->perm_code, ns_name,
				set_name);
	}

	cf_info(AS_SECURITY, " book:");

	dump_book(rinfo_book(p_rinfo));
}
