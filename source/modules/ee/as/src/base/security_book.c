/*
 * security_book.c
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

#include "base/security_book.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "citrusleaf/alloc.h"

#include "log.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/security.h"
#include "base/security_ee.h"


//==========================================================
// Typedefs & constants.
//

// Permission book object held by uinfo and rinfo.
struct book_s {
	uint64_t	global_perms;
	uint8_t		vdata[];
};

// Book sub-structure - locate a namespace's set-scoped permissions.
typedef struct set_info_s {
	uint32_t count;
	uint32_t count_offset;
} set_info;

// Book sub-structure - a namespace's set-scoped permissions.
typedef struct set_perm_s {
	uint16_t set_id;
	uint64_t perms;
} __attribute__ ((__packed__)) set_perms;


//==========================================================
// Globals.
//

static uint32_t g_max_priv_book_size = 0;


//==========================================================
// Forward declarations.
//

uint64_t book_get_perms_ns_scope(const book* p_book, uint32_t ns_ix);
uint64_t book_get_perms_set_scope(const book* p_book, uint32_t ns_ix, uint16_t set_id);
uint32_t book_get_set_count(const book* p_book, uint32_t ns_ix);
const set_perms* book_get_set_perms_list(const book* p_book, uint32_t ns_ix, uint32_t* p_count);
uint64_t get_perms_from_code(uint32_t perm_code);


//==========================================================
// Public API.
//

//------------------------------------------------
// Check if specified scoped permission is allowed
// in this book.
//
bool
book_allows_op(const book* p_book, uint32_t ns_ix, uint16_t set_id,
		uint64_t op_perm)
{
	if (op_perm == PERM_NONE) {
		return true;
	}

	if (! p_book) {
		return false;
	}

	if ((op_perm & p_book->global_perms) == op_perm) {
		return true;
	}

	if (ns_ix == NO_NS_IX) {
		return false;
	}

	if ((op_perm & book_get_perms_ns_scope(p_book, ns_ix)) == op_perm) {
		return true;
	}

	if (set_id == 0) {
		return false;
	}

	return (op_perm & book_get_perms_set_scope(p_book, ns_ix, set_id)) ==
			op_perm;
}

//------------------------------------------------
// Fill a pre-allocated book from one priv_code.
//
void
book_init_priv(book* p_book, uint32_t book_size, const priv_code* p_priv)
{
	memset(p_book, 0, book_size);

	uint32_t ns_ix = p_priv->ns_ix;
	uint64_t perms = get_perms_from_code(p_priv->perm_code);

	if (ns_ix == NO_NS_IX) {
		p_book->global_perms = perms;
		return;
	}

	uint64_t* p_ns_scope_perms = (uint64_t*)p_book->vdata;
	set_info* p_set_infos = (set_info*)(p_ns_scope_perms + g_num_namespaces);

	if (p_priv->set_id == INVALID_SET_ID) {
		p_ns_scope_perms[ns_ix] = perms;
		return;
	}

	// It is a set scope privilege.
	p_set_infos[ns_ix].count = 1;

	set_perms* p_set_perms = (set_perms*)(p_set_infos + g_num_namespaces);

	p_set_perms->set_id = p_priv->set_id;
	p_set_perms->perms = perms;
}

//------------------------------------------------
// Merge two or more permission books.
//
book*
book_merge(const book** books, uint32_t n_books, uint32_t* p_book_size)
{
	// Handle the set scope permissions first, since they're necessary to
	// determine the overall size.

	// For each namespace, allocate a temporary block of set_perms structs.
	set_perms* a_set_perms[g_num_namespaces];

	for (uint32_t n = 0; n < g_num_namespaces; n++) {
		uint32_t set_count = 0;

		// Accumulate the maximum possible set count.
		for (uint32_t b = 0; b < n_books; b++) {
			set_count += book_get_set_count(books[b], n);
		}

		// Stack-allocate based on this pessimistic maximum count.
		a_set_perms[n] = set_count != 0 ?
				alloca(set_count * sizeof(set_perms)) : NULL;
	}

	// Now we'll find the real set counts as we merge...
	uint32_t total_set_perms = 0;
	uint32_t set_counts[g_num_namespaces];

	for (uint32_t n = 0; n < g_num_namespaces; n++) {
		// Accumulate set count and set_perms list, starting empty.
		set_counts[n] = 0;
		set_perms* p_new_set_perms = a_set_perms[n];

		for (uint32_t b = 0; b < n_books; b++) {
			uint32_t count;
			const set_perms* p_set_perms =
					book_get_set_perms_list(books[b], n, &count);

			// Since all books have sorted sets info, we don't have to loop over
			// the accumulated list from the beginning every time - start from
			// (just past) where we left off the previous time.
			uint32_t k = 0;

			// For each book, iterate over all its sets and merge or insert each
			// set's info into the accumulated list from previous books.
			for (uint32_t j = 0; j < count; j++) {
				uint16_t cur_set_id = p_set_perms[j].set_id;
				uint64_t cur_perms = p_set_perms[j].perms;

				// Loop over accumulated list, keep it sorted.
				while (k < set_counts[n]) {
					uint16_t cur_new_set_id = p_new_set_perms[k].set_id;

					if (cur_set_id == cur_new_set_id) {
						p_new_set_perms[k].perms |= cur_perms;
						break;
					}

					if (cur_set_id < cur_new_set_id) {
						uint8_t* from = (uint8_t*)&p_new_set_perms[k];
						uint8_t* to = from + sizeof(set_perms);
						uint32_t size = (set_counts[n] - k) * sizeof(set_perms);

						memmove(to, from, size);
						p_new_set_perms[k].set_id = cur_set_id;
						p_new_set_perms[k].perms = cur_perms;
						set_counts[n]++;
						break;
					}

					k++;
				}

				if (k == set_counts[n]) {
					p_new_set_perms[k].set_id = cur_set_id;
					p_new_set_perms[k].perms = cur_perms;
					set_counts[n]++;
				}

				k++;
			}
		}

		total_set_perms += set_counts[n];
	}

	// We now know the overall size, and can allocate.

	uint32_t total_size =
			((1 + g_num_namespaces) * sizeof(uint64_t)) +
			(g_num_namespaces * sizeof(set_info)) +
			(total_set_perms * sizeof(set_perms));

	book* p_new_book = cf_malloc(total_size);

	// Merge all the global scope permissions.

	p_new_book->global_perms = PERM_NONE;

	for (uint32_t i = 0; i < n_books; i++) {
		p_new_book->global_perms |= books[i]->global_perms;
	}

	// Handle the namespace and set scope permissions.

	uint64_t* p_ns_scope_perms = (uint64_t*)p_new_book->vdata;
	set_info* p_set_infos = (set_info*)(p_ns_scope_perms + g_num_namespaces);
	uint32_t count_offset = 0;
	uint8_t* p_set_perms = (uint8_t*)(p_set_infos + g_num_namespaces);

	for (uint32_t n = 0; n < g_num_namespaces; n++) {
		// Merge all the namespace scope permissions.
		p_ns_scope_perms[n] = 0;

		for (uint32_t i = 0; i < n_books; i++) {
			p_ns_scope_perms[n] |= book_get_perms_ns_scope(books[i], n);
		}

		// Fill in the set scope permissions' count and location info.
		p_set_infos[n].count = set_counts[n];
		p_set_infos[n].count_offset = count_offset;
		count_offset += set_counts[n];

		// Copy the merged set scope permissions from their temporary blocks.

		uint32_t set_perms_size = set_counts[n] * sizeof(set_perms);

		if (a_set_perms[n]) {
			memcpy(p_set_perms, a_set_perms[n], set_perms_size);
			p_set_perms += set_perms_size;
		}
	}

	*p_book_size = total_size;

	return p_new_book;
}

//------------------------------------------------
// Make a book from an existing book and a single
// priv_code.
//
book*
book_merge_priv(const book* p_book, const priv_code* p_priv,
		uint32_t* p_book_size)
{
	uint8_t single_priv_book[g_max_priv_book_size];

	book_init_priv((book*)single_priv_book, g_max_priv_book_size, p_priv);

	const book* books[2];

	books[0] = p_book;
	books[1] = (book*)single_priv_book;

	return book_merge(books, 2, p_book_size);
}

//------------------------------------------------
// Make a book from a list of priv_codes.
//
book*
book_merge_privs(const priv_code* privs, uint32_t num_privs,
		uint32_t* p_book_size)
{
	uint8_t single_priv_books[num_privs * g_max_priv_book_size];
	uint8_t* p_book = single_priv_books;
	const book* a_single_priv_books[num_privs];

	for (int b = 0; b < num_privs; b++) {
		book_init_priv((book*)p_book, g_max_priv_book_size, &privs[b]);
		a_single_priv_books[b] = (book*)p_book;
		p_book += g_max_priv_book_size;
	}

	return book_merge(a_single_priv_books, num_privs, p_book_size);
}

//------------------------------------------------
// Size of a book made from a single privilege.
//
uint32_t
priv_book_size(const priv_code* p_priv)
{
	return p_priv->set_id != INVALID_SET_ID ?
			g_max_priv_book_size : g_max_priv_book_size - sizeof(set_perms);
}

//------------------------------------------------
// Store the maximum size of a book made from a
// single privilege (which can have at most one
// set_perms structure).
//
void
set_max_priv_book_size()
{
	g_max_priv_book_size =
			sizeof(book) +
			(g_num_namespaces * sizeof(uint64_t)) +
			(g_num_namespaces * sizeof(set_info)) +
			sizeof(set_perms);
}


//==========================================================
// Miscellaneous helpers.
//

//------------------------------------------------
// Get the specified namespace-scoped permissions.
//
uint64_t
book_get_perms_ns_scope(const book* p_book, uint32_t ns_ix)
{
	uint64_t* p_ns_scope_perms = (uint64_t*)p_book->vdata;

	return p_ns_scope_perms[ns_ix];
}

//------------------------------------------------
// Get the specified set-scoped permissions.
//
uint64_t
book_get_perms_set_scope(const book* p_book, uint32_t ns_ix, uint16_t set_id)
{
	set_info* p_set_infos = (set_info*)
			((uint64_t*)p_book->vdata + g_num_namespaces);

	uint32_t count = p_set_infos[ns_ix].count;

	if (count == 0) {
		return PERM_NONE;
	}

	set_perms* p_perms = (set_perms*)(p_set_infos + g_num_namespaces) +
			p_set_infos[ns_ix].count_offset;

	for (uint32_t j = 0; j < count; j++) {
		uint16_t cur_set_id = p_perms[j].set_id;

		if (set_id == cur_set_id) {
			return p_perms[j].perms;
		}

		if (set_id < cur_set_id) {
			break;
		}
	}

	return PERM_NONE;
}

//------------------------------------------------
// Get the specified namespace's number of
// set_perms structures.
//
uint32_t
book_get_set_count(const book* p_book, uint32_t ns_ix)
{
	set_info* p_set_infos = (set_info*)
			((uint64_t*)p_book->vdata + g_num_namespaces);

	return p_set_infos[ns_ix].count;
}

//------------------------------------------------
// Get the pointer to the specified namespace's
// (list of) set_perms structures.
//
const set_perms*
book_get_set_perms_list(const book* p_book, uint32_t ns_ix, uint32_t* p_count)
{
	set_info* p_set_infos = (set_info*)
			((uint64_t*)p_book->vdata + g_num_namespaces);

	uint32_t count = p_set_infos[ns_ix].count;

	*p_count = count;

	if (count == 0) {
		return NULL;
	}

	return (const set_perms*)(p_set_infos + g_num_namespaces) +
			p_set_infos[ns_ix].count_offset;
}

//------------------------------------------------
// Convert a permissions code to a permissions bit
// field.
//
uint64_t
get_perms_from_code(uint32_t perm_code)
{
	switch (perm_code) {
	case AS_SEC_PERM_CODE_USER_ADMIN:
	case AS_SEC_PERM_CODE_SYS_ADMIN:
	case AS_SEC_PERM_CODE_DATA_ADMIN:
	case AS_SEC_PERM_CODE_UDF_ADMIN:
	case AS_SEC_PERM_CODE_SINDEX_ADMIN:
		return ROLE_PERMS[perm_code];
	case AS_SEC_PERM_CODE_READ:
	case AS_SEC_PERM_CODE_READ_WRITE:
	case AS_SEC_PERM_CODE_READ_WRITE_UDF:
	case AS_SEC_PERM_CODE_WRITE:
	case AS_SEC_PERM_CODE_TRUNCATE:
		return ROLE_PERMS[(perm_code - AS_SEC_PERM_CODE_FIRST_NON_GLOBAL) +
				AS_SEC_PERM_CODE_LAST_GLOBAL_PLUS_1];
	default:
		cf_warning(AS_SECURITY, "invalid perm code %u", perm_code);
		return PERM_NONE;
	}
}


//==========================================================
// Public API - for debugging only.
//

#include <stdio.h>
#include "base/cfg.h"
#include "base/datamodel.h"

//------------------------------------------------
// Log the contents of this book.
//
void
dump_book(const book* p_book)
{
	if (! p_book) {
		cf_info(AS_SECURITY, "<null book>");
		return;
	}

	cf_info(AS_SECURITY, " - global: %lx", p_book->global_perms);

	for (uint32_t n = 0; n < g_num_namespaces; n++) {
		cf_info(AS_SECURITY, " - {%s}: %lx", g_config.namespaces[n]->name,
				book_get_perms_ns_scope(p_book, n));
	}

	set_info* p_set_infos = (set_info*)
			((uint64_t*)p_book->vdata + g_num_namespaces);
	set_perms* p_set_perms = (set_perms*)(p_set_infos + g_num_namespaces);

	for (uint32_t n = 0; n < g_num_namespaces; n++) {
		uint32_t count = p_set_infos[n].count;

		if (count == 0) {
			continue;
		}

		as_namespace* ns = g_config.namespaces[n];
		set_perms* p_perms = p_set_perms + p_set_infos[n].count_offset;

		for (uint32_t j = 0; j < count; j++) {
			uint16_t set_id = p_perms[j].set_id;
			const char* set_name = as_namespace_get_set_name(ns, set_id);
			char set_id_str[16];

			if (! set_name) {
				sprintf(set_id_str, "<%u>", set_id);
				set_name = (const char*)set_id_str;
			}

			cf_info(AS_SECURITY, " - {%s|%s}: %lx", ns->name, set_name,
					p_perms[j].perms);
		}
	}
}
