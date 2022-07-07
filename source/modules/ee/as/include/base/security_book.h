/*
 * security_book.h
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

#include "base/security_ee.h"

// Permission book object held by uinfo and rinfo.
typedef struct book_s book;

bool book_allows_op(const book* p_book, uint32_t ns_ix, uint16_t set_id, uint64_t op_perm);
void book_init_priv(book* p_book, uint32_t book_size, const priv_code* p_priv);
book* book_merge(const book** books, uint32_t n_books, uint32_t* p_book_size);
book* book_merge_priv(const book* p_book, const priv_code* p_priv, uint32_t* p_book_size);
book* book_merge_privs(const priv_code* privs, uint32_t num_privs, uint32_t* p_book_size);
uint32_t priv_book_size(const priv_code* p_priv);
void set_max_priv_book_size();

// For debugging only.
void dump_book(const book* p_book);
