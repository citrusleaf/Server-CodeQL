/*
 * proto_ee.c
 *
 * Copyright (C) 2019-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "base/proto.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_byte_order.h"

#include "cf_thread.h"
#include "log.h"


//==========================================================
// Typedefs & constants.
//

#define MIN_COMPRESSIBLE_SZ 128
#define MIN_COMPRESSION_GAIN 32
#define BUF_SZ_STEP (1024UL * 128)


//==========================================================
// Inlines & macros.
//

// TODO - consolidate with function in flat_ee.c?
#include "aerospike/as_atomic.h"

static inline void
update_average(double* avg, size_t val)
{
	while (true) {
		double cur = as_load_double(avg);
		double next = (cur * 0.99999) + ((double)val * 0.00001);

		if (as_cas_double(avg, cur, next)) {
			break;
		}
	}
}

static inline void
update_average_local(double* avg, size_t val)
{
	// Note - we weight val more in thread-local scenarios.
	*avg = (*avg * 0.999) + ((double)val * 0.001);
}


//==========================================================
// Public API.
//

// Resulting as_comp_proto is network-ordered. Original as_proto is compressed
// as provided - caller must ensure it is already network-ordered and sane.
const uint8_t*
as_proto_compress(const uint8_t* original, size_t* sz,
		as_proto_comp_stat* comp_stat)
{
	size_t original_sz = *sz;

	if (original_sz < MIN_COMPRESSIBLE_SZ) {
		update_average(&comp_stat->uncomp_pct, 100);
		return original;
	}

	static __thread size_t buf_sz = 0;
	static __thread uint8_t* buf = NULL;

	size_t final_sz = original_sz - MIN_COMPRESSION_GAIN;

	if (final_sz > buf_sz) {
		buf_sz = (final_sz + (BUF_SZ_STEP - 1)) & -BUF_SZ_STEP;
		cf_thread_realloc((void**)&buf, &buf_sz);
	}

	as_comp_proto* cproto = (as_comp_proto*)buf;
	size_t compressed_sz = final_sz - sizeof(as_comp_proto);

	if (compress2(cproto->data, &compressed_sz, original, original_sz,
			Z_BEST_SPEED) != Z_OK) {
		update_average(&comp_stat->uncomp_pct, 100);
		return original;
	}

	*cproto = (as_comp_proto){
			.proto = {
					.version = PROTO_VERSION,
					.type = PROTO_TYPE_AS_MSG_COMPRESSED,
					.sz = sizeof(cproto->orig_sz) + compressed_sz
			},
			.orig_sz = cf_swap_to_be64(original_sz)
	};

	as_proto_swap(&cproto->proto);

	*sz = sizeof(as_comp_proto) + compressed_sz;

	update_average(&comp_stat->uncomp_pct, 0);
	update_average(&comp_stat->avg_orig_sz, original_sz);
	update_average(&comp_stat->avg_comp_sz, *sz);

	return (const uint8_t*)buf;
}

// Resulting as_comp_proto is network-ordered. Original as_proto is compressed
// as provided - caller must ensure it is already network-ordered and sane. The
// as_proto may be embedded at the end of a struct - 'indent' is an offset from
// 'original' that specifies where the as_proto starts within that struct. The
// resulting as_comp_proto is also indented within the newly allocated buffer,
// and the prefix bytes are copied to the new buffer.
uint8_t*
as_proto_compress_alloc(const uint8_t* original, size_t alloc_sz, size_t indent,
		size_t* sz, as_proto_comp_stat* comp_stat)
{
	size_t original_sz = *sz; // excludes indent

	if (original_sz < MIN_COMPRESSIBLE_SZ) {
		update_average(&comp_stat->uncomp_pct, 100);
		return (uint8_t*)original;
	}

	size_t final_sz = original_sz - MIN_COMPRESSION_GAIN;

	if (alloc_sz == 0) {
		alloc_sz = indent + final_sz;
	}
	// else - trust that provided alloc_sz is big enough. Use provided size (as
	// opposed to calculated size) e.g. if replacing a buffer in a pool.

	uint8_t* buf = cf_malloc(alloc_sz);

	as_comp_proto* cproto = (as_comp_proto*)(buf + indent);
	size_t compressed_sz = final_sz - sizeof(as_comp_proto);

	if (compress2(cproto->data, &compressed_sz, original + indent,
			original_sz, Z_BEST_SPEED) != Z_OK) {
		cf_free(buf);
		update_average(&comp_stat->uncomp_pct, 100);
		return (uint8_t*)original;
	}

	memcpy(buf, original, indent);

	*cproto = (as_comp_proto){
			.proto = {
					.version = PROTO_VERSION,
					.type = PROTO_TYPE_AS_MSG_COMPRESSED,
					.sz = sizeof(cproto->orig_sz) + compressed_sz
			},
			.orig_sz = cf_swap_to_be64(original_sz)
	};

	as_proto_swap(&cproto->proto);

	*sz = sizeof(as_comp_proto) + compressed_sz; // excludes indent

	update_average(&comp_stat->uncomp_pct, 0);
	update_average(&comp_stat->avg_orig_sz, original_sz);
	update_average(&comp_stat->avg_comp_sz, *sz);

	return buf; // caller must free
}

// Resulting as_comp_proto is network-ordered. Original as_proto is compressed
// as provided - caller must ensure it is already network-ordered and sane.
// Currently only used by XDR. TODO - adopt thread local stats generally.
uint8_t*
as_proto_compress_alloc_xdr(const uint8_t* original, size_t* sz, uint32_t level,
		size_t threshold, as_proto_comp_stat* comp_stat)
{
	size_t original_sz = *sz;

	if (original_sz < threshold) {
		update_average_local(&comp_stat->uncomp_pct, 100);
		return (uint8_t*)original;
	}

	size_t final_sz = original_sz - MIN_COMPRESSION_GAIN;
	uint8_t* buf = cf_malloc(final_sz);

	as_comp_proto* cproto = (as_comp_proto*)buf;
	size_t compressed_sz = final_sz - sizeof(as_comp_proto);

	if (compress2(cproto->data, &compressed_sz, original, original_sz,
			(int)level) != Z_OK) {
		cf_free(buf);
		update_average_local(&comp_stat->uncomp_pct, 100);
		return (uint8_t*)original;
	}

	*cproto = (as_comp_proto){
			.proto = {
					.version = PROTO_VERSION,
					.type = PROTO_TYPE_AS_MSG_COMPRESSED,
					.sz = sizeof(cproto->orig_sz) + compressed_sz
			},
			.orig_sz = cf_swap_to_be64(original_sz)
	};

	as_proto_swap(&cproto->proto);

	*sz = sizeof(as_comp_proto) + compressed_sz;

	update_average_local(&comp_stat->uncomp_pct, 0);
	update_average_local(&comp_stat->avg_orig_sz, original_sz);
	update_average_local(&comp_stat->avg_comp_sz, *sz);

	return buf; // caller must free
}

// Resulting as_proto is host-ordered. Original cproto->proto is assumed to be
// host-ordered and already sanity-checked.
uint32_t
as_proto_uncompress(const as_comp_proto* cproto, as_proto** p_proto)
{
	uint64_t original_sz = cproto->orig_sz;

	// Hack to handle both little and big endian formats. Some clients wrongly
	// send the size in little-endian format. If we interpret a legal big-endian
	// size as little-endian, it will be > PROTO_SIZE_MAX. Use it as a clue.
	// TODO - remove in "six months".
	if (original_sz > PROTO_SIZE_MAX) {
		original_sz = cf_swap_from_be64(cproto->orig_sz);

		if (original_sz > PROTO_SIZE_MAX) {
			cf_warning(AS_PROTO, "bad compressed size %lu", original_sz);
			return AS_ERR_UNKNOWN;
		}
	}

	size_t buf_sz = original_sz;
	uint8_t* buf = cf_malloc(buf_sz);

	size_t compressed_sz = cproto->proto.sz - sizeof(cproto->orig_sz);
	int rv = uncompress(buf, &buf_sz, cproto->data, compressed_sz);

	if (rv != Z_OK) {
		cf_warning(AS_PROTO, "decompression failed with error %d", rv);
		cf_free(buf);
		return AS_ERR_UNKNOWN;
	}

	if (buf_sz != original_sz) {
		cf_warning(AS_PROTO, "decompressed size %zu is not expected size %lu",
				buf_sz, original_sz);
		cf_free(buf);
		return AS_ERR_UNKNOWN;
	}

	as_proto* proto = (as_proto*)buf;

	as_proto_swap(proto);

	if (! as_proto_wrapped_is_valid(proto, buf_sz)) {
		cf_warning(AS_PROTO, "decompressed proto (%d,%d,%lu,%zu)",
				proto->version, proto->type, (uint64_t)proto->sz, buf_sz);
		cf_free(buf);
		return AS_ERR_UNKNOWN;
	}

	*p_proto = proto;

	return AS_OK;
}
