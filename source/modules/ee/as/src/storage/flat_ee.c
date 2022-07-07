/*
 * flat_ee.c
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

#include "storage/flat.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "lz4.h"
#include "snappy-c.h"
#include "zstd.h"

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"

#include "bits.h"
#include "cf_thread.h"
#include "log.h"
#include "vmapx.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "storage/storage.h"


//==========================================================
// Forward declarations.
//

static uint32_t compress_lz4(uint8_t* out, uint32_t out_sz, const uint8_t* in, uint32_t in_sz);
static uint32_t compress_snappy(uint8_t* out, uint32_t out_sz, const uint8_t* in, uint32_t in_sz);
static uint32_t compress_zstd(uint8_t* out, uint32_t out_sz, const uint8_t* in, uint32_t in_sz, uint32_t level);
static void update_average(double* avg, uint32_t val);

static uint8_t* decompress(as_compression_method meth, uint32_t max_out_sz, uint32_t out_sz, const void* in, uint32_t in_sz);
static bool decompress_lz4(uint8_t* out, uint32_t out_sz, const uint8_t* in, uint32_t in_sz);
static bool decompress_snappy(uint8_t* out, uint32_t out_sz, const uint8_t* in, uint32_t in_sz);
static bool decompress_zstd(uint8_t* out, uint32_t out_sz, const uint8_t* in, uint32_t in_sz);


//==========================================================
// Public API.
//

as_flat_record*
as_flat_compress_bins_and_pack_record(const as_storage_rd* rd,
		uint32_t max_orig_sz, bool dirty, bool will_mark_end, uint32_t* flat_sz)
{
	as_namespace* ns = rd->ns;
	as_compression_method meth = as_load_int32(&ns->storage_compression);

	if (meth == AS_COMPRESSION_NONE) {
		return NULL;
	}

	uint32_t write_sz = SIZE_UP_TO_RBLOCK_SIZE(*flat_sz);

	// One allocation for two buffers.
	static __thread size_t buffers_sz = 0;
	static __thread uint8_t* buffers = NULL;

	size_t need_buffers_sz = max_orig_sz * 2;

	if (need_buffers_sz > buffers_sz) {
		buffers_sz = need_buffers_sz;
		cf_thread_realloc((void**)&buffers, &buffers_sz);
	}

	uint8_t* orig = buffers;
	uint32_t orig_sz;

	uint8_t* comp = buffers + max_orig_sz;
	uint32_t comp_sz;

	// Flatten bins into buffer #1.
	flatten_bins(rd, orig, &orig_sz);

	update_average(&ns->comp_avg_orig_sz, write_sz);

	if (rd->n_bins == 0) {
		update_average(&ns->comp_avg_comp_sz, write_sz);
		return NULL;
	}

	// Compress bins from buffer #1 into buffer #2.
	switch (meth) {
	case AS_COMPRESSION_LZ4:
		comp_sz = compress_lz4(comp, max_orig_sz, orig, orig_sz);
		break;
	case AS_COMPRESSION_SNAPPY:
		comp_sz = compress_snappy(comp, max_orig_sz, orig, orig_sz);
		break;
	case AS_COMPRESSION_ZSTD:
		comp_sz = compress_zstd(comp, max_orig_sz, orig, orig_sz,
				ns->storage_compression_level);
		break;
	default:
		comp_sz = 0;
		break;
	}

	// Don't allow compression to make things larger.
	if (comp_sz == 0 || comp_sz >= orig_sz) {
		update_average(&ns->comp_avg_comp_sz, write_sz);
		return NULL;
	}

	// Determine meta data size.

	uint32_t meta_sz = flat_record_overhead_size(rd);

	meta_sz += 1; // method
	meta_sz += uintvar_size(orig_sz);
	meta_sz += uintvar_size(comp_sz);

	uint32_t total_sz = meta_sz + comp_sz;

	if (will_mark_end) {
		total_sz += END_MARK_SZ;
	}

	uint32_t round_sz = SIZE_UP_TO_RBLOCK_SIZE(total_sz);

	// Compression may not have made things larger, but the added compression
	// fields may have. This would subvert the write block size check we already
	// did with the uncompressed size.
	if (round_sz >= write_sz) {
		update_average(&ns->comp_avg_comp_sz, write_sz);
		return NULL;
	}

	uint32_t n_rblocks = ROUNDED_SIZE_TO_N_RBLOCKS(round_sz);

	// Flatten meta data to buffer #1, append compressed bins from buffer #2.

	as_flat_comp_meta cm = {
			.method = meth, .orig_sz = orig_sz, .comp_sz = comp_sz
	};

	as_flat_record* flat = (as_flat_record*)buffers;
	uint8_t* meta_end = flatten_record_meta(rd, n_rblocks, dirty, &cm, flat);

	// Ensure that we're keeping the above size calculation in sync with
	// flatten_record_meta().
	cf_assert(meta_end - buffers == meta_sz, AS_FLAT, "size mismatch");

	memcpy(meta_end, comp, comp_sz);

	update_average(&ns->comp_avg_comp_sz, round_sz);
	*flat_sz = total_sz;

	return flat;
}

uint32_t
as_flat_orig_pickle_size(const as_remote_record* rr, uint32_t pickle_sz)
{
	if (rr->cm.method == AS_COMPRESSION_NONE) {
		return pickle_sz;
	}

	uint32_t cm_meta_sz = 1 +
			uintvar_size(rr->cm.orig_sz) + uintvar_size(rr->cm.comp_sz);

	return (rr->meta_sz - cm_meta_sz) + rr->cm.orig_sz;
}

bool
as_flat_decompress_bins(const as_flat_comp_meta* cm, as_storage_rd* rd)
{
	if (cm->method == AS_COMPRESSION_NONE) {
		return true;
	}

	uint8_t *decomp = decompress(cm->method, rd->ns->storage_write_block_size,
			cm->orig_sz, rd->flat_bins, cm->comp_sz);

	if (decomp == NULL) {
		return false;
	}

	rd->flat_end = decomp + cm->orig_sz;
	rd->flat_bins = decomp;

	return true;
}

bool
as_flat_decompress_buffer(const as_flat_comp_meta* cm, uint32_t max_orig_sz,
		const uint8_t** at, const uint8_t** end, const uint8_t** cb_end)
{
	if (cm->method == AS_COMPRESSION_NONE) {
		return true;
	}

	uint8_t* decomp = decompress(cm->method, max_orig_sz, cm->orig_sz, *at,
			cm->comp_sz);

	if (decomp == NULL) {
		return false;
	}

	if (cb_end != NULL) {
		*cb_end = *at + cm->comp_sz;
	}

	*at = decomp;
	*end = decomp + cm->orig_sz;

	return true;
}


//==========================================================
// Public API - enterprise only.
//

bool
as_flat_record_expired_or_evicted(const as_namespace* ns,
		uint32_t flat_void_time, uint32_t set_id)
{
	if (flat_void_time == 0) {
		return false;
	}

	if (ns->cold_start_now > flat_void_time) {
		return true;
	}

	if (ns->evict_void_time <= flat_void_time) {
		return false;
	}

	if (set_id == INVALID_SET_ID) {
		return true;
	}

	as_set* p_set;

	if (cf_vmapx_get_by_index(ns->p_sets_vmap, set_id - 1, (void**)&p_set) !=
			CF_VMAPX_OK) {
		cf_crash(AS_DRV_PMEM, "failed to get set-id %u from vmap", set_id);
	}

	return ! p_set->eviction_disabled;
}


//==========================================================
// Private API - for enterprise separation only.
//

uint8_t*
flatten_compression_meta(const as_flat_comp_meta* cm, as_flat_record* flat,
		uint8_t* buf)
{
	if (cm == NULL) {
		flat->is_compressed = 0;
		return buf;
	}

	*buf++ = (uint8_t)cm->method;
	buf = uintvar_pack(buf, cm->orig_sz);
	buf = uintvar_pack(buf, cm->comp_sz);

	flat->is_compressed = 1;

	return buf;
}

const uint8_t*
unflatten_compression_meta(const as_flat_record* flat, const uint8_t* at,
		const uint8_t* end, as_flat_comp_meta* cm)
{
	if (flat->is_compressed == 0) {
		return at;
	}

	if (flat->has_bins == 0) {
		cf_warning(AS_FLAT, "compressed but no bins");
		return NULL;
	}

	if (at >= end) {
		cf_warning(AS_FLAT, "incomplete compression metadata");
		return NULL;
	}

	cm->method = (as_compression_method)*at++;

	if (cm->method <= AS_COMPRESSION_NONE ||
			cm->method >= AS_COMPRESSION_LAST_PLUS_1) {
		cf_warning(AS_FLAT, "unsupported compression method %d", cm->method);
		return NULL;
	}

	cm->orig_sz = uintvar_parse(&at, end);

	if (cm->orig_sz == 0 || cm->orig_sz > MAX_WRITE_BLOCK_SIZE) {
		cf_warning(AS_FLAT, "bad original size %u", cm->orig_sz);
		return NULL;
	}

	cm->comp_sz = uintvar_parse(&at, end);

	if (cm->comp_sz == 0 || cm->comp_sz > MAX_WRITE_BLOCK_SIZE ||
			cm->comp_sz > cm->orig_sz) {
		cf_warning(AS_FLAT, "bad compressed size (%u,%u)", cm->comp_sz,
				cm->orig_sz);
		return NULL;
	}

	return at;
}

void
set_remote_record_xdr_flags(const as_flat_record* flat,
		const as_flat_extra_flags* extra_flags, as_remote_record* rr)
{
	rr->xdr_write = flat->xdr_write == 1;
	rr->xdr_tombstone = extra_flags->xdr_tombstone == 1;
	rr->xdr_nsup_tombstone = extra_flags->xdr_nsup_tombstone == 1;
	rr->xdr_bin_cemetery = extra_flags->xdr_bin_cemetery == 1;
}

void
set_flat_xdr_state(const as_record* r, as_flat_record* flat)
{
	flat->xdr_write = r->xdr_write;
}

as_flat_extra_flags
get_flat_extra_flags(const as_record* r)
{
	return (as_flat_extra_flags){
		.xdr_tombstone = r->xdr_tombstone,
		.xdr_nsup_tombstone = r->xdr_nsup_tombstone,
		.xdr_bin_cemetery = r->xdr_bin_cemetery
	};
}

void
unpack_bin_xdr_write(uint8_t flags, as_bin* b)
{
	if ((flags & BIN_XDR_WRITE) != 0) {
		b->xdr_write = 1;
	}
}

const uint8_t*
unpack_bin_src_id(uint8_t flags, const uint8_t* at, const uint8_t* end,
		as_bin* b)
{
	if ((flags & BIN_HAS_SRC_ID) == 0) {
		return at;
	}

	if (at >= end) {
		cf_warning(AS_FLAT, "incomplete flat bin");
		return NULL;
	}

	b->src_id = *at;

	return at + 1;
}

const uint8_t*
skip_bin_src_id(uint8_t flags, const uint8_t* at, const uint8_t* end)
{
	if ((flags & BIN_HAS_SRC_ID) == 0) {
		return at;
	}

	if (at >= end) {
		cf_warning(AS_FLAT, "incomplete flat bin");
		return NULL;
	}

	return at + 1;
}

void
flatten_bin_xdr_write(const as_bin* b, uint8_t* flags)
{
	if (b->xdr_write == 1) {
		*flags |= BIN_XDR_WRITE;
	}
}

uint32_t
bin_src_id_flat_size(const as_bin* b)
{
	return b->src_id == 0 ? 0 : 1;
}

uint32_t
flatten_bin_src_id(const as_bin* b, uint8_t* flags, uint8_t* at)
{
	if (b->src_id == 0) {
		return 0;
	}

	*flags |= BIN_HAS_SRC_ID;
	*at = b->src_id;

	return 1;
}


//==========================================================
// Local helpers - compression.
//

// Compression functions return 0 on error, compressed length on success.

static uint32_t
compress_lz4(uint8_t* out, uint32_t out_sz, const uint8_t* in, uint32_t in_sz)
{
	return (uint32_t)LZ4_compress_default((const char*)in, (char*)out,
			(int32_t)in_sz, (int32_t)out_sz);
}

static uint32_t
compress_snappy(uint8_t* out, uint32_t out_sz, const uint8_t* in,
		uint32_t in_sz)
{
	size_t comp_sz = out_sz;

	if (snappy_compress((const char*)in, in_sz, (char*)out, &comp_sz) !=
			SNAPPY_OK) {
		return 0;
	}

	return (uint32_t)comp_sz;
}

static uint32_t
compress_zstd(uint8_t* out, uint32_t out_sz, const uint8_t* in, uint32_t in_sz,
		uint32_t level)
{
	if (level == 0) {
		level = 9; // default to highest
	}

	level = level * ZSTD_maxCLevel() / 9;

	size_t comp_sz = ZSTD_compress(out, out_sz, in, in_sz, level);

	return ZSTD_isError(comp_sz) ? 0 : (uint32_t)comp_sz;
}

static void
update_average(double* avg, uint32_t val)
{
	while (true) {
		double cur = as_load_double(avg);
		double next = cur * 0.99999 + (double)val * 0.00001;

		if (as_cas_double(avg, cur, next)) {
			break;
		}
	}
}


//==========================================================
// Local helpers - decompression.
//

static uint8_t*
decompress(as_compression_method meth, uint32_t max_out_sz, uint32_t out_sz,
		const void* in, uint32_t in_sz)
{
	if (out_sz > max_out_sz) {
		return NULL;
	}

	// Alternate between 2 buffers - with secondary indexes, the record replace
	// path may need both on the same thread at once (storage and pickle).

	static __thread size_t buffer1_sz = 0;
	static __thread uint8_t* buffer1 = NULL;

	static __thread size_t buffer2_sz = 0;
	static __thread uint8_t* buffer2 = NULL;

	if ((size_t)max_out_sz > buffer1_sz) {
		buffer1_sz = buffer2_sz = max_out_sz;

		cf_thread_realloc((void**)&buffer1, &buffer1_sz);
		cf_thread_realloc((void**)&buffer2, &buffer2_sz);
	}

	static __thread uint8_t* out = NULL;

	out = out == buffer1 ? buffer2 : buffer1;

	bool ok;

	switch (meth) {
	case AS_COMPRESSION_LZ4:
		ok = decompress_lz4(out, out_sz, in, in_sz);
		break;
	case AS_COMPRESSION_SNAPPY:
		ok = decompress_snappy(out, out_sz, in, in_sz);
		break;
	case AS_COMPRESSION_ZSTD:
		ok = decompress_zstd(out, out_sz, in, in_sz);
		break;
	default:
		return NULL;
	}

	return ok ? out : NULL;
}

static bool
decompress_lz4(uint8_t* out, uint32_t out_sz, const uint8_t* in, uint32_t in_sz)
{
	return LZ4_decompress_safe((const char*)in, (char*)out, (int32_t)in_sz,
			(int32_t)out_sz) == (int32_t)out_sz;
}

static bool
decompress_snappy(uint8_t* out, uint32_t out_sz, const uint8_t* in,
		uint32_t in_sz)
{
	size_t orig_sz = out_sz;

	return snappy_uncompress((const char*)in, in_sz, (char*)out, &orig_sz) ==
			SNAPPY_OK && orig_sz == out_sz;
}

static bool
decompress_zstd(uint8_t* out, uint32_t out_sz, const uint8_t* in,
		uint32_t in_sz)
{
	size_t orig_sz = ZSTD_decompress(out, out_sz, in, in_sz);

	return ! ZSTD_isError(orig_sz) && orig_sz == out_sz;
}
