/*
 * flat.c
 *
 * Copyright (C) 2019-2020 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

//==========================================================
// Includes.
//

#include "storage/flat.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bits.h"
#include "log.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "base/proto.h"
#include "storage/storage.h"

//#include "warnings.h" // generates warnings we're living with for now


//==========================================================
// Inlines & macros.
//

// storage-engine memory may truncate n_rblocks at 19 bits - only check those.
static inline uint32_t
check_n_rblocks(uint32_t size)
{
	return SIZE_TO_N_RBLOCKS(size) & ((1 << 19) - 1);
}


//==========================================================
// Public API.
//

void
as_flat_pickle_record(as_storage_rd* rd)
{
	rd->pickle_sz = as_flat_record_size(rd);

	// Note - will no-op for storage-engine memory, which doesn't compress.
	as_flat_record* flat = as_flat_compress_bins_and_pack_record(rd,
			rd->ns->storage_write_block_size, false, false, &rd->pickle_sz);

	rd->pickle = cf_malloc(rd->pickle_sz);

	if (flat == NULL) {
		// Note - storage-engine memory may truncate n_rblocks at 19 bits.
		as_flat_pack_record(rd, SIZE_TO_N_RBLOCKS(rd->pickle_sz), false,
				(as_flat_record*)rd->pickle);
	}
	else {
		memcpy(rd->pickle, flat, rd->pickle_sz);
	}
}

uint32_t
as_flat_record_size(const as_storage_rd* rd)
{
	as_namespace* ns = rd->ns;

	// Start with the record storage overhead.
	uint32_t write_sz = flat_record_overhead_size(rd);

	// Add the bins' sizes, including bin overhead.
	for (uint16_t b = 0; b < rd->n_bins; b++) {
		as_bin* bin = &rd->bins[b];

		uint32_t name_sz = 0;
		uint32_t meta_sz = 0;

		if (! ns->single_bin) {
			name_sz = 1 +
					(uint32_t)strlen(as_bin_get_name_from_id(ns, bin->id));

			if (as_bin_has_meta(bin)) {
				meta_sz = 1;

				if (bin->lut != 0) {
					meta_sz += sizeof(flat_bin_lut);
				}

				meta_sz += bin_src_id_flat_size(bin);
			}
		}

		write_sz += name_sz + meta_sz + as_bin_particle_flat_size(bin);
	}

	return write_sz;
}

void
as_flat_pack_record(const as_storage_rd* rd, uint32_t n_rblocks,
		bool dirty, as_flat_record* flat)
{
	uint8_t* buf = flatten_record_meta(rd, n_rblocks, dirty, NULL, flat);

	flatten_bins(rd, buf, NULL);
}

bool
as_flat_unpack_remote_record_meta(as_namespace* ns, as_remote_record* rr)
{
	if (rr->pickle_sz < sizeof(as_flat_record)) {
		cf_warning(AS_FLAT, "record too small %zu", rr->pickle_sz);
		return false;
	}

	as_flat_record* flat = (as_flat_record*)rr->pickle;

	if (flat->magic != AS_FLAT_MAGIC) {
		cf_warning(AS_FLAT, "bad magic %u", flat->magic);
		return false;
	}

	if (flat->n_rblocks != check_n_rblocks((uint32_t)rr->pickle_sz)) {
		cf_warning(AS_FLAT, "n_rblocks mismatch (%u,%zu)", flat->n_rblocks,
				rr->pickle_sz);
		return false;
	}

	rr->keyd = &flat->keyd;
	rr->generation = flat->generation;
	rr->last_update_time = flat->last_update_time;

	as_flat_opt_meta opt_meta = { { 0 } };

	const uint8_t* flat_bins = as_flat_unpack_record_meta(flat,
				rr->pickle + rr->pickle_sz, &opt_meta, ns->single_bin);

	if (flat_bins == NULL) {
		return false;
	}

	set_remote_record_xdr_flags(flat, &opt_meta.extra_flags, rr);

	rr->void_time = opt_meta.void_time;
	rr->set_name = opt_meta.set_name;
	rr->set_name_len = opt_meta.set_name_len;
	rr->key = opt_meta.key;
	rr->key_size = opt_meta.key_size;
	rr->n_bins = (uint16_t)opt_meta.n_bins;
	rr->cm = opt_meta.cm;
	rr->meta_sz = (uint32_t)(flat_bins - rr->pickle);

	return true;
}

// Caller has already checked that end is within read buffer.
const uint8_t*
as_flat_unpack_record_meta(const as_flat_record* flat, const uint8_t* end,
		as_flat_opt_meta* opt_meta, bool single_bin)
{
	if (flat->generation == 0) {
		cf_warning(AS_FLAT, "generation 0");
		return NULL;
	}

	const uint8_t* at = flat->data;

	if (flat->has_extra_flags == 1) {
		if (at + sizeof(opt_meta->extra_flags) > end) {
			cf_warning(AS_FLAT, "incomplete extra flags");
			return NULL;
		}

		opt_meta->extra_flags = *(as_flat_extra_flags*)at;

		if (opt_meta->extra_flags.unused != 0) {
			cf_warning(AS_FLAT, "unsupported extra storage fields");
			return NULL;
		}

		at += sizeof(opt_meta->extra_flags);
	}

	if (flat->has_void_time == 1) {
		if (at + sizeof(opt_meta->void_time) > end) {
			cf_warning(AS_FLAT, "incomplete void-time");
			return NULL;
		}

		opt_meta->void_time = *(uint32_t*)at;
		at += sizeof(opt_meta->void_time);
	}

	if (flat->has_set == 1) {
		if (at >= end) {
			cf_warning(AS_FLAT, "incomplete set name len");
			return NULL;
		}

		opt_meta->set_name_len = *at++;

		if (opt_meta->set_name_len == 0 ||
				opt_meta->set_name_len >= AS_SET_NAME_MAX_SIZE) {
			cf_warning(AS_FLAT, "bad set name len %u", opt_meta->set_name_len);
			return NULL;
		}

		opt_meta->set_name = (const char*)at;
		at += opt_meta->set_name_len;
	}

	if (flat->has_key == 1) {
		opt_meta->key_size = uintvar_parse(&at, end);

		if (opt_meta->key_size == 0) {
			cf_warning(AS_FLAT, "bad key size");
			return NULL;
		}

		opt_meta->key = (const uint8_t*)at;
		at += opt_meta->key_size;
	}

	if (flat->has_bins == 1) {
		if (single_bin) {
			opt_meta->n_bins = 1;
		}
		else {
			opt_meta->n_bins = uintvar_parse(&at, end);

			if (opt_meta->n_bins == 0 || opt_meta->n_bins > RECORD_MAX_BINS) {
				cf_warning(AS_FLAT, "bad n-bins %u", opt_meta->n_bins);
				return NULL;
			}
		}
	}

	at = unflatten_compression_meta(flat, at, end, &opt_meta->cm);

	if (at > end) {
		cf_warning(AS_FLAT, "incomplete record metadata");
		return NULL;
	}

	return at; // could be NULL, but would already have logged warning
}

// TODO - remove in "six months" - not bothering with EE separation.
bool
as_flat_fix_padded_rr(as_remote_record* rr, bool single_bin)
{
	if (rr->pickle_sz % RBLOCK_SIZE != 0) {
		return true; // new node sent this - already exact
	}

	if (rr->cm.method == AS_COMPRESSION_NONE) {
		const uint8_t* flat_bins = rr->pickle + rr->meta_sz;
		const uint8_t* end = rr->pickle + rr->pickle_sz;

		const uint8_t* exact_end = as_flat_check_packed_bins(flat_bins, end,
				rr->n_bins, single_bin);

		if (exact_end == NULL) {
			return false;
		}

		rr->pickle_sz = exact_end - rr->pickle;
	}
	else {
		rr->pickle_sz = rr->meta_sz + rr->cm.comp_sz;
	}

	return true;
}

int
as_flat_unpack_remote_bins(as_remote_record* rr, as_bin* bins)
{
	as_namespace* ns = rr->rsv->ns;
	const uint8_t* flat_bins = rr->pickle + rr->meta_sz;
	const uint8_t* end = rr->pickle + rr->pickle_sz;

	if (! as_flat_decompress_buffer(&rr->cm, ns->storage_write_block_size,
			&flat_bins, &end, NULL)) {
		cf_warning(AS_FLAT, "failed record decompression");
		return -AS_ERR_UNKNOWN;
	}

	return as_flat_unpack_bins(ns, flat_bins, end, rr->n_bins, bins);
}

int
as_flat_unpack_bins(as_namespace* ns, const uint8_t* at, const uint8_t* end,
		uint16_t n_bins, as_bin* bins)
{
	uint16_t i;

	for (i = 0; i < n_bins; i++) {
		as_bin* b = &bins[i];

		if (! ns->single_bin) {
			if (at >= end) {
				cf_warning(AS_FLAT, "incomplete flat bin");
				break;
			}

			size_t name_len = *at++;

			if (name_len >= AS_BIN_NAME_MAX_SZ) {
				cf_warning(AS_FLAT, "bad flat bin name");
				break;
			}

			if (at + name_len > end) {
				cf_warning(AS_FLAT, "incomplete flat bin");
				break;
			}

			if (! as_bin_set_id_from_name_w_len(ns, b, at, name_len)) {
				cf_warning(AS_FLAT, "flat bin name failed to assign id");
				break;
			}

			at += name_len;

			as_bin_clear_meta(b);

			if (at >= end) {
				cf_warning(AS_FLAT, "incomplete flat bin");
				break;
			}

			if ((*at & BIN_HAS_META) != 0) {
				uint8_t flags = *at++;

				if ((flags & BIN_UNKNOWN_FLAGS) != 0) {
					cf_warning(AS_FLAT, "unknown bin flags");
					break;
				}

				unpack_bin_xdr_write(flags, b);

				if ((flags & BIN_HAS_LUT) != 0) {
					if (at + sizeof(flat_bin_lut) > end) {
						cf_warning(AS_FLAT, "incomplete flat bin");
						break;
					}

					b->lut = ((flat_bin_lut*)at)->lut;
					at += sizeof(flat_bin_lut);
				}

				if ((at = unpack_bin_src_id(flags, at, end, b)) == NULL) {
					break;
				}
			}
		}

		at = ns->storage_data_in_memory ?
				as_bin_particle_alloc_from_flat(b, at, end) :
				as_bin_particle_cast_from_flat(b, at, end);

		if (at == NULL) {
			break;
		}
	}

	if (i < n_bins) {
		as_bin_destroy_all_dim(ns, bins, i);
		return -AS_ERR_UNKNOWN;
	}

	if (at > end) {
		cf_warning(AS_FLAT, "incomplete flat bin");
		as_bin_destroy_all_dim(ns, bins, n_bins);
		return -AS_ERR_UNKNOWN;
	}

	// Some (but not all) callers pass end as an rblock-rounded value.
	if (at + RBLOCK_SIZE <= end) {
		cf_warning(AS_FLAT, "extra rblocks follow flat bin");
		as_bin_destroy_all_dim(ns, bins, n_bins);
		return -AS_ERR_UNKNOWN;
	}

	return 0;
}

const uint8_t*
as_flat_check_packed_bins(const uint8_t* at, const uint8_t* end,
		uint32_t n_bins, bool single_bin)
{
	for (uint32_t i = 0; i < n_bins; i++) {
		if (at >= end) {
			cf_warning(AS_FLAT, "incomplete flat bin");
			return NULL;
		}

		if (! single_bin) {
			uint8_t name_len = *at++;

			if (name_len >= AS_BIN_NAME_MAX_SZ) {
				cf_warning(AS_FLAT, "bad flat bin name");
				return NULL;
			}

			at += name_len;

			if ((*at & BIN_HAS_META) != 0) {
				uint8_t flags = *at++;

				if ((flags & BIN_HAS_LUT) != 0) {
					at += sizeof(flat_bin_lut);
				}

				if ((at = skip_bin_src_id(flags, at, end)) == NULL) {
					return NULL;
				}
			}
		}

		if ((at = as_particle_skip_flat(at, end)) == NULL) {
			return NULL;
		}
	}

	if (at > end) {
		cf_warning(AS_FLAT, "incomplete flat record");
		return NULL;
	}

	if (at + RBLOCK_SIZE <= end) {
		cf_warning(AS_FLAT, "extra rblocks follow flat record");
		return NULL;
	}

	return at;
}


//==========================================================
// Private API - for enterprise separation only.
//

uint32_t
flat_record_overhead_size(const as_storage_rd* rd)
{
	as_record* r = rd->r;

	// Start with size of record header struct.
	size_t size = sizeof(as_flat_record);

	as_flat_extra_flags extra_flags = get_flat_extra_flags(r);

	if (flat_extra_flags_used(&extra_flags)) {
		size += sizeof(as_flat_extra_flags);
	}

	if (r->void_time != 0) {
		size += sizeof(uint32_t);
	}

	if (rd->set_name) {
		size += 1 + rd->set_name_len;
	}

	if (rd->key) {
		size += uintvar_size(rd->key_size) + rd->key_size;
	}

	if (! rd->ns->single_bin && rd->n_bins != 0) {
		size += uintvar_size(rd->n_bins);
	}

	return (uint32_t)size;
}

uint8_t*
flatten_record_meta(const as_storage_rd* rd, uint32_t n_rblocks, bool dirty,
		const as_flat_comp_meta* cm, as_flat_record* flat)
{
	as_namespace* ns = rd->ns;
	as_record* r = rd->r;

	flat->magic = dirty ? AS_FLAT_MAGIC_DIRTY : AS_FLAT_MAGIC;
	flat->n_rblocks = n_rblocks;

	// Flags are filled in below.
	flat->tree_id = r->tree_id;
	flat->keyd = r->keyd;
	flat->last_update_time = r->last_update_time;
	flat->generation = r->generation;

	set_flat_xdr_state(r, flat);

	uint8_t* at = flat->data;

	as_flat_extra_flags extra_flags = get_flat_extra_flags(r);

	if (flat_extra_flags_used(&extra_flags)) {
		flat->has_extra_flags = 1;

		*(as_flat_extra_flags*)at = extra_flags;
		at += sizeof(as_flat_extra_flags);
	}
	else {
		flat->has_extra_flags = 0;
	}

	if (r->void_time != 0) {
		*(uint32_t*)at = r->void_time;
		at += sizeof(uint32_t);

		flat->has_void_time = 1;
	}
	else {
		flat->has_void_time = 0;
	}

	if (rd->set_name) {
		*at++ = (uint8_t)rd->set_name_len;
		memcpy(at, rd->set_name, rd->set_name_len);
		at += rd->set_name_len;

		flat->has_set = 1;
	}
	else {
		flat->has_set = 0;
	}

	if (rd->key) {
		at = uintvar_pack(at, rd->key_size);
		memcpy(at, rd->key, rd->key_size);
		at += rd->key_size;

		flat->has_key = 1;
	}
	else {
		flat->has_key = 0;
	}

	if (rd->n_bins != 0) {
		if (! ns->single_bin) {
			at = uintvar_pack(at, rd->n_bins);
		}

		flat->has_bins = 1;
	}
	else {
		flat->has_bins = 0;
	}

	return flatten_compression_meta(cm, flat, at);
}

void
flatten_bins(const as_storage_rd* rd, uint8_t* buf, uint32_t* sz)
{
	as_namespace* ns = rd->ns;

	uint8_t* start = buf;

	for (uint16_t b = 0; b < rd->n_bins; b++) {
		as_bin* bin = &rd->bins[b];

		if (! ns->single_bin) {
			const char* bin_name = as_bin_get_name_from_id(ns, bin->id);
			size_t name_len = strlen(bin_name);

			*buf++ = (uint8_t)name_len;
			memcpy(buf, bin_name, name_len);
			buf += name_len;

			if (as_bin_has_meta(bin)) {
				uint8_t* flags = buf++;

				*flags = BIN_HAS_META;

				flatten_bin_xdr_write(bin, flags);

				if (bin->lut != 0) {
					*flags |= BIN_HAS_LUT;
					((flat_bin_lut*)buf)->lut = bin->lut;
					buf += sizeof(flat_bin_lut);
				}

				buf += flatten_bin_src_id(bin, flags, buf);
			}
		}

		buf += as_bin_particle_to_flat(bin, buf);
	}

	if (sz != NULL) {
		*sz = (uint32_t)(buf - start);
	}
}
