/*
 * bin_ee.c
 *
 * Copyright (C) 2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "base/datamodel.h"
#include "storage/storage.h"


//==========================================================
// Public API.
//

uint8_t
as_bin_get_particle_type(const as_bin* b)
{
	switch (b->state) {
	case AS_BIN_STATE_INUSE_INTEGER:
		return AS_PARTICLE_TYPE_INTEGER;
	case AS_BIN_STATE_INUSE_FLOAT:
		return AS_PARTICLE_TYPE_FLOAT;
	case AS_BIN_STATE_INUSE_BOOL:
		return AS_PARTICLE_TYPE_BOOL;
	case AS_BIN_STATE_INUSE_OTHER:
		return b->particle->type;
	case AS_BIN_STATE_UNUSED:
	case AS_BIN_STATE_TOMBSTONE: // can get here from update_sindex()
	default:
		return AS_PARTICLE_TYPE_NULL;
	}
}

bool
as_bin_particle_is_tombstone(as_particle_type type)
{
	return type == AS_PARTICLE_TYPE_NULL;
}

bool
as_bin_is_tombstone(const as_bin* b)
{
	return b->state == AS_BIN_STATE_TOMBSTONE;
}

bool
as_bin_is_live(const as_bin* b)
{
	return b->state != AS_BIN_STATE_TOMBSTONE &&
			b->state != AS_BIN_STATE_UNUSED;
}

void
as_bin_set_tombstone(as_bin* b)
{
	b->state = AS_BIN_STATE_TOMBSTONE;
	b->particle = NULL; // not needed - but polite
}

bool
as_bin_empty_if_all_tombstones(as_storage_rd* rd, bool is_dd)
{
	for (uint32_t i = 0; i < rd->n_bins; i++) {
		if (rd->bins[i].state != AS_BIN_STATE_TOMBSTONE) {
			return false;
		}
	}

	// All bins are tombstones. If conflict resolving, leave a bin cemetery.
	// Otherwise, empty the bins array to delete the record.

	if (! (rd->resolve_writes && is_dd)) {
		rd->n_bins = 0; // will delete the record
	}

	return true;
}

void
as_bin_clear_meta(as_bin* b)
{
	b->xdr_write = 0;
	b->unused_flags = 0;
	b->lut = 0;
	b->src_id = 0;
}


//==========================================================
// Special API for downgrades.
//

#include "base/index.h"
#include "fabric/exchange.h"

int
as_bin_downgrade_pickle(as_storage_rd* rd)
{
	if (as_exchange_min_compatibility_id() >= 10) {
		return 0;
	}

	as_record* r = rd->r;

	if (as_exchange_min_compatibility_id() == 9 && r->xdr_bin_cemetery == 0) {
		return 0;
	}

	as_storage_record_get_set_name(rd);
	as_storage_rd_load_key(rd);

	as_bin stack_bins[rd->ns->single_bin ? 0 : RECORD_MAX_BINS];

	if (as_storage_rd_load_bins(rd, stack_bins) != 0) {
		return -1;
	}

	if (r->xdr_bin_cemetery == 1) {
		// Convert to normal tombstone.

		uint16_t n_bins = rd->n_bins;

		// Just while flattening.
		r->xdr_bin_cemetery = 0;
		rd->n_bins = 0;

		as_flat_pickle_record(rd);

		// Restore original values.
		r->xdr_bin_cemetery = 1;
		rd->n_bins = n_bins;

		return 1;
	}

	// Note - can't get here if min-compatibility-id is 9.

	if (! rd->ns->single_bin) {
		if (as_exchange_min_compatibility_id() == 8) {
			// Strip src-id.
			if (! rd->ns->storage_data_in_memory || r->has_bin_meta) {
				for (uint32_t i = 0; i < rd->n_bins; i++) {
					rd->bins[i].src_id = 0;
				}
			}
		}
		else {
			// Compatibility-id < 8 - remove all tombstones and all metadata.
			for (uint32_t i = 0; i < rd->n_bins; i++) {
				as_bin* b = &rd->bins[i];

				if (as_bin_is_tombstone(b)) {
					as_bin_remove(rd, i--);
				}
				else {
					b->xdr_write = 0;
					b->lut = 0;
					b->src_id = 0;
				}
			}
		}
	}

	as_flat_pickle_record(rd);

	return 1;
}
