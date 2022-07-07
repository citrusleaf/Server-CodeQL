/*
 * meta_batch_ee.h
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#pragma once

//==========================================================
// Includes.
//

#include "fabric/meta_batch.h"

#include <stdbool.h>
#include <stdint.h>

#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_queue.h"


//==========================================================
// Forward declarations.
//

struct as_index_s;


//==========================================================
// Typedefs & constants.
//

typedef struct meta_record_s {
	cf_digest keyd;
	uint16_t generation;
	uint64_t last_update_time: 40;
} __attribute__ ((__packed__)) meta_record;

typedef struct meta_batch_s {
	bool is_final;
	uint32_t n_records;
	meta_record *records;
} meta_batch;

typedef struct meta_in_q_s {
	uint32_t current_rec_i;
	meta_batch current_batch;
	cf_queue batch_q;
	cf_atomic32 last_acked;
	bool is_done;
} meta_in_q;

typedef struct meta_out_q_s {
	meta_batch current_batch;
	cf_queue batch_q;
	uint32_t sequence;
	cf_atomic32 last_acked;
} meta_out_q;

typedef enum {
	META_IN_Q_OK,
	META_IN_Q_EAGAIN,
	META_IN_Q_DONE,
} meta_in_q_result;

#define MAX_META_BATCH_SIZE 10000
#define META_BATCH_RETRANSMIT_MS (1000 * 5)


//==========================================================
// Public API.
//

void meta_in_q_push_batch(meta_in_q *iq, const meta_batch *batch);
meta_in_q_result meta_in_q_current_rec(meta_in_q *iq, meta_record **mrecp);
void meta_in_q_next_rec(meta_in_q *iq);

void meta_out_q_add_rec(meta_out_q *oq, struct as_index_s *r);
void meta_out_q_batch_close(meta_out_q *oq);
void meta_out_q_next_batch(meta_out_q *oq, meta_batch *mb);

static inline bool
meta_in_q_handle_sequence(meta_in_q *iq, uint32_t sequence)
{
	return cf_atomic32_setmax(&iq->last_acked, (int32_t)sequence) != 0;
}

static inline void
meta_out_q_sequence_ack(meta_out_q *oq, uint32_t sequence)
{
	cf_atomic32_setmax(&oq->last_acked, (int32_t)sequence);
}

static inline bool
is_meta_out_q_synced(const meta_out_q *oq)
{
	return oq->sequence == cf_atomic32_get(oq->last_acked);
}
