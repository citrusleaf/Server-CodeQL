/*
 * meta_batch_ee.c
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

#include "fabric/meta_batch.h"
#include "fabric/meta_batch_ee.h"

#include <stdbool.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_queue.h"

#include "base/index.h"
#include "base/datamodel.h"


//==========================================================
// Inlines & macros.
//

static inline void
meta_batch_clear(meta_batch *mb)
{
	mb->is_final = false;
	mb->n_records = 0;
	mb->records = NULL;
}


//==========================================================
// Public API.
//

meta_in_q *
meta_in_q_create()
{
	meta_in_q *iq = cf_malloc(sizeof(meta_in_q));

	iq->current_rec_i = 0;
	meta_batch_clear(&iq->current_batch);
	cf_queue_init(&iq->batch_q, sizeof(meta_batch), 64, true);
	iq->last_acked = 0;
	iq->is_done = false;

	return iq;
}


void
meta_in_q_destroy(meta_in_q *iq)
{
	if (iq->current_batch.records) {
		cf_free(iq->current_batch.records);
	}

	meta_batch batch;

	while (cf_queue_pop(&iq->batch_q, &batch, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
		if (batch.records) {
			cf_free(batch.records);
		}
	}

	cf_queue_destroy(&iq->batch_q);
	cf_free(iq);
}


void
meta_in_q_rejected(meta_in_q *iq)
{
	iq->is_done = true;
}


meta_out_q *
meta_out_q_create()
{
	meta_out_q *oq = cf_malloc(sizeof(meta_out_q));

	meta_batch_clear(&oq->current_batch);
	cf_queue_init(&oq->batch_q, sizeof(meta_batch), 64, true);
	oq->sequence = 0;
	oq->last_acked = 0;

	return oq;
}


void
meta_out_q_destroy(meta_out_q *oq)
{
	if (oq->current_batch.records) {
		cf_free(oq->current_batch.records);
	}

	meta_batch batch;

	while (cf_queue_pop(&oq->batch_q, &batch, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
		if (batch.records) {
			cf_free(batch.records);
		}
	}

	cf_queue_destroy(&oq->batch_q);
	cf_free(oq);
}


//==========================================================
// Public API - enterprise only.
//


void
meta_in_q_push_batch(meta_in_q *iq, const meta_batch *batch)
{
	cf_queue_push(&iq->batch_q, batch);
}


// Fetches the current element in meta_in_q.
// Returns:
//   META_IN_Q_OK - Element available and returned in mrecp.
//   META_IN_Q_EAGAIN - Nothing available, more elements expected.
//   META_IN_Q_DONE - Nothing available, no further elements expected.
meta_in_q_result
meta_in_q_current_rec(meta_in_q *iq, meta_record **mrecp)
{
	if (iq->current_batch.records &&
			iq->current_rec_i == iq->current_batch.n_records) {
		iq->current_rec_i = 0;
		iq->is_done = iq->current_batch.is_final;

		cf_free(iq->current_batch.records);

		meta_batch_clear(&iq->current_batch);
	}

	if (iq->is_done) {
		return META_IN_Q_DONE;
	}

	if (! iq->current_batch.records) {
		if (cf_queue_pop(&iq->batch_q, &iq->current_batch, CF_QUEUE_NOWAIT) ==
				CF_QUEUE_EMPTY) {
			return META_IN_Q_EAGAIN;
		}

		if (iq->current_batch.n_records == 0) {
			iq->is_done = true;
			return META_IN_Q_DONE;
		}
	}

	*mrecp = iq->current_batch.records + iq->current_rec_i;

	return META_IN_Q_OK;
}


void
meta_in_q_next_rec(meta_in_q *iq)
{
	iq->current_rec_i++;
}


void
meta_out_q_add_rec(meta_out_q *oq, as_record *r)
{
	if (! oq->current_batch.records) {
		oq->current_batch.records =
				cf_malloc(sizeof(meta_record) * MAX_META_BATCH_SIZE);
	}

	meta_record *mrec =
			oq->current_batch.records + oq->current_batch.n_records;

	mrec->keyd = r->keyd;
	mrec->generation = r->generation;
	mrec->last_update_time = r->last_update_time;

	if (++oq->current_batch.n_records == MAX_META_BATCH_SIZE) {
		cf_queue_push(&oq->batch_q, &oq->current_batch);
		meta_batch_clear(&oq->current_batch);
	}
}


void
meta_out_q_batch_close(meta_out_q *oq)
{
	oq->current_batch.is_final = true;

	// Note - pushes even if current_batch.n_records is 0.
	cf_queue_push(&oq->batch_q, &oq->current_batch);
	meta_batch_clear(&oq->current_batch);
}


void
meta_out_q_next_batch(meta_out_q *oq, meta_batch *mb)
{
	cf_queue_pop(&oq->batch_q, mb, CF_QUEUE_FOREVER);
}
