/*
 * gc_ee.c
 *
 * Copyright (C) 2021 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "sindex/gc.h"

#include "citrusleaf/cf_queue.h"

#include "arenax.h"
#include "cf_mutex.h"
#include "log.h"

#include "base/datamodel.h"
#include "base/index.h"


//==========================================================
// Typedefs & constants.
//

typedef struct rlist_af_ele_s {
	cf_arenax_handle r_h: 40;
	cf_arenax_puddle* puddle;
	cf_mutex* olock;
} __attribute__ ((__packed__)) rlist_af_ele;


//==========================================================
// Private API - for enterprise separation only.
//

void
create_rlist(as_namespace* ns)
{
	ns->si_gc_rlist = cf_queue_create(ns->xmem_type == CF_XMEM_TYPE_FLASH ?
			sizeof(rlist_af_ele) : sizeof(rlist_ele), false);
}

void
push_to_rlist(as_namespace* ns, as_index_ref* r_ref)
{
	if (ns->xmem_type == CF_XMEM_TYPE_FLASH) {
		rlist_af_ele ele = {
				.r_h = r_ref->r_h,
				.puddle = r_ref->puddle,
				.olock = r_ref->olock
		};

		cf_queue_push(ns->si_gc_rlist, &ele);
	}
	else {
		rlist_ele ele = { .r_h = r_ref->r_h };

		cf_queue_push(ns->si_gc_rlist, &ele);
	}
}

void
purge_rlist(as_namespace* ns, cf_queue* rlist)
{
	if (ns->xmem_type == CF_XMEM_TYPE_FLASH) {
		rlist_af_ele ele;

		while (cf_queue_pop(rlist, &ele, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
			as_index* r = (as_index*)cf_arenax_resolve(ns->arena, ele.r_h);

			cf_assert(r->in_sindex == 1, AS_SINDEX, "bad in_sindex bit");
			cf_assert(r->rc == 1, AS_SINDEX, "bad ref count %u", r->rc);

			as_record_destroy(r, ns);

			cf_mutex_lock(ele.olock);

			cf_arenax_free(ns->arena, ele.r_h, ele.puddle);

			cf_mutex_unlock(ele.olock);
		}
	}
	else {
		rlist_ele ele;

		while (cf_queue_pop(rlist, &ele, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
			as_index* r = (as_index*)cf_arenax_resolve(ns->arena, ele.r_h);

			cf_assert(r->in_sindex == 1, AS_SINDEX, "bad in_sindex bit");
			cf_assert(r->rc == 1, AS_SINDEX, "bad ref count %u", r->rc);

			as_record_destroy(r, ns);
			cf_arenax_free(ns->arena, ele.r_h, NULL);
		}
	}

	cf_queue_destroy(rlist);
}
