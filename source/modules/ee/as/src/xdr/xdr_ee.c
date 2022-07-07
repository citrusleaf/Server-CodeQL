/*
 * xdr_ee.c
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

#include "base/xdr.h"
#include "xdr/xdr_ee.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/cf_clock.h"

#include "cf_thread.h"
#include "log.h"

#include "base/datamodel.h"
#include "base/index.h"
#include "fabric/partition.h"
#include "xdr/dc.h"
#include "xdr/dc_manager.h"

#include "warnings.h"


//==========================================================
// Typedefs & constants.
//

typedef struct tomb_raid_overall_info_s {
	as_namespace* ns;
	uint32_t pid;
	uint64_t lut_threshold;
	uint64_t n_dropped;
} tomb_raid_overall_info;

typedef struct tomb_raid_per_thread_info_s {
	as_namespace* ns;
	as_index_tree* tree;
	uint64_t lut_threshold;
	uint64_t n_dropped;
} tomb_raid_per_thread_info;


//==========================================================
// Forward declarations.
//

void xdr_tomb_raider_start(void);
static void* run_tomb_raider(void* udata);
static void drop_xdr_tombstones(as_namespace* ns);
static void* run_drop_xdr_tombstones(void* udata);
static bool drop_xdr_tombstones_reduce_cb(as_index_ref* r_ref, void* udata);


//==========================================================
// Public API.
//

void
as_xdr_init(void)
{
	as_dc_manager_init();
}

void
as_xdr_start(void)
{
	as_dc_manager_start();
	xdr_tomb_raider_start();
}


//==========================================================
// Public API - enterprise only.
//

void
xdr_do_trace(const as_dc* dc, uint32_t ident, uint64_t lut, const char* format,
		...)
{
	va_list args;
	va_start(args, format);

	char buffer[1000];
	vsnprintf(buffer, sizeof(buffer), format, args);

	va_end(args);

	const char* pretty_lut = as_xdr_pretty_ms(lut);
	pid_t tid = cf_thread_sys_tid() % 10000;
	uint64_t now = cf_getms() % 1000000;
	const char* dc_name = dc != NULL ? dc->cfg.name : "*";

	cf_detail(AS_XDR, "trace %08x:%s:%04d:%06lu:%s %s", ident, pretty_lut, tid,
			now, dc_name, buffer);
}

void
xdr_do_pretty_ms(char* pretty, uint64_t cl_ms)
{
	uint64_t epoch_ms = cl_ms + CITRUSLEAF_EPOCH_MS;

	time_t epoch = (time_t)(epoch_ms / 1000);
	int32_t ms = (int32_t)(epoch_ms % 1000);

	struct tm decomposed;

	if (cf_log_is_using_local_time()) {
		localtime_r(&epoch, &decomposed);
	}
	else {
		gmtime_r(&epoch, &decomposed);
	}

	snprintf(pretty, 39, "%lu_%02d%02d%02d_%02d%02d%02d.%03d", cl_ms,
			decomposed.tm_year - 100, decomposed.tm_mon + 1, decomposed.tm_mday,
			decomposed.tm_hour, decomposed.tm_min, decomposed.tm_sec, ms);
}


//==========================================================
// Local helpers.
//

void
xdr_tomb_raider_start(void)
{
	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_namespace* ns = g_config.namespaces[ns_ix];

		cf_info(AS_XDR, "{%s} starting XDR tomb raider thread", ns->name);

		cf_thread_create_detached(run_tomb_raider, ns);
	}
}

static void*
run_tomb_raider(void* udata)
{
	as_namespace* ns = (as_namespace*)udata;

	uint64_t last_time = cf_get_seconds();

	while (true) {
		sleep(1); // wake up every second to check

		uint64_t period = as_load_uint32(&ns->xdr_tomb_raider_period);;
		uint64_t curr_time = cf_get_seconds();

		if (period == 0 || curr_time - last_time < period) {
			continue;
		}

		last_time = curr_time;

		if (ns->n_xdr_tombstones != 0) {
			drop_xdr_tombstones(ns);
		}
	}

	return NULL;
}

static void
drop_xdr_tombstones(as_namespace* ns)
{
	uint64_t start_ms = cf_getms();
	uint32_t n_threads = as_load_uint32(&ns->n_xdr_tomb_raider_threads);

	cf_info(AS_NSUP, "{%s} xdr-tomb-raid-start: threads %u", ns->name,
			n_threads);

	cf_tid tids[n_threads];

	tomb_raid_overall_info overall = {
			.ns = ns,
			.lut_threshold = as_dc_manager_ns_min_lst(ns)
	};

	for (uint32_t i = 0; i < n_threads; i++) {
		tids[i] = cf_thread_create_joinable(run_drop_xdr_tombstones,
				(void*)&overall);
	}

	for (uint32_t i = 0; i < n_threads; i++) {
		cf_thread_join(tids[i]);
	}

	cf_info(AS_XDR, "{%s} xdr-tomb-raid-done: dropped %lu total-ms %lu",
			ns->name, overall.n_dropped, cf_getms() - start_ms);
}

static void*
run_drop_xdr_tombstones(void* udata)
{
	tomb_raid_overall_info* overall = (tomb_raid_overall_info*)udata;
	as_namespace* ns = overall->ns;

	tomb_raid_per_thread_info per_thread = {
			.ns = ns,
			.lut_threshold = overall->lut_threshold
	};

	uint32_t pid;

	while ((pid = as_faa_uint32(&overall->pid, 1)) < AS_PARTITIONS) {
		as_partition_reservation rsv;
		as_partition_reserve(ns, pid, &rsv);

		per_thread.tree = rsv.tree;

		as_index_reduce(rsv.tree, drop_xdr_tombstones_reduce_cb,
				(void*)&per_thread);
		as_partition_release(&rsv);
	}

	as_add_uint64(&overall->n_dropped, (int64_t)per_thread.n_dropped);

	return NULL;
}

static bool
drop_xdr_tombstones_reduce_cb(as_index_ref* r_ref, void* udata)
{
	as_index* r = r_ref->r;
	tomb_raid_per_thread_info* per_thread = (tomb_raid_per_thread_info*)udata;
	as_namespace* ns = per_thread->ns;

	if (r->xdr_tombstone == 1 &&
			r->last_update_time < per_thread->lut_threshold) {
		as_index_delete(per_thread->tree, &r->keyd);
		per_thread->n_dropped++;
	}

	as_record_done(r_ref, ns);

	return true;
}
