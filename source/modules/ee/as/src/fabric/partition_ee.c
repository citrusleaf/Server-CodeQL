/*
 * partition_ee.c
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

#include "fabric/partition.h"
#include "fabric/partition_ee.h"

#include <stdbool.h>
#include <stdint.h>

#include "cf_mutex.h"
#include "node.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/proto.h"
#include "base/transaction.h"


//==========================================================
// Forward declarations.
//

int partition_check_source(const as_namespace* ns, const as_partition* p, cf_node src, bool* from_replica);


//==========================================================
// Public API.
//

void
as_partition_isolate_version(const as_namespace* ns, as_partition* p)
{
	if (as_partition_version_has_data(&p->version)) {
		p->version.master = 0;
		p->version.subset = 1;
	}
}

int
as_partition_check_source(const as_namespace* ns, as_partition* p, cf_node src,
		bool* from_replica)
{
	if (! ns->cp) {
		return AS_OK;
	}

	cf_mutex_lock(&p->lock);

	int result = partition_check_source(ns, p, src, from_replica);

	cf_mutex_unlock(&p->lock);

	return result;
}


//==========================================================
// Public API - enterprise only.
//

int
as_partition_check_repl_ping(as_namespace* ns, uint32_t pid, uint32_t regime,
		cf_node src)
{
	as_partition* p = &ns->partitions[pid];

	cf_mutex_lock(&p->lock);

	int result = partition_check_source(ns, p, src, NULL);

	if (result != AS_OK) {
		cf_mutex_unlock(&p->lock);
		return result;
	}

	result = regime < p->regime ? AS_ERR_CLUSTER_KEY_MISMATCH : AS_OK;

	cf_mutex_unlock(&p->lock);

	return result;
}

partition_xdr_state
as_partition_xdr_state(as_namespace* ns, uint32_t pid)
{
	as_partition* p = &ns->partitions[pid];

	cf_mutex_lock(&p->lock);

	partition_xdr_state result;

	if (p->working_master == g_config.self_node) {
		result.role = XDR_ROLE_MASTER;
	}
	else if (find_self_in_replicas(p) >= 0) {
		result.role = XDR_ROLE_PROLE;
	}
	else {
		result.role = XDR_ROLE_NONE;
	}

	result.is_immigrating = p->pending_immigrations != 0;

	cf_mutex_unlock(&p->lock);

	return result;
}


//==========================================================
// Private API - for enterprise separation only.
//

int
partition_reserve_unavailable(const as_namespace* ns, const as_partition* p,
		as_transaction* tr, cf_node* node)
{
	if (! ns->cp) {
		*node = (cf_node)0;
		return -2;
	}

	if (as_transaction_is_allow_unavailable_read(tr) && p->tree != NULL) {
		*node = g_config.self_node;
		tr->flags |= AS_TRANSACTION_FLAG_RSV_UNAVAILABLE;
		return 0;
	}

	*node = (cf_node)0;

	return -2;
}

bool
partition_reserve_promote(const as_namespace* ns, const as_partition* p,
		as_transaction* tr)
{
	if (! ns->cp) {
		return false;
	}

	if (as_transaction_is_strict_read(tr) ||
			as_transaction_is_restart_strict(tr)) {
		return true;
	}

	if (g_config.self_node != p->working_master) {
		tr->flags |= AS_TRANSACTION_FLAG_RSV_PROLE;
	}

	return false;
}


//==========================================================
// Local helpers.
//

int
partition_check_source(const as_namespace* ns, const as_partition* p,
		cf_node src, bool* from_replica)
{
	int src_n = index_of_node(p->replicas, p->n_nodes, src);

	if (src_n == -1) {
		return AS_ERR_CLUSTER_KEY_MISMATCH;
	}

	if (from_replica) {
		*from_replica = src_n < p->n_replicas;
	}

	return AS_OK;
}
