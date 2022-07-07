/*
 * xdr_ee.h
 *
 * Copyright (C) 2020 Aerospike, Inc.
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

#include <alloca.h>
#include <stdint.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_digest.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/exp.h"
#include "base/xdr.h"


//==========================================================
// Forward declarations.
//

struct as_dc_s;
struct as_exp_s;


//==========================================================
// Typedefs & constants.
//

typedef struct seed_node_cfg_s {
	char* host;
	char* port;
	char* tls_name;
} seed_node_cfg;

// Use wrapper struct which can be rc-alloc'd (too hard to rc-alloc exp).
typedef struct xdr_filter_s {
	struct as_exp_s* exp;
	char* b64;
} xdr_filter;


//==========================================================
// Public API.
//

// Not called directly - called by the macros below.
void xdr_do_trace(const struct as_dc_s* dc, uint32_t ident, uint64_t lut,
		const char* format, ...);
void xdr_do_pretty_ms(char* pretty, uint64_t cl_ms);

#define as_xdr_trace(dc, keyd, lut, ...) \
{ \
	uint32_t sample = as_load_uint32(&g_config.xdr_cfg.trace_sample); \
\
	if (sample != 0) { \
		uint32_t ident = *(uint32_t*)&(keyd)->digest[DIGEST_RAND_BASE_BYTE]; \
\
		if (ident % sample == 0) { \
			xdr_do_trace((dc), ident, lut, __VA_ARGS__); \
		} \
	} \
}

#define as_xdr_pretty_ms(cl_ms) \
	({ \
		char* pretty = alloca(39); \
		xdr_do_pretty_ms(pretty, cl_ms); \
		pretty; \
	})

static inline bool
ships_specified_bins(as_xdr_bin_policy policy)
{
	switch (policy) {
	case XDR_BIN_POLICY_CHANGED_AND_SPECIFIED:
	case XDR_BIN_POLICY_CHANGED_OR_SPECIFIED:
		return true;
	default:
		return false;
	}
}

static inline bool
ships_changed_bins(as_xdr_bin_policy policy)
{
	switch (policy) {
	case XDR_BIN_POLICY_ONLY_CHANGED:
	case XDR_BIN_POLICY_CHANGED_AND_SPECIFIED:
	case XDR_BIN_POLICY_CHANGED_OR_SPECIFIED:
		return true;
	default:
		return false;
	}
}

static inline void
seed_node_cfg_cleanup(seed_node_cfg* node_cfg)
{
	cf_free(node_cfg->host);
	cf_free(node_cfg->port);

	if (node_cfg->tls_name != NULL) {
		cf_free(node_cfg->tls_name);
	}
}

static inline void
xdr_filter_release(xdr_filter* filter)
{
	if (cf_rc_release(filter) == 0) {
		as_exp_destroy(filter->exp);
		cf_free(filter->b64);
		cf_rc_free(filter);
	}
}
