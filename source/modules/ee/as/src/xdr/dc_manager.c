/*
 * dc_manager.c
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

#include "xdr/dc_manager.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_clock.h"

#include "dynbuf.h"
#include "log.h"
#include "msg.h"
#include "vector.h"

#include "base/cfg.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "base/smd.h"
#include "base/xdr.h"
#include "fabric/exchange.h"
#include "fabric/fabric.h"
#include "xdr/cluster.h"
#include "xdr/dc.h"
#include "xdr/xdr_ee.h"

//#include "warnings.h" // generates warnings we're living with for now


//==========================================================
// Typedefs & constants.
//

static const msg_template xdr_mt[] = {
	{ XDR_FIELD_DC_NAME, M_FT_BUF },
	{ XDR_FIELD_NAMESPACE, M_FT_BUF },
	{ XDR_FIELD_PID, M_FT_UINT32 },
	{ XDR_FIELD_LST, M_FT_UINT64 }
};

COMPILER_ASSERT(sizeof(xdr_mt) / sizeof(msg_template) == NUM_XDR_FIELDS);

#define XDR_MSG_SCRATCH_SIZE 64


//==========================================================
// Globals.
//

uint32_t g_n_dcs = 0;
static as_dc* g_dcs[AS_XDR_MAX_DCS];


//==========================================================
// Forward declarations.
//

static as_dc* get_dc_by_name(const char* name);
static as_dc* get_dc_by_name_w_len(const uint8_t* name, size_t len);

static bool add_seed(as_xdr_dc_cfg* dc_cfg, seed_node_cfg* node_cfg);
static bool remove_seed(as_xdr_dc_cfg* cfg, const char* host, const char* port);
static int32_t find_seed(const as_xdr_dc_cfg* cfg, const char* host, const char* port);

static void xdr_smd_accept_cb(const cf_vector* items, as_smd_accept_type accept_type);
static int xdr_msg_cb(cf_node node, msg* m, void* udata);
static void xdr_cluster_changed_cb(const as_exchange_cluster_changed_event* ex_event, void* udata);

static void set_ns_ships_client_drops(const as_xdr_dc_ns_cfg* cfg, as_namespace* ns);
static void set_ns_ships_nsup_drops(const as_xdr_dc_ns_cfg* cfg, as_namespace* ns);
static void reset_ns_ships_client_drops(as_namespace* ns);
static void reset_ns_ships_nsup_drops(as_namespace* ns);

static void set_ns_ships_changed_bins(const as_xdr_dc_ns_cfg* cfg, as_namespace* ns);
static void set_ns_ships_bin_luts(const as_xdr_dc_ns_cfg* cfg, as_namespace* ns);
static void reset_ns_ships_changed_bins(as_namespace* ns);
static void reset_ns_ships_bin_luts(as_namespace* ns);


//==========================================================
// Inlines & macros.
//

static inline const char*
safe_set_name(const as_namespace* ns, uint16_t set_id)
{
	const char* set_name = as_namespace_get_set_name(ns, set_id);

	return set_name != NULL ? set_name : "";
}

static inline uint64_t
lst_from_smd(const as_smd_item* item)
{
	return strtoul(item->value, NULL, 10);
}


//==========================================================
// Public API.
//

as_xdr_dc_cfg*
as_xdr_startup_create_dc(const char* name)
{
	if (*name == '\0') {
		cf_crash_nostack(AS_XDR, "missing DC name");
	}

	if (strlen(name) >= DC_NAME_MAX_SZ) {
		cf_crash_nostack(AS_XDR, "DC name %s too long (max length is %u)", name,
				DC_NAME_MAX_SZ - 1);
	}

	if (g_n_dcs == AS_XDR_MAX_DCS) {
		cf_crash_nostack(AS_XDR, "too many DCs");
	}

	as_dc* dc = as_dc_create(name, g_n_dcs);

	g_dcs[g_n_dcs++] = dc;

	dc->cfg.ns_cfg_v = cf_vector_create(sizeof(as_xdr_dc_ns_cfg*),
			AS_NAMESPACE_SZ, 0);

	return &dc->cfg;
}

as_xdr_dc_ns_cfg*
as_xdr_startup_create_dc_ns_cfg(const char* ns_name)
{
	as_xdr_dc_ns_cfg* cfg = as_dc_create_ns_cfg(ns_name);

	cfg->ignored_bins = cf_vector_create(sizeof(char*), 8, 0);
	cfg->ignored_sets = cf_vector_create(sizeof(char*), 8, 0);
	cfg->shipped_bins = cf_vector_create(sizeof(char*), 8, 0);
	cfg->shipped_sets = cf_vector_create(sizeof(char*), 8, 0);

	return cfg;
}

void
as_xdr_startup_add_seed(as_xdr_dc_cfg* cfg, char* host, char* port,
		char* tls_name)
{
	seed_node_cfg node_cfg = {
			.host = host,
			.port = port,
			.tls_name = tls_name
	};

	if (! add_seed(cfg, &node_cfg)) {
		cf_crash_nostack(AS_XDR, "DC %s can't add seed", cfg->name);
	}
}

void
as_xdr_link_tls(void)
{
	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc_link_tls(g_dcs[dc_ix]);
	}
}

void
as_xdr_get_submit_info(const as_record* r, uint64_t prev_lut,
		as_xdr_submit_info* info)
{
	if (g_n_dcs == 0) {
		// g_n_dcs may change. Use info->lut to indicate validity of info.
		info->lut = 0;
		return;
	}

	info->keyd = r->keyd;
	info->lut = r->last_update_time;
	info->prev_lut = prev_lut;
	info->set_id = as_index_get_set_id(r);
	info->xdr_write = r->xdr_write == 1;
	info->xdr_tombstone = r->xdr_tombstone == 1;
	info->xdr_nsup_tombstone = r->xdr_nsup_tombstone == 1;
}

void
as_xdr_submit(const as_namespace* ns, const as_xdr_submit_info* info)
{
	if (info->lut == 0) {
		return;
	}

	as_xdr_trace(NULL, &info->keyd, info->lut, "transaction - {%s|%s} pid %u",
			ns->name, safe_set_name(ns, info->set_id),
			as_partition_getid(&info->keyd));

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state == DC_CONNECTED) {
			as_dc_submit(dc, ns, info);
		}
	}
}

void
as_xdr_ticker(uint64_t delta_time)
{
	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state != DC_UNUSED) {
			as_dc_ticker(dc, delta_time);
		}
	}
}

void
as_xdr_cleanup_tl_stats(void)
{
	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state != DC_UNUSED) {
			as_dc_cleanup_tl_stats(dc);
		}
	}
}


//==========================================================
// Public API - enterprise only - startup.
//

void
as_dc_manager_cfg_post_process(void)
{
	// All configured DCs will be contiguous and in-use at this stage.
	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		as_dc_cfg_post_process(dc);

		cf_vector_destroy(dc->cfg.ns_cfg_v);
	}
}

void
as_dc_manager_init(void)
{
	// Add each configured DC's configured namespaces.
	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];
		as_xdr_dc_cfg* dc_cfg = &dc->cfg;

		for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
			as_namespace* ns = g_config.namespaces[ns_ix];
			as_xdr_dc_ns_cfg* dc_ns_cfg = dc_cfg->ns_cfgs[ns_ix];

			as_dc_init_ns(dc, ns);

			if (dc_ns_cfg != NULL) {
				set_ns_ships_client_drops(dc_ns_cfg, ns);
				set_ns_ships_nsup_drops(dc_ns_cfg, ns);
				set_ns_ships_changed_bins(dc_ns_cfg, ns);
				set_ns_ships_bin_luts(dc_ns_cfg, ns);

				// Don't force LST, safe_lst will be set at SMD module load.
				as_dc_add_ns(dc, ns, 0);
				continue;
			}
			// else - namespace not added in config file.

			// Prepare default config in case namespace is added dynamically.
			dc_cfg->ns_cfgs[ns_ix] = as_dc_create_ns_cfg(ns->name);

			// Forces run_dc() to call process_disabled() once.
			as_dc_remove_ns(dc, ns);
		}
	}

	as_smd_module_load(AS_SMD_MODULE_XDR, xdr_smd_accept_cb, NULL, NULL);
}

void
as_dc_manager_start(void)
{
	as_fabric_register_msg_fn(M_TYPE_XDR, xdr_mt, sizeof(xdr_mt),
			XDR_MSG_SCRATCH_SIZE, xdr_msg_cb, NULL);

	as_exchange_register_listener(xdr_cluster_changed_cb, NULL);

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
			as_namespace* ns = g_config.namespaces[ns_ix];

			// cfg_post_process() or init() time is ideal, but vmaps not ready.
			as_dc_setup_ns_bins(dc, ns);
			as_dc_setup_ns_sets(dc, ns);
		}

		as_dc_run(dc);

		if (as_dc_has_any_ns(dc)) {
			as_dc_connect(dc);
		}
	}
}


//==========================================================
// Public API - enterprise only - DC lifecycle.
//

bool
as_dc_manager_create_dc(const char* dc_name)
{
	if (get_dc_by_name(dc_name) != NULL) {
		cf_warning(AS_XDR, "DC %s already present", dc_name);
		return false;
	}

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state == DC_UNUSED && as_dc_reuse(dc, dc_name)) {
			return true;
		}
	}

	if (g_n_dcs == AS_XDR_MAX_DCS) {
		cf_warning(AS_XDR, "too many DCs");
		return false;
	}

	as_dc* dc = as_dc_create(dc_name, g_n_dcs);

	as_xdr_dc_cfg* cfg = &dc->cfg;

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_namespace* ns = g_config.namespaces[ns_ix];

		as_dc_init_ns(dc, ns);

		// Prepare default config in case namespace is added dynamically.
		cfg->ns_cfgs[ns_ix] = as_dc_create_ns_cfg(ns->name);

		// Forces run_dc() to call process_disabled() once.
		as_dc_remove_ns(dc, ns);
	}

	// Make accessible after initializing - DC may move from another slot by
	// fast recreate, and e.g. a stale fabric msg may try to access.

	// NOT g_dcs[g_n_dcs++] = dc; ... g_n_dcs changes before dc is loaded!
	g_dcs[g_n_dcs] = dc;
	g_n_dcs++;

	as_dc_run(dc);

	return true;
}

bool
as_dc_manager_delete_dc(const char* dc_name)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (dc == NULL) {
		cf_warning(AS_XDR, "DC %s not found", dc_name);
		return false;
	}

	if (! as_dc_delete(dc)) {
		return false;
	}

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_namespace* ns = g_config.namespaces[ns_ix];

		reset_ns_ships_client_drops(ns);
		reset_ns_ships_nsup_drops(ns);
		reset_ns_ships_changed_bins(ns);
		reset_ns_ships_bin_luts(ns);
	}

	return true;
}

bool
as_dc_manager_dc_is_connected(const char* dc_name)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (dc == NULL) {
		cf_warning(AS_XDR, "DC %s not found", dc_name);
		return false;
	}

	return dc->state == DC_CONNECTED;
}

bool
as_dc_manager_add_seed(const char* dc_name, const char* host, const char* port,
		const char* tls_name)
{
	as_dc* dc = get_dc_by_name(dc_name);

	seed_node_cfg node_cfg = {
			.host = cf_strdup(host),
			.port = cf_strdup(port),
			.tls_name = tls_name != NULL ? cf_strdup(tls_name) : NULL
	};

	if (! add_seed(&dc->cfg, &node_cfg)) {
		return false;
	}

	as_cluster_queue_seed(dc->ix, true, host, port, tls_name);

	return true;
}

bool
as_dc_manager_remove_seed(const char* dc_name, const char* host,
		const char* port)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (! remove_seed(&dc->cfg, host, port)) {
		return false;
	}

	as_cluster_queue_seed(dc->ix, false, host, port, NULL);

	return true;
}


//==========================================================
// Public API - enterprise only - namespace lifecycle.
//

bool
as_dc_manager_add_ns(const char* dc_name, as_namespace* ns, uint32_t rewind)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (dc == NULL) {
		cf_warning(AS_XDR, "DC %s not found", dc_name);
		return false;
	}

	if (! as_dc_connect(dc)) {
		return false;
	}

	uint64_t lst = cf_clepoch_milliseconds();
	uint64_t rewind_ms = (uint64_t)rewind * 1000;

	if (rewind_ms < lst) {
		lst -= rewind_ms;
	}
	else {
		lst = 1;
	}

	as_xdr_dc_ns_cfg* dc_ns_cfg = dc->cfg.ns_cfgs[ns->ix];

	set_ns_ships_client_drops(dc_ns_cfg, ns);
	set_ns_ships_nsup_drops(dc_ns_cfg, ns);
	set_ns_ships_changed_bins(dc_ns_cfg, ns);
	set_ns_ships_bin_luts(dc_ns_cfg, ns);

	as_dc_add_ns(dc, ns, lst);

	cf_info(AS_XDR, "DC %s - added namespace %s", dc_name, ns->name);

	return true;
}

bool
as_dc_manager_remove_ns(const char* dc_name, as_namespace* ns)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (dc == NULL) {
		cf_warning(AS_XDR, "DC %s not found", dc_name);
		return false;
	}

	as_dc_remove_ns(dc, ns);

	if (! as_dc_has_any_ns(dc)) {
		as_dc_disconnect(dc);
	}

	reset_ns_ships_client_drops(ns);
	reset_ns_ships_nsup_drops(ns);
	reset_ns_ships_changed_bins(ns);
	reset_ns_ships_bin_luts(ns);

	cf_info(AS_XDR, "DC %s - removed namespace %s", dc_name, ns->name);

	return true;
}

bool
as_dc_manager_update_ns_remote_namespace(const char* dc_name,
		const as_namespace* ns, const char* ns_name)
{
	as_dc* dc = get_dc_by_name(dc_name);

	return as_dc_update_ns_remote_namespace(dc, ns, ns_name);
}


//==========================================================
// Public API - enterprise only - setup namespace filters.
//

bool
as_dc_manager_update_ns_bins(const char* dc_name, as_namespace* ns,
		const char* bin_name, bool enabled)
{
	if (ns->single_bin) {
		cf_warning(AS_XDR, "can't specify bins for single-bin namespace");
		return false;
	}

	as_dc* dc = get_dc_by_name(dc_name);

	return as_dc_update_ns_bins(dc, ns, bin_name, enabled);
}

bool
as_dc_manager_update_ns_sets(const char* dc_name, as_namespace* ns,
		const char* set_name, bool enabled)
{
	as_dc* dc = get_dc_by_name(dc_name);

	return as_dc_update_ns_sets(dc, ns, set_name, enabled);
}

void
as_dc_manager_update_ns_ships_client_drops(const char* dc_name,
		as_namespace* ns)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (! as_dc_has_ns(dc, ns)) {
		// Switching on  - defer until adding namespace.
		// Switching off - prior removal of namespace already switched off.
		return;
	}

	if (! dc->cfg.ns_cfgs[ns->ix]->ignore_expunges) {
		ns->xdr_ships_drops = true;
	}
	else {
		reset_ns_ships_client_drops(ns);
	}
}

void
as_dc_manager_update_ns_ships_nsup_drops(const char* dc_name, as_namespace* ns)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (! as_dc_has_ns(dc, ns)) {
		// Switching on  - defer until adding namespace.
		// Switching off - prior removal of namespace already switched off.
		return;
	}

	if (dc->cfg.ns_cfgs[ns->ix]->ship_nsup_deletes) {
		ns->xdr_ships_nsup_drops = true;
	}
	else {
		reset_ns_ships_nsup_drops(ns);
	}
}

void
as_dc_manager_update_ns_ships_changed_bins(const char* dc_name,
		as_namespace* ns)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (! as_dc_has_ns(dc, ns)) {
		// Switching on  - defer until adding namespace.
		// Switching off - prior removal of namespace already switched off.
		return;
	}

	if (ships_changed_bins(dc->cfg.ns_cfgs[ns->ix]->bin_policy)) {
		ns->xdr_ships_changed_bins = true;
	}
	else {
		reset_ns_ships_changed_bins(ns);
	}
}

void
as_dc_manager_update_ns_ships_bin_luts(const char* dc_name, as_namespace* ns)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (! as_dc_has_ns(dc, ns)) {
		// Switching on  - defer until adding namespace.
		// Switching off - prior removal of namespace already switched off.
		return;
	}

	if (dc->cfg.ns_cfgs[ns->ix]->ship_bin_luts) {
		ns->xdr_ships_bin_luts = true;
	}
	else {
		reset_ns_ships_bin_luts(ns);
	}
}


//==========================================================
// Public API - enterprise only - LST.
//

uint64_t
as_dc_manager_ns_min_lst(const as_namespace* ns)
{
	uint64_t min_lst = UINT64_MAX;

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state != DC_UNUSED) {
			uint64_t dc_min_lst = as_dc_ns_min_lst(dc, ns);

			if (dc_min_lst < min_lst) {
				min_lst = dc_min_lst;
			}
		}
	}

	return min_lst;
}


//==========================================================
// Public API - enterprise only - config access.
//

as_xdr_dc_cfg*
as_dc_manager_get_cfg(const char* dc_name)
{
	as_dc* dc = get_dc_by_name(dc_name);

	return dc != NULL ? &dc->cfg : NULL;
}

as_xdr_dc_cfg*
as_dc_manager_get_cfg_by_ix(uint32_t dc_ix)
{
	as_dc* dc = g_dcs[dc_ix];

	// DC may be in DC_UNUSED state.
	return dc_ix < g_n_dcs ? &dc->cfg : NULL;
}


//==========================================================
// Public API - enterprise only - info & stats.
//

void
as_dc_manager_get_dcs(cf_dyn_buf* db)
{
	cf_dyn_buf_append_string(db, "dcs=");

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state != DC_UNUSED) {
			cf_dyn_buf_append_string(db, dc->cfg.name);
			cf_dyn_buf_append_char(db, ',');
		}
	}

	cf_dyn_buf_chomp_char(db, ',');
	cf_dyn_buf_append_char(db, ';');
}

void
as_dc_manager_get_dc_config(const char* dc_name, const as_namespace* ns,
		cf_dyn_buf* db)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (dc == NULL) {
		cf_warning(AS_XDR, "DC %s not found", dc_name);
		cf_dyn_buf_append_string(db, "ERROR::DC-not-found");
		return;
	}

	if (ns != NULL) {
		as_dc_get_ns_config(dc, ns, db);
	}
	else {
		as_dc_get_config(dc, db);
	}
}

void
as_dc_manager_get_dc_stats(const char* dc_name, const as_namespace* ns,
		cf_dyn_buf* db)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (dc == NULL) {
		cf_warning(AS_XDR, "DC %s not found", dc_name);
		cf_dyn_buf_append_string(db, "ERROR::DC-not-found");
		return;
	}

	if (ns != NULL) {
		as_dc_get_ns_stats(dc, ns, db);
	}
	else {
		as_dc_get_stats(dc, db);
	}
}

void
as_dc_manager_get_dc_state(const char* dc_name, const as_namespace* ns,
		cf_dyn_buf* db)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (dc == NULL) {
		cf_warning(AS_XDR, "DC %s not found", dc_name);
		cf_dyn_buf_append_string(db, "ERROR::DC-not-found");
		return;
	}

	if (ns != NULL) {
		if (! as_dc_get_state(dc, ns, db, true)) {
			cf_warning(AS_XDR, "namespace %s not associated", ns->name);
			cf_dyn_buf_append_string(db, "ERROR::namespace-not-associated");
		}

		return;
	}

	bool any = false;

	for (uint32_t ns_ix = 0 ; ns_ix < g_config.n_namespaces; ns_ix++) {
		if (as_dc_get_state(dc, g_config.namespaces[ns_ix], db, ! any)) {
			any = true;
		}
	}

	if (! any) {
		cf_warning(AS_XDR, "no namespace(s) associated");
		cf_dyn_buf_append_string(db, "ERROR::no-namespace(s)-associated");
	}
}

void
as_dc_manager_get_dc_display_filters(const char* dc_name,
		const as_namespace* ns, bool b64, cf_dyn_buf* db)
{
	as_dc* dc = get_dc_by_name(dc_name);

	if (dc == NULL) {
		cf_warning(AS_XDR, "DC %s not found", dc_name);
		cf_dyn_buf_append_string(db, "ERROR::DC-not-found");
		return;
	}

	if (ns != NULL) {
		as_dc_get_ns_display_filter(dc, ns, b64, db);
		return;
	}

	for (uint32_t ns_ix = 0 ; ns_ix < g_config.n_namespaces; ns_ix++) {
		as_dc_get_ns_display_filter(dc, g_config.namespaces[ns_ix], b64, db);
	}
}


//==========================================================
// Local helpers - get as_dc from name.
//

static as_dc*
get_dc_by_name(const char* name)
{
	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state != DC_UNUSED && strcmp(dc->cfg.name, name) == 0) {
			return dc;
		}
	}

	return NULL;
}

static as_dc*
get_dc_by_name_w_len(const uint8_t* name, size_t len)
{
	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state != DC_UNUSED && strlen(dc->cfg.name) == len &&
				memcmp(name, dc->cfg.name, len) == 0) {
			return dc;
		}
	}

	return NULL;
}


//==========================================================
// Local helpers - seed nodes.
//

static bool
add_seed(as_xdr_dc_cfg* dc_cfg, seed_node_cfg* node_cfg)
{
	if (cf_vector_size(&dc_cfg->seed_nodes) >= AS_CLUSTER_SZ) {
		cf_warning(AS_XDR, "DC %s has too many seed nodes", dc_cfg->name);
		seed_node_cfg_cleanup(node_cfg);
		return false;
	}

	cf_mutex_lock(&dc_cfg->seed_lock);

	if (find_seed(dc_cfg, node_cfg->host, node_cfg->port) != -1) {
		cf_warning(AS_XDR, "%s:%s present in DC %s", node_cfg->host,
				node_cfg->port, dc_cfg->name);
		cf_mutex_unlock(&dc_cfg->seed_lock);
		seed_node_cfg_cleanup(node_cfg);
		return false;
	}

	cf_vector_append(&dc_cfg->seed_nodes, node_cfg);

	cf_mutex_unlock(&dc_cfg->seed_lock);

	return true;
}

static bool
remove_seed(as_xdr_dc_cfg* cfg, const char* host, const char* port)
{
	cf_mutex_lock(&cfg->seed_lock);

	int32_t ix = find_seed(cfg, host, port);

	if (ix == -1) {
		cf_warning(AS_XDR, "%s:%s not present in DC %s", host, port, cfg->name);
		cf_mutex_unlock(&cfg->seed_lock);
		return false;
	}

	cf_vector* nv = &cfg->seed_nodes;
	seed_node_cfg node_cfg;

	cf_vector_get(nv, (uint32_t)ix, &node_cfg);
	cf_vector_delete(nv, (uint32_t)ix);

	cf_mutex_unlock(&cfg->seed_lock);

	seed_node_cfg_cleanup(&node_cfg);

	return true;
}

static int32_t
find_seed(const as_xdr_dc_cfg* cfg, const char* host, const char* port)
{
	const cf_vector* nv = &cfg->seed_nodes;
	seed_node_cfg node_cfg;

	uint32_t sz = cf_vector_size(nv);

	for (uint32_t i = 0; i < sz; i++) {
		cf_vector_get(nv, i, &node_cfg);

		if (strcmp(node_cfg.host, host) == 0 &&
				strcmp(node_cfg.port, port) == 0) {
			// Don't match TLS name - it is not part of identity.
			return (int32_t)i;
		}
	}

	return -1;
}


//==========================================================
// Local helpers - modules' callbacks.
//

// dc|ns : <lst>  or  dc|ns|F : <b64-filter>
static void
xdr_smd_accept_cb(const cf_vector* items, as_smd_accept_type accept_type)
{
	for (uint32_t i = 0; i < cf_vector_size(items); i++) {
		as_smd_item* item = cf_vector_get_ptr(items, i);

		const char* dc_name = item->key;
		const char* tok = strchr(dc_name, TOK_DELIMITER);

		if (tok == NULL) {
			cf_warning(AS_XDR, "bad smd key - %s", dc_name);
			continue;
		}

		size_t dc_name_len = (size_t)(tok - dc_name);
		as_dc* dc = get_dc_by_name_w_len((const uint8_t*)dc_name, dc_name_len);

		if (dc == NULL) {
			cf_detail(AS_XDR, "skipping unknown DC");
			continue;
		}

		const char* ns_name = tok + 1;
		as_namespace* ns;

		if ((tok = strchr(ns_name, TOK_DELIMITER)) != NULL) {
			if (*(tok + 1) != TOK_FILTER) {
				cf_detail(AS_XDR, "skipping unknown smd key - %s", dc_name);
				continue;
			}

			size_t ns_name_len = (size_t)(tok - ns_name);

			ns = as_namespace_get_bybuf((const uint8_t*)ns_name, ns_name_len);
		}
		else {
			ns = as_namespace_get_byname(ns_name);
		}

		if (ns == NULL) {
			cf_detail(AS_XDR, "skipping unknown namespace - %s", ns_name);
			continue;
		}

		if (tok != NULL) {
			as_dc_set_ns_filter(dc, ns, item->value);
		}
		else {
			if (accept_type == AS_SMD_ACCEPT_OPT_START) {
				as_dc_init_safe_lsts(dc, ns, lst_from_smd(item));
			}
			else {
				// Non-hub nodes need the value for the XDR tomb raider.
				as_dc_update_ns_persisted_lst(dc, ns, lst_from_smd(item));
			}
		}
	}
}

static int
xdr_msg_cb(cf_node node, msg* m, void* udata)
{
	(void)node;
	(void)udata;

	uint8_t* dc_name;
	size_t dc_name_len;

	if (msg_get_buf(m, XDR_FIELD_DC_NAME, &dc_name, &dc_name_len,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_XDR, "got msg without DC name");
		as_fabric_msg_put(m);
		return 0;
	}

	as_dc* dc = get_dc_by_name_w_len(dc_name, dc_name_len);

	if (dc == NULL) {
		// May add/remove DC node by node.
		cf_detail(AS_XDR, "got unknown DC name");
		as_fabric_msg_put(m);
		return 0;
	}

	uint8_t* ns_name;
	size_t ns_name_len;

	if (msg_get_buf(m, XDR_FIELD_NAMESPACE, &ns_name, &ns_name_len,
			MSG_GET_DIRECT) != 0) {
		cf_warning(AS_XDR, "got msg without ns name");
		as_fabric_msg_put(m);
		return 0;
	}

	as_namespace* ns = as_namespace_get_bybuf(ns_name, ns_name_len);

	if (ns == NULL) {
		cf_warning(AS_XDR, "got invalid namespace");
		as_fabric_msg_put(m);
		return 0;
	}

	uint32_t pid;

	if (msg_get_uint32(m, XDR_FIELD_PID, &pid) != 0) {
		cf_warning(AS_XDR, "got msg without pid");
		as_fabric_msg_put(m);
		return 0;
	}

	if (pid >= AS_PARTITIONS) {
		cf_warning(AS_XDR, "got invalid pid %u", pid);
		as_fabric_msg_put(m);
		return 0;
	}

	uint64_t lst;

	if (msg_get_uint64(m, XDR_FIELD_LST, &lst) != 0) {
		cf_warning(AS_XDR, "got msg without lst");
		as_fabric_msg_put(m);
		return 0;
	}

	as_dc_accept_safe_lst(dc, ns, pid, lst);

	as_fabric_msg_put(m);
	return 0;
}

static void
xdr_cluster_changed_cb(const as_exchange_cluster_changed_event* ex_event,
		void* udata)
{
	(void)ex_event;
	(void)udata;

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state != DC_UNUSED) {
			as_dc_cluster_changed_cb(dc);
		}
	}
}


//==========================================================
// Local helpers - drop shipping.
//

static void
set_ns_ships_client_drops(const as_xdr_dc_ns_cfg* cfg, as_namespace* ns)
{
	if (! cfg->ignore_expunges) {
		ns->xdr_ships_drops = true;
	}
}

static void
set_ns_ships_nsup_drops(const as_xdr_dc_ns_cfg* cfg, as_namespace* ns)
{
	if (cfg->ship_nsup_deletes) {
		ns->xdr_ships_nsup_drops = true;
	}
}

static void
reset_ns_ships_client_drops(as_namespace* ns)
{
	if (! ns->xdr_ships_drops) {
		return; // namespace does not ship client drops to any DC
	}
	// else - namespace was shipping client drops to at least one DC.

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state == DC_UNUSED) {
			continue;
		}

		if (as_dc_has_ns(dc, ns) &&
				! dc->cfg.ns_cfgs[ns->ix]->ignore_expunges) {
			return; // namespace still ships client drops to at least one DC
		}
	}

	// Namespace no longer ships client drops to any DC.
	ns->xdr_ships_drops = false;
}

static void
reset_ns_ships_nsup_drops(as_namespace* ns)
{
	if (! ns->xdr_ships_nsup_drops) {
		return; // namespace does not ship nsup drops to any DC
	}
	// else - namespace was shipping nsup drops to at least one DC.

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state == DC_UNUSED) {
			continue;
		}

		if (as_dc_has_ns(dc, ns) &&
				dc->cfg.ns_cfgs[ns->ix]->ship_nsup_deletes) {
			return; // namespace still ships nsup drops to at least one DC
		}
	}

	// Namespace no longer ships nsup drops to any DC.
	ns->xdr_ships_nsup_drops = false;
}


//==========================================================
// Local helpers - changed bin shipping.
//

static void
set_ns_ships_changed_bins(const as_xdr_dc_ns_cfg* cfg, as_namespace* ns)
{
	if (ships_changed_bins(cfg->bin_policy)) {
		ns->xdr_ships_changed_bins = true;
	}
}

static void
set_ns_ships_bin_luts(const as_xdr_dc_ns_cfg* cfg, as_namespace* ns)
{
	if (cfg->ship_bin_luts) {
		ns->xdr_ships_bin_luts = true;
	}
}

static void
reset_ns_ships_changed_bins(as_namespace* ns)
{
	if (! ns->xdr_ships_changed_bins) {
		return; // namespace does not ship changed bins to any DC
	}
	// else - namespace was shipping changed bins to at least one DC.

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state == DC_UNUSED) {
			continue;
		}

		if (as_dc_has_ns(dc, ns) &&
				ships_changed_bins(dc->cfg.ns_cfgs[ns->ix]->bin_policy)) {
			return; // namespace still ships changed bins to at least one DC
		}
	}

	// Namespace no longer ships changed bins to any DC.
	ns->xdr_ships_changed_bins = false;
}

static void
reset_ns_ships_bin_luts(as_namespace* ns)
{
	if (! ns->xdr_ships_bin_luts) {
		return; // namespace does not ship bin LUTs to any DC
	}
	// else - namespace was shipping bin LUTs to at least one DC.

	for (uint32_t dc_ix = 0; dc_ix < g_n_dcs; dc_ix++) {
		as_dc* dc = g_dcs[dc_ix];

		if (dc->state == DC_UNUSED) {
			continue;
		}

		if (as_dc_has_ns(dc, ns) && dc->cfg.ns_cfgs[ns->ix]->ship_bin_luts) {
			return; // namespace still ships bin LUTs to at least one DC
		}
	}

	// Namespace no longer ships bin LUTs to any DC.
	ns->xdr_ships_bin_luts = false;
}
