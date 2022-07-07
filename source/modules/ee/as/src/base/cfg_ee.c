/*
 * cfg_ee.c
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

#include "base/cfg.h"

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#include "log.h"
#include "vault_ee.h"
#include "xmem_ee.h"

#include "base/datamodel.h"
#include "base/features_ee.h"
#include "base/security_ee.h"
#include "base/transaction_policy.h"
#include "fabric/hb.h"
#include "xdr/dc_manager.h"


//==========================================================
// Forward declarations.
//

static void post_process_namespace(as_namespace* ns);

static void load_feature_keys(void);
static bool is_dir(const char* path);
static DIR* get_dir(const char* path);
static bool get_file(DIR* dir, const char* path, char* file_path);


//==========================================================
// Public API.
//

void
as_config_init_namespace(as_namespace* ns)
{
	ns->cfg_prefer_uniform_balance = true;
}

bool
as_config_error_enterprise_only()
{
	return false;
}

bool
as_config_error_enterprise_feature_only(const char* name)
{
	return ! as_features_by_name(name);
}

// TODO - until we have an info split.
bool
as_info_error_enterprise_only()
{
	return false;
}


//==========================================================
// Private API - for enterprise separation only.
//

void
cfg_enterprise_only(const cfg_line* p_line)
{
}

void
cfg_post_process()
{
	cf_vault_cfg_post_process(); // before fetching feature key(s)

	load_feature_keys();

	as_hb_cluster_nodes_limit_set(as_features_cluster_nodes_limit());

	if (g_config.sec_cfg.ldap_configured && ! as_features_ldap()) {
		cf_crash_nostack(AS_CFG, "feature key does not allow 'ldap' to be configured");
	}

	for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
		post_process_namespace(g_config.namespaces[ns_ix]);
	}

	as_security_cfg_post_process();
	as_dc_manager_cfg_post_process();
}


//==========================================================
// Local helpers.
//

static void
post_process_namespace(as_namespace* ns)
{
	if (ns->storage_compression != AS_COMPRESSION_NONE &&
			! as_features_compression()) {
		cf_crash_nostack(AS_CFG, "{%s} feature key does not allow 'compression'",
				ns->name);
	}

	if (ns->storage_encryption_key_file && ! as_features_encryption_at_rest()) {
		cf_crash_nostack(AS_CFG, "{%s} feature key does not allow 'encryption-key-file'",
				ns->name);
	}

	if (ns->xmem_type == CF_XMEM_TYPE_PMEM && ! as_features_pmem()) {
		cf_crash_nostack(AS_CFG, "{%s} feature key does not allow 'index-type pmem'",
				ns->name);
	}

	if (ns->storage_type == AS_STORAGE_ENGINE_PMEM && ! as_features_pmem()) {
		cf_crash_nostack(AS_CFG, "{%s} feature key does not allow 'storage-engine pmem'",
				ns->name);
	}

	if (ns->cp) {
		if (! as_features_strong_consistency()) {
			cf_crash_nostack(AS_CFG, "{%s} feature key does not allow 'strong-consistency'",
					ns->name);
		}

		if (ns->conflict_resolution_policy !=
				AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_UNDEF) {
			cf_crash_nostack(AS_CFG, "{%s} 'conflict-resolution-policy' is not applicable with 'strong-consistency'",
					ns->name);
		}

		if (ns->write_dup_res_disabled) {
			cf_crash_nostack(AS_CFG, "{%s} 'disable-write-dup-res' is not applicable with 'strong-consistency'",
					ns->name);
		}

		if (ns->read_consistency_level != AS_READ_CONSISTENCY_LEVEL_PROTO) {
			cf_crash_nostack(AS_CFG, "{%s} 'read-consistency-level-override' is not applicable with 'strong-consistency'",
					ns->name);
		}

		if (ns->write_commit_level != AS_WRITE_COMMIT_LEVEL_PROTO) {
			cf_crash_nostack(AS_CFG, "{%s} 'write-commit-level-override' is not applicable with 'strong-consistency'",
					ns->name);
		}

		ns->conflict_resolution_policy =
				AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_CP;
		ns->read_consistency_level = AS_READ_CONSISTENCY_LEVEL_ALL;
		ns->write_commit_level = AS_WRITE_COMMIT_LEVEL_ALL;
	}
	else {
		if (ns->cp_allow_drops) {
			cf_crash_nostack(AS_CFG, "{%s} 'strong-consistency-allow-expunge' is only applicable with 'strong-consistency'",
					ns->name);
		}

		if (ns->storage_commit_to_device) {
			cf_crash_nostack(AS_CFG, "{%s} 'commit-to-device' is only applicable with 'strong-consistency'",
					ns->name);
		}

		if (ns->conflict_resolution_policy ==
				AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_UNDEF) {
			ns->conflict_resolution_policy =
					AS_NAMESPACE_CONFLICT_RESOLUTION_POLICY_GENERATION;
		}
	}

	if (ns->xmem_type == CF_XMEM_TYPE_UNDEFINED) {
		ns->xmem_type = CF_XMEM_TYPE_SHMEM;
	}

	if (! cf_xmem_type_cfg_init(ns->xmem_type, ns->xmem_mounts,
			ns->n_xmem_mounts, ns->mounts_size_limit, &ns->xmem_type_cfg)) {
		cf_crash_nostack(AS_CFG, "{%s} missing or invalid mount point", ns->name);
	}

	if (g_config.stay_quiesced) {
		ns->pending_quiesce = true;
	}
}


//==========================================================
// Local helpers - load feature key(s).
//

static void
load_feature_keys(void)
{
	if (g_config.n_feature_key_files == 0) {
		g_config.n_feature_key_files = 1; // use default path
	}

	bool valid_feature_key = false;

	for (uint32_t i = 0; i < g_config.n_feature_key_files; i++) {
		const char* path = g_config.feature_key_files[i];

		if (is_dir(path)) {
			DIR* dir = get_dir(path);
			char file_path[PATH_MAX];

			while (get_file(dir, path, file_path)) {
				if (as_features_init(file_path)) {
					valid_feature_key = true;
				}
			}

			closedir(dir);
		}
		else if (as_features_init(path)) {
			valid_feature_key = true;
		}
	}

	if (! valid_feature_key) {
		cf_crash_nostack(AS_CFG, "no valid feature key found");
	}
}

static bool
is_dir(const char* path)
{
	struct stat buf;

	return stat(path, &buf) == 0 && S_ISDIR(buf.st_mode);
}

static DIR*
get_dir(const char* path)
{
	DIR* dir = opendir(path);

	if (dir == NULL) {
		cf_crash(AS_CFG, "error opening directory %s: %d (%s)", path, errno,
				cf_strerror(errno));
	}

	return dir;
}

static bool
get_file(DIR* dir, const char* path, char* file_path)
{
	while (true) {
		errno = 0;

		struct dirent* ent = readdir(dir);

		if (ent == NULL) {
			if (errno != 0) {
				cf_crash(AS_CFG, "error reading directory %s: %d (%s)", path,
						errno, cf_strerror(errno));
			}

			return false; // no more files
		}

		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
			continue;
		}

		size_t path_len = strlen(path);
		size_t name_len = strlen(ent->d_name);

		if (path_len + 1 + name_len + 1 > PATH_MAX) {
			cf_crash(AS_CFG, "file path len too big");
		}

		strcpy(file_path, path);

		if (file_path[path_len - 1] != '/') {
			file_path[path_len++] = '/';
		}

		strcpy(file_path + path_len, ent->d_name);

		return true;
	}
}
