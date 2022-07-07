/*
 * features_ee.c
 *
 * Copyright (C) 2017-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "base/features.h"
#include "base/features_ee.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "fetch.h"
#include "log.h"

#include "citrusleaf/alloc.h"

#include "warnings.h"


//==========================================================
// Typedefs & constants.
//

// 2 - 5.4.0 - so older builds won't ignore cluster_nodes_limit.
#define FEATURE_KEY_VERSION 2

#define PARSE_SPACE " \t\f\v"

typedef struct features_s {
	uint64_t	feature_key_version;
	uint64_t	serial_number;
	time_t		valid_until_date;
	uint64_t	valid_until_version;
	bool		change_notification;
	uint64_t	cluster_nodes_limit;
	bool		compression;
	bool		encryption_at_rest;
	bool		ldap;
	bool		pmem;
	bool		strong_consistency;
} features;

typedef struct asdb_features_s {
	bool		change_notification;
	uint64_t	cluster_nodes_limit;
	bool		compression;
	bool		encryption_at_rest;
	bool		ldap;
	bool		pmem;
	bool		strong_consistency;
} asdb_features;

#include "features_pub.c"


//==========================================================
// Forward declarations.
//

static char* get_line(char** line_ctx);
static void trim_line(char* line);

static void process_feature(const char* key, const char* val, const char* path, int32_t line_no);
static void check_mandatory(const char* path);
static bool expired(const char* path);
static void accumulate_features(void);
static void accumulate_info(char* info);
static bool parse_integer(const char* str, uint64_t* val);
static bool parse_boolean(const char* str, bool* val);
static bool parse_date(const char* str, time_t* simple_time);
static bool parse_version(const char* str, uint64_t* version);

static size_t add_to_message(uint8_t* mess, size_t mess_len, const char* str);
static size_t add_to_info(char* info, size_t info_len, const char* key, const char* val);
static size_t add_to_signature(uint8_t* sig, size_t sig_sz, size_t limit, const uint8_t* data, size_t data_len, const char* path, int32_t line_no);
static void verify_signature(const uint8_t* mess, size_t mess_len, const uint8_t* sig, size_t sig_sz);

extern const char aerospike_build_id[];


//==========================================================
// Globals.
//

static features g_features;

static asdb_features g_asdb_features = {
	.change_notification = false,
	.cluster_nodes_limit = 0,
	.compression = false,
	.encryption_at_rest = false,
	.ldap = false,
	.pmem = false,
	.strong_consistency = false
};

static const char NULL_STR[] = "null";
static char* g_features_info = (char*)NULL_STR;


//==========================================================
// Public API.
//

const char*
as_features_info()
{
	return g_features_info;
}


//==========================================================
// Public API - enterprise only.
//

bool
as_features_init(const char* path)
{
	g_features = (features){ 0 };

	char* features_conf = cf_fetch_string(path);

	if (features_conf == NULL) {
		cf_crash_nostack(AS_CFG, "failed to get feature key %s", path);
	}

	size_t conf_len = strlen(features_conf);

	cf_detail(AS_CFG, "fetched feature key %s with len %zu", path, conf_len);

	uint8_t mess[conf_len];
	size_t mess_len = 0;

	char* info = cf_malloc(conf_len);
	size_t info_len = 0;

	char* line;
	char* line_ctx = features_conf;
	int32_t line_no = 0;

	while ((line = get_line(&line_ctx)) != NULL) {
		line_no++;

		trim_line(line);

		if (strcmp(line, "----- SIGNATURE ------------------------------------------------") == 0) {
			cf_detail(AS_CFG, "signature from line %d", line_no);
			break;
		}

		char* key = strtok(line, PARSE_SPACE);

		if (key == NULL) {
			continue;
		}

		char* val = strtok(NULL, PARSE_SPACE);

		if (val == NULL) {
			cf_crash_nostack(AS_CFG, "missing value for key %s in %s, line %d",
					key, path, line_no);
		}

		if (strtok(NULL, PARSE_SPACE) != NULL) {
			cf_crash_nostack(AS_CFG, "trailing garbage in %s, line %d", path,
					line_no);
		}

		process_feature(key, val, path, line_no);

		mess_len = add_to_message(mess, mess_len, key);
		mess_len = add_to_message(mess, mess_len, val);

		info_len = add_to_info(info, info_len, key, val);
	}

	mess[mess_len] = 0;
	cf_detail(AS_CFG, "signed message %s", mess);

	info[info_len - 1] = 0;
	cf_detail(AS_CFG, "info string %s", info);

	// Parse signature.

	uint8_t sig[5000];
	size_t sig_sz = 0;

	bool has_end = false;

	while ((line = get_line(&line_ctx)) != NULL) {
		line_no++;

		trim_line(line);

		if (strcmp(line, "----- END OF SIGNATURE -----------------------------------------") == 0) {
			cf_detail(AS_CFG, "signature through line %d", line_no);
			has_end = true;
			break;
		}

		char* enc = strtok(line, PARSE_SPACE);

		if (enc == NULL) {
			cf_crash_nostack(AS_CFG, "malformed signature in %s, line %d", path,
					line_no);
		}

		if (strtok(NULL, PARSE_SPACE) != NULL) {
			cf_crash_nostack(AS_CFG, "trailing garbage in %s, line %d", path,
					line_no);
		}

		sig_sz = add_to_signature(sig, sig_sz, sizeof(sig), (uint8_t*)enc,
				strlen(enc), path, line_no);
	}

	if (! has_end) {
		cf_crash_nostack(AS_CFG, "malformed signature in %s, line %d", path,
				line_no);
	}

	cf_free(features_conf);

	// Validate everything.

	cf_detail(AS_CFG, "signature len %zu", sig_sz);

	verify_signature(mess, mess_len, sig, sig_sz);

	check_mandatory(path);

	if (expired(path)) {
		cf_free(info);
		return false;
	}

	accumulate_features();
	accumulate_info(info);

	cf_info(AS_CFG, "loaded feature key #%lu (%s)", g_features.serial_number,
			path);

	return true;
}

bool
as_features_change_notification(void)
{
	return g_asdb_features.change_notification;
}

uint32_t
as_features_cluster_nodes_limit(void)
{
	return (uint32_t)g_asdb_features.cluster_nodes_limit;
}

bool
as_features_compression(void)
{
	return g_asdb_features.compression;
}

bool
as_features_encryption_at_rest(void)
{
	return g_asdb_features.encryption_at_rest;
}

bool
as_features_ldap(void)
{
	return g_asdb_features.ldap;
}

bool
as_features_pmem(void)
{
	return g_asdb_features.pmem;
}

bool
as_features_strong_consistency(void)
{
	return g_asdb_features.strong_consistency;
}

bool
as_features_by_name(const char* name)
{
	if (strcmp(name, "change-notification") == 0) {
		return as_features_change_notification();
	}

	if (strcmp(name, "cluster-nodes-limit") == 0) {
		return as_features_cluster_nodes_limit() != 0;
	}

	if (strcmp(name, "compression") == 0) {
		return as_features_compression();
	}

	if (strcmp(name, "encryption-at-rest") == 0) {
		return as_features_encryption_at_rest();
	}

	if (strcmp(name, "ldap") == 0) {
		return as_features_ldap();
	}

	if (strcmp(name, "pmem") == 0) {
		return as_features_pmem();
	}

	if (strcmp(name, "strong-consistency") == 0) {
		return as_features_strong_consistency();
	}

	cf_crash(AS_CFG, "unknown feature name %s", name);
	return false;
}


//==========================================================
// Local helpers.
//

static char*
get_line(char** line_ctx)
{
	char* line = *line_ctx;
	char* at = line;

	// Search for the next newline. Ignore '\r' here - they'll end up in the
	// returned line.
	while (*at != '\0') {
		if (*at == '\n') {
			*at++ = '\0';
			break;
		}

		at++;
	}

	if (at != line) {
		*line_ctx = at; // points to next line or null terminator
		return line;
	}

	return NULL; // no more lines - already pointing at null terminator
}

static void
trim_line(char* line)
{
	while (*line != '\0') {
		if (*line == '#' || *line == '\r') {
			*line = '\0';
			return;
		}

		line++;
	}
}

static void
process_feature(const char* key, const char* val, const char* path,
		int32_t line_no)
{
	cf_detail(AS_CFG, "feature %s %s", key, val);
	bool ok;

	if (strcmp(key, "feature-key-version") == 0) {
		ok = parse_integer(val, &g_features.feature_key_version) &&
				g_features.feature_key_version <= FEATURE_KEY_VERSION;
	}
	else if (strcmp(key, "serial-number") == 0) {
		ok = parse_integer(val, &g_features.serial_number);
	}
	else if (strcmp(key, "valid-until-date") == 0) {
		ok = parse_date(val, &g_features.valid_until_date);
	}
	else if (strcmp(key, "valid-until-version") == 0) {
		ok = parse_version(val, &g_features.valid_until_version);
	}
	else if (strcmp(key, "asdb-change-notification") == 0) {
		ok = parse_boolean(val, &g_features.change_notification);
	}
	else if (strcmp(key, "asdb-cluster-nodes-limit") == 0) {
		ok = parse_integer(val, &g_features.cluster_nodes_limit);
	}
	else if (strcmp(key, "asdb-compression") == 0) {
		ok = parse_boolean(val, &g_features.compression);
	}
	else if (strcmp(key, "asdb-encryption-at-rest") == 0) {
		ok = parse_boolean(val, &g_features.encryption_at_rest);
	}
	else if (strcmp(key, "asdb-ldap") == 0) {
		ok = parse_boolean(val, &g_features.ldap);
	}
	else if (strcmp(key, "asdb-pmem") == 0) {
		ok = parse_boolean(val, &g_features.pmem);
	}
	else if (strcmp(key, "asdb-strong-consistency") == 0) {
		ok = parse_boolean(val, &g_features.strong_consistency);
	}
	else {
		cf_detail(AS_CFG, "skipping non-server feature %s in %s, line %d",
				key, path, line_no);
		return;
	}

	if (! ok) {
		cf_crash_nostack(AS_CFG,
				"invalid value %s for feature %s in %s, line %d",
				val, key, path, line_no);
	}
}

static void
check_mandatory(const char* path)
{
	if (g_features.feature_key_version == 0) {
		cf_crash_nostack(AS_CFG, "missing feature key version in %s", path);
	}

	if (g_features.serial_number == 0) {
		cf_crash_nostack(AS_CFG, "missing serial number in %s", path);
	}
}

static bool
expired(const char* path)
{
	if (g_features.valid_until_date > 0) {
		time_t now = time(NULL);

		// Add 86400 to keep working on the day on which we expire.

		if (now >= g_features.valid_until_date + 86400) {
			cf_warning(AS_CFG, "feature key %s expired (date)", path);
			return true;
		}
	}

	if (g_features.valid_until_version > 0) {
		uint64_t ver = 0;

		if (! parse_version(aerospike_build_id, &ver)) {
			cf_crash_nostack(AS_CFG, "error while parsing build ID");
		}

		// Examples:
		//
		//   valid-until-version | works up to (and including) version
		//   --------------------+------------------------------------
		//   1                   | 1.x.y.z  for any x, y, z
		//   1.2                 | 1.2.x.y  for any x, y
		//   1.2.3               | 1.2.3.x  for any x
		//   1.2.3.4             | 1.2.3.4

		if (ver > g_features.valid_until_version) {
			cf_warning(AS_CFG, "feature key %s expired (version)", path);
			return true;
		}
	}

	return false;
}

static void
accumulate_features(void)
{
	if (g_features.change_notification) {
		g_asdb_features.change_notification = true;
	}

	if (g_features.cluster_nodes_limit > g_asdb_features.cluster_nodes_limit) {
		g_asdb_features.cluster_nodes_limit = g_features.cluster_nodes_limit;
	}

	if (g_features.compression) {
		g_asdb_features.compression = true;
	}

	if (g_features.encryption_at_rest) {
		g_asdb_features.encryption_at_rest = true;
	}

	if (g_features.ldap) {
		g_asdb_features.ldap = true;
	}

	if (g_features.pmem) {
		g_asdb_features.pmem = true;
	}

	if (g_features.strong_consistency) {
		g_asdb_features.strong_consistency = true;
	}
}

static void
accumulate_info(char* info)
{
	if (g_features_info == NULL_STR) {
		g_features_info = info;
		return;
	}

	size_t orig_len = strlen(g_features_info);
	size_t len = strlen(info);

	g_features_info = cf_realloc(g_features_info, orig_len + 1 + len + 1);
	g_features_info[orig_len] = '\n';
	strcpy(g_features_info + orig_len + 1, info);

	cf_free(info);
}

static bool
parse_integer(const char* str, uint64_t* val)
{
	char* end;
	*val = strtoul(str, &end, 10);
	return *end == 0;
}

static bool
parse_boolean(const char* str, bool* val)
{
	return (*val = strcmp(str, "true") == 0) || strcmp(str, "false") == 0;
}

static bool
parse_date(const char* str, time_t* simple_time)
{
	struct tm local;

	memset(&local, 0, sizeof(local));
	local.tm_isdst = -1;

	char* res = strptime(str, "%Y-%m-%d", &local);

	if (res == NULL || *res != 0) {
		return false;
	}

	time_t tmp = mktime(&local);

	if (tmp == (time_t)-1) {
		return false;
	}

	*simple_time = tmp;
	return true;
}

static bool
parse_version(const char* str, uint64_t* version)
{
	uint64_t accu = 0;
	const char* walker = str;
	int32_t n_parts = 0;

	while (true) {
		char* end;
		uint64_t part = strtoul(walker, &end, 10);

		if (end == walker || part > 65535) {
			return false;
		}

		if (n_parts >= 4) {
			return false;
		}

		accu = (accu << 16) | part;
		n_parts++;

		if (end[0] == 0 || end[0] == '-') {
			break;
		}

		if (end[0] != '.') {
			return false;
		}

		walker = end + 1;
	}

	// Turn short versions like, e.g., "3.1" into "3.1.65535.65535",
	// so that the short version "3.1" means "good for all 3.1.x.y
	// versions".

	while (n_parts < 4) {
		accu = (accu << 16) | 65535;
		n_parts++;
	}

	*version = accu;
	return true;
}

static size_t
add_to_message(uint8_t* mess, size_t mess_len, const char* str)
{
	size_t str_len = strlen(str);

	memcpy(mess + mess_len, str, str_len);
	mess[mess_len + str_len] = '$';

	return mess_len + str_len + 1;
}

static size_t
add_to_info(char* info, size_t info_len, const char* key, const char* val)
{
	size_t key_len = strlen(key);
	size_t val_len = strlen(val);

	memcpy(info + info_len, key, key_len);
	info_len += key_len;

	info[info_len++] = '=';

	memcpy(info + info_len, val, val_len);
	info_len += val_len;

	info[info_len++] = ';';

	return info_len;
}

static size_t
add_to_signature(uint8_t* sig, size_t sig_sz, size_t limit, const uint8_t* data,
		size_t data_len, const char* path, int32_t line_no)
{
	if (data_len % 4 != 0) {
		cf_crash_nostack(AS_CFG, "malformed signature in %s, line %d", path,
				line_no);
	}

	size_t exp_sz = data_len / 4 * 3;

	if (sig_sz + exp_sz > limit) {
		cf_crash_nostack(AS_CFG, "signature overflow in %s, line %d", path,
				line_no);
	}

	int32_t dec_sz = EVP_DecodeBlock(sig + sig_sz, data, (int32_t)data_len);

	if (dec_sz < 0 || (size_t)dec_sz != exp_sz) {
		cf_crash_nostack(AS_CFG, "invalid signature in %s, line %d", path,
				line_no);
	}

	return sig_sz + exp_sz;
}

static void
verify_signature(const uint8_t* mess, size_t mess_len, const uint8_t* sig,
		size_t sig_sz)
{
	cf_detail(AS_CFG, "verifying signature");

	while (sig_sz > 0) {
		sig_sz--;

		if (sig[sig_sz] == '$') {
			break;
		}
	}

	if (sig_sz == 0) {
		cf_crash_nostack(AS_CFG, "invalid signature format");
	}

	cf_detail(AS_CFG, "effective size %zu", sig_sz);

	const uint8_t* pub_key = AS_PUB_KEY;
	EC_KEY* ec = d2i_EC_PUBKEY(NULL, &pub_key, sizeof(AS_PUB_KEY));

	if (ec == NULL) {
		cf_crash(AS_CFG, "d2i_EC_PUBKEY() failed");
	}

	EVP_PKEY* pkey = EVP_PKEY_new();

	if (pkey == NULL) {
		cf_crash(AS_CFG, "EVP_PKEY_new() failed");
	}

	if (EVP_PKEY_assign_EC_KEY(pkey, ec) < 1) {
		cf_crash(AS_CFG, "EVP_PKEY_assign_EC_KEY() failed");
	}

	EVP_MD_CTX* dctx = EVP_MD_CTX_create();

	if (dctx == NULL) {
		cf_crash(AS_CFG, "EVP_MD_CTX_create() failed");
	}

	if (EVP_DigestVerifyInit(dctx, NULL, EVP_sha256(), NULL, pkey) < 1) {
		cf_crash(AS_CFG, "EVP_DigestVerifyInit() failed");
	}

	if (EVP_DigestVerifyUpdate(dctx, mess, mess_len) < 1) {
		cf_crash(AS_CFG, "EVP_DigestVerifyUpdate() failed");
	}

	if (EVP_DigestVerifyFinal(dctx, (uint8_t*)sig, sig_sz) < 1) {
		cf_crash_nostack(AS_CFG, "invalid feature key signature");
	}

	EVP_MD_CTX_destroy(dctx);
	EVP_PKEY_free(pkey);
}
