/*
 * vault_ee.c
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

#include "vault.h"
#include "vault_ee.h"

#include <curl/curl.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "jansson.h"

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_b64.h"

#include "fetch.h"
#include "log.h"

#include "warnings.h"


//==========================================================
// Typedefs & constants.
//

static const char TOKEN_HEADER_NAME[] = "X-Vault-Token: ";

static const char TRAILING_WHITESPACE[] = " \t\n\r\f\v";

// Matches CURL_MAX_WRITE_SIZE but needs not to have a particular relationship
// to it.
#define NET_IO_CHUNK_SIZE (16 * 1024)

typedef struct curl_io_buf_s {
	size_t capacity;
	size_t size;
	uint8_t* buf; // to be passed to cf_free when done
} curl_io_buf;


//==========================================================
// Globals.
//

cf_vault_config g_vault_cfg = { 0 };

static char* g_token_header;


//==========================================================
// Forward declarations.
//

static char* read_json(const char* url);
static uint8_t* parse_json(const char* json_buf, size_t* size_r);
static size_t curl_write_cb(void* contents, size_t size, size_t nmemb, void* userp);


//==========================================================
// Public API.
//

bool
cf_vault_is_configured(void)
{
	bool config_complete = true;

	if (g_vault_cfg.url == NULL) {
		cf_warning(CF_VAULT, "must configure 'vault-url'");
		config_complete = false;
	}

	if (g_vault_cfg.ca == NULL) {
		cf_warning(CF_VAULT, "must configure 'vault-ca'");
		config_complete = false;
	}

	if (g_vault_cfg.token_file == NULL) {
		cf_warning(CF_VAULT, "must configure 'vault-token-file'");
		config_complete = false;
	}

	if (g_vault_cfg.path == NULL) {
		cf_warning(CF_VAULT, "must configure 'vault-path'");
		config_complete = false;
	}

	return config_complete;
}

uint8_t*
cf_vault_fetch_bytes(const char* path, size_t* size_r)
{
	// Assumes path has "vault:" prefix.
	const char* suffix = path + sizeof(CF_VAULT_PATH_PREFIX) - 1;

	size_t url_size = strlen(g_vault_cfg.url) + 1 + // '/'
			strlen(g_vault_cfg.path) + 1 + // '/'
			strlen(suffix) + 1; // '\0'
	char* url = (char*)cf_malloc(url_size);

	sprintf(url, "%s/%s/%s", g_vault_cfg.url, g_vault_cfg.path, suffix);

	char* json_buf = read_json(url);

	uint8_t* buf = parse_json(json_buf, size_r);

	if (json_buf != NULL) {
		cf_free(json_buf);
	}

	if (buf == NULL) {
		cf_warning(CF_VAULT, "unable to fetch Vault secret at %s", url);
	}

	cf_free(url);

	return buf;
}


//==========================================================
// Public API - enterprise only.
//

void
cf_vault_cfg_post_process(void)
{
	const char* path = g_vault_cfg.token_file;

	if (path == NULL) {
		return;
	}

	if (cf_vault_is_vault_path(path)) {
		cf_crash_nostack(CF_VAULT,
				"vault-token-file cannot have 'vault:' prefix");
	}

	char* token = cf_fetch_string(path);

	if (token == NULL) {
		cf_crash_nostack(CF_VAULT, "can't read Vault token");
	}

	size_t size = sizeof(TOKEN_HEADER_NAME) + strlen(token);

	g_token_header = cf_malloc(size);
	sprintf(g_token_header, "%s%s", TOKEN_HEADER_NAME, token);
	cf_free(token);

	curl_global_init(CURL_GLOBAL_ALL);
}


//==========================================================
// Local helpers.
//

static char*
read_json(const char* url)
{
	CURL* curl = curl_easy_init();

	if (curl == NULL) {
		cf_warning(CF_VAULT, "failed to initialize a curl session to Vault");
		return NULL;
	}

	char err_buf[CURL_ERROR_SIZE] = "";
	CURLcode err = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err_buf);

	cf_assert(err == CURLE_OK, CF_VAULT, "impossible libcurl error");

	curl_io_buf json_buf = { .capacity = 0, .size = 0, .buf = NULL };

	struct curl_slist* http_headers = curl_slist_append(NULL, g_token_header);

	if (http_headers == NULL) {
		cf_warning(CF_VAULT, "failed to append to a curl slist");
		curl_easy_cleanup(curl);
		return NULL;
	}

	// Enable unconditionally once CentOS 6 support is removed.
#ifdef CURLOPT_HEADEROPT
	err = curl_easy_setopt(curl, CURLOPT_HEADEROPT, CURLHEADER_SEPARATE);
	cf_assert(err == CURLE_OK, CF_VAULT, "impossible libcurl error");
#endif

	err = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_headers);
	cf_assert(err == CURLE_OK, CF_VAULT, "impossible libcurl error");

	err = curl_easy_setopt(curl, CURLOPT_URL, url);

	if (err != CURLE_OK) {
		cf_warning(CF_VAULT, "curl_easy_setopt failed: %s (%s)",
				curl_easy_strerror(err), err_buf);
		curl_slist_free_all(http_headers);
		curl_easy_cleanup(curl);
		return NULL;
	}

	err = curl_easy_setopt(curl, CURLOPT_CAINFO, g_vault_cfg.ca);

	if (err != CURLE_OK) {
		cf_warning(CF_VAULT, "curl_easy_setopt failed: %s (%s)",
				curl_easy_strerror(err), err_buf);
		curl_slist_free_all(http_headers);
		curl_easy_cleanup(curl);
		return NULL;
	}

	err = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
	cf_assert(err == CURLE_OK, CF_VAULT, "impossible libcurl error");

	json_buf.buf = cf_malloc(NET_IO_CHUNK_SIZE);
	json_buf.capacity = NET_IO_CHUNK_SIZE;

	err = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&json_buf);
	cf_assert(err == CURLE_OK, CF_VAULT, "impossible libcurl error");

	err = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
	cf_assert(err == CURLE_OK, CF_VAULT, "impossible libcurl error");

	err = curl_easy_perform(curl);

	if (err != CURLE_OK) {
		cf_warning(CF_VAULT, "failed to read Vault secret from %s: %s (%s)",
				url, curl_easy_strerror(err), err_buf);
		cf_free(json_buf.buf);
		curl_slist_free_all(http_headers);
		curl_easy_cleanup(curl);
		return NULL;
	}

	long http_status;

	err = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

	if (err != CURLE_OK) {
		cf_warning(CF_VAULT, "curl_easy_getinfo failed: %s (%s)",
				curl_easy_strerror(err), err_buf);
		cf_free(json_buf.buf);
		curl_slist_free_all(http_headers);
		curl_easy_cleanup(curl);
		return NULL;
	}

	if (http_status != 200 && http_status != 204) {
		cf_warning(CF_VAULT,
				"failed to read Vault secret from %s: HTTP status %ld", url,
				http_status);
		cf_free(json_buf.buf);
		curl_slist_free_all(http_headers);
		curl_easy_cleanup(curl);
		return NULL;
	}

	curl_slist_free_all(http_headers);
	curl_easy_cleanup(curl);

	return (char *)json_buf.buf;
}

static uint8_t*
parse_json(const char* json_buf, size_t* size_r)
{
	if (json_buf == NULL) {
		return NULL;
	}

	json_error_t err;
	json_t* doc = json_loads(json_buf, 0, &err);

	if (doc == NULL) {
		cf_warning(CF_VAULT,
				"failed to parse Vault server JSON payload at line %d (%s)",
				err.line, err.text);
		return NULL;
	}

	json_t* error_array = json_object_get(doc, "errors");

	if (error_array != NULL) {
		cf_warning(CF_VAULT, "Vault server returned JSON error: %s", json_buf);
		json_decref(doc);
		return NULL;
	}

	const char* payload_str;
	size_t payload_len;

	// Attempt to parse as secrets engine V2 output, at data.data.key
	int unpack_err = json_unpack(doc, "{s:{s:{s:s%}}}", "data", "data", "key",
			&payload_str, &payload_len);

	if (unpack_err != 0) {
		// Attempt to parse as secrets engine V1 output, at data.key
		unpack_err = json_unpack(
				doc, "{s:{s:s%}}", "data", "key", &payload_str, &payload_len);
	}

	if (unpack_err != 0) {
		cf_warning(CF_VAULT, "failed to process Vault server JSON payload");
		json_decref(doc);
		return NULL;
	}

	if (payload_len == 0) {
		cf_warning(CF_VAULT, "empty Vault secret");
		json_decref(doc);
		return NULL;
	}

	while (strchr(TRAILING_WHITESPACE, payload_str[payload_len - 1]) != NULL) {
		payload_len--;

		if (payload_len == 0) {
			cf_warning(CF_VAULT, "whitespace-only Vault secret");
			json_decref(doc);
			return NULL;
		}
	}

	// Extra byte - if this is a string, the caller will add '\0'.
	uint32_t size = cf_b64_decoded_buf_size((uint32_t)payload_len) + 1;
	uint8_t* buf = cf_malloc(size);

	if (! cf_b64_validate_and_decode(payload_str, (uint32_t)payload_len, buf,
			&size)) {
		cf_warning(CF_VAULT, "failed to base64-decode Vault secret");
		cf_free(buf);
		json_decref(doc);
		return NULL;
	}

	json_decref(doc);

	*size_r = size;
	return buf;
}

static size_t
curl_write_cb(void* contents, size_t size, size_t nmemb, void* userp)
{
	size_t chunk_size = size * nmemb; // size always 1, but play safe
	curl_io_buf* buf = (curl_io_buf*)userp;

	if (buf->capacity < buf->size + chunk_size + 1) {
		while (buf->capacity < buf->size + chunk_size + 1) {
			buf->capacity *= 2;
		}

		buf->buf = cf_realloc(buf->buf, buf->capacity);
	}

	memcpy(buf->buf + buf->size, contents, chunk_size);
	buf->size += chunk_size;
	buf->buf[buf->size] = '\0';

	return chunk_size;
}
