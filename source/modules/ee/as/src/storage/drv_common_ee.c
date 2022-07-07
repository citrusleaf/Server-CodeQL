/*
 * drv_common_ee.c
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

#include "storage/drv_common.h"
#include "storage/drv_common_ee.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_digest.h"

#include "bits.h"
#include "cf_thread.h"
#include "fetch.h"
#include "fips_ee.h"
#include "log.h"

#include "base/datamodel.h"
#include "storage/drv_common.h"

#pragma GCC poison AS_DRV_PMEM
#pragma GCC poison AS_DRV_SSD


//==========================================================
// Forward declarations.
//

static void thread_exit_cb(void* udata);
static void init_encryption_key(as_namespace* ns, bool old);
static void rectify_user_key(const uint8_t* buf, size_t buf_sz, size_t key_sz, uint8_t* key);


//==========================================================
// Public API.
//

// Check device headers to see if we can warm or cool restart.
bool
drv_peek_devices(as_namespace* ns)
{
	uint32_t num_devices = as_namespace_device_count(ns);

	// Note - can't configure commit-to-device and disable-odsync.
	uint32_t device_direct_flags =
			O_DIRECT | (ns->storage_disable_odsync ? 0 : O_DSYNC);
	uint32_t file_direct_flags =
			(ns->storage_commit_to_device || ns->storage_direct_files ?
					device_direct_flags : 0);

	uint32_t open_flag = O_RDWR | (ns->n_storage_devices != 0 ?
			device_direct_flags : file_direct_flags);

	// We haven't determined device's io_min_size yet - for this peek, just use
	// largest io_min_size (4K). Also assumes prefix is first in header, and
	// magic is within first 4K of prefix.

	drv_prefix* prefix = cf_valloc(HI_IO_MIN_SIZE);
	bool found_used_device = false;

	// If all devices are fresh (no used devices), switch to cold restart.
	for (uint32_t i = 0; i < num_devices; i++) {
		// Note that O_CREAT is not set.
		int fd = open(ns->storage_devices[i], open_flag);

		if (fd == -1) {
			if (ns->n_storage_files != 0) {
				cf_info(AS_STORAGE, "{%s} peek couldn't open file %s: %s",
						ns->name, ns->storage_devices[i], cf_strerror(errno));
				continue;
			}
			else {
				cf_crash(AS_STORAGE, "{%s} peek couldn't open %s: %s",
						ns->name, ns->storage_devices[i], cf_strerror(errno));
			}
		}

		if (! pread_all(fd, (void*)prefix, HI_IO_MIN_SIZE, 0)) {
			cf_crash(AS_STORAGE, "%s: read failed: errno %d (%s)",
					ns->storage_devices[i], errno, cf_strerror(errno));
		}

		if (prefix->magic == DRV_HEADER_MAGIC) {
			// This is a used drive with sane header.
			found_used_device = true;
		}
		else {
			// This is a fresh drive.
			cf_info(AS_STORAGE, "{%s} peek found fresh device %s", ns->name,
					ns->storage_devices[i]);
		}

		close(fd);
	}

	cf_free(prefix);

	return found_used_device;
}

void
drv_init_sets_info(as_namespace* ns, bool sets_not_evicting[],
		uint64_t set_truncate_luts[], bool sets_indexed[])
{
	uint32_t num_sets = cf_vmapx_count(ns->p_sets_vmap);

	for (uint32_t j = 0; j < num_sets; j++) {
		as_set* p_set;
		uint32_t set_id = j + 1;

		if (cf_vmapx_get_by_index(ns->p_sets_vmap, j, (void**)&p_set) !=
				CF_VMAPX_OK) {
			cf_crash(AS_STORAGE, "failed to get set id %u from vmap", set_id);
		}

		if (p_set->eviction_disabled) {
			sets_not_evicting[set_id] = true;
		}

		set_truncate_luts[set_id] = p_set->truncate_lut;

		if (p_set->index_enabled) {
			sets_indexed[set_id] = true;
		}
	}
}

void
drv_xts_encrypt(as_encryption_method meth, const uint8_t* key, uint64_t tweak,
		const uint8_t* in, size_t sz_in, uint8_t* out)
{
	static __thread EVP_CIPHER_CTX* ctx = NULL;

	if (ctx == NULL) {
		ctx = EVP_CIPHER_CTX_new();
		cf_thread_add_exit(thread_exit_cb, &ctx);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_CIPHER_CTX_init(ctx);
#endif

	const EVP_CIPHER* ciph = meth == AS_ENCRYPTION_AES_128 ?
			EVP_aes_128_xts() : EVP_aes_256_xts();
	uint8_t iv[16] = { 0 };

	memcpy(iv, &tweak, sizeof(tweak));

	if (EVP_EncryptInit_ex(ctx, ciph, NULL, key, iv) < 1) {
		cf_crash(AS_STORAGE, "EVP_EncryptInit_ex() failed");
	}

	int32_t sz_out_1 = 0;

	if (EVP_EncryptUpdate(ctx, out, &sz_out_1, in, (int32_t)sz_in) < 1) {
		cf_crash(AS_STORAGE, "EVP_EncryptUpdate() failed");
	}

	int32_t sz_out_2 = 0;

	if (EVP_EncryptFinal_ex(ctx, out + sz_out_1, &sz_out_2) < 1) {
		cf_crash(AS_STORAGE, "EVP_EncryptFinal_ex() failed");
	}

	if (sz_out_1 + sz_out_2 != sz_in) {
		cf_crash(AS_STORAGE, "unexpected encrypted size: %d + %d vs. %zu",
				sz_out_1, sz_out_2, sz_in);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_CIPHER_CTX_cleanup(ctx);
#else
	EVP_CIPHER_CTX_reset(ctx);
#endif
}

void
drv_xts_decrypt(as_encryption_method meth, const uint8_t* key, uint64_t tweak,
		const uint8_t* in, size_t sz_in, uint8_t* out)
{
	static __thread EVP_CIPHER_CTX *ctx = NULL;

	if (ctx == NULL) {
		ctx = EVP_CIPHER_CTX_new();
		cf_thread_add_exit(thread_exit_cb, &ctx);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_CIPHER_CTX_init(ctx);
#endif

	const EVP_CIPHER *ciph = meth == AS_ENCRYPTION_AES_128 ?
			EVP_aes_128_xts() : EVP_aes_256_xts();
	uint8_t iv[16] = { 0 };

	memcpy(iv, &tweak, sizeof(tweak));

	if (EVP_DecryptInit_ex(ctx, ciph, NULL, key, iv) < 1) {
		cf_crash(AS_STORAGE, "EVP_DecryptInit_ex() failed");
	}

	int32_t sz_out_1 = 0;

	if (EVP_DecryptUpdate(ctx, out, &sz_out_1, in, (int32_t)sz_in) < 1) {
		cf_crash(AS_STORAGE, "EVP_DecryptUpdate() failed");
	}

	int32_t sz_out_2 = 0;

	if (EVP_DecryptFinal_ex(ctx, out + sz_out_1, &sz_out_2) < 1) {
		cf_crash(AS_STORAGE, "EVP_DecryptFinal_ex() failed");
	}

	if (sz_out_1 + sz_out_2 != sz_in) {
		cf_crash(AS_STORAGE, "unexpected decrypted size: %d + %d vs. %zu",
				sz_out_1, sz_out_2, sz_in);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_CIPHER_CTX_cleanup(ctx);
#else
	EVP_CIPHER_CTX_reset(ctx);
#endif
}

void
drv_init_encryption_key(as_namespace* ns)
{
	init_encryption_key(ns, false);

	// If rotating keys ...
	if (ns->storage_encryption_old_key_file != NULL) {
		init_encryption_key(ns, true);
	}
}


//==========================================================
// Local helpers.
//

static void
thread_exit_cb(void* udata)
{
	EVP_CIPHER_CTX** p_ctx = (EVP_CIPHER_CTX**)udata;

	EVP_CIPHER_CTX_free(*p_ctx);
	*p_ctx = NULL;
}

static void
init_encryption_key(as_namespace* ns, bool old)
{
	char* key_file = ns->storage_encryption_key_file;
	uint8_t* key = ns->storage_encryption_key;

	if (old) {
		key_file = ns->storage_encryption_old_key_file;
		key = ns->storage_encryption_old_key;
	}

	size_t buf_sz;
	uint8_t* buf = cf_fetch_bytes(key_file, &buf_sz);

	if (buf == NULL) {
		cf_crash_nostack(AS_STORAGE, "{%s} can't get encryption key from %s",
				ns->name, key_file);
	}

	size_t key_sz = ns->storage_encryption == AS_ENCRYPTION_AES_128 ? 32 : 64;

	rectify_user_key(buf, buf_sz, key_sz, key);

	dead_memset(buf, 0, buf_sz);
	cf_free(buf);

	if (g_fips) {
		return;
	}

	// Log the encryption method, file, and a hash of the key to help verify
	// whether or not they changed since last startup.

	cf_digest d;

	cf_digest_compute(key, key_sz, &d);

	cf_info(AS_STORAGE, "{%s} encryption aes-%s %skey-file %s key-hash %pD",
			ns->name,
			ns->storage_encryption == AS_ENCRYPTION_AES_128 ? "128" : "256",
			old ? "old-" : "", key_file, &d);
}

static void
rectify_user_key(const uint8_t* buf, size_t buf_sz, size_t key_sz, uint8_t* key)
{
	// AES in XTS mode needs a key twice the usual size. We use SHA-256 for
	// AES-128 and SHA-512 for AES-256.
	const EVP_MD* md = key_sz == 32 ? EVP_sha256() : EVP_sha512();

	uint8_t salt[16] = { 0 };

	memcpy(salt, buf, buf_sz < sizeof(salt) ? buf_sz : sizeof(salt));

	PKCS5_PBKDF2_HMAC((const char*)buf, (int)buf_sz, salt, (int)sizeof(salt),
			4096, md, (int)key_sz, key);
}
