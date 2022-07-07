/*
 * tls_ee.c
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#include "tls_ee.h"

#include <ctype.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_clock.h"

#include "cf_mutex.h"
#include "cf_thread.h"
#include "fetch.h"
#include "log.h"
#include "socket.h"
#include "vault.h"

#if defined SSL_OP_NO_TLSv1_3
#define TLSv1_3_SUPPORTED false // disable for now - 1.3 doesn't work properly
#else
#define SSL_OP_NO_TLSv1_3 0x20000000U
#define TLSv1_3_SUPPORTED false
#endif

#define CHANGE_CHECK_PERIOD 60

struct cf_tls_info_s {
	pthread_rwlock_t rwlock;
	const char *which;
	cf_tls_spec *spec;

	// TLS config, peer validation, etc.
	SSL_CTX *ssl_ctx_ser;
	SSL_CTX *ssl_ctx_cli;
	cf_tls_peer_names peer_names;
	struct cert_blacklist_s *cert_blacklist;

	// File change detection
	tls_change_ctx *ch_cert_blacklist;

	tls_change_ctx *ch_cert_file_ser;
	tls_change_ctx *ch_key_file_ser;

	tls_change_ctx *ch_cert_file_cli;
	tls_change_ctx *ch_key_file_cli;
};

typedef struct log_string_s {
	char s[1024];
} log_string;

static bool s_tls_inited = false;
static cf_mutex s_tls_init_mutex = CF_MUTEX_INIT;
static int s_ex_info_index = -1;
static int s_ex_peer_names_index = -1;

#if OPENSSL_VERSION_NUMBER < 0x10100000
static cf_mutex *lock_cs;
#endif

// Forward declaration
bool
as_tls_match_name(X509 *x509, const char *name, bool allow_wildcard);

static char *
tls_error_string()
{
	// NOTE - the return value of this function is only valid until
	// the same thread calls the function again.
	static __thread char errbuf[1024];

	BIO *bio = BIO_new(BIO_s_mem());

	ERR_print_errors(bio);

	char *buf = NULL;
	size_t len = BIO_get_mem_data(bio, &buf);

	if (len > sizeof(errbuf) - 1) {
		len = sizeof(errbuf) - 1;
	}

	memcpy(errbuf, buf, len);
	errbuf[len] = '\0';

	BIO_free(bio);

	return errbuf;
}

static log_string
get_session_info(const SSL_CIPHER *cipher)
{
	log_string out;
	SSL_CIPHER_description(cipher, out.s, sizeof(out.s));
	size_t len = strlen(out.s);

	if (len > 0) {
		out.s[len - 1] = '\0'; // remove the trailing \n
	}

	return out;
}

static void
log_session_info(cf_socket *sock)
{
	const SSL_CIPHER *cipher = SSL_get_current_cipher(sock->ssl);

	if (cipher != NULL) {
		cf_detail(CF_TLS, "TLS cipher: %s", get_session_info(cipher).s);
	}
	else {
		cf_warning(CF_TLS, "TLS no current cipher");
	}
}

static void
log_verify_details(cf_socket *sock)
{
	long vr = SSL_get_verify_result(sock->ssl);
	if (vr != X509_V_OK) {
		cf_warning(CF_TLS, "TLS verify result: %s",
				   X509_verify_cert_error_string(vr));
	}
}

static log_string
get_cert_info(X509 *cert)
{
	char i_str[256];
	X509_NAME* i_nam = X509_get_issuer_name(cert);
	X509_NAME_oneline(i_nam, i_str, sizeof(i_str));

	ASN1_INTEGER* sn = X509_get_serialNumber(cert);
	BIGNUM* snbn = ASN1_INTEGER_to_BN(sn, NULL);
	char* snhex = BN_bn2hex(snbn);

	char s_str[256];
	X509_NAME* s_nam = X509_get_subject_name(cert);
	X509_NAME_oneline(s_nam, s_str, sizeof(s_str));

	log_string out;
	snprintf(out.s, sizeof(out.s), "%s [%s] -> %s", i_str, snhex, s_str);

	BN_free(snbn);
	OPENSSL_free(snhex);

	return out;
}

static uint64_t
compute_deadline(uint64_t timeout)
{
	uint64_t now = cf_clock_getabsolute();
	uint64_t deadline = now + timeout;
	// Did we overflow the uint64_t?
	if (deadline < now) {
		deadline = ULONG_MAX;
	}
	return deadline;
}

static int
tls_socket_wait(cf_socket *sock, short events, uint64_t deadline)
{
	struct pollfd fds[1];
	fds[0].fd = sock->fd;
	fds[0].events = events;
	fds[0].revents = 0;

	while (true) {
		uint64_t now = cf_clock_getabsolute();
		if (now > deadline) {
			return 0;
		}
	 	uint64_t delta = deadline - now;
		if (delta > INT_MAX) {
			delta = INT_MAX;
		}
		int timeout_msec = (int) delta;

		int rv = poll(fds, 1, timeout_msec);
		if (rv == -1) {
			cf_warning(CF_TLS, "poll failed: %s", cf_strerror(errno));
			return -1;
		}
		else if (rv == 0) {	// Timeout
			return 0;
		}
		else {
			if (fds[0].revents & events) {
				return 1;
			}
			// Otherwise loop back around ...
		}
	}
}

#if OPENSSL_VERSION_NUMBER < 0x10100000
static void
threads_locking_callback(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		cf_mutex_lock(&(lock_cs[type]));
	} else {
		cf_mutex_unlock(&(lock_cs[type]));
	}
}

static void
threads_thread_id(CRYPTO_THREADID *tid)
{
	CRYPTO_THREADID_set_numeric(tid, (unsigned long)cf_thread_sys_tid());
}

static void
threading_setup(void)
{
	int i;

	lock_cs = cf_malloc(CRYPTO_num_locks() * sizeof(cf_mutex));
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		cf_mutex_init(&(lock_cs[i]));
	}

	CRYPTO_THREADID_set_callback(threads_thread_id);
	CRYPTO_set_locking_callback(threads_locking_callback);
}

static void
threading_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		cf_mutex_destroy(&(lock_cs[i]));
	}
	cf_free(lock_cs);
}
#endif

static int
handle_tls_error(cf_socket *sock, int rv, char const *caller, uint64_t deadline)
{
	// NOTE - This routine does one of the following things:
	// * Sets errno to EPERM and returns -1 for SSL specific errors.
	// * Sets errno to ETIMEDOUT and returns -1 if we passed the deadline.
	// * Sets errno to ENOTCONN and returns -1 if the TLS connection is closed.
	// * Returns -1 if errno has been set correctly by something we called.
	// * Returns 0 if the caller should loop and retry the original call.

	int orig_errno = errno;

	// Is this a timeout?
	if (rv > 0 && cf_clock_getabsolute() >= deadline) {
		errno = ETIMEDOUT;
		return -1;
	}

	unsigned long errcode;
	char errbuf[1024];
	int sslerr = SSL_get_error(sock->ssl, rv);

	const char *rem_str = "(unknown)";

	if (sslerr == SSL_ERROR_SSL || sslerr == SSL_ERROR_SYSCALL) {
		cf_sock_addr rem;

		if (cf_socket_remote_name(sock, &rem) >= 0) {
			rem_str = cf_sock_addr_print(&rem);
		}
	}

	// cf_clock_getabsolute() and cf_socket_remote_name() may have overwritten
	// errno - restore original.
	errno = orig_errno;

	switch (sslerr) {
	case SSL_ERROR_NONE:
		// The TLS/SSL I/O operation completed. This result code is
		// returned if and only if ret > 0.
		return 0;
	case SSL_ERROR_WANT_READ:
		rv = tls_socket_wait(sock, POLLIN, deadline);
		if (rv < 0) {
			// errno set in tls_socket_wait.
			return -1;
		}
		else if (rv == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		// Loop back around and retry.
		return 0;
	case SSL_ERROR_WANT_WRITE:
		rv = tls_socket_wait(sock, POLLOUT, deadline);
		if (rv < 0) {
			// errno set in tls_socket_wait.
			return -1;
		}
		else if (rv == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		// Loop back around and retry.
		return 0;
	case SSL_ERROR_ZERO_RETURN:
		// The connection has been closed.
		errno = ENOTCONN;
		return -1;
	case SSL_ERROR_SSL:
		log_verify_details(sock);
		cf_warning(CF_TLS, "%s with %s failed: %s", caller, rem_str, tls_error_string());
		errno = EPERM;
		return -1;
	case SSL_ERROR_SYSCALL:
		errcode = ERR_get_error();
		if (errcode != 0) {
			ERR_error_string_n(errcode, errbuf, sizeof(errbuf));
			cf_warning(CF_TLS, "%s I/O error with %s: %s", caller, rem_str, errbuf);
			errno = EPERM;
		}
		else {
			// Documented erroneous behavior that EOF causes error with errno 0.
			if (rv == 0 || errno == 0) {
				cf_warning(CF_TLS, "%s I/O unexpected EOF with %s", caller, rem_str);
				errno = EPERM;
			}
			else {
				cf_warning(CF_TLS, "%s I/O error with %s: %s",
						   caller, rem_str, cf_strerror(errno));
				// errno is set correctly.
			}
		}
		return -1;
	default:
		cf_warning(CF_TLS, "%s: unexpected ssl error: %d", caller, sslerr);
		errno = EPERM;
		return -1;
	}
}

typedef struct cert_spec_s {
	char const* hex_serial;
	char const* issuer_name;
} cert_spec;

typedef struct cert_blacklist_s {
	size_t ncerts;
	cert_spec certs[];
} cert_blacklist;

static int
cert_spec_compare(const void* ptr1, const void* ptr2)
{
	const cert_spec* csp1 = (const cert_spec*) ptr1;
	const cert_spec* csp2 = (const cert_spec*) ptr2;

	cf_detail(CF_TLS, "Comparing serial number %s %s", csp1->hex_serial, csp2->hex_serial);
	int rv = strcasecmp(csp1->hex_serial, csp2->hex_serial);
	if (rv != 0) {
		return rv;
	}

	if (csp1->issuer_name == NULL && csp2->issuer_name == NULL) {
		return 0;
	}

	if (csp1->issuer_name == NULL) {
		return -1;
	}

	if (csp2->issuer_name == NULL) {
		return 1;
	}

	cf_detail(CF_TLS, "Comparing issuer %s %s", csp1->issuer_name, csp2->issuer_name);
	return strcasecmp(csp1->issuer_name, csp2->issuer_name);
}

static cert_blacklist*
cert_blacklist_read(const char *path, const char *which)
{
	FILE* fp = fopen(path, "r");
	if (fp == NULL) {
		cf_warning(CF_TLS, "Failed to open cert blacklist '%s': %s",
				   path, strerror(errno));
		return NULL;
	}

	size_t capacity = 32;
	size_t sz = sizeof(cert_blacklist) + (capacity * sizeof(cert_spec));
	cert_blacklist* cbp = cf_malloc(sz);
	cbp->ncerts = 0;

	char buffer[1024];
	while (true) {
		char* line = fgets(buffer, sizeof(buffer), fp);
		if (! line) {
			break;
		}

		// Lines begining with a '#' are comments.
		if (line[0] == '#') {
			continue;
		}

		char* saveptr = NULL;
		char* hex_serial = strtok_r(line, " \t\r\n", &saveptr);
		if (! hex_serial) {
			continue;
		}

		// Skip all additional whitespace.
		while (isspace(*saveptr)) {
			++saveptr;
		}

		// Everything to the end of the line is issuer name.  Note we
		// do not consider whitespace a separator anymore.
		char* issuer_name = strtok_r(NULL, "\r\n", &saveptr);

		// Do we need more room?
		if (cbp->ncerts == capacity) {
			capacity *= 2;
			size_t sz = sizeof(cert_blacklist) + (capacity * sizeof(cert_spec));
			cbp = cf_realloc(cbp, sz);
		}

		cbp->certs[cbp->ncerts].hex_serial = cf_strdup(hex_serial);
		cbp->certs[cbp->ncerts].issuer_name =
			issuer_name ? cf_strdup(issuer_name) : NULL;

		cf_detail(CF_TLS, "blacklisting %s %s", hex_serial, issuer_name ? (char *) cf_strdup(issuer_name) : "");

		cbp->ncerts++;
	}

	qsort(cbp->certs, cbp->ncerts, sizeof(cert_spec), cert_spec_compare);

	fclose(fp);

	cf_info(CF_TLS, "loaded %zu TLS blacklist entr%s for %s",
			cbp->ncerts, cbp->ncerts == 1 ? "y" : "ies", which);

	return cbp;
}

static bool
cert_blacklist_check(cert_blacklist* cbp,
					 const char* hex_serial,
					 const char* issuer_name)
{
	cert_spec key;

	// First check for just the serial number.
	key.hex_serial = hex_serial;
	key.issuer_name = NULL;
	if (bsearch(&key, cbp->certs,
				cbp->ncerts, sizeof(cert_spec), cert_spec_compare)) {
		return true;
	}

	// Then check for an exact match w/ issuer name as well.
	key.hex_serial = hex_serial;
	key.issuer_name = issuer_name;
	if (bsearch(&key, cbp->certs,
				cbp->ncerts, sizeof(cert_spec), cert_spec_compare)) {
		return true;
	}

	return false;
}

static void
cert_blacklist_destroy(cert_blacklist* cbp)
{
	if (! cbp) {
		return;
	}

	for (size_t ii = 0; ii < cbp->ncerts; ++ii) {
		cert_spec* csp = &cbp->certs[ii];
		cf_free((void*) csp->hex_serial);
		if (csp->issuer_name) {
			cf_free((void*) csp->issuer_name);
		}
	}

	cf_free(cbp);
}

void
tls_info_free(cf_tls_info* info)
{
	if (info->ssl_ctx_ser != NULL) {
		SSL_CTX_free(info->ssl_ctx_ser);
	}

	if (info->ssl_ctx_cli != NULL) {
		SSL_CTX_free(info->ssl_ctx_cli);
	}

	if (info->cert_blacklist != NULL) {
		cert_blacklist_destroy(info->cert_blacklist);
	}

	if (info->ch_cert_blacklist != NULL) {
		cf_free(info->ch_cert_blacklist->path);
		cf_free(info->ch_cert_blacklist);
	}

	if (info->ch_cert_file_ser != NULL) {
		cf_free(info->ch_cert_file_ser->path);
		cf_free(info->ch_cert_file_ser);
	}

	if (info->ch_key_file_ser != NULL) {
		cf_free(info->ch_key_file_ser->path);
		cf_free(info->ch_key_file_ser);
	}

	if (info->ch_cert_file_cli != NULL) {
		cf_free(info->ch_cert_file_cli->path);
		cf_free(info->ch_cert_file_cli);
	}

	if (info->ch_key_file_cli != NULL) {
		cf_free(info->ch_key_file_cli->path);
		cf_free(info->ch_key_file_cli);
	}

	cf_free(info);
}

tls_change_ctx *
tls_change_init(const char *path)
{
	if (cf_vault_is_vault_path(path) || cf_fetch_is_env_path(path)) {
		tls_change_ctx *cc = cf_malloc(sizeof(tls_change_ctx));

		cc->path = cf_strdup(path);
		cc->next_check = 0; // flag Vault/env path to not refresh after startup
		// Other members will never be looked at.

		return cc;
	}

	cf_detail(CF_TLS, "initializing change check for file %s", path);
	struct stat buf;

	if (stat(path, &buf) < 0) {
		cf_warning(CF_TLS, "error while change-checking file %s: %d (%s)",
				path, errno, cf_strerror(errno));
		return NULL;
	}

	tls_change_ctx *cc = cf_malloc(sizeof(tls_change_ctx));

	cc->path = cf_strdup(path);
	cc->next_check = time(NULL) + CHANGE_CHECK_PERIOD;
	cc->mtim = buf.st_mtim;
	cc->handled = true;

	return cc;
}

tls_change_status
tls_change_check(tls_change_ctx *cc)
{
	if (cc == NULL || cc->next_check == 0) {
		return TLS_CHANGE_STATUS_NOT_CHANGED;
	}

	cf_detail(CF_TLS, "change check requested for file %s", cc->path);

	// Keep indicating change until the caller confirms that it was able to
	// successfully act upon our change notification.
	if (! cc->handled) {
		cf_detail(CF_TLS, "change not yet handled");
		return TLS_CHANGE_STATUS_CHANGED;
	}

	time_t now = time(NULL);

	if (now < cc->next_check) {
		cf_detail(CF_TLS, "check not due yet");
		return TLS_CHANGE_STATUS_NOT_CHANGED;
	}

	cf_detail(CF_TLS, "change-checking file %s", cc->path);
	struct stat buf;

	if (stat(cc->path, &buf) < 0) {
		cf_warning(CF_TLS, "error while change-checking file %s: %d (%s)",
				cc->path, errno, cf_strerror(errno));
		return TLS_CHANGE_STATUS_ERROR;
	}

	cc->next_check = now + CHANGE_CHECK_PERIOD;

	struct timespec *cur = &buf.st_mtim;
	struct timespec *old = &cc->mtim;

	cf_detail(CF_TLS, "current mtime %" PRIu64 ":%" PRIu64 ", old mtime %"
			PRIu64 ":%" PRIu64, (uint64_t)cur->tv_sec, (uint64_t)cur->tv_nsec,
			(uint64_t)old->tv_sec, (uint64_t)old->tv_nsec);

	if (cur->tv_sec == old->tv_sec && cur->tv_nsec == old->tv_nsec) {
		cf_detail(CF_TLS, "no change");
		return TLS_CHANGE_STATUS_NOT_CHANGED;
	}

	cf_detail(CF_TLS, "file changed");
	cc->mtim = buf.st_mtim;
	cc->handled = false;
	return TLS_CHANGE_STATUS_CHANGED;
}

void
tls_change_handled(tls_change_ctx *cc)
{
	cc->handled = true;
}

static log_string
get_subject_name(X509 *peer_cert)
{
	X509_NAME *sub_nam = X509_get_subject_name(peer_cert);
	log_string out;
	X509_NAME_oneline(sub_nam, out.s, sizeof(out.s));

	return out;
}

static char*
get_common_name(X509* peer_cert)
{
	X509_NAME* sub_nam = X509_get_subject_name(peer_cert);
	int pos = X509_NAME_get_index_by_NID(sub_nam, NID_commonName, -1);

	if (pos < 0) {
		cf_warning(CF_TLS, "peer's subject name lacks common name");
		return NULL;
	}

	X509_NAME_ENTRY* ent = X509_NAME_get_entry(sub_nam, pos);
	ASN1_STRING* asn1 = X509_NAME_ENTRY_get_data(ent);
	uint8_t* utf8;

	if (ASN1_STRING_to_UTF8(&utf8, asn1) < 0) {
		cf_warning(CF_TLS, "unable to convert peer's common name to UTF-8");
		return NULL;
	}

	return (char*)utf8;
}

static int
verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
	// If the cert has already failed we're done.
	if (! preverify_ok) {
		return preverify_ok;
	}

	SSL* ssl = X509_STORE_CTX_get_ex_data(
					ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

	// The verify callback is called for each cert in the chain.

	X509* current_cert = X509_STORE_CTX_get_current_cert(ctx);

	cf_detail(CF_TLS, "TLS cert: %s", get_cert_info(current_cert).s);

	cf_tls_info* info = SSL_get_ex_data(ssl, s_ex_info_index);
	cf_tls_peer_names* peer_names = SSL_get_ex_data(ssl, s_ex_peer_names_index);

	if (info->cert_blacklist != NULL) {
		// Is this cert blacklisted?
		char name[256];
		X509_NAME* iname = X509_get_issuer_name(current_cert);
		X509_NAME_oneline(iname, name, sizeof(name));

		ASN1_INTEGER* sn = X509_get_serialNumber(current_cert);
		BIGNUM* snbn = ASN1_INTEGER_to_BN(sn, NULL);
		char* snhex = BN_bn2hex(snbn);
		BN_free(snbn);

		bool listed = cert_blacklist_check(info->cert_blacklist, snhex, name);

		if (listed) {
			cf_warning(CF_TLS, "BLACKLISTED: %s %s", snhex, name);
			OPENSSL_free(snhex);
			return 0;
		}

		OPENSSL_free(snhex);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000
	X509 *peer_cert = ctx->cert;
#else
	X509 *peer_cert = X509_STORE_CTX_get0_cert(ctx);
#endif

	// If the name is set make sure the cert matches.
	if (current_cert == peer_cert) {
		bool match = true;

		for (uint32_t i = 0; i < peer_names->n_names; ++i) {
			cf_detail(CF_TLS, "checking certificate name %s against %s",
					get_subject_name(peer_cert).s, peer_names->names[i]);

			match = as_tls_match_name(peer_cert, peer_names->names[i], false);

			cf_detail(CF_TLS, "TLS cert name %s %s %s",
					get_subject_name(peer_cert).s,
					match ? "matches" : "does not match", peer_names->names[i]);

			if (match) {
				break;
			}
		}

		cf_detail(CF_TLS, "TLS cert name %s %s", get_subject_name(peer_cert).s,
				match ? "matches" : "does not match");

		return match ? 1 : 0;
	}

	// If we make it here we are a root or chain cert and are not
	// blacklisted.
	return 1;
}

typedef enum as_tls_protocol_e {
	// SSLv2 is always disabled per RFC 6176, we maintain knowledge of
	// it so we can give helpful error messages ...

	AS_TLS_PROTOCOL_SSLV2	= 1 << 0,
	AS_TLS_PROTOCOL_SSLV3	= 1 << 1,
	AS_TLS_PROTOCOL_TLSV1	= 1 << 2,
	AS_TLS_PROTOCOL_TLSV1_1	= 1 << 3,
	AS_TLS_PROTOCOL_TLSV1_2	= 1 << 4,
	AS_TLS_PROTOCOL_TLSV1_3	= 1 << 5,

	AS_TLS_PROTOCOL_NONE	= 0x00,

	AS_TLS_PROTOCOL_ALL		= AS_TLS_PROTOCOL_TLSV1 |
							  AS_TLS_PROTOCOL_TLSV1_1 |
							  AS_TLS_PROTOCOL_TLSV1_2
							  // Exclude 1.3 until we can make it work.
} as_tls_protocol;

static bool
protocols_parse(const char *protocol_spec, uint16_t* protocols_r)
{
	// Work on a copy, because parsing is destructive.
	char *copy = cf_strdup(protocol_spec);

	*protocols_r = AS_TLS_PROTOCOL_NONE;

	char const* delim = ", \t";
	char* saveptr = NULL;
	for (char* tok = strtok_r(copy, delim, &saveptr);
		 tok != NULL;
		 tok = strtok_r(NULL, delim, &saveptr)) {
		char act = '\0';
		uint16_t current = AS_TLS_PROTOCOL_NONE;

		// Is there a +/- prefix?
		if ((*tok == '+') || (*tok == '-')) {
			act = *tok;
			++tok;
		}

		if (strcasecmp(tok, "SSLv2") == 0) {
			cf_warning(CF_TLS, "SSLv2 not supported (RFC 6176)");
			cf_free(copy);
			return false;
		}
		else if (strcasecmp(tok, "SSLv3") == 0) {
			cf_warning(CF_TLS, "SSLv3 no longer supported - ignoring");
			current = 0;
		}
		else if (strcasecmp(tok, "TLSv1") == 0) {
			current = AS_TLS_PROTOCOL_TLSV1;
		}
		else if (strcasecmp(tok, "TLSv1.1") == 0) {
			current = AS_TLS_PROTOCOL_TLSV1_1;
		}
		else if (strcasecmp(tok, "TLSv1.2") == 0) {
			current = AS_TLS_PROTOCOL_TLSV1_2;
		}
		else if (strcasecmp(tok, "TLSv1.3") == 0) {
			if (! TLSv1_3_SUPPORTED) {
				cf_warning(CF_TLS, "TLSv1.3 not supported");
				cf_free(copy);
				return false;
			}

			current = AS_TLS_PROTOCOL_TLSV1_3;
		}
		else if (strcasecmp(tok, "all") == 0) {
			current = AS_TLS_PROTOCOL_ALL;
		}
		else {
			cf_warning(CF_TLS, "unknown TLS protocol %s", tok);
			cf_free(copy);
			return false;
		}

		if (act == '-') {
			*protocols_r &= ~current;
		}
		else if (act == '+') {
			*protocols_r |= current;
		}
		else {
			if (*protocols_r != AS_TLS_PROTOCOL_NONE) {
				cf_warning(CF_TLS, "TLS protocol %s overrides already set parameters. Check if a +/- prefix is missing ...",
					 tok);
				cf_free(copy);
				return false;
			}

			*protocols_r = current;
		}
	}

	cf_free(copy);
	return true;
}

void
tls_check_init()
{
	// Bail if we've already initialized.
	if (s_tls_inited) {
		return;
	}

	// Acquire the initialization mutex.
	cf_mutex_lock(&s_tls_init_mutex);

	// Check the flag again, in case we lost a race.
	if (! s_tls_inited) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
		OpenSSL_add_all_algorithms();
		ERR_load_BIO_strings();
		ERR_load_crypto_strings();
		SSL_load_error_strings();
		SSL_library_init();

		threading_setup();

		// Install an atexit handler to cleanup.
		atexit(tls_cleanup);
#endif

		s_ex_info_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		s_ex_peer_names_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

		__sync_synchronize();

		s_tls_inited = true;
	}

	cf_mutex_unlock(&s_tls_init_mutex);
}

void
tls_cleanup()
{
	// Skip if we were never initialized.
	if (! s_tls_inited) {
		return;
	}

	// Cleanup global OpenSSL state, must be after all other OpenSSL
	// API calls, of course ...

#if OPENSSL_VERSION_NUMBER < 0x10100000
	threading_cleanup();
#endif

	// https://wiki.openssl.org/index.php/Library_Initialization#Cleanup
	//
	FIPS_mode_set(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	tls_thread_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();

	// http://stackoverflow.com/questions/29845527/how-to-properly-uninitialize-openssl
	STACK_OF(SSL_COMP) *ssl_comp_methods = SSL_COMP_get_compression_methods();
	if (ssl_comp_methods != NULL) {
		sk_SSL_COMP_free(ssl_comp_methods);
	}
}

void
tls_thread_cleanup()
{
	// Skip if we were never initialized.
	if (! s_tls_inited) {
		return;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000
	ERR_remove_state(0);
#endif
}

void
tls_socket_init(cf_socket *sock)
{
	sock->ssl = NULL;
}

void
tls_socket_term(cf_socket *sock)
{
	if (sock->ssl) {
		SSL_free(sock->ssl);
	}
}

bool
tls_get_peer_name(cf_socket* sock, char* name, uint32_t* name_len)
{
	if (sock->ssl == NULL) {
		return false;
	}

	X509* peer_cert = SSL_get_peer_certificate(sock->ssl);

	if (peer_cert == NULL) {
		return false;
	}

	char* peer_name = get_common_name(peer_cert);

	if (peer_name == NULL) {
		X509_free(peer_cert);
		return false;
	}

	uint32_t len = strlen(peer_name);

	if (len > *name_len) {
		cf_warning(CF_TLS, "TLS common name %s too long", peer_name);
		OPENSSL_free(peer_name);
		X509_free(peer_cert);
		return false;
	}

	memcpy(name, peer_name, len);
	*name_len = len;

	OPENSSL_free(peer_name);
	X509_free(peer_cert);

	return true;
}

int
tls_socket_shutdown(cf_socket *sock)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	// No shutdown required, if we never called SSL_accept() or SSL_connect().
	// There doesn't seem to be an API function to check for this. Works up
	// to OpenSSL 1.0.2.
	if (sock->ssl->handshake_func == NULL) {
		return 0;
	}
#endif

	// See:
	// http://stackoverflow.com/questions/28056056/handling-ssl-shutdown-correctly

	uint64_t deadline = cf_clock_getabsolute() + 500;

	while (true) {
		int rv = SSL_shutdown(sock->ssl);
		if (rv == 0 || rv == 1) {
			// We managed to send our close_notify alert and we had (1) or
			// hadn't (0) previously received the client's.
			return 0;
		}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
		// Same as above, but for OpenSSL 1.1.0+. We are shutting down before
		// we could make it to the TLS handshake.

		unsigned long err = ERR_peek_error();
		unsigned long rea = ERR_GET_REASON(err);

		if (err != 0 && (rea == SSL_R_UNINITIALIZED ||
				rea == SSL_R_SHUTDOWN_WHILE_IN_INIT)) {
			ERR_clear_error();
			return 0;
		}
#endif

		// We didn't manage to send our close_notify alert. See whether we
		// can fix the situation. If we could, then loop back.
		rv = handle_tls_error(sock, rv, "SSL_shutdown", deadline);
		if (rv < 0) {
			return rv;
		}
	}
}

void
tls_socket_close(cf_socket *sock)
{
	// Nothing to do so far.
}

static const char *
null_none(const char *str)
{
	return str == NULL ? "(none)" : str;
}

static bool
load_cert(SSL_CTX *ctx, const char* path, const char* name)
{
	size_t cert_sz;
	uint8_t *cert_buf = cf_fetch_bytes(path, &cert_sz);

	if (cert_buf == NULL) {
		cf_warning(CF_TLS, "failed to load cert file %s", path);
		return false;
	}

	BIO *cert_bio = BIO_new_mem_buf(cert_buf, cert_sz);

	if (cert_bio == NULL) {
		cf_free(cert_buf);
		return false;
	}

	SSL_CTX_clear_extra_chain_certs(ctx);

	X509 *cer;
	bool matched = false;

	while ((cer = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) != NULL) {
		char sub_str[256];
		X509_NAME* sub_nam = X509_get_subject_name(cer);
		X509_NAME_oneline(sub_nam, sub_str, sizeof(sub_str));

		cf_detail(CF_TLS, "checking certificate name %s against tls-name %s",
				sub_str, name);

		if (as_tls_match_name(cer, name, true)) {
			if (SSL_CTX_use_certificate(ctx, cer) != 1 &&
					// See https://groups.google.com/forum/#!topic/mailing.openssl.users/nRvRzmKnEQA
					ERR_peek_error() != SSL_ERROR_NONE) {
				X509_free(cer);
				BIO_vfree(cert_bio);
				cf_free(cert_buf);
				return false;
			}

			X509_free(cer);
			matched = true;
		}
		else {
			if (SSL_CTX_add_extra_chain_cert(ctx, cer) != 1 &&
					// See https://groups.google.com/forum/#!topic/mailing.openssl.users/nRvRzmKnEQA
					ERR_peek_error() != SSL_ERROR_NONE) {
				X509_free(cer);
				BIO_vfree(cert_bio);
				cf_free(cert_buf);
				return false;
			}
		}
	}

	BIO_vfree(cert_bio);
	cf_free(cert_buf);

	if (! matched) {
		cf_warning(CF_TLS, "tls-name %s does not match any certificate name in %s",
				name, path);
		return false;
	}

	return true;
}

static int32_t
password_cb(char *buf, int32_t size, int32_t rwflag, void *udata)
{
	cf_tls_spec *spec = udata;

	cf_assert(rwflag == 0, CF_TLS, "unexpected write request for TLS key %s",
			spec->key_file);

	if (spec->pw_string == NULL) {
		cf_warning(CF_TLS, "TLS key %s requires a password (key-file-password)",
				spec->key_file);
		return -1;
	}

	int32_t len = strlen(spec->pw_string);

	if (len > size) {
		cf_warning(CF_TLS, "TLS key password is too long (>%d characters)",
				size);
		return -1;
	}

	memcpy(buf, spec->pw_string, len);
	return len;
}

static bool
load_private_key(SSL_CTX *ctx, cf_tls_spec *tspec)
{
	size_t key_sz;
	uint8_t *key_buf = cf_fetch_bytes(tspec->key_file, &key_sz);

	if (key_buf == NULL) {
		cf_warning(CF_TLS, "failed to load key file %s", tspec->key_file);
		return false;
	}

	BIO *key_bio = BIO_new_mem_buf(key_buf, key_sz);

	if (key_bio == NULL) {
		cf_free(key_buf);
		return false;
	}

	EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, password_cb, tspec);

	BIO_vfree(key_bio);
	cf_free(key_buf);

	if (pkey == NULL) {
		if (ERR_GET_REASON(ERR_peek_error()) == EVP_R_BAD_DECRYPT) {
			cf_warning(CF_TLS, "invalid password for key file %s",
					tspec->key_file);
		}

		return false;
	}

	return SSL_CTX_use_PrivateKey(ctx, pkey) == 1;
}

static SSL_CTX *
create_context(const SSL_METHOD *method, uint16_t protocols, cf_tls_spec *tspec)
{
	SSL_CTX *ctx = SSL_CTX_new(method);

	if (ctx == NULL) {
		cf_warning(CF_TLS, "failed to create new TLS context: %s", tls_error_string());
		return NULL;
	}

	/* always disable SSLv2, as per RFC 6176 */
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

	if (! (protocols & AS_TLS_PROTOCOL_TLSV1)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
	}
	if (! (protocols & AS_TLS_PROTOCOL_TLSV1_1)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
	}
	if (! (protocols & AS_TLS_PROTOCOL_TLSV1_2)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
	}
	if (! (protocols & AS_TLS_PROTOCOL_TLSV1_3)) {
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
	}

	if (SSL_CTX_set_session_id_context(ctx, (unsigned char *)&ctx, sizeof(ctx)) != 1) {
		cf_warning(CF_TLS, "failed to set session id context: %s", tls_error_string());
		SSL_CTX_free(ctx);
		return NULL;
	}

	if (tspec->ca_file || tspec->ca_path) {
		if (SSL_CTX_load_verify_locations(ctx, tspec->ca_file, tspec->ca_path) != 1) {
			cf_warning(CF_TLS, "failed to read ca-file %s / ca-path %s for %s: %s",
					null_none(tspec->ca_file), null_none(tspec->ca_path), tspec->name,
					tls_error_string());
			SSL_CTX_free(ctx);
			return NULL;
		}
	}

	if (tspec->cert_file != NULL) {
		if (! load_cert(ctx, tspec->cert_file, tspec->name)) {
			if (ERR_peek_error() != SSL_ERROR_NONE) {
				cf_warning(CF_TLS, "failed to load cert file %s: %s",
						tspec->cert_file, tls_error_string());
			}

			SSL_CTX_free(ctx);
			return NULL;
		}
	}

	if (tspec->key_file != NULL) {
		if (! load_private_key(ctx, tspec)) {
			if (ERR_peek_error() != SSL_ERROR_NONE) {
				cf_warning(CF_TLS, "failed to load key file %s: %s",
						tspec->key_file, tls_error_string());
			}

			SSL_CTX_free(ctx);
			return NULL;
		}
	}

	if (tspec->cipher_suite) {
		if (SSL_CTX_set_cipher_list(ctx, tspec->cipher_suite) != 1) {
			cf_warning(CF_TLS, "no compatible cipher found");
			SSL_CTX_free(ctx);
			return NULL;
		}

		// It's bogus that we have to create an SSL just to get the
		// cipher list, but SSL_CTX_get_ciphers doesn't appear to
		// exist.

		SSL *ssl = SSL_new(ctx);

		for (int prio = 0; true; ++prio) {
			char const *cipherstr = SSL_get_cipher_list(ssl, prio);

			if (!cipherstr) {
				break;
			}

			cf_info(CF_TLS, "cipher %d: %s", prio + 1, cipherstr);
		}

		SSL_free(ssl);
	}

#if 0
	if (spec->crl_check || spec->crl_check_all) {
		X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
		unsigned long flags = X509_V_FLAG_CRL_CHECK;
		if (spec->crl_check_all) {
			flags |= X509_V_FLAG_CRL_CHECK_ALL;
		}
		X509_VERIFY_PARAM_set_flags(param, flags);
		SSL_CTX_set1_param(ctx, param);
		X509_VERIFY_PARAM_free(param);
	}
#endif

	return ctx;
}

static SSL_CTX *
create_server_context(cf_tls_spec *tspec)
{
	if (tspec->cert_file == NULL) {
		cf_warning(CF_TLS, "missing cert-file for %s", tspec->name);
		return NULL;
	}

	if (tspec->key_file == NULL) {
		cf_warning(CF_TLS, "missing key-file for %s", tspec->name);
		return NULL;
	}

	uint16_t protocols;

	if (! protocols_parse(tspec->protocols, &protocols)) {
		return NULL;
	}

	const SSL_METHOD *method;

#if OPENSSL_VERSION_NUMBER < 0x10100000
	if (protocols == AS_TLS_PROTOCOL_TLSV1) {
		method = TLSv1_server_method();
	}
	else if (protocols == AS_TLS_PROTOCOL_TLSV1_1) {
		method = TLSv1_1_server_method();
	}
	else if (protocols == AS_TLS_PROTOCOL_TLSV1_2) {
		method = TLSv1_2_server_method();
	}
	else {
		// Multiple protocols are enabled, use a flexible method.
		method = SSLv23_server_method();
	}
#else
	method = TLS_server_method();
#endif

	SSL_CTX *ctx = create_context(method, protocols, tspec);

	if (ctx == NULL) {
		return NULL;
	}

	// Required by some distros (at least Centos-7) to support certain ciphers.
#if OPENSSL_VERSION_NUMBER >= 0x10002000
	SSL_CTX_set_ecdh_auto(ctx, 1);
#endif

	// Disregard the client's cipher preferences. Java clients seem to prefer
	// non-GCM AES over GCM AES.
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

	return ctx;
}

static SSL_CTX *
create_client_context(cf_tls_spec *tspec)
{
	// tspec->cert_file & tspec->key_file are optional for client.

	uint16_t protocols;

	if (! protocols_parse(tspec->protocols, &protocols)) {
		return NULL;
	}

	const SSL_METHOD *method;

#if OPENSSL_VERSION_NUMBER < 0x10100000
	if (protocols == AS_TLS_PROTOCOL_TLSV1) {
		method = TLSv1_client_method();
	}
	else if (protocols == AS_TLS_PROTOCOL_TLSV1_1) {
		method = TLSv1_1_client_method();
	}
	else if (protocols == AS_TLS_PROTOCOL_TLSV1_2) {
		method = TLSv1_2_client_method();
	}
	else {
		// Multiple protocols are enabled, use a flexible method.
		method = SSLv23_client_method();
	}
#else
	method = TLS_client_method();
#endif

	return create_context(method, protocols, tspec);
}

static bool
load_cbl(cf_tls_info *info, const char *path)
{
	info->cert_blacklist = cert_blacklist_read(path, info->which);

	if (info->cert_blacklist == NULL) {
		cf_warning(CF_TLS, "reading certificate blacklist %s failed", path);
		return false;
	}

	info->ch_cert_blacklist = tls_change_init(path);

	return info->ch_cert_blacklist != NULL;
}

char *
tls_read_password(const char *path)
{
	const char *real_path = path;

	if (strncmp(path, "file:", 5) == 0) {
		real_path += 5;
	}

	char* pw = cf_fetch_string(real_path);

	if (pw == NULL) {
		cf_crash_nostack(CF_TLS, "can't fetch TLS key password %s", path);
	}

	return pw;
}

cf_tls_info *
tls_config_server_context(cf_tls_spec *tspec, bool auth_client, uint32_t n_peer_names, char **peer_names)
{
	cf_tls_info *info = cf_malloc(sizeof(cf_tls_info));
	memset(info, 0, sizeof(cf_tls_info));

	pthread_rwlock_init(&info->rwlock, NULL);
	info->which = "client service";
	info->spec = tspec;

	info->ssl_ctx_ser = create_server_context(tspec);

	if (info->ssl_ctx_ser == NULL) {
		tls_info_free(info);
		return NULL;
	}

	info->ssl_ctx_cli = NULL;

	info->peer_names.n_names = n_peer_names;
	info->peer_names.names = peer_names;

	info->cert_blacklist = NULL;
	info->ch_cert_blacklist = NULL;

	info->ch_cert_file_ser = tls_change_init(tspec->cert_file);

	if (info->ch_cert_file_ser == NULL) {
		tls_info_free(info);
		return NULL;
	}

	info->ch_key_file_ser = tls_change_init(tspec->key_file);

	if (info->ch_key_file_ser == NULL) {
		tls_info_free(info);
		return NULL;
	}

	info->ch_cert_file_cli = NULL;
	info->ch_key_file_cli = NULL;

	// Accept either client or server certificates. This allows us to reuse
	// an already existing server certificate for XDR clients.
	SSL_CTX_set_purpose(info->ssl_ctx_ser, X509_PURPOSE_ANY);

	if (! auth_client) {
		SSL_CTX_set_verify(info->ssl_ctx_ser, SSL_VERIFY_NONE, NULL);
		return info;
	}

	SSL_CTX_set_verify(info->ssl_ctx_ser, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_callback);

	if (tspec->cert_blacklist != NULL &&
			! load_cbl(info, tspec->cert_blacklist)) {
		tls_info_free(info);
		return NULL;
	}

	return info;
}

cf_tls_info *
tls_config_intra_context(cf_tls_spec *tspec, const char *which)
{
	cf_tls_info *info = cf_malloc(sizeof(cf_tls_info));
	memset(info, 0, sizeof(cf_tls_info));

	pthread_rwlock_init(&info->rwlock, NULL);
	info->which = which;
	info->spec = tspec;

	info->ssl_ctx_ser = create_server_context(tspec);

	if (info->ssl_ctx_ser == NULL) {
		tls_info_free(info);
		return NULL;
	}

	info->ssl_ctx_cli = create_client_context(tspec);

	if (info->ssl_ctx_cli == NULL) {
		tls_info_free(info);
		return NULL;
	}

	info->peer_names.n_names = 1;
	info->peer_names.names = &tspec->name;

	info->cert_blacklist = NULL;
	info->ch_cert_blacklist = NULL;

	info->ch_cert_file_ser = tls_change_init(tspec->cert_file);

	if (info->ch_cert_file_ser == NULL) {
		tls_info_free(info);
		return NULL;
	}

	info->ch_key_file_ser = tls_change_init(tspec->key_file);

	if (info->ch_key_file_ser == NULL) {
		tls_info_free(info);
		return NULL;
	}

	info->ch_cert_file_cli = tls_change_init(tspec->cert_file);

	if (info->ch_cert_file_cli == NULL) {
		tls_info_free(info);
		return NULL;
	}

	info->ch_key_file_cli = tls_change_init(tspec->key_file);

	if (info->ch_key_file_cli == NULL) {
		tls_info_free(info);
		return NULL;
	}

	SSL_CTX_set_verify(info->ssl_ctx_ser, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_callback);

	SSL_CTX_set_verify(info->ssl_ctx_cli, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_callback);

	// Expect the peer cluster node (the "client") to present a server certificate,
	// instead of a client certificate.
	SSL_CTX_set_purpose(info->ssl_ctx_ser, X509_PURPOSE_SSL_SERVER);

	if (tspec->cert_blacklist != NULL &&
			! load_cbl(info, tspec->cert_blacklist)) {
		tls_info_free(info);
		return NULL;
	}

	return info;
}

cf_tls_info *
tls_config_xdr_client_context(cf_tls_spec *tspec)
{
	cf_tls_info *info = cf_malloc(sizeof(cf_tls_info));
	memset(info, 0, sizeof(cf_tls_info));

	pthread_rwlock_init(&info->rwlock, NULL);
	info->which = "XDR client";
	info->spec = tspec;

	info->ssl_ctx_ser = NULL;
	info->ssl_ctx_cli = create_client_context(tspec);

	if (info->ssl_ctx_cli == NULL) {
		tls_info_free(info);
		return NULL;
	}

	info->peer_names.n_names = 0;
	info->peer_names.names = NULL;

	info->cert_blacklist = NULL;
	info->ch_cert_blacklist = NULL;

	if (tspec->cert_file != NULL) {
		info->ch_cert_file_cli = tls_change_init(tspec->cert_file);

		if (info->ch_cert_file_cli == NULL) {
			tls_info_free(info);
			return NULL;
		}
	}

	if (tspec->key_file != NULL) {
		info->ch_key_file_cli = tls_change_init(tspec->key_file);

		if (info->ch_key_file_cli == NULL) {
			tls_info_free(info);
			return NULL;
		}
	}

	SSL_CTX_set_verify(info->ssl_ctx_cli, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_callback);

	if (tspec->cert_blacklist != NULL &&
			! load_cbl(info, tspec->cert_blacklist)) {
		tls_info_free(info);
		return NULL;
	}

	return info;
}

static int32_t
reload_cert_and_key(SSL_CTX *ctx, cf_tls_spec *tspec)
{
	cf_assert(tspec->cert_file != NULL && tspec->key_file != NULL, CF_TLS,
			"missing cert-file or key-file");

	if (! load_cert(ctx, tspec->cert_file, tspec->name)) {
		if (ERR_peek_error() != SSL_ERROR_NONE) {
			cf_warning(CF_TLS, "failed to load cert file %s: %s",
					tspec->cert_file, tls_error_string());
		}

		return -1;
	}

	if (! load_private_key(ctx, tspec)) {
		if (ERR_peek_error() != SSL_ERROR_NONE) {
			cf_warning(CF_TLS, "failed to load key file %s: %s",
					tspec->key_file, tls_error_string());
		}

		return -1;
	}

	return 0;
}

static void
socket_prepare(SSL_CTX *ctx, const char *ch_role, tls_change_ctx *ch_cert_file,
		tls_change_ctx *ch_key_file, cf_tls_info *info,
		cf_tls_peer_names *peer_names, cf_socket *sock)
{
	pthread_rwlock_wrlock(&info->rwlock);

	tls_change_status cs = tls_change_check(ch_cert_file);

	if (cs == TLS_CHANGE_STATUS_ERROR) {
		cf_detail(CF_TLS, "error while change-checking cert-file");
	}
	else if (cs == TLS_CHANGE_STATUS_NOT_CHANGED) {
		cf_detail(CF_TLS, "cert-file not changed");
	}
	else {
		cf_info(CF_TLS, "cert-file %s changed for %s (%s)", ch_cert_file->path,
				info->which, ch_role);

		usleep(10000);

		if (reload_cert_and_key(ctx, info->spec) == 0) {
			tls_change_handled(ch_cert_file);
		}
	}

	cs = tls_change_check(ch_key_file);

	if (cs == TLS_CHANGE_STATUS_ERROR) {
		cf_detail(CF_TLS, "error while change-checking key-file");
	}
	else if (cs == TLS_CHANGE_STATUS_NOT_CHANGED) {
		cf_detail(CF_TLS, "key-file not changed");
	}
	else {
		cf_info(CF_TLS, "key-file %s changed for %s (%s)", ch_key_file->path,
				info->which, ch_role);

		usleep(10000);

		if (reload_cert_and_key(ctx, info->spec) == 0) {
			tls_change_handled(ch_key_file);
		}
	}

	cs = tls_change_check(info->ch_cert_blacklist);

	if (cs == TLS_CHANGE_STATUS_ERROR) {
		cf_detail(CF_TLS, "error while change-checking cert-blacklist");
	}
	else if (cs == TLS_CHANGE_STATUS_NOT_CHANGED) {
		cf_detail(CF_TLS, "cert-blacklist not changed");
	}
	else {
		cf_info(CF_TLS, "cert-blacklist %s changed",
				info->ch_cert_blacklist->path);

		usleep(10000);

		cert_blacklist *cbl = cert_blacklist_read(info->ch_cert_blacklist->path,
				info->which);

		if (cbl != NULL) {
			cert_blacklist_destroy(info->cert_blacklist);
			info->cert_blacklist = cbl;
			tls_change_handled(info->ch_cert_blacklist);
		}
	}

	sock->ssl = SSL_new(ctx);

	pthread_rwlock_unlock(&info->rwlock);

	if (sock->ssl == NULL) {
		cf_crash(CF_TLS, "SSL_new() failed: %s", tls_error_string());
	}

	if (SSL_set_fd(sock->ssl, sock->fd) == 0) {
		cf_crash(CF_TLS, "SSL_set_fd() failed: %s", tls_error_string());
	}

	SSL_set_ex_data(sock->ssl, s_ex_info_index, info);
	SSL_set_ex_data(sock->ssl, s_ex_peer_names_index,
			peer_names == NULL ? &info->peer_names : peer_names);

	sock->state = CF_SOCKET_STATE_TLS_HANDSHAKE;
}

void
tls_socket_prepare_server(cf_tls_info *info, cf_socket *sock)
{
	socket_prepare(info->ssl_ctx_ser, "server", info->ch_cert_file_ser,
			info->ch_key_file_ser, info, NULL, sock);
}

void
tls_socket_prepare_client(cf_tls_info *info, cf_socket *sock)
{
	socket_prepare(info->ssl_ctx_cli, "client", info->ch_cert_file_cli,
			info->ch_key_file_cli, info, NULL, sock);
}

void
tls_socket_prepare_xdr_client(cf_tls_info *info, cf_tls_peer_names *peer_names,
		cf_socket *sock)
{
	socket_prepare(info->ssl_ctx_cli, "client", info->ch_cert_file_cli,
			info->ch_key_file_cli, info, peer_names, sock);
}

// If we don't expect to read more data for now, OpenSSL must not have
// buffered any data, either. Otherwise we will later end up polling the
// socket for data that OpenSSL has already read and we'll get stuck.

void
tls_socket_must_not_have_data(cf_socket *sock, const char *caller)
{
	if (sock->state == CF_SOCKET_STATE_NON_TLS) {
		return;
	}

	size_t pend = tls_socket_pending(sock);

	if (pend > 0) {
		cf_warning(CF_TLS, "unexpected pending TLS data after %s: %zu byte(s)",
				caller, pend);
	}
}

static int
tls_socket_accept_connect(cf_socket *sock, int (*func)(SSL *SSL),
		char const *caller)
{
	cf_tls_info *info = SSL_get_ex_data(sock->ssl, s_ex_info_index);

	pthread_rwlock_rdlock(&info->rwlock);

	int rv = func(sock->ssl);

	pthread_rwlock_unlock(&info->rwlock);

	if (rv > 0) {
		log_session_info(sock);
		sock->state = CF_SOCKET_STATE_TLS_READY;
		return 0;
	}

	switch (SSL_get_error(sock->ssl, rv)) {
	case SSL_ERROR_WANT_READ:
		return EPOLLIN;

	case SSL_ERROR_WANT_WRITE:
		return EPOLLOUT;

	default:
		handle_tls_error(sock, rv, caller, UINT64_MAX);
		return EPOLLERR;
	}
}

int
tls_socket_accept(cf_socket *sock)
{
	return tls_socket_accept_connect(sock, SSL_accept, "SSL_accept");
}

int
tls_socket_connect(cf_socket *sock)
{
	return tls_socket_accept_connect(sock, SSL_connect, "SSL_connect");
}

static int
tls_socket_accept_connect_block(cf_socket *sock, int (*func)(SSL *ssl),
		char const *caller, uint32_t io_timeout)
{
	uint64_t total_deadline = compute_deadline(1000);
	cf_tls_info *info = SSL_get_ex_data(sock->ssl, s_ex_info_index);

	while (true) {
		pthread_rwlock_rdlock(&info->rwlock);

		int rv = func(sock->ssl);

		pthread_rwlock_unlock(&info->rwlock);

		if (rv == 1) {
			log_session_info(sock);
			sock->state = CF_SOCKET_STATE_TLS_READY;
			tls_socket_must_not_have_data(sock, caller);
			return 1;
		}

		uint64_t io_deadline = compute_deadline(io_timeout);
		uint64_t deadline = total_deadline < io_deadline ?
				total_deadline : io_deadline;

		if (handle_tls_error(sock, rv, caller, deadline) < 0) {
			return -1;
		}
	}
}

int
tls_socket_accept_block(cf_socket *sock, uint32_t timeout)
{
	return tls_socket_accept_connect_block(sock, SSL_accept, "SSL_accept",
			timeout);
}

int
tls_socket_connect_block(cf_socket *sock, uint32_t timeout)
{
	return tls_socket_accept_connect_block(sock, SSL_connect, "SSL_connect",
			timeout);
}

int
tls_socket_recv(cf_socket *sock, void *buf, size_t len, int32_t flags, uint64_t timeout)
{
	cf_assert((flags & ~MSG_WAITALL) == 0, CF_TLS, "unexpected flag");

	uint64_t deadline = compute_deadline(timeout);
	size_t pos = 0;

	while (true) {
		int rv;

		do {
			rv = SSL_read(sock->ssl, (uint8_t *)buf + pos, (int)(len - pos));

			if (rv <= 0) {
				break;
			}

			pos += rv;

			if (pos >= len) {
				return pos;
			}
		}
		while (tls_socket_pending(sock) > 0);

		if (handle_tls_error(sock, rv, "SSL_read", deadline) < 0) {
			if (errno == ETIMEDOUT && pos > 0) {
				return pos;
			}

			return -1;
		}
	}
}

int
tls_socket_send(cf_socket *sock, void const *buf, size_t len, int32_t flags, uint64_t timeout)
{
	if ((flags & ~(MSG_NOSIGNAL | MSG_MORE)) != 0) {
		cf_crash(CF_TLS, "unexpected flags to tls_socket_send: 0x%0x", flags);
	}

	uint64_t deadline = compute_deadline(timeout);

	while (true) {
		int rv = SSL_write(sock->ssl, (uint8_t *)buf, (int)len);

		if (rv > 0) {
			// By default, SSL_write() doesn't do partial writes.
			cf_assert(rv == len, CF_TLS,
					"unexpected SSL_write() result: %d vs. %d", rv, (int)len);
			return rv;
		}

		if (handle_tls_error(sock, rv, "SSL_write", deadline) < 0) {
			return -1;
		}
	}
}

int
tls_socket_pending(cf_socket *sock)
{
	return sock->ssl ? SSL_pending(sock->ssl) : 0;
}
