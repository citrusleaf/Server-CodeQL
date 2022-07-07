/*
 * tls_ee.h
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "tls.h"

typedef struct tls_change_ctx_s {
	char *path;
	time_t next_check;
	struct timespec mtim;
	bool handled;
} tls_change_ctx;

typedef enum {
	TLS_CHANGE_STATUS_ERROR,
	TLS_CHANGE_STATUS_NOT_CHANGED,
	TLS_CHANGE_STATUS_CHANGED
} tls_change_status;

typedef struct cf_tls_peer_names_s {
	uint32_t n_names;
	char **names;
} cf_tls_peer_names;

bool tls_get_peer_name(cf_socket* sock, char* name, uint32_t* name_len);

tls_change_ctx *tls_change_init(const char *path);
tls_change_status tls_change_check(tls_change_ctx *cc);
void tls_change_handled(tls_change_ctx *cc);

cf_tls_info *tls_config_xdr_client_context(cf_tls_spec *tspec);
void tls_info_free(cf_tls_info* info);

void tls_socket_prepare_xdr_client(cf_tls_info *info, cf_tls_peer_names *peer_names, cf_socket *sock);
