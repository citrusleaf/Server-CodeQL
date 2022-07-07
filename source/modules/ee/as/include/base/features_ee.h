/*
 * features_ee.h
 *
 * Copyright (C) 2017-2020 Aerospike, Inc.
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

#include <stdbool.h>
#include <stdint.h>


//==========================================================
// Public API.
//

bool as_features_init(const char *path);
bool as_features_change_notification(void);
uint32_t as_features_cluster_nodes_limit(void);
bool as_features_compression(void);
bool as_features_encryption_at_rest(void);
bool as_features_ldap(void);
bool as_features_pmem(void);
bool as_features_strong_consistency(void);
bool as_features_by_name(const char *name);
