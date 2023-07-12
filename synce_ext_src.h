/**
 * @file synce_ext_src.h
 * @brief Interface between synce device and ext_src controller module.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_EXT_SRC_H
#define HAVE_SYNCE_EXT_SRC_H
#include <stdint.h>
#include "util.h"
#include "synce_msg.h"

struct synce_dev;
struct config;

struct synce_ext_src {
	int state;
	int extended;
	uint8_t ql;
	uint8_t ext_ql;
	char name[IF_NAMESIZE];
	char *external_enable_cmd;
	char *external_disable_cmd;
	const uint16_t *priority_list;
	int priority_list_count;
};

/**
 * Alloc memory for a single synce_ext_src instance.
 *
 * @param ext_src_name		Human readable name of an external source
 * @return			Pointer to allocated instance
 */
struct synce_ext_src *synce_ext_src_create(const char *ext_src_name);

/**
 * Initialize synce device capable ext_src after ext_src was created.
 *
 * @param ext_src		synce_ext_src instance to be initialized
 * @param cfg			Configuration struct based on SYNCE type,
 *				must hold properities of the configured ext_src.
 * @param network_option	Network option that shall be used on the device
 * @param is_extended		If extended tlv support is on
 * @return			0 on success, failure otherwise
 */
int synce_ext_src_init(struct synce_ext_src *ext_src, struct config *cfg,
		       int network_option, int is_extended);

/**
 * Free resource under the synce_ext_src instance. Caller shall free the passed
 * pointer afterwards.
 *
 * @param ext_src		Pointer to the ext_src being released
 */
void synce_ext_src_destroy(struct synce_ext_src *ext_src);

/**
 * Get name of an external source.
 *
 * @param ext_src	Questioned instance
 * @return		Name of an external source
 */
const char *synce_ext_src_get_name(struct synce_ext_src *ext_src);

/**
 * Enable recover clock on an external source.
 *
 * @param ext_src	Questioned instance
 * @return		0 on success, negative on failure
 */
int synce_ext_src_enable_ext_clock(struct synce_ext_src *ext_src);

/**
 * Enable recover clock on an external source.
 *
 * @param ext_src	Questioned instance
 * @return		0 on success, negative on failure
 */
int synce_ext_src_disable_ext_clock(struct synce_ext_src *ext_src);

/**
 * get combined QL priority of an external source.
 *
 * @param ext_src	Questioned instance
 * @return		16 bit priority, QL combined with extended QL
 */
uint16_t get_ext_src_ql_priority(struct synce_ext_src *ext_src);

/**
 * get priority parameters of a given ext_src.
 *
 * @param ext_src		Questioned instance
 * @param priority_list		Pointer to priority list to be fetched from ext_src
 * @return			Number of priorities in list
 */
uint16_t get_ext_src_priority_params(struct synce_ext_src *ext_src,
				     const uint16_t **priority_list);

#endif /* HAVE_SYNCE_EXT_SRC_H */
