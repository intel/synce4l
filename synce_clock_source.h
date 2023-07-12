/**
 * @file synce_clock_source.h
 * @brief Interface between synce device and clock_source controller module.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_CLOCK_SOURCE_H
#define HAVE_SYNCE_CLOCK_SOURCE_H
#include <stdint.h>
#include "util.h"
#include "synce_msg.h"

enum clk_type {
	PORT = 0,
	EXT_SRC,
};

struct synce_dev;
struct config;

struct synce_clock_source {
	LIST_ENTRY(synce_clock_source) list;
	enum clk_type type;
	union {
		struct synce_ext_src *ext_src;
		struct synce_port *port;
	};
};

/**
 * Alloc memory for a single synce_clock_source instance.
 *
 * @return			Pointer to allocated instance
 */
struct synce_clock_source *synce_clock_source_create();

/**
 * Add clock source instance to clock_source list.
 *
 * @param clock_source		synce_clock_source instance to be added
 * @param clock_source_name	Human readable name of an clock_sourcel source
 * @param clk_type		type of clock source, eigther PORT or EXT_SRC
 * @return			Pointer to allocated instance
 */
int synce_clock_source_add_source(struct synce_clock_source *clock_source,
				  const char *clock_source_name,
				  enum clk_type type);

/**
 * Initialize synce device capable clock_source after clock_source was created.
 *
 * @param clock_source		synce_clock_source instance to be initialized
 * @param cfg			Configuration struct based on SYNCE type,
 *				must hold properities of the configured clock_source.
 * @param network_option	Network option that shall be used on the device
 * @param is_extended		If extended tlv support is on
 * @param recover_time		What time was set for recovery [s]
 * @return			0 on success, failure otherwise
 */
int synce_clock_source_init(struct synce_clock_source *clock_source,
			    struct config *cfg, int network_option,
			    int is_extended, int recovery_time);

/**
 * Get name of an clock source.
 *
 * @param clock_source	Questioned instance
 * @return		Name of an clock source
 */
const char
*synce_clock_source_get_name(struct synce_clock_source *clock_source);

/**
 * Free resource under the synce_clock_source instance. Caller shall free the
 * passed pointer afterwards.
 *
 * @param clock_source		Pointer to the clock_source being released
 */
void synce_clock_source_destroy(struct synce_clock_source *clock_source);

/**
 * Compare left with right clock_source, which has higher incoming Quality Level.
 *
 * @param left		clock_source instance for comparison
 * @param right		clock_source instance for comparison
 * @return		Pointer to best QL instance, NULL on failure or equal
 */
struct synce_clock_source
*synce_clock_source_compare_ql(struct synce_clock_source *left,
			       struct synce_clock_source *right);

/**
 * get QL and priority params of a clock_source.
 *
 * @param clock_source		Questioned instance
 * @param priority_list		Pointer to priority list to be fetched from pc
 * @param priority_count	Number of priorities in list
 * @return			16 bit priority, QL combined with extended QL
 */
uint16_t
get_clock_source_priority_params(struct synce_clock_source *clock_source,
				 const uint16_t **priority_list,
				 uint16_t *priority_count);

#endif /* HAVE_SYNCE_CLOCK_SOURCE_H */
