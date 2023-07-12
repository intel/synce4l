/**
 * @file synce_clock_source.c
 * @brief Interface between synce device and clock_source controller module.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <stdlib.h>
#include <errno.h>
#include <sys/queue.h>
#include <net/if.h>
#include <stdbool.h>
#include <linux/limits.h>

#include "util.h"
#include "synce_clock_source.h"
#include "synce_ext_src.h"
#include "synce_port.h"
#include "synce_port_ctrl.h"
#include "print.h"
#include "config.h"
#include "synce_msg.h"

struct synce_clock_source *synce_clock_source_create()
{
	struct synce_clock_source *p = NULL;

	p = malloc(sizeof(struct synce_clock_source));
	if (!p) {
		pr_err("%s failed", __func__);
		return NULL;
	}
	memset(p, 0, sizeof(struct synce_clock_source));

	return p;
}

int synce_clock_source_add_source(struct synce_clock_source *clock_source,
		const char *clock_source_name, enum clk_type type)
{
	if (!clock_source) {
		pr_err("%s clock_source is NULL", __func__);
		return -ENODEV;
	}

	clock_source->type = type;
	if (type == PORT) {
		clock_source->port = synce_port_create(clock_source_name);
		if (!clock_source->port)
			return -ENODEV;
	} else {
		clock_source->ext_src = synce_ext_src_create(clock_source_name);
		if (!clock_source->ext_src)
			return -ENODEV;
	}

	return 0;
}

int synce_clock_source_init(struct synce_clock_source *clock_source,
			    struct config *cfg, int network_option,
			    int is_extended, int recovery_time)
{
	if (!clock_source) {
		pr_err("%s clock_source is NULL", __func__);
		return -ENODEV;
	}

	if (clock_source->type == PORT)
		return synce_port_init(clock_source->port, cfg,
				       network_option, is_extended,
				       recovery_time);
	return synce_ext_src_init(clock_source->ext_src, cfg,
				  network_option, is_extended);
}

void synce_clock_source_destroy(struct synce_clock_source *clock_source)
{
	if (!clock_source) {
		pr_err("%s clock_source is NULL", __func__);
		return;
	}

	if (clock_source->type == PORT) {
		synce_port_destroy(clock_source->port);
		free(clock_source->port);
	} else {
		synce_ext_src_destroy(clock_source->ext_src);
		free(clock_source->ext_src);
	}
}

const char *synce_clock_source_get_name(struct synce_clock_source *clock_source)
{
	if (!clock_source) {
		pr_err("%s clock_source is NULL", __func__);
		return NULL;
	}

	if (clock_source->type == PORT)
		return synce_port_get_name(clock_source->port);
	return synce_ext_src_get_name(clock_source->ext_src);
}

struct synce_clock_source
*is_valid_clock_source(struct synce_clock_source *clock_source)
{
	if (clock_source && clock_source->type == PORT) {
		if (!clock_source->port->pc)
			return NULL;
		if (!is_valid_source(clock_source->port->pc))
			return NULL;
	}
	return clock_source;
}

struct synce_clock_source
*synce_clock_source_compare_ql(struct synce_clock_source *left,
			       struct synce_clock_source *right)
{
	const uint16_t *left_priority_list = NULL, *right_priority_list = NULL;
	uint16_t left_priority_count, right_priority_count;
	uint16_t left_ql_priority, right_ql_priority;
	struct synce_clock_source *best = NULL;
	int i;

	left = is_valid_clock_source(left);
	right = is_valid_clock_source(right);

	if (!left && !right) {
		pr_err("both left and right are invalid");
		goto out;
	} else if (!left != !right) {
		best = left ? left : right;
		pr_debug("only one valid source %s",
			 synce_clock_source_get_name(best));
		goto out;
	}

	left_ql_priority = get_clock_source_priority_params(left,
							   &left_priority_list,
							   &left_priority_count);
	right_ql_priority = get_clock_source_priority_params(right,
							    &right_priority_list,
							    &right_priority_count);

	/* the left and right lists should be the same */
	if (left_priority_list != right_priority_list ||
	    left_priority_count != right_priority_count) {
		pr_err("priority lists on compared sources are different");
		return NULL;
	}

	/* we can use either left or right priority list */
	for (i = 0; i < left_priority_count; i++) {
		if (left_priority_list[i] == left_ql_priority) {
			best = left;
			goto out;
		}
		if (left_priority_list[i] == right_ql_priority) {
			best = right;
			goto out;
		}
	}

	pr_debug("didn't found neither of QLs on priorities list");
out:
	if (!best)
		pr_debug("no valid source found");

	return best;
}

uint16_t
get_clock_source_priority_params(struct synce_clock_source *clock_source,
				 const uint16_t **priority_list,
				 uint16_t *priority_count)
{
	if (!clock_source) {
		pr_err("%s clock_source is NULL", __func__);
		return 0;
	}

	if (clock_source->type == PORT) {
		*priority_count = get_priority_params(
				clock_source->port->pc, priority_list);
		return get_ql_priority(clock_source->port->pc);
	}
	*priority_count = get_ext_src_priority_params(
			clock_source->ext_src, priority_list);
	return get_ext_src_ql_priority(clock_source->ext_src);
}
