/**
 * @file synce_ext_src.c
 * @brief Interface between synce device and ext_src controller module.
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
#include "synce_ext_src.h"
#include "synce_port_ctrl.h"
#include "print.h"
#include "config.h"
#include "synce_msg.h"
#include "nl_dpll.h"

enum ext_src_state {
	EXT_SRC_UNKNOWN = 0,
	EXT_SRC_CREATED,
	EXT_SRC_INITED,
	EXT_SRC_FAILED,
	EXT_SRC_NOT_USED,
};

struct synce_ext_src *synce_ext_src_create(const char *ext_src_name)
{
	struct synce_ext_src *p = NULL;

	if (!ext_src_name) {
		pr_err("%s failed - ext_src_name not provided", __func__);
		return NULL;
	}

	p = malloc(sizeof(struct synce_ext_src));
	if (!p) {
		pr_err("%s failed", __func__);
		return NULL;
	}
	memset(p, 0, sizeof(struct synce_ext_src));
	memcpy(p->name, ext_src_name, sizeof(p->name));
	p->state = EXT_SRC_CREATED;

	return p;
}

int synce_ext_src_init(struct synce_ext_src *ext_src, struct config *cfg,
		       int network_option, int is_extended,
		       struct dpll_mon *dpll_mon)
{
	if (!ext_src) {
		pr_err("%s ext_src is NULL", __func__);
		return -ENODEV;
	}

	if (ext_src->state != EXT_SRC_CREATED)
		goto err_ext_src;

	ext_src->extended = is_extended;
	ext_src->ql = config_get_int(cfg, ext_src->name, "input_QL");
	ext_src->ext_ql = config_get_int(cfg, ext_src->name, "input_ext_QL");

	switch (network_option)	{
	case SYNCE_NETWORK_OPT_1:
		ext_src->priority_list = O1N_priority;
		ext_src->priority_list_count = O1N_PRIORITY_COUNT;
		break;
	case SYNCE_NETWORK_OPT_2:
		ext_src->priority_list = O2N_priority;
		ext_src->priority_list_count = O2N_PRIORITY_COUNT;
		break;
	default:
		pr_err("wrong network option - only 1 and 2 supported");
		goto err_ext_src;
	}

	ext_src->board_label = config_get_string(cfg, ext_src->name, "board_label");
	ext_src->panel_label = config_get_string(cfg, ext_src->name, "panel_label");
	ext_src->package_label = config_get_string(cfg, ext_src->name, "package_label");

	if (dpll_mon) {
		ext_src->pin = dpll_mon_add_pin(dpll_mon, ext_src->board_label,
						ext_src->panel_label,
						ext_src->package_label, 0);
		if (!ext_src->pin) {
			pr_err("could not init pin for ext_src: %s %s %s",
			       ext_src->board_label, ext_src->panel_label,
			       ext_src->package_label);
			goto err_ext_src;
		}
		ext_src->state = EXT_SRC_INITED;
		return 0;
	}
	ext_src->external_enable_cmd =
		config_get_string(cfg, ext_src->name,
				  "external_enable_cmd");
	if (!ext_src->external_enable_cmd) {
		pr_err("external_enable_cmd config not provided for %s",
		       ext_src->name);
		goto err_ext_src;
	}
	ext_src->external_disable_cmd =
		config_get_string(cfg, ext_src->name,
				  "external_disable_cmd");
	if (!ext_src->external_disable_cmd) {
		pr_err("external_disable_cmd config not provided for %s",
		       ext_src->name);
		goto err_ext_src;
	}

	ext_src->state = EXT_SRC_INITED;

	return 0;
err_ext_src:
	ext_src->state = EXT_SRC_FAILED;
	return -ENODEV;
}

void synce_ext_src_destroy(struct synce_ext_src *ext_src)
{
	if (!ext_src) {
		pr_err("%s ext_src is NULL", __func__);
		return;
	}

}

uint16_t get_ext_src_ql_priority(struct synce_ext_src *ext_src)
{
	if (ext_src->extended) {
		return QL_PRIORITY(ext_src->ql,
				   ext_src->ext_ql);
	} else {
		return QL_PRIORITY(ext_src->ql,
				   QL_OTHER_CLOCK_TYPES_ENHSSM);
	}
}

const char *synce_ext_src_get_name(struct synce_ext_src *ext_src)
{
	if (!ext_src) {
		pr_err("%s ext_src is NULL", __func__);
		return NULL;
	}

	return ext_src->name;
}

int synce_ext_src_enable_ext_clock(struct synce_ext_src *ext_src)
{
	if (!ext_src) {
		pr_err("%s ext_src is NULL", __func__);
		return -EINVAL;
	}

	if (!ext_src->external_enable_cmd) {
		pr_err("external_enable_cmd is null on %s", ext_src->name);
		return -EINVAL;
	}

	pr_debug("using external_enable_cmd: %s on %s",
		 ext_src->external_enable_cmd, ext_src->name);

	return system(ext_src->external_enable_cmd);
}

int synce_ext_src_disable_ext_clock(struct synce_ext_src *ext_src)
{
	if (!ext_src) {
		pr_err("%s ext_src is NULL", __func__);
		return -EINVAL;
	}

	if (!ext_src->external_disable_cmd) {
		pr_err("external_disable_cmd is null on %s", ext_src->name);
		return -EINVAL;
	}

	pr_debug("using external_disable_cmd: %s on %s",
		 ext_src->external_disable_cmd, ext_src->name);

	return system(ext_src->external_disable_cmd);
}

uint16_t get_ext_src_priority_params(struct synce_ext_src *ext_src,
			     const uint16_t **priority_list)
{
	*priority_list = ext_src->priority_list;
	return ext_src->priority_list_count;
}

int synce_ext_src_is_active(struct dpll_mon *dpll_mon,
			    struct synce_ext_src *ext_src)
{
	return dpll_mon_pin_is_active(dpll_mon, ext_src->pin);
}

int synce_ext_src_prio_set(struct dpll_mon *dpll_mon,
			   struct synce_ext_src *ext_src, uint32_t prio)
{
	return dpll_mon_pin_prio_set(dpll_mon, ext_src->pin, prio);
}
