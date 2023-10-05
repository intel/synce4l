/**
 * @file synce_dev_ctrl.c
 * @brief Interface for acquiring SyncE capable device EEC state changes
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "print.h"
#include "synce_dev_ctrl.h"
#include "dpll_mon.h"

#define EEC_STATE_STR_RETURN_SIZE	0xff

struct synce_dev_ctrl {
	const char *eec_get_state_cmd;
	struct eec_state_str ess;
	struct dpll_mon *dpll_mon;
};

static int eec_str_state_to_enum(struct synce_dev_ctrl *dc, char *str_state,
				  enum eec_state *enum_state)
{
	if (!strncmp(str_state, dc->ess.holdover, EEC_STATE_STR_RETURN_SIZE)) {
		*enum_state = EEC_HOLDOVER;
	} else if (!strncmp(str_state, dc->ess.locked_ho,
			    EEC_STATE_STR_RETURN_SIZE)) {
		*enum_state = EEC_LOCKED_HO_ACQ;
	} else if (!strncmp(str_state, dc->ess.locked,
			    EEC_STATE_STR_RETURN_SIZE)) {
		*enum_state = EEC_LOCKED;
	} else if (!strncmp(str_state, dc->ess.freerun,
			    EEC_STATE_STR_RETURN_SIZE)) {
		*enum_state = EEC_FREERUN;
	} else if (!strncmp(str_state, dc->ess.invalid,
			    EEC_STATE_STR_RETURN_SIZE)) {
		*enum_state = EEC_INVALID;
	} else {
		*enum_state = EEC_UNKNOWN;
	}

	if (*enum_state == EEC_UNKNOWN) {
		pr_err("eec state missing for str_state: '%s'", str_state);
		return -EINVAL;
	}

	return 0;
}

static int get_eec_state_from_cmd(struct synce_dev_ctrl *dc,
				  enum eec_state *state)
{
	char buf[EEC_STATE_STR_RETURN_SIZE] = {0}, *c;
	FILE *fp;
	int ret;

	fp = popen(dc->eec_get_state_cmd, "r");
	if (!fp) {
		pr_err("failed open process: '%s'", dc->eec_get_state_cmd);
		return EEC_UNKNOWN;
	}

	if (!fgets(buf, sizeof(buf), fp)) {
		pr_err("failed read process output: '%s'", dc->eec_get_state_cmd);
		goto out;
	}

	c = buf;
	while (*c != '\0') {
		if (*(++c) == '\n') {
			*c = '\0';
		}
	}

out:
	ret = pclose(fp);
	if (ret) {
		pr_err("process '%s' exit status: %d",
		       dc->eec_get_state_cmd, ret);
	}

	return ret ? EEC_UNKNOWN : eec_str_state_to_enum(dc, buf, state);
}

int synce_dev_ctrl_get_state_from_nl_dpll(struct synce_dev_ctrl *dc,
					  enum eec_state *state)
{
	return dpll_mon_lock_state_get(dc->dpll_mon, state);
}

int synce_dev_ctrl_get_state_from_cmd(struct synce_dev_ctrl *dc,
				      enum eec_state *state)
{
	int ret = -EINVAL;

	if (!dc->eec_get_state_cmd) {
		pr_err("%s: dc->eec_get_state_cmd is NULL", __func__);
		return ret;
	}

	ret = get_eec_state_from_cmd(dc, state);
	if (ret || *state < EEC_INVALID || *state > EEC_HOLDOVER) {
		return ret;
	}

	return 0;
}

int synce_dev_ctrl_get_state(struct synce_dev_ctrl *dc,
			     enum eec_state *state)
{
	int ret = -EINVAL;

	if (!dc) {
		pr_err("%s: dc is NULL", __func__);
		return ret;
	}

	if (!state) {
		pr_err("%s: state is NULL", __func__);
		return ret;
	}

	if (dc->dpll_mon)
		ret = synce_dev_ctrl_get_state_from_nl_dpll(dc, state);
	else
		ret = synce_dev_ctrl_get_state_from_cmd(dc, state);

	return ret;
}

struct synce_dev_ctrl *synce_dev_ctrl_create(void)
{
	struct synce_dev_ctrl *dc = malloc(sizeof(struct synce_dev_ctrl));
	return dc;
}

int synce_dev_ctrl_init(struct synce_dev_ctrl *dc, const char *dev_name,
			const char *eec_get_state_cmd,
			struct eec_state_str *ess, struct dpll_mon *dpll_mon)
{
	if (!dc || !dev_name) {
		return -ENODEV;
	}

	if (dpll_mon) {
		dc->dpll_mon = dpll_mon;
		pr_info("%s: using dpll subsystem", __func__);
		return 0;
	} else {
		pr_info("%s: using legacy mode", __func__);
		dc->dpll_mon = NULL;
	}
	pr_info("%s: using provided commands", __func__);
	if (!eec_get_state_cmd) {
		pr_err("failure: eec_get_state_cmd is NULL on %s", dev_name);
		return -ENXIO;
	}
	if (!ess->holdover) {
		pr_err("failure: ess.holdover is NULL on %s", dev_name);
		return -ENXIO;
	}
	if (!ess->locked_ho) {
		pr_err("failure: ess.locked_ho is NULL on %s", dev_name);
		return -ENXIO;
	}
	if (!ess->locked) {
		pr_err("failure: ess.locked is NULL on %s", dev_name);
		return -ENXIO;
	}
	if (!ess->freerun) {
		pr_err("failure: ess.freerun is NULL on %s", dev_name);
		return -ENXIO;
	}
	if (!ess->invalid) {
		pr_err("failure: ess.invalid is NULL on %s", dev_name);
		return -ENXIO;
	}

	dc->eec_get_state_cmd = eec_get_state_cmd;
	dc->ess = *ess;

	return 0;
}
