/**
 * @file synce_dev_ctrl.h
 * @brief Interface for acquiring SyncE capable device EEC state changes
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_DEV_CTRL_H
#define HAVE_SYNCE_DEV_CTRL_H

struct dpll_mon;

/* possible EEC states */
enum eec_state {
	EEC_UNKNOWN = -1,
	EEC_INVALID,
	EEC_FREERUN,
	EEC_LOCKED,
	EEC_LOCKED_HO_ACQ,
	EEC_HOLDOVER,
};

/* possibe EEC state strings */
struct eec_state_str {
	const char *holdover;
	const char *locked_ho;
	const char *locked;
	const char *freerun;
	const char *invalid;
};

/* Opaque type */
struct synce_dev_ctrl;

/**
 * Acquire current state of EEC of SyncE capable device.
 *
 * @param dc		Instance of EEC device controller
 * @param state		State acquired from the device
 * @return		Zero on success, non-zero if failure
 */
int synce_dev_ctrl_get_state(struct synce_dev_ctrl *dc,
			     enum eec_state *state);

/**
 * Initialize EEC device controller instance.
 *
 * @param dc			Instance of EEC device controller to be
 *				initialized
 * @param dev_name		Name of device
 * @param eec_get_state_cmd	A command to obtain current eec state
 * @param ess			Pointer to a struct holding valid eec state
 *				strings
 * @dpll_mon			Pointer do dpll_mon class
 * @return			Zero on success, non-zero if failure
 */
int synce_dev_ctrl_init(struct synce_dev_ctrl *dc, const char *dev_name,
			const char *eec_get_state_cmd,
			struct eec_state_str *ess,
			struct dpll_mon *dpll_mon);

/**
 * Allocate memory for a single EEC device controller instance.
 *
 * @return	Pointer to allocated instance or NULL if allocation failed
 */
struct synce_dev_ctrl *synce_dev_ctrl_create(void);

#endif /* HAVE_SYNCE_DEV_CTRL_H */
