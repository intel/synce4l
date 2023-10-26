/**
 * @file synce_dev.h
 * @brief Interface for handling SyncE capable devices and its ports
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_DEV_H
#define HAVE_SYNCE_DEV_H

#include <stdint.h>

#define SYNCE_DEV_STEP_WAITING		1

struct config;
struct synce_dev;

/**
 * Initialize SyncE device and its ports after device was created.
 *
 * @param dev	Device to be initialized
 * @param cfg	Configuration struct based on SYNCE type, must hold
 *		properities of configured device ports
 * @return	0 on success, failure otherwise
 */
int synce_dev_init(struct synce_dev *dev, struct config *cfg);

/**
 * Alloc memory for a single SyncE device.
 *
 * @param dev_name	Human readable name of a device
 * @return		0 on success, failure otherwise
 */
struct synce_dev *synce_dev_create(const char *dev_name);

/**
 * Step a SyncE device. Probe for events, changes and act on them.
 *
 * @param dev	Device to be stepped
 * @return	0 on success, failure otherwise
 */
int synce_dev_step(struct synce_dev *dev);

/**
 * Acquire SyncE device name.
 *
 * @param dev   Questioned SyncE device instance
 * @return	The device name
 */
const char *synce_dev_name(struct synce_dev *dev);

/**
 * Clean-up on memory allocated for device and its ports.
 *
 * @param dev	SyncE device to be cleared
 */
void synce_dev_destroy(struct synce_dev *dev);

/**
 * Check if SyncE device is running.
 *
 * @param dev	Questioned SyncE device
 * @return	0 if false, 1 if true
 */
int synce_dev_is_running(struct synce_dev *dev);

/**
 * Return QL of the device.
 *
 * @param dev		Questioned SyncE device
 * @param ql		on return, return the current QL of device
 */
void synce_dev_get_ql(struct synce_dev *dev, uint8_t *ql);

/**
 * Return EXT_QL of the device.
 *
 * @param dev		Questioned SyncE device
 * @param ext_ql	on return, return the current EXT_QL of device
 */
void synce_dev_get_ext_ql(struct synce_dev *dev, uint8_t *ext_ql);

/**
 * checks if external clock source exists.
 *
 * @param dev		related device
 * @param ext_src_name	on success, returns the name of external clock source
 *			specified in command
 *
 * @return		0 on success or -1 on bad command
 */
int synce_dev_check_ext_src_name(struct synce_dev *dev, char *ext_src_name);

/**
 * Set QL or EXT_QL of external clock source of device.
 *
 * @param dev		SyncE device to configure
 * @param ext_src_name	Name of the external clock source to configure
 * @param extended	if extended = 0 set QL, otherwise set EXT_QL
 * @param ql		new QL/EXT_QL value
 */
void synce_dev_set_ext_src_ql(struct synce_dev *dev, char *ext_src_name,
			      int extended, int ql);

/**
 * Get name of a device.
 *
 * @param device	Questioned instance
 * @return		Name of a device
 */
const char *synce_dev_get_name(struct synce_dev *dev);
#endif
