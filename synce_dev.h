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

#endif
