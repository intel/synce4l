/**
 * @file synce_clock.h
 * @brief Implements a SyncE clock interface.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_CLOCK_H
#define HAVE_SYNCE_CLOCK_H

#include <stdint.h>
#include "config.h"

/* Opaque type */
struct synce_clock;
struct synce_dev;

/**
 * Create a SyncE clock instance.
 *
 * @param cfg	Pointer to the SYNCE-type configuration database
 * @return	Pointer to the single global SyncE clock instance
 */
struct synce_clock *synce_clock_create(struct config *cfg);

/**
 * Destroy resources associated with the synce clock.
 *
 * @param clk	Pointer to synce_clock instance
 */
void synce_clock_destroy(struct synce_clock *clk);

/**
 * Poll for synce events and dispatch them.
 *
 * @param clk	A pointer to a synce_clock instance obtained with
 *		synce_clock_create().
 * @return	Zero on success, non-zero otherwise
 */
int synce_clock_poll(struct synce_clock *clk);

/**
 * return device instance from clock.
 *
 * @param clk		Questioned instance
 * @param dev_name	dev_name to search
 * @param dev		on return, return pointer to dev instance
 * @return		0 if found or -1 if not found
 */
int synce_clock_get_dev(struct synce_clock *clk, char *dev_name,
			struct synce_dev **dev);

/**
 * return socket path of clock.
 *
 * @param clk		Questioned instance
 * @return		socket_path name
 */
char *synce_clock_get_socket_path(struct synce_clock *clk);
#endif
