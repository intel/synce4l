/**
 * @file synce_clock.h
 * @brief Implements a SyncE clock interface.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_CLOCK_H
#define HAVE_SYNCE_CLOCK_H

#include "config.h"

/* Opaque type */
struct synce_clock;

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

#endif
