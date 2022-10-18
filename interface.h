/**
 * @file interface.h
 * @brief Implements network interface data structures.
 * @note SPDX-FileCopyrightText: 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 *
 * This code is based on the fragments from the linuxptp project.
 */
#ifndef HAVE_INTERFACE_H
#define HAVE_INTERFACE_H

#include<string.h>
#include <stdbool.h>
#include <sys/queue.h>

#define MAX_IFNAME_SIZE 108 /* = UNIX_PATH_MAX */

#if (IF_NAMESIZE > MAX_IFNAME_SIZE)
#error if_namesize larger than expected.
#endif

/** Opaque type */
struct interface;

/**
 * Creates an instance of an interface.
 * @param name  The device which indentifies this interface.
 * @return      A pointer to an interface instance on success, NULL otherwise.
 */
struct interface *interface_create(const char *name);

/**
 * Destroys an instance of an interface.
 * @param iface  A pointer obtained via interface_create().
 */
void interface_destroy(struct interface *iface);

/**
 * Obtains the name of a network interface.
 * @param iface  The interface of interest.
 * @return       The device name of the network interface.
 */
const char *interface_name(struct interface *iface);

#endif
