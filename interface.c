/**
 * @file interface.c
 * @brief Implements network interface data structures.
 * @note SPDX-FileCopyrightText: 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 *
 * This code is based on the fragments from the linuxptp project.
 */
#include <stdlib.h>
#include "interface.h"

struct interface {
	STAILQ_ENTRY(interface) list;
	char name[MAX_IFNAME_SIZE + 1];
	char synce_parent_label[MAX_IFNAME_SIZE + 1];
	int synce_flags;
};

struct interface *interface_create(const char *name)
{
	struct interface *iface;

	iface = calloc(1, sizeof(struct interface));
	if (!iface) {
		return NULL;
	}
	strncpy(iface->name, name, MAX_IFNAME_SIZE);

	return iface;
}

void interface_destroy(struct interface *iface)
{
	free(iface);
}

const char *interface_name(struct interface *iface)
{
	return iface->name;
}
