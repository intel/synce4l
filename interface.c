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

#define HAS_SYNCE_PARENT (1 << 0)

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

void interface_se_set_parent_dev(struct interface *iface, const char *dev_name)
{
	strncpy(iface->synce_parent_label, dev_name, MAX_IFNAME_SIZE);
	iface->synce_flags |= HAS_SYNCE_PARENT;
}

const char *interface_se_get_parent_dev_label(struct interface *iface)
{
	return iface->synce_parent_label;
}

bool interface_se_has_parent_dev(struct interface *iface)
{
	return !!(iface->synce_flags & HAS_SYNCE_PARENT);
}
