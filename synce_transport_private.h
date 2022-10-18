/**
 * @file synce_transport_private.h
 * @brief Implements the SyncE transport private structures.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_TRANSPORT_PRIVATE_H
#define HAVE_SYNCE_TRANSPORT_PRIVATE_H

#include <net/if.h>

struct synce_transport {
	char iface[IFNAMSIZ];
	int iface_index;
	int raw_socket_fd;
};

#endif
