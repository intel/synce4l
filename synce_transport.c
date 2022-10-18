/**
 * @file synce_transport.c
 * @brief Implements the SyncE transport interface.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <errno.h>
#include <stdio.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include "print.h"
#include "synce_msg.h"
#include "synce_msg_private.h"
#include "esmc_socket.h"
#include "synce_transport.h"
#include "synce_transport_private.h"

struct synce_transport *synce_transport_create(const char *iface)
{
	struct synce_transport *transport;

	transport = malloc(sizeof(struct synce_transport));
	if (!transport) {
		pr_err("transport creation in SyncE failed");
		return NULL;
	}

	if (snprintf(transport->iface, IFNAMSIZ, "%s", iface) >= IFNAMSIZ) {
		pr_err("interface name too long");
		goto err;
	}

	transport->raw_socket_fd = open_esmc_socket(iface);
	if (transport->raw_socket_fd < 0) {
		pr_err("socket creation in SyncE transport failed");
		goto err;
	}

	transport->iface_index = sk_interface_index(transport->raw_socket_fd,
						    iface);
	if (transport->iface_index < 0) {
		goto err_socket;
	}

	return transport;

err_socket:
	close(transport->raw_socket_fd);
err:
	free(transport);

	return NULL;
}

void synce_transport_delete(struct synce_transport *transport)
{
	close(transport->raw_socket_fd);
	free(transport);
}

int synce_transport_send_pdu(struct synce_transport *transport,
			     struct synce_pdu *pdu)
{
	int tlvs_size, pdu_size;

	tlvs_size = synce_msg_get_esmc_tlvs_size(pdu);

	pdu_size = sizeof(pdu->header) + tlvs_size;

	if (send_raw_esmc_frame(transport->raw_socket_fd, (void *)pdu,
				pdu_size, transport->iface_index)) {
		return -EIO;
	}

	return 0;
}

int synce_transport_recv_pdu(struct synce_transport *transport,
			     struct synce_pdu *pdu)
{
	int ret;

	synce_msg_reset_tlvs(pdu);

	ret = recv_raw_esmc_frame(transport->raw_socket_fd, &pdu->data,
				  sizeof(pdu->data));
	if (ret < 0) {
		return -EAGAIN;
	} else if (ret > 0 && ret < ETH_ZLEN) {
		pr_err("%s failed: received only %i bytes", __func__, ret);
		return -EBADMSG;
	}

	synce_msg_recover_tlvs(pdu);

	return 0;
}
