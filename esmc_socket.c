/**
 * @file esmc_socket.c
 * @brief Implements the ESMC socket.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include "print.h"
#include "address.h"
#include "synce_msg.h"
#include "synce_msg_private.h"
#include "esmc_socket.h"

int open_esmc_socket(const char *iface)
{
	unsigned char multicast_macaddr[MAC_LEN] = SYNCE_DEST_MACADDR;
	struct sockaddr_ll addr;
	struct packet_mreq mreq;
	int fd, index, err;

	fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(SYNCE_ETHERTYPE));
	if (fd < 0) {
		pr_err("socket failed: %m");
		return -1;
	}
	index = sk_interface_index(fd, iface);
	if (index < 0) {
		goto no_option;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = index;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(SYNCE_ETHERTYPE);
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_err("bind failed: %m");
		goto no_option;
	}
	err = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface,
			 strnlen(iface, IFNAMSIZ));
	if (err) {
		pr_err("setsockopt SO_BINDTODEVICE failed: %m");
		goto no_option;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = MAC_LEN;
	if (sizeof(mreq.mr_address) * sizeof(mreq.mr_address[0]) <
	    sizeof(multicast_macaddr) * sizeof(multicast_macaddr[0])) {
		pr_err("setting multicast address failed");
		goto no_option;
	}
	memset(mreq.mr_address, 0, sizeof(mreq.mr_address));
	// we need to copy only 6 bytes to mreq.mr_address
	memcpy(mreq.mr_address, multicast_macaddr, sizeof(multicast_macaddr));

	err = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	if (err) {
		pr_warning("setsockopt PACKET_MR_MULTICAST failed: %m");
	}

	return fd;

no_option:
	close(fd);

	return -1;
}

int send_raw_esmc_frame(int socket, void *frame, int frame_len, int ifindex)
{
	struct sockaddr_ll saddrll;
	int ret, frame_size;

	memset(&saddrll, 0, sizeof(saddrll));
	saddrll.sll_ifindex = ifindex;

	frame_size = frame_len > ETH_ZLEN ? frame_len : ETH_ZLEN;
	ret = sendto(socket, frame, frame_size, 0,
		     (struct sockaddr *)&saddrll, sizeof(saddrll));
	if (ret < 0) {
		pr_err("%s failed: %m", __func__);
		return errno;
	}

	return 0;
}

int recv_raw_esmc_frame(int socket, void *buff, size_t buff_len)
{
	return recv(socket, buff, buff_len, 0);
}