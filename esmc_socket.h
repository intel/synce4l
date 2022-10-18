/**
 * @file esmc_socket.h
 * @brief Implements the ESMC socket.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_ESMC_SOCKET_H
#define HAVE_ESMC_SOCKET_H

/**
 * Creates a raw ESMC socket and binds it to given interface.
 *
 * This high level API creates raw socket and binds it to specified
 * interface and binds it to ESMC L2 multicast address. Thanks to
 * those binds we are able to receive frames only on specified interface.
 *
 * @param iface	A name of interface to bind to raw socket
 * @return	A raw socket file descriptor, negative if error occurred
 */
int open_esmc_socket(const char *iface);

/**
 * Sends a raw ESMC frame on given interface.
 *
 * @param socket		A file descriptor of open raw ESMC socket
 * @param frame		A pointer to raw ESMC frame buffer
 * @param frame_len	A size of frame to be sent
 * @return		Zero on success, non-zero if the sending failed
 */
int send_raw_esmc_frame(int socket, void *frame, int frame_len, int ifindex);

/**
 * Receives a raw ESMC frame on given interface.
 *
 * @param socket		A file descriptor of open raw ESMC socket
 * @param buff		A pointer to raw ESMC frame buffer
 * @param buff_len	A buffer size - maximum data to recv
 * @return		Zero on success, non-zero if the reception failed
 */
int recv_raw_esmc_frame(int socket, void *buff, size_t buff_len);

#endif
