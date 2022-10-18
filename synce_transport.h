/**
 * @file synce_transport.h
 * @brief Implements the SyncE transport interface.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_TRANSPORT_H
#define HAVE_SYNCE_TRANSPORT_H

#include <stdint.h>

struct synce_transport;
struct ClockIdentity;
struct synce_pdu;

/**
 * Create a SyncE transport.
 *
 * This high level API creates SyncE transport but and initialize it.
 *
 * @param iface	A name of interface to create transport for
 * @return	A SyncE transport structure
 */
struct synce_transport *synce_transport_create(const char *iface);

/**
 * Delete a SyncE transport.
 *
 * This high level API deletes SyncE transport and frees all memory allocations.
 *
 * @param transport	A SyncE transport interface
 */
void synce_transport_delete(struct synce_transport *transport);

/**
 * Send PDU via SyncE transport.
 *
 * @param transport		A SyncE transport interface
 * @param pdu			A pointer to a ESMC SyncE PDU
 * @return			Zero on success, non-zero if failure
 */
int synce_transport_send_pdu(struct synce_transport *transport,
			     struct synce_pdu *pdu);

/**
 * Recv PDU via SyncE transport.
 *
 * @param transport		A SyncE transport interface
 * @param pdu			A pointer to a ESMC SyncE PDU
 * @return			Zero on success, non-zero if failure
 */
int synce_transport_recv_pdu(struct synce_transport *transport,
			     struct synce_pdu *pdu);

#endif
