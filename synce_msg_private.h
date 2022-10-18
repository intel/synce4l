/**
 * @file synce_msg_private.h
 * @brief Implements the ESMC message private structures.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_MSG_PRIVATE_H
#define HAVE_SYNCE_MSG_PRIVATE_H

/* SyncE Frame */
#define SYNCE_DEST_MACADDR { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 }
#define SYNCE_ETHERTYPE ETH_P_SLOW
#define SYNCE_ETHERSUBTYPE 0x0A
#define SYNCE_ITUOUI { 0x00, 0x19, 0xA7 }
#define SYNCE_ITUOUI_SIZE 3
#define SYNCE_ITUSUBTYPE 0x0001
#define SYNCE_VERSION 1
#define SYNCE_VERSION_SHIFT 4
#define SYNCE_EVENT_SHIFT 4

/* QL TLV */
#define QL_TLV_TYPE 1
#define QL_TLV_LEN 0x4
#define QL_TLV_SSM_MASK 0x0f
#define EXT_QL_TLV_TYPE 2
#define EXT_QL_TLV_LEN 0x14

#include <errno.h>
#include <sys/queue.h>
#include <linux/if_ether.h>

#include "ether.h"

struct macaddr {
	uint8_t addr[MAC_LEN];
} PACKED;

struct ql_tlv {
	uint8_t type;
	uint16_t length;
	uint8_t ssmCode; /* unused:4 | SSM code:4 */
} PACKED;

struct extended_ql_tlv {
	uint8_t type;
	uint16_t length;
	uint8_t enhancedSsmCode;
	struct ClockIdentity clockIdentity;
	uint8_t flag;
	uint8_t cascaded_eEEcs;
	uint8_t cascaded_EEcs;
	uint8_t reserved[5];
} PACKED;

struct esmc_tlv {
	union {
		struct ql_tlv ql_tlv;
		struct extended_ql_tlv extended_ql_tlv;
	};
	TAILQ_ENTRY(esmc_tlv) list;
} PACKED;

struct esmc_header {
	struct macaddr      dstAddr;
	struct macaddr      srcAddr;
	uint16_t            ethertype;
	uint8_t             ethersubtype;
	uint8_t             ituOui[SYNCE_ITUOUI_SIZE]; /* Organizationally Unique Identifier */
	uint16_t            ituSubtype;
	uint8_t             verEvtflag; /* version:4 | event flag:1 | reserved:3 */
	uint8_t             reserved[3];
} PACKED;

struct esmc_data {
	uint8_t buffer[ETH_DATA_LEN];
};

struct synce_pdu {
	union {
		struct esmc_header header;
		struct esmc_data data;
	} PACKED;
	TAILQ_HEAD(ql_tlv_list, esmc_tlv) tlv_list;
};

#endif
