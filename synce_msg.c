/**
 * @file synce_msg.c
 * @brief Implements the ESMC message type.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <stdlib.h>
#include <stdbool.h>
#include <sys/queue.h>

#include "address.h"
#include "util.h"
#include "print.h"
#include "synce_msg.h"
#include "synce_msg_private.h"

static void init_tlvs(struct synce_pdu *pdu)
{
	TAILQ_INIT(&pdu->tlv_list);
}

struct synce_pdu *synce_msg_create(const char *iface)
{
	const unsigned char dstMac[] = SYNCE_DEST_MACADDR;
	const unsigned char ituOui[] = SYNCE_ITUOUI;
	struct synce_pdu *pdu;
	struct address srcMac;

	if (sk_interface_macaddr(iface, &srcMac)) {
		pr_err("mac get failed");
		return NULL;
	}

	pdu = (struct synce_pdu *) malloc(sizeof(struct synce_pdu));
	if (!pdu) {
		pr_err("memory allocation for SyncE PDU failed");
		return NULL;
	}
	memset(pdu, 0, sizeof(struct synce_pdu));
	memcpy(&pdu->header.dstAddr, &dstMac, sizeof(pdu->header.dstAddr));
	pdu->header.ethertype = htons(ETH_P_SLOW);
	pdu->header.ethersubtype = SYNCE_ETHERSUBTYPE;
	memcpy(&pdu->header.ituOui, &ituOui, sizeof(pdu->header.ituOui));
	pdu->header.ituSubtype = htons(SYNCE_ITUSUBTYPE);
	pdu->header.verEvtflag = SYNCE_VERSION << SYNCE_VERSION_SHIFT;
	memset(&pdu->header.reserved, 0, sizeof(pdu->header.reserved));
	memcpy(&pdu->header.srcAddr, &srcMac.sll.sll_addr,
	       sizeof(pdu->header.srcAddr));

	init_tlvs(pdu);

	return pdu;
}

void synce_msg_delete(struct synce_pdu *pdu)
{
	synce_msg_reset_tlvs(pdu);
	free(pdu);
}

static void attach_esmc_tlv(struct synce_pdu *pdu, struct esmc_tlv *tlv)
{
	TAILQ_INSERT_TAIL(&pdu->tlv_list, tlv, list);
}

int synce_msg_get_esmc_tlvs_size(struct synce_pdu *pdu)
{
	struct esmc_tlv *tlv;
	int size = 0;

	TAILQ_FOREACH(tlv, &pdu->tlv_list, list) {
		size += ntohs(tlv->ql_tlv.length);
	}

	return size;
}

static int generate_tlvs(struct synce_pdu *pdu)
{
	struct esmc_tlv *tlv;
	void *cur;
	int size;

	size = synce_msg_get_esmc_tlvs_size(pdu);
	if (ETH_DATA_LEN - ETH_FCS_LEN - size < 0) {
		pr_err("too many tlvs");
		return -EMSGSIZE;
	}

	cur = (void *)pdu + sizeof(struct esmc_header);
	TAILQ_FOREACH(tlv, &pdu->tlv_list, list) {
		size = ntohs(tlv->ql_tlv.length);
		memcpy(cur, tlv, size);
		cur += size;
	}

	return 0;
}

int synce_msg_attach_ql_tlv(struct synce_pdu *pdu, uint8_t ssmCode)
{
	struct esmc_tlv *tlv;

	if (~QL_TLV_SSM_MASK & ssmCode) {
		pr_err("4 upper bits of QL TLV ssmCode should not be used");
		return -EINVAL;
	}

	tlv = malloc(sizeof(struct esmc_tlv));
	if (!tlv) {
		pr_err("malloc failed for TLV: %m");
		return -EINVAL;
	}

	memset(tlv, 0, sizeof(*tlv));
	tlv->ql_tlv.type = QL_TLV_TYPE;
	tlv->ql_tlv.length = htons(QL_TLV_LEN);
	tlv->ql_tlv.ssmCode = ssmCode;

	attach_esmc_tlv(pdu, tlv);

	generate_tlvs(pdu);

	return 0;
}

int synce_msg_get_ql_tlv(struct synce_pdu *pdu, uint8_t *ssmCode)
{
	struct esmc_tlv *tlv;

	if (!pdu || !ssmCode) {
		return -ENXIO;
	}

	TAILQ_FOREACH(tlv, &pdu->tlv_list, list) {
		if (tlv->ql_tlv.type == QL_TLV_TYPE) {
			break;
		}
	}

	if (!tlv) {
		return -EAGAIN;
	}

	*ssmCode = tlv->ql_tlv.ssmCode;

	return 0;
}

int synce_msg_attach_extended_ql_tlv(struct synce_pdu *pdu,
				     struct synce_msg_ext_ql *ext_ql)
{
	struct esmc_tlv *tlv;

	if (!pdu || !ext_ql) {
		pr_err("either pdu or ext_ql not provided");
		return -ENXIO;
	}

	tlv = malloc(sizeof(struct esmc_tlv));
	if (!tlv) {
		pr_err("malloc failed for TLV: %m");
		return -ENOMEM;
	}

	memset(tlv, 0, sizeof(*tlv));
	tlv->extended_ql_tlv.type = EXT_QL_TLV_TYPE;
	tlv->extended_ql_tlv.length = htons(EXT_QL_TLV_LEN);
	tlv->extended_ql_tlv.enhancedSsmCode = ext_ql->enhancedSsmCode;
	memcpy(&tlv->extended_ql_tlv.clockIdentity, &ext_ql->clockIdentity,
	       sizeof(tlv->extended_ql_tlv.clockIdentity));
	tlv->extended_ql_tlv.flag = ext_ql->flag;
	tlv->extended_ql_tlv.cascaded_eEEcs = ext_ql->cascaded_eEEcs;
	tlv->extended_ql_tlv.cascaded_EEcs = ext_ql->cascaded_EEcs;

	attach_esmc_tlv(pdu, tlv);

	generate_tlvs(pdu);

	return 0;
}

int synce_msg_get_extended_ql_tlv(struct synce_pdu *pdu,
				  struct synce_msg_ext_ql *ext_ql)
{
	struct esmc_tlv *tlv;

	if (!pdu || !ext_ql) {
		return -ENXIO;
	}

	TAILQ_FOREACH(tlv, &pdu->tlv_list, list) {
		if (tlv->ql_tlv.type == EXT_QL_TLV_TYPE) {
			break;
		}
	}

	if (!tlv) {
		return -EAGAIN;
	}

	ext_ql->enhancedSsmCode = tlv->extended_ql_tlv.enhancedSsmCode;
	memcpy(&ext_ql->clockIdentity, &tlv->extended_ql_tlv.clockIdentity,
	       sizeof(ext_ql->clockIdentity));
	ext_ql->flag = tlv->extended_ql_tlv.flag;
	ext_ql->cascaded_eEEcs = tlv->extended_ql_tlv.cascaded_eEEcs;
	ext_ql->cascaded_EEcs = tlv->extended_ql_tlv.cascaded_EEcs;

	return 0;
}

void synce_msg_reset_tlvs(struct synce_pdu *pdu)
{
	struct esmc_tlv *tlv, *tlv_temp;

	tlv = TAILQ_FIRST(&pdu->tlv_list);
	while (tlv != NULL) {
		tlv_temp = TAILQ_NEXT(tlv, list);
		free(tlv);
		tlv = tlv_temp;
	}
	init_tlvs(pdu);
}

static bool is_valid_synce_tlv(struct esmc_tlv *tlv)
{
	if (tlv->ql_tlv.type == QL_TLV_TYPE &&
	    ntohs(tlv->ql_tlv.length) == QL_TLV_LEN)
		return true;
	if (tlv->ql_tlv.type == EXT_QL_TLV_TYPE &&
	    ntohs(tlv->ql_tlv.length) == EXT_QL_TLV_LEN)
		return true;
	return false;
}

void synce_msg_recover_tlvs(struct synce_pdu *pdu)
{
	struct esmc_tlv *tlv, *new_tlv;

	if (TAILQ_EMPTY(&pdu->tlv_list)) {
		init_tlvs(pdu);
	}

	synce_msg_reset_tlvs(pdu);

	tlv = (struct esmc_tlv *)((void *)pdu + sizeof(struct esmc_header));
	while (is_valid_synce_tlv(tlv)) {
		new_tlv = malloc(sizeof(struct esmc_tlv));
		if (!new_tlv) {
			pr_err("allocate new_tlv failed");
			return;
		}
		memset(new_tlv, 0, sizeof(*new_tlv));
		/* We copy data from receiving buffer into larger structure. The
		 * TLV size is validated in is_valid_synce_tlv before copying.
		 */
		memcpy(new_tlv, tlv, ntohs(tlv->ql_tlv.length));
		TAILQ_INSERT_TAIL(&pdu->tlv_list, new_tlv, list);
		tlv = (struct esmc_tlv *)((void *)tlv + ntohs(tlv->ql_tlv.length));
	}
}
