/**
 * @file synce_msg.h
 * @brief Implements the ESMC message type.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_MSG_H
#define HAVE_SYNCE_MSG_H

#define SYNCE_NETWORK_OPT_1		1
#define SYNCE_NETWORK_OPT_2		2

/* Enhanced SSM codes for SyncE */
#define QL_EEC1_ENHSSM			0xFF
#define QL_EEC2_ENHSSM			0xFF
#define QL_OTHER_CLOCK_TYPES_ENHSSM	0xFF
#define QL_PRTC_ENHSSM			0x20
#define QL_ePRTC_ENHSSM			0x21
#define QL_eEEC_ENHSSM			0x22
#define QL_ePRC_ENHSSM			0x23

/* SSM codes and enhanced SSM codes for SyncE in option 1 networks */
#define O1N_QL_PRC_SSM			0x2
#define O1N_QL_PRC_ENHSSM		0xFF
#define O1N_QL_SSU_A_SSM		0x4
#define O1N_QL_SSU_A_ENHSSM		0xFF
#define O1N_QL_SSU_B_SSM		0x8
#define O1N_QL_SSU_B_ENHSSM		0xFF
#define O1N_QL_EEC1_SSM			0xB
#define O1N_QL_EEC1_ENHSSM		0xFF
#define O1N_QL_DNU_SSM			0xF
#define O1N_QL_DNU_ENHSSM		0xFF
#define O1N_QL_PRTC_SSM			0x2
#define O1N_QL_PRTC_ENHSSM		0x20
#define O1N_QL_EPRTC_SSM		0x2
#define O1N_QL_EPRTC_ENHSSM		0x21
#define O1N_QL_EEEC_SSM			0xB
#define O1N_QL_EEEC_ENHSSM		0x22
#define O1N_QL_EPRC_SSM			0x2
#define O1N_QL_EPRC_ENHSSM		0x23

/* SSM codes and enhanced SSM codes for SyncE in option 2 networks */
#define O2N_QL_PRS_SSM			0x1
#define O2N_QL_PRS_ENHSSM		0xFF
#define O2N_QL_STU_SSM			0x0
#define O2N_QL_STU_ENHSSM		0xFF
#define O2N_QL_ST2_SSM			0x7
#define O2N_QL_ST2_ENHSSM		0xFF
#define O2N_QL_TNC_SSM			0x4
#define O2N_QL_TNC_ENHSSM		0xFF
#define O2N_QL_ST3E_SSM			0xD
#define O2N_QL_ST3E_ENHSSM		0xFF
#define O2N_QL_ST3_SSM			0xA
#define O2N_QL_ST3_ENHSSM		0xFF
#define O2N_QL_EEC2_SSM			0xA
#define O2N_QL_EEC2_ENHSSM		0xFF
#define O2N_QL_PROV_SSM			0xE
#define O2N_QL_PROV_ENHSSM		0xFF
#define O2N_QL_DUS_SSM			0xF
#define O2N_QL_DUS_ENHSSM		0xFF
#define O2N_QL_PRTC_SSM			0x1
#define O2N_QL_PRTC_ENHSSM		0x20
#define O2N_QL_EPRTC_SSM		0x1
#define O2N_QL_EPRTC_ENHSSM		0x21
#define O2N_QL_EEEC_SSM			0xA
#define O2N_QL_EEEC_ENHSSM		0x22
#define O2N_QL_EPRC_SSM			0x1
#define O2N_QL_EPRC_ENHSSM		0x23

/* Flags as defined in SyncE specification */
#define MIXED_EEC_CHAIN_FLAG		(1 << 0)
#define PARTIAL_EEC_CHAIN_FLAG		(1 << 1)

/* 5 seconds is a period defined by standard for QL-failed state */
#define QL_FAILED_PERIOD_SEC		5

struct synce_msg_ext_ql {
	uint8_t enhancedSsmCode;
	struct ClockIdentity clockIdentity;
	uint8_t flag;
	uint8_t cascaded_eEEcs;
	uint8_t cascaded_EEcs;
};

/**
 * Create a ESMC Protocol Data Unit (PDU) template.
 *
 * This high level API creates structure for storing ESMC PDU and
 * initializes TLV vector for conveniently storing and processing
 * TLV structures (esmc_tlv). All the fields are stored in network
 * byte ordering.
 *
 * @param iface	A name of interface to create prepopulated template for
 * @return	A pointer to a ESMC SyncE PDU prepopulated template
 */
struct synce_pdu *synce_msg_create(const char *iface);

/**
 * Delete a ESMC Protocol Data Unit (PDU) from memory.
 *
 * This high level API frees all the memory stored in TLV vector and
 * then free ESMC PDU itself.
 *
 * @param pdu	A pointer to a ESMC SyncE PDU
 */
void synce_msg_delete(struct synce_pdu *pdu);

/**
 * Attach QL TLV to SyncE PDU.
 *
 * @param pdu		A pointer to a ESMC SyncE PDU
 * @param ssmCode	SSM Code of newly created QL TLV
 * @return		Zero on success, non-zero if failure
 */
int synce_msg_attach_ql_tlv(struct synce_pdu *pdu, uint8_t ssmCode);

/**
 * Get QL TLVs SSM Code from SyncE PDU.
 *
 * @param pdu			A pointer to a ESMC SyncE PDU
 * @param ssmCode		SSM Code variable to store
 * @return			Zero on success, non-zero if failure
 */
int synce_msg_get_ql_tlv(struct synce_pdu *pdu, uint8_t *ssmCode);

/**
 * Attach Extended QL TLV to SyncE PDU.
 *
 * @param pdu			A pointer to a ESMC SyncE PDU
 * @param enhancedSsmCode	Enhanced SSM Code of newly created QL TLV
 * @param clockIdentity		SyncE clockIdentity of the originator of the extended QL TLV
 * @param flag			Flag (see ITU-T G.8264)
 * @param cascaded_eEEcs		Number of cascaded eEECs from the nearest SSU/PRC/ePRC
 * @param cascaded_EEcs		Number of cascaded EECs from the nearest SSU/PRC/ePRC
 * @return			Zero on success, non-zero if failure
 */
int synce_msg_attach_extended_ql_tlv(struct synce_pdu *pdu,
				     struct synce_msg_ext_ql *ext_ql);

/**
 * Get QL Extended TLVs from SyncE PDU in.
 *
 * @param pdu			A pointer to a ESMC SyncE PDU
 * @param ext_ql			A pointer to Extended Quality level
 * @return			Zero on success, non-zero if failure
 */
int synce_msg_get_extended_ql_tlv(struct synce_pdu *pdu,
				  struct synce_msg_ext_ql *ext_ql);

/**
 * Reset (clear and reinitialize) all the TLV vector entries.
 *
 * @param pdu	A pointer to a ESMC SyncE PDU
 */
void synce_msg_reset_tlvs(struct synce_pdu *pdu);

/**
 * Recover TLVs from ESMC frame into TLV vector entries in PDU structure.
 *
 * @param pdu	A pointer to a ESMC SyncE PDU
 */
void synce_msg_recover_tlvs(struct synce_pdu *pdu);

/**
 * Returns the size of TLV vector entries in PDU.
 *
 * @param pdu	A pointer to a ESMC SyncE PDU
 * @return	Number of bytes of all TLV entries attached to PDU
 */
int synce_msg_get_esmc_tlvs_size(struct synce_pdu *pdu);

#endif
