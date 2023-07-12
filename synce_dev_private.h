/**
 * @file synce_dev_private.h
 * @brief Implements the SyncE capable devices and its ports private structures.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */

#ifndef HAVE_SYNCE_DEV_PRIVATE_H
#define HAVE_SYNCE_DEV_PRIVATE_H


struct interface {
	STAILQ_ENTRY(interface) list;
};

enum synce_dev_state {
	DEVICE_UNKNOWN,
	DEVICE_CREATED,
	DEVICE_INITED,
	DEVICE_RUNNING,
	DEVICE_FAILED,
};

struct synce_dev {
	LIST_ENTRY(synce_dev) list;
	enum synce_dev_state state;
	char name[IF_NAMESIZE];
	int num_ports;
	bool ext_src_is_best;
	LIST_HEAD(synce_clock_sources_head, synce_clock_source) clock_sources;
	struct synce_clock_source *best_source;
	int num_clock_sources;
	int network_option;
	uint8_t ql;
	uint8_t ext_ql;
	int extended_tlv;
	int recover_time;
	enum eec_state d_state;
	enum eec_state last_d_state;
	struct synce_dev_ctrl *dc;
};

#endif
