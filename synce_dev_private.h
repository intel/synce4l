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

struct synce_dev_ops {
	int (*update_ql)(struct synce_dev *dev);
	int (*step)(struct synce_dev *dev);
};

enum synce_dev_state {
	DEVICE_UNKNOWN,
	DEVICE_CREATED,
	DEVICE_INITED,
	DEVICE_RUNNING,
	DEVICE_FAILED,
};

enum synce_input_mode {
	INPUT_MODE_LINE,
	INPUT_MODE_EXTERNAL
};

struct synce_dev {
	LIST_ENTRY(synce_dev) list;
	enum synce_dev_state state;
	char name[IF_NAMESIZE];
	LIST_HEAD(synce_ports_head, synce_port) ports;
	struct synce_port *best_source;
	int num_ports;
	int input_mode;
	int network_option;
	uint8_t ql;
	uint8_t ext_ql;
	int extended_tlv;
	int recover_time;
	enum eec_state d_state;
	enum eec_state last_d_state;
	struct synce_dev_ctrl *dc;
	struct synce_dev_ops ops;
};

#endif
