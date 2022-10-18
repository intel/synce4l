/**
 * @file synce_port_ctrl.h
 * @brief Interface between synce port and socket handling theads, used
 * for controling data on the wire. Allows acquire incoming data and
 * submit new outgoing data.
 * TX thread is always present, RX only if required (line input mode).
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNC_PORT_CTRL_H
#define HAVE_SYNC_PORT_CTRL_H
#include <stdint.h>

/* Opaque types */
struct synce_port_ctrl;
struct config;
struct synce_msg_ext_ql;

/**
 * Check if created threads are running.
 *
 * @param pc		Questioned instance
 * @return		1 if true, 0 if false, negative on failure
 */
int synce_port_ctrl_running(struct synce_port_ctrl *pc);

/**
 * Stop threads, deinit given instance.
 *
 * @param pc		Managed instance
 * @return		0 on success, otherwise fault
 */
int synce_port_ctrl_destroy(struct synce_port_ctrl *pc);

/**
 * Check if QL-failed condition is present.
 *
 * @param pc		Questioned instance
 * @return		1 if true, 0 if false, negative on failure
 */
int synce_port_ctrl_rx_ql_failed(struct synce_port_ctrl *pc);

/**
 * Check if Do Not Use QL is present on a port.
 *
 * @param pc		Questioned instance
 * @param dnu		Value to compare against
 * @return		1 if true, 0 if false, negative on failure
 */
int synce_port_ctrl_rx_dnu(struct synce_port_ctrl *pc, uint8_t dnu);

/**
 * Check if QL has changed on RX.
 *
 * @param pc		Questioned instance
 * @return		1 if true, 0 if false, negative on failure
 */
int synce_port_ctrl_rx_ql_changed(struct synce_port_ctrl *pc);

/**
 * Check if extended TLV was acquired on RX wire.
 *
 * @param pc		Questioned instance
 * @return		1 if true, 0 if false, negative on failure
 */
int synce_port_ctrl_rx_ext_tlv(struct synce_port_ctrl *pc);

/**
 * Acquire last QL on the RX wire.
 *
 * @param pc		Questioned instance
 * @param ql		Returned QL
 * @return		0 on success, negative on failure
 */
int synce_port_ctrl_get_rx_ql(struct synce_port_ctrl *pc, uint8_t *ql);

/**
 * Acquire last extended QL on the RX wire.
 *
 * @param pc		Questioned instance
 * @param ext_ql	Returned extended QL struct
 * @return		0 on success, negative on failure
 */
int synce_port_ctrl_get_rx_ext_ql(struct synce_port_ctrl *pc,
				  struct synce_msg_ext_ql *ext_ql);

/**
 * Set QL for TX thread.
 *
 * @param pc		Managed instance
 * @param ql		QL to be sent
 * @return		0 on success, negative on failure
 */
int synce_port_ctrl_set_tx_ql(struct synce_port_ctrl *pc, uint8_t ql);

/**
 * Set extended QL for TX thread.
 *
 * @param pc		Managed instance
 * @param ext_ql	Extended QL to be sent
 * @return		0 on success, negative on failure
 */
int synce_port_ctrl_set_tx_ext_ql(struct synce_port_ctrl *pc,
				  struct synce_msg_ext_ql *ext_ql);
/**
 * Whenever new QL was set for TX thread, rebuild must be invoked explicitly.
 *
 * @param pc		Managed instance
 * @return		0 on success, negative on failure
 */
int synce_port_ctrl_rebuild_tx(struct synce_port_ctrl *pc);

/**
 * Explicit start sending QL that was set for TX thread, used once init and set
 * QL are finished.
 *
 * @param pc		Managed instance
 * @return		0 on success, negative on failure
 */
int synce_port_ctrl_enable_tx(struct synce_port_ctrl *pc);

/**
 * Check if sources given port sources are valid, than compare them,
 * choose the one with higher priority in terms of its received QL.
 *
 * @param left			Port instance for comparison
 * @param right			Port instance for comparison
 * @return			Pointer to a higher quality input port instance,
 *				NULL on failure or equal
 */
struct synce_port_ctrl
*synce_port_ctrl_compare_ql(struct synce_port_ctrl *left,
			    struct synce_port_ctrl *right);

/**
 * Initialize given instance with the given config.
 *
 * @param pc			Instance to be initialized
 * @param cfg			Configuration of SYNCE type
 * @param rx_enabled		If RX thread shall also start
 * @param extended_tlv		If extended tlv was enabled
 * @param recover_time		What time was set for recovery [s]
 * @param network_option	Network option, either 0 or 1
 * @return			0 on success, otherwise fail
 */
int synce_port_ctrl_init(struct synce_port_ctrl *pc, struct config *cfg,
			 int rx_enabled, int extended_tlv, int recover_time,
			 int network_option);

/**
 * Create instance and set name of its port.
 *
 * @param name		Port name
 * @return		Pointer to allocated instance
 */
struct synce_port_ctrl *synce_port_ctrl_create(const char *name);

/**
 * Invalidate QL received in the past.
 *
 * @param pc		Port control instance
 */
void synce_port_ctrl_invalidate_rx_ql(struct synce_port_ctrl *pc);

#endif /* HAVE_SYNC_PORT_CTRL_H */
