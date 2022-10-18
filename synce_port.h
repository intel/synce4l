/**
 * @file synce_port.h
 * @brief Interface between synce device and port controller module.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_PORT_H
#define HAVE_SYNCE_PORT_H
#include <stdint.h>
#include "util.h"
#include "synce_msg.h"

struct synce_dev;
struct config;

struct synce_port {
	LIST_ENTRY(synce_port) list;
	int sync_mode;
	int state;
	struct synce_port_ctrl *pc;
	uint8_t ql;
	uint8_t ql_dnu;
	uint8_t ql_forced;
	struct synce_msg_ext_ql ext_ql_msg;
	struct synce_msg_ext_ql ext_ql_msg_dnu;
	struct synce_msg_ext_ql ext_ql_msg_forced;
	char name[IF_NAMESIZE];
	char *recover_clock_enable_cmd;
	char *recover_clock_disable_cmd;
};

/**
 * Alloc memory for a single synce_port instance.
 *
 * @param port_name	Human readable name of a port
 * @return		Pointer to allocated instance
 */
struct synce_port *synce_port_create(const char *port_name);

/**
 * Initialize synce device capable port after port was created.
 *
 * @param port			synce_port instance to be initialized
 * @param cfg			Configuration struct based on SYNCE type,
 *				must hold properities of the configured port.
 * @param network_option	Network option that shall be used on the device
 * @param is_extended		If extended tlv support is on
 * @param rx_enabled		If rx of ESMC shall start
 * @param recovery_time		Seconds for period of recovering from QL-failed
 *				state.
 * @param forced_ql		Value of QL when QL is forced for the device,
 *				used in external input mode
 * @param forced_ext_ql		Value of ext QL when QL is forced for the
 *				device,	used in external input mode
 * @return			0 on success, failure otherwise
 */
int synce_port_init(struct synce_port *port, struct config *cfg,
		    int network_option, int is_extended,
		    int rx_enabled, int recovery_time,
		    uint8_t forced_ql, uint8_t forced_ext_ql);

/**
 * Free resource under the synce_port instance. Caller shall free the passed
 * pointer afterwards.
 *
 * @param port		Pointer to the port being released
 */
void synce_port_destroy(struct synce_port *port);

/**
 * Check if port ctrl threads are running.
 *
 * @param port		Questioned port
 * @return		0 if false, otherwise true
 */
int synce_port_thread_running(struct synce_port *port);

/**
 * Check if QL-failed condition is present.
 *
 * @param port		Questioned instance
 * @return		1 if true, 0 if false, negative on failure
 */
int synce_port_rx_ql_failed(struct synce_port *port);

/**
 * Check if QL has changed on RX.
 *
 * @param port		Questioned instance
 * @return		1 if true, 0 if false, negative on failure
 */
int synce_port_rx_ql_changed(struct synce_port *port);

/**
 * Set QL-DNU on TX TLV of associated port.
 *
 * @param port		Managed port
 * @param extended	If new extended TLV shall be created
 * @return		0 on success, negative otherwise
 */
int synce_port_set_tx_ql_dnu(struct synce_port *port, int extended);

/**
 * Set QL from config file on TX TLV of associated port. Useful in
 * external_input scenario.
 *
 *
 * @param port		Managed port
 * @param extended      If new extended TLV shall be created
 * @return		0 on success, negative otherwise
 */
int synce_port_set_tx_ql_forced(struct synce_port *port, int extended);

/**
 * Set QL for TX thread - but copy QL from best port.
 *
 * @param port		Managed instance
 * @param best_p	Best port instance
 * @param extended	If new extended TLV shall be created
 * @return		0 on success, negative on failure
 */
int synce_port_set_tx_ql_from_best_input(struct synce_port *port,
					 struct synce_port *best_p,
					 int extended);

/**
 * Check if given port has Do Not Use QL.
 *
 * @param port		Questioned instance
 * @return		1 if DNU is present, 0 if not, negative on failure
 */
int synce_port_is_rx_dnu(struct synce_port *port);

/**
 * Compare left with right port, which has higher incoming Quality Level.
 *
 * @param left		Port instance for comparison
 * @param righ		Port instance for comparison
 * @return		Pointer to best QL instance, NULL on failure or equal
 */
struct synce_port *synce_port_compare_ql(struct synce_port *left,
					 struct synce_port *right);

/**
 * Get name of a port.
 *
 * @param port		Questioned instance
 * @return		Name of a port
 */
const char *synce_port_get_name(struct synce_port *port);

/**
 * Enable recover clock on a port.
 *
 * @param port		Questioned instance
 * @return		0 on success, negative on failure
 */
int synce_port_enable_recover_clock(struct synce_port *port);

/**
 * Enable recover clock on a port.
 *
 * @param port		Questioned instance
 * @return		0 on success, negative on failure
 */
int synce_port_disable_recover_clock(struct synce_port *port);

/**
 * Invalidate QL received on the port in the past.
 *
 * @param port		Questioned instance
 */
void synce_port_invalidate_rx_ql(struct synce_port *port);

#endif /* HAVE_SYNCE_PORT_H */
