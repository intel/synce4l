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
#include  "dpll_mon.h"

struct synce_dev;
struct config;
struct dpll_mon_pin;

struct synce_port {
	int sync_mode;
	int state;
	struct synce_port_ctrl *pc;
	uint8_t ql;
	uint8_t ql_dnu;
	uint8_t ql_forced;
	int ql_failed;
	struct synce_msg_ext_ql ext_ql_msg;
	struct synce_msg_ext_ql ext_ql_msg_dnu;
	struct synce_msg_ext_ql ext_ql_msg_forced;
	char name[IF_NAMESIZE];
	char *recover_clock_enable_cmd;
	char *recover_clock_disable_cmd;
	struct dpll_mon_pin *pin;
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
 * @param recovery_time		Seconds for period of recovering from QL-failed
 *				state.
 * @param dpll_mon		valid pointer if dpll subsystem is used
 * @return			0 on success, failure otherwise
 */
int synce_port_init(struct synce_port *port, struct config *cfg,
		    int network_option, int is_extended, int recovery_time,
		    struct dpll_mon *dpll_mon);

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
 * Check if RX QL is in state that requires to rebuild priorities for a dpll
 * device on a dpll subsystem.
 *
 * @param port		Questioned instance
 * @return		1 if true, 0 if false, negative on failure
 */
int synce_port_rx_ql_require_prio_rebuild(struct synce_port *port);

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

/**
 * check if port is an active dpll's input
 *
 * @param dpll_mon	Pointer to dpll_mon class
 * @param port		Questioned instance
 * @return		0 - not active, 1 - active
 */
int synce_port_is_active(struct dpll_mon *dpll_mon, struct synce_port *port);

/**
 * request to set priority of a port pin on a dpll, if pin is muxed
 * and priority != dnu_prio, then set the priority on the parent and change pin
 * state (with the parent) to CONNECTED as long as there is not yet used parent
 * (configured with prio == dnu_prio)
 *
 * @param dpll_mon	Pointer to dpll_mon class
 * @param port		Configured instance
 * @param prio		Priority value to be set
 * @return		0 - success, error code - failure
 */
int synce_port_prio_set(struct dpll_mon *dpll_mon, struct synce_port *port,
			uint32_t prio);

#endif /* HAVE_SYNCE_PORT_H */
