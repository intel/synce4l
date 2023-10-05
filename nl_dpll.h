/**
 * @file nl_dpll.c
 * @brief Header for netlink dpll communication class
 * @note SPDX-FileCopyrightText: Copyright 2023 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */

#ifndef HAVE_NL_DPLL_H
#define HAVE_NL_DPLL_H

#ifdef CONFIG_DPLL
#include <linux/dpll.h>
#else
#include "headers/dpll.h"
#endif
#include "print.h"
#include "synce_dev_ctrl.h"
#include <netlink/socket.h>
#include <netlink/handlers.h>

/**
 * socket handler functions arguments
 *
 * @param err	internal socket handling - indicates error
 * @param done	internal socket handling - indicates msg received
 * @param arg	private data pointer callback function can use
 */
struct sk_arg {
	int err;
	int done;
	void *arg;
};

/**
 * Create netlink socket for dpll subsystem.
 *
 * @param cb	callback function parsing the valid responses
 * @param arg	arguments for the callback
 * @return:	socket - succes, NULL - failure
 */
struct nl_sock *nl_dpll_sk_create(nl_recvmsg_msg_cb_t cb, struct sk_arg *arg);

/**
 * Destroy dpll subsystem netlink socket.
 *
 * @param sk	socket to destroy
 */
void nl_dpll_sk_destroy(struct nl_sock *sk);

/**
 * Resolve dpll subsystem family id from the dpll subsystem socket.
 *
 * @param sk	dpll subsystem socket
 * @return:	positive - family id, 0 or negative - failure
 */
int nl_dpll_family_resolve(struct nl_sock *sk);

/**
 * Send netlink `do` request with DPLL_CMD_DEVICE_ID_GET command to dpll
 * over given socket.
 *
 * @param sk		dpll subsystem socket
 * @param arg		pointer to callback argument
 * @param family	resolved dpll family id
 * @param clock_id	searched clock_id
 * @param module_name	searched module_name
 * @return:		0 - success, negative - failure
 */
int nl_dpll_device_id_get(struct nl_sock *sk, struct sk_arg *arg,
			  int family, uint64_t clock_id,
			  const char *module_name);

/**
 * Send netlink `do` request with DPLL_CMD_DEVICE_GET command to dpll
 * over given socket.
 *
 * @param sk		dpll subsystem socket
 * @param arg		pointer to callback argument
 * @param family	resolved dpll family id
 * @param dpll_id	id of device to perform get command
 * @return:		0 - success, negative - failure
 */
int nl_dpll_device_get(struct nl_sock *sk, struct sk_arg *arg,
		       int family, uint32_t dpll_id);

/**
 * Send netlink `do` request with DPLL_CMD_PIN_ID_GET command to dpll
 * over given socket.
 *
 * @param sk		dpll subsystem socket
 * @param arg		pointer to callback argument
 * @param family	resolved dpll family id
 * @param clock_id	searched clock_id
 * @param module_name	searched module_name
 * @param board_label	searched board_label
 * @param panel_label	searched panel_label
 * @param package_label	searched package_label
 * @param type		searched type
 * @return:		0 - success, negative - failure
 */
int nl_dpll_pin_id_get(struct nl_sock *sk, struct sk_arg *arg,
		       int family, uint64_t clock_id, const char *module_name,
		       const char *board_label, const char *panel_label,
		       const char *package_label, enum dpll_pin_type type);

/**
 * Send netlink `do` request with DPLL_CMD_PIN_GET command to dpll
 * over given socket.
 *
 * @param sk		dpll subsystem socket
 * @param arg		pointer to callback argument
 * @param family	resolved dpll family id
 * @param pin_id	searched pin_id
 * @return:		0 - success, negative - failure
 */
int nl_dpll_pin_get(struct nl_sock *sk, struct sk_arg *arg,
		    int family, uint32_t pin_id);

/**
 * Send netlink `dump` request with DPLL_CMD_PIN_GET command to dpll
 * over given socket.
 *
 * @param sk		dpll subsystem socket
 * @param arg		pointer to callback argument
 * @param family	resolved dpll family id
 * @return:		0 - success, negative - failure
 */
int nl_dpll_pin_dump(struct nl_sock *sk, struct sk_arg *arg,
		     int family);

/**
 * Send netlink `do` request with DPLL_CMD_PIN_SET command to dpll
 * over given socket. Set given priority for a given pin.
 *
 * @param sk		dpll subsystem socket
 * @param family	resolved dpll family id
 * @param pin_id	id of pin being configured
 * @param dev_id	device id to set priority on
 * @param prio		requested prio value
 * @return:		0 - success, negative - failure
 */
int nl_dpll_pin_prio_set(struct nl_sock *sk, int family,
			 uint32_t pin_id, uint32_t dev_id,
			 uint32_t prio);

/**
 * Send netlink `do` request with DPLL_CMD_PIN_SET command to dpll
 * over given socket. Set given state for a given pin.
 *
 * @param sk		dpll subsystem socket
 * @param family	resolved dpll family id
 * @param pin_id	id of pin being configured
 * @param dev_id	device id to set state on
 * @param state		requested state value
 * @return:		0 - success, negative - failure
 */
int nl_dpll_pin_state_set(struct nl_sock *sk, int family, uint32_t pin_id,
			  uint32_t dev_id, enum dpll_pin_state state);

/**
 * Send netlink `do` request with DPLL_CMD_PIN_SET command to dpll
 * over given socket. Set given state for a given pin/parent-pin pair.
 *
 * @param sk		dpll subsystem socket
 * @param family	resolved dpll family id
 * @param pin_id	id of pin being configured
 * @param parent_id	id of parent to set the state with
 * @param state		requested state value
 * @return:		0 - success, negative - failure
 */
int nl_dpll_pin_parent_state_set(struct nl_sock *sk, int family,
				 uint32_t pin_id, uint32_t parent_id,
				 enum dpll_pin_state state);

/**
 * Create monitor socket and register the callback for handling notifications
 * from dpll subsystem.
 *
 * @param cb	callback function to parse notifications
 * @param arg	pointer to callback argument
 * @return	valid socket pointer - success, NULL - failure
 */
struct nl_sock *nl_dpll_mon_socket_create(nl_recvmsg_msg_cb_t cb, void *arg);

/**
 * Create socket to ROUTE netlink family.
 *
 * @return	valid socket pointer - success, NULL - failure
 */
struct nl_sock *nl_rt_sk_create(nl_recvmsg_msg_cb_t cb, struct sk_arg *arg);

/**
 * Send `dump` link request over ROUTE netlink socket.
 *
 * @param rt_sk		socket to send request
 * @param arg		pointer to callback argument
 * @return		0 - success, negative - failure
 */
int nl_rt_dump_links(struct nl_sock *rt_sk, struct sk_arg *arg);

#endif /* HAVE_NL_DPLL_H */
