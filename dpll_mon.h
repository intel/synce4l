/**
 * @file dpll_mon.h
 * @brief Header for a dpll monitor class
 * @note SPDX-FileCopyrightText: Copyright 2023 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */

#ifndef HAVE_DPLL_MON_H
#define HAVE_DPLL_MON_H

#ifdef CONFIG_DPLL
#include <linux/dpll.h>
#else
#include "headers/dpll.h"
#endif

#include "synce_dev_ctrl.h"
#include <stdint.h>

struct dpll_mon;

/**
 * Check if dpll is already found and ready to use. Also step the device
 * initialization state machine if dpll appeared in the system.
 *
 * @param dm		Questioned instance
 * @return		0 - not present or not ready, 1 - present and ready
 */
int dpll_mon_dev_running(struct dpll_mon *dm);

/**
 * Create a dpll mon instance.
 *
 * @param clock_id	Clock id of dpll
 * @param module_name	Module name of dpll
 * @param name		Name of dpll device in synce4l
 * @param dnu_prio	Do Not Use priority value for a dpll device
 * @return		valid pointer to dpll_mon - success, NULL - failure
 */
struct dpll_mon *dpll_mon_create(uint64_t clock_id, const char *module_name,
				 const char *name, uint32_t dnu_prio);

/**
 * Initialize dpll mon instance sockets and state.
 *
 * @param dm		Created instance.
 * @return		0 - success, negative - failure
 */
int dpll_mon_init(struct dpll_mon *dm);

/**
 * Destroy and release resources of dpll mon instance.
 *
 * @param dm		Pointer to instance being destroyed.
 */
void dpll_mon_destroy(struct dpll_mon *dm);

/**
 * Get mode of dpll controlled by dpll mon instance.
 *
 * @param dm		Questioned instance.
 * @param mode		On success holds current mode of dpll.
 * @return		0 - success, negative - failure.
 */
int dpll_mon_mode_get(struct dpll_mon *dm, enum dpll_mode *mode);

/**
 * Get lock state of dpll controlled by dpll mon instance.
 *
 * @param dm		Questioned instance.
 * @param state		On success holds current state of dpll.
 * @return		0 - success, negative - failure.
 */
int dpll_mon_lock_state_get(struct dpll_mon *dm, enum eec_state *state);

/**
 * Add a pin of given arguemnts as monitored and valid input for a dpll device
 * being monitored by the dpll mon instance.
 *
 * @param dm		Instance being modified.
 * @param board_label	Board label of a pin
 * @param panel_label	Panel label of a pin
 * @param package_label	Package label of a pin
 * @param type		Type of a pin
 * @return		Not NULL pointer - success, NULL - failure
 */
struct dpll_mon_pin
*dpll_mon_add_pin(struct dpll_mon *dm, const char *board_label,
		  const char *panel_label, const char *package_label,
		  enum dpll_pin_type type);

/**
 * Add a pin connected with a netdevice as monitored and valid input for a dpll
 * device being monitored by the dpll mon instance.
 *
 * @param dm		Instance being modified.
 * @param ifname	Name of netdevice which own the pin.
 * @return		Not NULL pointer - success, NULL - failure
 */
struct dpll_mon_pin
*dpll_mon_add_port_pin(struct dpll_mon *dm, const char *ifname);

/**
 * Check if given pin is an active input for a dpll device being monitored by
 * the dpll mon instance.
 *
 * @param dm		Questioned instance.
 * @param pin		Valid pointer to a pin.
 * @return		0 - is not an active source, 1 - is active source
 */
int dpll_mon_pin_is_active(struct dpll_mon *dm, struct dpll_mon_pin *pin);

/**
 * Request to set priority of a pin on a dpll controlled by dpll mon instance,
 * if pin is muxed and priority != dnu_prio, then set the priority on the
 * parent and change pin state (with the parent) to CONNECTED as long as there
 * is not yet used parent (configured with prio == dnu_prio).
 *
 * @param dm		Instance of dpll mon which owns the pin.
 * @param pin		Valid pointer to a pin.
 * @param prio		Requested priority for a pin.
 * @return		0 - success, negative - failed to send request
 */
int dpll_mon_pin_prio_set(struct dpll_mon *dm, struct dpll_mon_pin *pin,
			  uint32_t prio);

/**
 * Request to set Do Not Use priority on all valid pins for all the pins
 * controlled by the dpll_mon's dpll.
 *
 * @param dm		Instance of dpll mon which owns the pin.
 * @return		0 - success, negative - failed to send request
 */
int dpll_mon_pins_prio_dnu_set(struct dpll_mon *dm);

#endif /* HAVE_DPLL_MON_H */
