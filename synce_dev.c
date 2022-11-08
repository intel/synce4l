/**
 * @file synce_dev.c
 * @brief Interface for handling SyncE capable devices and its ports
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <stdlib.h>
#include <sys/queue.h>
#include <net/if.h>
#include <errno.h>
#include "interface.h"
#include "address.h"
#include "print.h"
#include "config.h"
#include "util.h"
#include "synce_dev.h"
#include "synce_port.h"
#include "synce_dev_ctrl.h"
#include "synce_dev_private.h"
#include "synce_msg.h"


static int add_port(struct synce_dev *dev, struct synce_port *port)
{
	struct synce_port *port_iter, *last_port = NULL;

	LIST_FOREACH(port_iter, &dev->ports, list) {
		last_port = port_iter;
	}

	if (last_port) {
		LIST_INSERT_AFTER(last_port, port, list);
	} else {
		LIST_INSERT_HEAD(&dev->ports, port, list);
	}
	return 0;
}

static int rx_enabled(struct synce_dev *dev)
{
	return dev->input_mode == INPUT_MODE_LINE;
}

static void destroy_ports(struct synce_dev *dev)
{
	struct synce_port *port, *tmp;

	LIST_FOREACH_SAFE(port, &dev->ports, list, tmp) {
		synce_port_destroy(port);
		LIST_REMOVE(port, list);
		free(port);
	}
	dev->num_ports = 0;
}

static void destroy_dev_ctrl(struct synce_dev *dev)
{
	free(dev->dc);
	dev->dc = NULL;
}

static int init_ports(int *count, struct synce_dev *dev, struct config *cfg)
{
	struct interface *iface;
	struct synce_port *port;
	const char *port_name;

	*count = 0;
	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		/* given device takes care only of its child ports */
		if (interface_se_has_parent_dev(iface) &&
		    (strncmp(interface_se_get_parent_dev_label(iface),
			      dev->name, sizeof(dev->name)) == 0)) {
			port_name = interface_name(iface);

			port = synce_port_create(port_name);
			if (!port) {
				pr_err("failed to create port %s on device %s",
				       port_name, dev->name);
				continue;
			}

			if (synce_port_init(port, cfg, dev->network_option,
					    dev->extended_tlv, rx_enabled(dev),
					    dev->recover_time, dev->ql,
					    dev->ext_ql)) {
				pr_err("failed to configure port %s on device %s",
				       port_name, dev->name);
				synce_port_destroy(port);
				free(port);
				continue;
			}

			if (add_port(dev, port)) {
				pr_err("failed to add port %s to device %s",
				       port_name, dev->name);
				synce_port_destroy(port);
				free(port);
				continue;
			} else {
				(*count)++;
				pr_debug("port %s added on device %s addr %p",
					 port_name, dev->name, port);
			}
		}
	}

	if (*count == 0) {
		pr_err("device %s has no ports configured", dev->name);
		return -ENODEV;
	}

	return 0;
}

static void update_dev_state(struct synce_dev *dev)
{
	struct synce_port *p;
	int count = 0;

	LIST_FOREACH(p, &dev->ports, list) {
		if (synce_port_thread_running(p)) {
			count++;
		}
	}

	if (dev->num_ports == count) {
		dev->state = DEVICE_RUNNING;
	} else {
		pr_warning("found %d ports running - %d configured on %s",
			   count, dev->num_ports, dev->name);
	}
}

static int port_set_dnu(struct synce_port *p, int extended_tlv)
{
	int ret;

	if (!p) {
		pr_err("%s port is NULL", __func__);
		ret = -EFAULT;
		return ret;
	}

	ret = synce_port_set_tx_ql_dnu(p, extended_tlv);
	if (ret) {
		pr_err("set tx DNU fail on %s", synce_port_get_name(p));
		return ret;
	}

	return ret;
}

static int port_set_ql_external_input(struct synce_port *p, int extended)
{
	int ret = synce_port_set_tx_ql_forced(p, extended);

	if (ret) {
		pr_err("set QL external failed");
		return ret;
	}

	return ret;
}

static int update_ql_external_input(struct synce_dev *dev)
{
	struct synce_port *p;
	int ret = 0;

	LIST_FOREACH(p, &dev->ports, list) {
		if (dev->d_state == EEC_HOLDOVER) {
			ret = port_set_dnu(p, dev->extended_tlv);
		} else if (dev->d_state == EEC_LOCKED ||
			   dev->d_state == EEC_LOCKED_HO_ACQ) {
			ret = port_set_ql_external_input(p, dev->extended_tlv);
		}

		if (ret) {
			pr_err("update QL failed d_state %d, err:%d on %s",
			       dev->d_state, ret, dev->name);
			break;
		}

	}

	return ret;
}

static int port_set_ql_line_input(struct synce_dev *dev,
				  struct synce_port *p,
				  struct synce_port *best_p)
{
	int ret = synce_port_set_tx_ql_from_best_input(p, best_p,
						       dev->extended_tlv);

	if (ret) {
		pr_err("set QL failed");
		return ret;
	}

	if (!ret) {
		pr_debug("%s on %s", __func__, dev->name);
	}

	return ret;
}

static int update_ql_line_input(struct synce_dev *dev)
{
	struct synce_port *p, *best_p = dev->best_source;
	int ret = 0;

	LIST_FOREACH(p, &dev->ports, list) {
		if (dev->d_state == EEC_HOLDOVER) {
			pr_debug("act on EEC_HOLDOVER for %s",
				 synce_port_get_name(p));
			ret = port_set_dnu(p, dev->extended_tlv);
			if (ret) {
				pr_err("%s set DNU failed on %s",
				       __func__, dev->name);
				return ret;
			}
		} else if ((dev->d_state == EEC_LOCKED ||
			   dev->d_state == EEC_LOCKED_HO_ACQ) && best_p) {
			pr_debug("act on EEC_LOCKED/EEC_LOCKED_HO_ACQ for %s",
				 synce_port_get_name(p));
			/* on best port send DNU, all the others
			 * propagate what came from best source
			 */
			if (p != best_p) {
				ret = port_set_ql_line_input(dev, p,
								 best_p);
			} else {
				ret = port_set_dnu(p, dev->extended_tlv);
			}

			if (ret) {
				pr_err("%s set failed on %s",
				       __func__, dev->name);
				return ret;
			}
		} else {
			pr_debug("nothing to do for %s d_state %d, best_p %p",
				 synce_port_get_name(p), dev->d_state, best_p);
		}
	}

	return ret;
}

static void detach_port_eec(struct synce_port *port, struct synce_dev *dev)
{
	int ret = synce_port_disable_recover_clock(port);

	if (ret) {
		pr_err("disable recover clock cmd failed on %s", dev->name);
		return;
	}
}

static void force_all_eecs_detach(struct synce_dev *dev)
{
	enum eec_state state;
	struct synce_port *p;

	LIST_FOREACH(p, &dev->ports, list) {
		pr_debug("trying to detach EEC RCLK for %s",
			 synce_port_get_name(p));
		detach_port_eec(p, dev);
	}

	if (synce_dev_ctrl_get_state(dev->dc, &state)) {
		pr_err("failed getting EEC state");
		dev->last_d_state = EEC_UNKNOWN;
		dev->d_state = EEC_UNKNOWN;
	} else {
		dev->last_d_state = state;
		dev->d_state = state;
	}
};

static void dev_update_ql(struct synce_dev *dev)
{
	if (dev->ops.update_ql(dev)) {
		pr_err("update QL fail on %s", dev->name);
	}
}

static int rx_ql_changed(struct synce_dev *dev)
{
	struct synce_port *p;
	int ret = 0;

	LIST_FOREACH(p, &dev->ports, list) {
		ret = synce_port_rx_ql_changed(p);
		if (ret) {
			break;
		}
	}

	return ret;
}

static struct synce_port *find_dev_best_source(struct synce_dev *dev)
{
	struct synce_port *p, *best_p = dev->best_source;

	LIST_FOREACH(p, &dev->ports, list) {
		if (best_p != p) {
			if (synce_port_compare_ql(best_p, p) == p) {
				pr_debug("old best %s replaced by %s on %s",
					 synce_port_get_name(best_p),
					 synce_port_get_name(p), dev->name);
				best_p = p;
			}
		}
	}

	if (best_p) {
		if (synce_port_is_rx_dnu(best_p)) {
			return NULL;
		}
	}

	return best_p;
}

static int set_input_source(struct synce_dev *dev,
			    struct synce_port *new_best_source)
{
	const char *best_name = synce_port_get_name(new_best_source);
	int ret;

	if (!best_name) {
		pr_err("get best input name failed on %s", dev->name);
		return -ENXIO;
	}

	ret = synce_port_enable_recover_clock(new_best_source);
	if (ret) {
		pr_err("enable recover clock cmd failed on %s", dev->name);
		return ret;
	}

	return ret;
}

static int act_on_d_state(struct synce_dev *dev)
{
	int ret = 0;

	if (dev->d_state != dev->last_d_state) {
		ret = dev->ops.update_ql(dev);
		if (ret) {
			pr_err("update QL fail on %s", dev->name);
		} else {
			dev->last_d_state = dev->d_state;
			pr_debug("%s QL updated on %s", __func__, dev->name);
		}
	}

	return ret;
}

static int dev_step_external_input(struct synce_dev *dev)
{
	return act_on_d_state(dev);
}

static void choose_best_source(struct synce_dev *dev)
{
	struct synce_port *new_best;

	new_best = find_dev_best_source(dev);
	if (!new_best) {
		pr_info("best source not found on %s", dev->name);
		force_all_eecs_detach(dev);
		dev_update_ql(dev);
		dev->best_source = NULL;
	} else if (new_best != dev->best_source) {
		force_all_eecs_detach(dev);
		if (set_input_source(dev, new_best)) {
			pr_err("set best source failed on %s",
				dev->name);
		} else {
			/* if input source is changing
			 * current input is invalid, send DNU and wait
			 * for EEC being locked in further dev_step
			 */
			dev_update_ql(dev);
			/* EEC was invalidated we can now set new
			 * best_source for further use
			 */
			dev->best_source = new_best;
		}
	} else {
		pr_info("clock source has not changed on %s", dev->name);
		/* no port change, just update QL on TX */
		dev_update_ql(dev);

	}
}

static int dev_step_line_input(struct synce_dev *dev)
{
	int ret;

	ret = act_on_d_state(dev);
	if (ret) {
		pr_err("act on d_state fail on %s", dev->name);
		return ret;
	}

	if (rx_ql_changed(dev)) {
		choose_best_source(dev);
	} else if (dev->best_source) {
		if (synce_port_rx_ql_failed(dev->best_source)) {
			synce_port_invalidate_rx_ql(dev->best_source);
			force_all_eecs_detach(dev);
			dev_update_ql(dev);
			dev->best_source = NULL;
			choose_best_source(dev);
		}
	}

	return ret;
}

static void init_ops(struct synce_dev *dev)
{
	if (rx_enabled(dev)) {
		dev->ops.update_ql = &update_ql_line_input;
		dev->ops.step = &dev_step_line_input;
	} else {
		dev->ops.update_ql = &update_ql_external_input;
		dev->ops.step = &dev_step_external_input;
	}
}

#define INPUT_MODE_LINE_STRING "line"
#define INPUT_MODE_EXTERNAL_STRING "external"
int synce_dev_init(struct synce_dev *dev, struct config *cfg)
{
	const char *eec_get_state_cmd, *input_mode;
	struct eec_state_str ess;
	int count, ret;

	if (dev->state != DEVICE_CREATED) {
		goto err;
	}

	LIST_INIT(&dev->ports);
	input_mode = config_get_string(cfg, dev->name, "input_mode");
	dev->ql = config_get_int(cfg, dev->name, "external_input_QL");
	dev->ext_ql = config_get_int(cfg, dev->name, "external_input_ext_QL");
	dev->extended_tlv = config_get_int(cfg, dev->name, "extended_tlv");
	dev->network_option = config_get_int(cfg, dev->name, "network_option");
	dev->recover_time = config_get_int(cfg, dev->name, "recover_time");
	dev->best_source = NULL;
	eec_get_state_cmd = config_get_string(cfg, dev->name, "eec_get_state_cmd");
	ess.holdover = config_get_string(cfg, dev->name, "eec_holdover_value");
	ess.locked_ho = config_get_string(cfg, dev->name, "eec_locked_ho_value");
	ess.locked = config_get_string(cfg, dev->name, "eec_locked_value");
	ess.freerun = config_get_string(cfg, dev->name, "eec_freerun_value");
	ess.invalid = config_get_string(cfg, dev->name, "eec_invalid_value");
	dev->dc = synce_dev_ctrl_create();
	if (!dev->dc) {
		pr_err("device_ctrl create fail on %s", dev->name);
		goto err;
	}

	if (!strncmp(input_mode, INPUT_MODE_LINE_STRING,
		     sizeof(INPUT_MODE_LINE_STRING))) {
		dev->input_mode = INPUT_MODE_LINE;
	} else if (!strncmp(input_mode, INPUT_MODE_EXTERNAL_STRING,
		   sizeof(INPUT_MODE_EXTERNAL_STRING))) {
		dev->input_mode = INPUT_MODE_EXTERNAL;
	} else {
		pr_err("input_mode not supported for %s", dev->name);
		goto err;
	}

	ret = synce_dev_ctrl_init(dev->dc, dev->name, eec_get_state_cmd, &ess);
	if (ret) {
		pr_err("synce_dev_ctrl init ret %d on %s", ret, dev->name);
		goto err;
	}
	if (init_ports(&count, dev, cfg))
		goto err;

	init_ops(dev);
	dev->num_ports = count;
	dev->state = DEVICE_INITED;

	dev->d_state = EEC_HOLDOVER;
	dev->ops.update_ql(dev);

	/* in case somebody manually set recovered clock before */
	if (dev->input_mode == INPUT_MODE_LINE) {
		force_all_eecs_detach(dev);
	}
	pr_info("inited num_ports %d for %s", count, dev->name);

	return 0;

err:
	dev->state = DEVICE_FAILED;
	pr_err("%s failed for %s", __func__, dev->name);
	return -ENODEV;
}

struct synce_dev *synce_dev_create(const char *dev_name)
{
	struct synce_dev *dev = NULL;

	if (!dev_name) {
		return NULL;
	}

	dev = malloc(sizeof(struct synce_dev));
	if (!dev) {
		return NULL;
	}

	memcpy(dev->name, dev_name, sizeof(dev->name));
	dev->state = DEVICE_CREATED;
	dev->d_state = EEC_UNKNOWN;
	dev->last_d_state = EEC_UNKNOWN;
	pr_debug("created %s", dev->name);

	return dev;
}

int synce_dev_step(struct synce_dev *dev)
{
	int ret = -EFAULT;

	if (!dev) {
		pr_err("%s dev is NULL", __func__);
		return ret;
	}

	update_dev_state(dev);
	if (dev->state != DEVICE_RUNNING) {
		pr_err("dev %s is not running", dev->name);
		return ret;
	}

	ret = synce_dev_ctrl_get_state(dev->dc, &dev->d_state);
	if (ret) {
		pr_warning("could not acquire eec state on %s", dev->name);
		return ret;
	}

	ret = dev->ops.step(dev);

	return ret;
}

const char *synce_dev_name(struct synce_dev *dev)
{
	return dev->name;
}

int synce_dev_is_running(struct synce_dev *dev)
{
	update_dev_state(dev);

	return !!(dev->state & DEVICE_RUNNING);
}

void synce_dev_destroy(struct synce_dev *dev)
{
	if (!dev) {
		pr_err("%s dev is NULL", __func__);
		return;
	}

	if (dev->input_mode == INPUT_MODE_LINE && dev->state != DEVICE_FAILED) {
		force_all_eecs_detach(dev);
	}

	destroy_ports(dev);
	destroy_dev_ctrl(dev);
}
