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
#include "synce_port_ctrl.h"
#include "synce_ext_src.h"
#include "synce_clock_source.h"
#include "synce_dev_ctrl.h"
#include "synce_dev_private.h"
#include "synce_msg.h"

static int add_clock_source(struct synce_dev *dev,
			    struct synce_clock_source *clock_source)
{
	struct synce_clock_source *clock_source_iter, *last_clock_source = NULL;

	LIST_FOREACH(clock_source_iter, &dev->clock_sources, list) {
		last_clock_source = clock_source_iter;
	}

	if (last_clock_source) {
		LIST_INSERT_AFTER(last_clock_source, clock_source, list);
	} else {
		LIST_INSERT_HEAD(&dev->clock_sources, clock_source, list);
	}
	return 0;
}

static void destroy_clock_sources(struct synce_dev *dev)
{
	struct synce_clock_source *clock_source, *tmp;

	LIST_FOREACH_SAFE(clock_source, &dev->clock_sources, list, tmp) {
		synce_clock_source_destroy(clock_source);
		LIST_REMOVE(clock_source, list);
		free(clock_source);
	}
	dev->num_clock_sources = 0;
	dev->num_ports = 0;
}

static void destroy_dev_ctrl(struct synce_dev *dev)
{
	free(dev->dc);
	dev->dc = NULL;
}

static int init_ports(int *count, int *clock_source_count,struct synce_dev *dev, struct config *cfg)
{
	struct synce_clock_source *clock_source;
	struct interface *iface;
	const char *port_name;
	enum clk_type type;

	*clock_source_count = 0;
	*count = 0;
	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		/* given device takes care only of its child ports */
		if (interface_se_has_parent_dev(iface) &&
		    (strncmp(interface_se_get_parent_dev_label(iface),
			      dev->name, sizeof(dev->name)) == 0)) {
			port_name = interface_name(iface);
			type = PORT;
			if (interface_section_is_external_source(iface))
				type = EXT_SRC;

			clock_source = synce_clock_source_create();
			if (!clock_source) {
				pr_err("failed to create clock_source %s on device %s",
				       port_name, dev->name);
				continue;
			}

			if (synce_clock_source_add_source(clock_source,
							  port_name, type)) {
				pr_err("failed to configure clock_source %s on device %s",
				       port_name, dev->name);
				free(clock_source);
				continue;
			}

			if (synce_clock_source_init(clock_source, cfg,
						    dev->network_option,
						    dev->extended_tlv,
						    dev->recover_time)) {
				pr_err("failed to configure clock_source %s on device %s",
				       port_name, dev->name);
				synce_clock_source_destroy(clock_source);
				free(clock_source);
				continue;
			}

			if (add_clock_source(dev, clock_source)) {
				pr_err("failed to add clock_source %s to device %s",
				       port_name, dev->name);
				synce_clock_source_destroy(clock_source);
				free(clock_source);
				continue;
			} else {
				(*clock_source_count)++;
				if (clock_source->type == PORT)
					(*count)++;
				pr_debug("clock_source %s added on device %s addr %p",
					 port_name, dev->name, clock_source);
			}
			continue;
		}
	}

	if (*clock_source_count == 0) {
		pr_err("device %s has no ports configured", dev->name);
		return -ENODEV;
	}

	return 0;
}

static void update_dev_state(struct synce_dev *dev)
{
	struct synce_clock_source *c;
	struct synce_port *p;
	int count = 0;

	LIST_FOREACH(c, &dev->clock_sources, list) {
		if (c->type == PORT ) {
			p = c->pointer.port;
			if (synce_port_thread_running(p)) {
				count++;
			}
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
	struct synce_clock_source *c;
	struct synce_port *p;
	int ret = 0;

	LIST_FOREACH(c, &dev->clock_sources, list) {
		if (c->type == PORT ) {
			p = c->pointer.port;
			if (dev->d_state == EEC_HOLDOVER) {
				ret = port_set_dnu(p, dev->extended_tlv);
			} else if (dev->d_state == EEC_LOCKED ||
				   dev->d_state == EEC_LOCKED_HO_ACQ) {
				ret = port_set_ql_external_input(p,
							dev->extended_tlv);
			}

			if (ret) {
				pr_err("update QL failed d_state %d, err:%d on %s",
				       dev->d_state, ret, dev->name);
				break;
			}
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
	struct synce_port *p, *best_p;
	struct synce_clock_source *c;
	int ret = 0;

	best_p = dev->best_source ? dev->best_source->pointer.port : NULL;

	LIST_FOREACH(c, &dev->clock_sources, list) {
		if (c->type == PORT ) {
			p = c->pointer.port;
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
				   dev->d_state == EEC_LOCKED_HO_ACQ) &&
				   best_p) {
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
					 synce_port_get_name(p),
					 dev->d_state, best_p);
			}
		}
	}

	return ret;
}

static int update_ql(struct synce_dev *dev)
{
	if (dev->ext_src_is_best)
		return update_ql_external_input(dev);
	else
		return update_ql_line_input(dev);
}

static void detach_port_eec(struct synce_port *port, struct synce_dev *dev)
{
	int ret = synce_port_disable_recover_clock(port);

	if (ret) {
		pr_err("disable recover clock cmd failed on %s", dev->name);
		return;
	}
}

static void detach_ext_src_eec(struct synce_ext_src *ext_src,
			       struct synce_dev *dev)
{
	int ret = synce_ext_src_disable_ext_clock(ext_src);

	if (ret) {
		pr_err("disable external clock cmd failed on %s", dev->name);
		return;
	}
}

static void detach_clock_source_eec(struct synce_clock_source *clock_source,
				    struct synce_dev *dev)
{
	if (clock_source->type == PORT)
		detach_port_eec(clock_source->pointer.port,dev);
	else
		detach_ext_src_eec(clock_source->pointer.ext_src,dev);
}

static void force_all_eecs_detach(struct synce_dev *dev)
{
	struct synce_clock_source *p;
	enum eec_state state;

	LIST_FOREACH(p, &dev->clock_sources, list) {
		pr_debug("trying to detach EEC Source CLK for %s",
			 synce_clock_source_get_name(p));
		detach_clock_source_eec(p, dev);
	}

	if (synce_dev_ctrl_get_state(dev->dc, &state)) {
		pr_err("failed getting EEC state");
		dev->last_d_state = EEC_UNKNOWN;
		dev->d_state = EEC_UNKNOWN;
	} else {
		dev->last_d_state = state;
		dev->d_state = state;
	}
}

static void dev_update_ql(struct synce_dev *dev)
{
	if (update_ql(dev)) {
		pr_err("update QL fail on %s", dev->name);
	}
}

static int rx_ql_changed(struct synce_dev *dev)
{
	struct synce_clock_source *c;
	struct synce_port *p;
	int ret = 0;

	LIST_FOREACH(c, &dev->clock_sources, list) {
		if (c->type == PORT ) {
			p = c->pointer.port;
			ret = synce_port_rx_ql_changed(p);
			if (ret) {
				break;
			}
		}
	}

	return ret;
}

void set_port_ql_from_ext_src(struct synce_dev *dev, struct synce_port *port,
			      struct synce_ext_src *ext_src)
{
	port->ql_forced = ext_src->ql;
	if (dev->extended_tlv)
		port->ext_ql_msg_forced.enhancedSsmCode = ext_src->ext_ql;
}

static struct synce_clock_source *find_dev_best_clock_source(struct synce_dev *dev)
{
	struct synce_clock_source *c, *best_c = dev->best_source;

	LIST_FOREACH(c, &dev->clock_sources, list) {
		if (best_c != c) {
			if (synce_clock_source_compare_ql(best_c, c) == c) {
				pr_debug("old ext best %s replaced by %s on %s",
					 synce_clock_source_get_name(best_c),
					 synce_clock_source_get_name(c), dev->name);
				best_c = c;
			}
		}
	}

	if (best_c && best_c->type == PORT) {
		if (synce_port_is_rx_dnu(best_c->pointer.port))
			return NULL;
	} else if (best_c && best_c->type == EXT_SRC)
		LIST_FOREACH(c, &dev->clock_sources, list) {
			if (c->type == PORT)
				set_port_ql_from_ext_src(dev, c->pointer.port,
							 best_c->pointer.ext_src);
		}

	return best_c;
}

static int set_input_port_source(struct synce_dev *dev,
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

static int set_input_ext_source(struct synce_dev *dev,
				struct synce_ext_src *new_best_source)
{
	const char *best_name = synce_ext_src_get_name(new_best_source);
	int ret;

	if (!best_name) {
		pr_err("get best input name failed on %s", dev->name);
		return -ENXIO;
	}

	ret = synce_ext_src_enable_ext_clock(new_best_source);
	if (ret) {
		pr_err("enable recover clock cmd failed on %s", dev->name);
		return ret;
	}

	return ret;
}

static int set_input_source(struct synce_dev *dev,
			    struct synce_clock_source *new_best)
{
	if (new_best->type == PORT)
		return set_input_port_source(dev,new_best->pointer.port);
	return set_input_ext_source(dev,new_best->pointer.ext_src);
}

static int act_on_d_state(struct synce_dev *dev)
{
	int ret = 0;

	if (dev->d_state != dev->last_d_state) {
		ret = update_ql(dev);
		if (ret) {
			pr_err("update QL fail on %s", dev->name);
		} else {
			dev->last_d_state = dev->d_state;
			pr_debug("%s QL updated on %s", __func__, dev->name);
		}
	}

	return ret;
}

static void choose_best_source(struct synce_dev *dev)
{
	struct synce_clock_source *new_best;
	bool ext_src_is_best = false;

	new_best = find_dev_best_clock_source(dev);
	if (new_best && new_best->type == EXT_SRC)
		ext_src_is_best = true;

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
			dev->ext_src_is_best = ext_src_is_best;
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
	} else if (dev->best_source && dev->best_source->type == PORT) {
		if (synce_port_rx_ql_failed(dev->best_source->pointer.port)) {
			synce_port_invalidate_rx_ql(dev->best_source->pointer.port);
			force_all_eecs_detach(dev);
			dev_update_ql(dev);
			dev->best_source = NULL;
			choose_best_source(dev);
		}
	}

	return ret;
}

int synce_dev_init(struct synce_dev *dev, struct config *cfg)
{
	int count, clock_source_count, ret;
	const char *eec_get_state_cmd;
	struct eec_state_str ess;

	if (dev->state != DEVICE_CREATED) {
		goto err;
	}

	LIST_INIT(&dev->clock_sources);
	dev->extended_tlv = config_get_int(cfg, dev->name, "extended_tlv");
	dev->network_option = config_get_int(cfg, dev->name, "network_option");
	dev->recover_time = config_get_int(cfg, dev->name, "recover_time");
	dev->best_source = NULL;
	dev->ext_src_is_best = false;
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

	ret = synce_dev_ctrl_init(dev->dc, dev->name, eec_get_state_cmd, &ess);
	if (ret) {
		pr_err("synce_dev_ctrl init ret %d on %s", ret, dev->name);
		goto err;
	}
	if (init_ports(&count, &clock_source_count, dev, cfg))
		goto err;

	dev->num_ports = count;
	dev->num_clock_sources = clock_source_count;
	dev->state = DEVICE_INITED;

	dev->d_state = EEC_HOLDOVER;
	update_ql(dev);

	/* in case somebody manually set recovered clock before */
	force_all_eecs_detach(dev);

	pr_info("inited num_clock_sources %d (%d ports) for %s",
		clock_source_count, count, dev->name);

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

	ret = dev_step_line_input(dev);

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

	if (dev->state != DEVICE_FAILED) {
		force_all_eecs_detach(dev);
	}

	destroy_clock_sources(dev);
	destroy_dev_ctrl(dev);
}
