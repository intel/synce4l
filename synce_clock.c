/**
 * @file synce_clock.c
 * @brief Implements a SyncE clock interface.
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/queue.h>

#include "synce_clock.h"
#include "interface.h"
#include "synce_dev.h"
#include "print.h"
#include "config.h"

#define MSEC_TO_USEC(X)		(X * 1000)
#define SYNCE_CLOCK_INIT_DELAY_USEC	200000
#define SYNCE_CLOCK_INIT_N_TRIES	10

struct interface {
	STAILQ_ENTRY(interface) list;
};

struct synce_dev {
	LIST_ENTRY(synce_dev) list;
};

enum synce_clock_state {
	SYNCE_CLK_UNKNOWN = 0,
	SYNCE_CLK_INITED,
	SYNCE_CLK_DEV_RDY,
	SYNCE_CLK_DEV_INITED,
	SYNCE_CLK_RUNNING,
	SYNCE_CLK_FAILED,
};

struct synce_clock {
	int num_devices;
	int state;
	int poll_interval_ms;
	LIST_HEAD(devices_head, synce_dev) devices;
};

static struct synce_clock *create_synce_clock(void)
{
	static struct synce_clock clk;

	if (clk.state != SYNCE_CLK_UNKNOWN) {
		synce_clock_destroy(&clk);
		pr_info("old synce_clock destroyed");
	}
	clk.state = SYNCE_CLK_INITED;

	return &clk;
}

static void add_device(struct synce_clock *clk, struct synce_dev *dev)
{
	struct synce_dev *dev_iter, *last_dev = NULL;

	LIST_FOREACH(dev_iter, &clk->devices, list) {
		last_dev = dev_iter;
	}

	if (last_dev) {
		LIST_INSERT_AFTER(last_dev, dev, list);
	} else {
		LIST_INSERT_HEAD(&clk->devices, dev, list);
	}
}

static int create_synce_devices(struct synce_clock *clk, struct config *cfg)
{
	struct interface *iface;
	struct synce_dev *dev;
	const char *dev_name;
	int count = 0;

	if (clk->state != SYNCE_CLK_INITED) {
		goto err;
	}

	LIST_INIT(&clk->devices);
	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		/* only parent devices shall be addresed */
		if (!interface_se_has_parent_dev(iface)) {
			dev_name = interface_name(iface);
			dev = synce_dev_create(dev_name);
			if (!dev) {
				pr_err("failed to create device %s", dev_name);
				continue;
			}

			pr_debug("device init %s addr %p", dev_name, dev);
			add_device(clk, dev);
			count++;
		}
	}

	if (!count) {
		pr_err("no devices created");
		goto err;
	}

	pr_info("created num_devices: %d", count);
	clk->num_devices = count;
	clk->state = SYNCE_CLK_DEV_RDY;

	return 0;
err:
	clk->state = SYNCE_CLK_FAILED;
	return -EINVAL;
}

static int init_synce_devices(struct synce_clock *clk, struct config *cfg)
{
	struct synce_dev *dev, *tmp;
	int count = 0;

	if (clk->state != SYNCE_CLK_DEV_RDY) {
		goto err;
	}

	LIST_FOREACH_SAFE(dev, &clk->devices, list, tmp) {
		/* Each parent device will init its ports */
		if (synce_dev_init(dev, cfg)) {
			pr_err("failed to init device %s",
			       synce_dev_name(dev));
			synce_dev_destroy(dev);
			LIST_REMOVE(dev, list);
			free(dev);
			continue;
		} else {
			pr_debug("device inited %s", synce_dev_name(dev));
			count++;
		}
	}

	if (count == 0) {
		pr_err("no SyncE devices initialized");
		goto err;
	} else if (count != clk->num_devices) {
		pr_warning("initialized only %d from %d SyncE devices",
			   count, clk->num_devices);
		clk->num_devices = count;
	}
	clk->state = SYNCE_CLK_DEV_INITED;

	return 0;
err:
	clk->state = SYNCE_CLK_FAILED;
	return -EINVAL;
}

static void remove_failed_devices(struct synce_clock *clk)
{
	struct synce_dev *dev, *tmp;
	int failed_cnt = 0;

	LIST_FOREACH_SAFE(dev, &clk->devices, list, tmp) {
		if (!synce_dev_is_running(dev)) {
			synce_dev_destroy(dev);
			LIST_REMOVE(dev, list);
			free(dev);
			failed_cnt++;
		}
	}
	clk->num_devices -= failed_cnt;
	pr_warning("Found dead devices: %d", failed_cnt);
	pr_info("devices still running: %d", clk->num_devices);
}

static int verify_clock_state(struct synce_clock *clk)
{
	int i, running, timeout = SYNCE_CLOCK_INIT_N_TRIES;
	struct synce_dev *dev;

	if (clk->state < SYNCE_CLK_DEV_INITED) {
		return -ENODEV;
	}

	/* let threads get running */
	for (i = 0; i < timeout; ++i) {
		running = 0;
		LIST_FOREACH(dev, &clk->devices, list) {
			if (synce_dev_is_running(dev))
				running++;
		}

		if (running == clk->num_devices) {
			clk->state = SYNCE_CLK_RUNNING;
			break;
		}
		usleep(SYNCE_CLOCK_INIT_DELAY_USEC);
	}

	pr_debug("running num_devices %d configured %d",
		 running, clk->num_devices);

	/* If at least one dev is running we leave clock running
	 * while removing failed devices.
	 * Previous traces shall indicate which ones have failed.
	 */
	if (!running) {
		pr_err("no device is running");
		return -ENODEV;
	} else if (running != clk->num_devices) {
		remove_failed_devices(clk);
	}

	return 0;
}

struct synce_clock *synce_clock_create(struct config *cfg)
{
	struct synce_clock *clk;
	int err;

	if (!cfg) {
		pr_err("%s cfg is NULL", __func__);
		return NULL;
	}

	clk = create_synce_clock();
	if (!clk) {
		return NULL;
	}
	err = create_synce_devices(clk, cfg);
	if (err) {
		goto destroy;
	}
	err = init_synce_devices(clk, cfg);
	if (err) {
		goto destroy;
	}
	err = verify_clock_state(clk);
	if (err) {
		goto destroy;
	}

	clk->poll_interval_ms = config_get_int(cfg, NULL, "poll_interval_ms");

	return clk;

destroy:
	synce_clock_destroy(clk);

	return NULL;
}

void synce_clock_destroy(struct synce_clock *clk)
{
	struct synce_dev *dev, *tmp;

	pr_debug("%s", __func__);

	LIST_FOREACH_SAFE(dev, &clk->devices, list, tmp) {
		synce_dev_destroy(dev);
		LIST_REMOVE(dev, list);
		free(dev);
	}
	clk->num_devices = 0;
	clk->state = SYNCE_CLK_UNKNOWN;

	return;
}

int synce_clock_poll(struct synce_clock *clk)
{
	struct synce_dev *dev;
	int ret = -ENODEV;

	if (clk->state == SYNCE_CLK_RUNNING) {
		LIST_FOREACH(dev, &clk->devices, list) {
			ret = synce_dev_step(dev);
			if (ret) {
				pr_err("dev_step fail");
			}
		}
	}
	usleep(MSEC_TO_USEC(clk->poll_interval_ms));

	return ret;
}
