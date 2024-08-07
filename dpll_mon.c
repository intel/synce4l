/**
 * @file dpll_mon.c
 * @brief Implements a dpll monitor class
 * @note SPDX-FileCopyrightText: Copyright 2023 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <netlink/msg.h>
#include <unistd.h>
#include <sys/queue.h>
#include <linux/if_link.h>
#include "dpll_mon.h"
#include "print.h"
#include "nl_dpll.h"
#include "netlink/genl/genl.h"
#include "synce_thread_common.h"

#define MAX_ATTR ((int)DPLL_A_MAX > (int)DPLL_A_PIN_MAX ? \
	DPLL_A_MAX : DPLL_A_PIN_MAX)
#define PIN_READY_TRIES		10
#define PIN_VALID		1
#define PARENT_VALID		2
#define PARENT_NOT_USED		0xffffffff

enum dpll_mon_state {
	DPLL_MON_STATE_INVALID,
	DPLL_MON_STATE_CREATED,
	DPLL_MON_STATE_INIT_READY,
	DPLL_MON_STATE_DEV_ID_READY,
	DPLL_MON_STATE_DEV_GET_WAIT,
	DPLL_MON_STATE_DEV_INITED,
	DPLL_MON_STATE_PIN_DUMP_WAIT,
	DPLL_MON_STATE_PINS_VALID,
	DPLL_MON_STATE_PINS_INITED,
	DPLL_MON_STATE_RUNNING,
	DPLL_MON_STATE_DPLL_REINIT,
	DPLL_MON_STATE_STOPPING,
	DPLL_MON_STATE_STOPPED,
};

struct parent_pin {
	STAILQ_ENTRY(parent_pin) list;
	enum dpll_pin_state state;
	uint32_t id;
};

struct dpll_mon_pin {
	STAILQ_ENTRY(dpll_mon_pin) list;
	const char *board_label;
	const char *panel_label;
	const char *package_label;
	const char *ifname;
	enum dpll_pin_type type;
	enum dpll_pin_state state;
	uint32_t prio;
	uint32_t id;
	int if_index;
	int valid;
	int muxed;
	int ready;
	uint32_t parent_used_by;
	int prio_valid;
	int id_requested;

	STAILQ_HEAD(parents_head, parent_pin) parents;
};

struct dpll_mon {
	enum dpll_mon_state state;
	pthread_t thread_id;
	int family;
	unsigned int dpll_id;
	uint64_t clock_id;
	const char *name;
	const char *module_name;
	enum dpll_mode dpll_mode;
	enum dpll_lock_status lock_status;
	struct nl_sock *mon_sk;
	struct nl_sock *dev_sk;
	struct sk_arg dev_args;
	struct nl_sock *rt_sk;
	struct sk_arg rt_args;
	uint32_t dev_dnu_prio;
	int init_err;
	pthread_mutex_t lock;

	STAILQ_HEAD(pins_head, dpll_mon_pin) pins;
};

static const enum eec_state lock_status_to_state[] = {
	[DPLL_LOCK_STATUS_UNLOCKED] = EEC_FREERUN,
	[DPLL_LOCK_STATUS_LOCKED] = EEC_LOCKED,
	[DPLL_LOCK_STATUS_LOCKED_HO_ACQ] = EEC_LOCKED_HO_ACQ,
	[DPLL_LOCK_STATUS_HOLDOVER] = EEC_HOLDOVER,
};

static int dpll_mon_recv(struct nl_msg *msg, void *arg);

static int lock_mutex(struct dpll_mon *dm, const char *func)
{
	int ret = pthread_mutex_lock(&dm->lock);

	if (ret) {
		pr_err("%s: lock mutex failed err: %d on %s",
		       func, ret, dm->name);
	}

	return ret;
}

static int unlock_mutex(struct dpll_mon *dm, const char *func)
{
	int ret = pthread_mutex_unlock(&dm->lock);

	if (ret) {
		pr_err("%s: lock mutex failed err: %d on %s",
		       func, ret, dm->name);
	}

	return ret;
}

static void dpll_mon_state_set(struct dpll_mon *dm, enum dpll_mon_state state)
{
	dm->state = state;
	dm->init_err = 0;
	pr_debug("dpll mon for %s new state: %d", dm->name, state);
}

struct dpll_mon *dpll_mon_create(uint64_t clock_id, const char *module_name,
				 const char *dev_name, uint32_t dnu_prio)
{
	struct dpll_mon *dm;

	dm = calloc(1, sizeof(struct dpll_mon));
	if (!dm)
		return NULL;

	dm->clock_id = clock_id;
	dm->module_name = module_name;
	dm->name = dev_name;
	dm->dev_dnu_prio = dnu_prio;
	dpll_mon_state_set(dm, DPLL_MON_STATE_CREATED);

	return dm;
}

static void *dpll_mon_thread(void *data)
{
	struct dpll_mon *dm = (struct dpll_mon *) data;
	volatile enum dpll_mon_state *state;

	if (!dm) {
		pr_err("%s tx data is NULL", __func__);
		pthread_exit(NULL);
	}

	state = &dm->state;
	pr_debug("dpll_mon thread started state:%d", *state);
	while (*state >= DPLL_MON_STATE_INIT_READY &&
	       *state <= DPLL_MON_STATE_DPLL_REINIT) {
		nl_recvmsgs_default(dm->mon_sk);
		usleep(MSEC_TO_USEC(20));
	};
	*state = (*state == DPLL_MON_STATE_STOPPING) ?
		DPLL_MON_STATE_STOPPED : *state;
	pr_debug("dpll_mon thread exit state %d=%s for %s", *state,
		 *state == DPLL_MON_STATE_STOPPED ? "OK" : "failed", dm->name);
	pthread_exit(NULL);
}

static void dpll_mon_device_id_update(struct dpll_mon *dm, struct nlattr **tb)
{
	if (tb[DPLL_A_ID]) {
		dm->dpll_id = nla_get_u32(tb[DPLL_A_ID]);
		pr_debug("dpll_id:%u received on %s", dm->dpll_id, dm->name);
	}
}

static void pr_debug_pin(const char *text, struct dpll_mon_pin *pin)
{
	pr_debug("%s:%p pin_id:%u for pin board_label:%s panel_label:%s package_label:%s type:%u ifname:%s v:%d r:%d",
		 text, pin, pin->id,
		 pin->board_label ? pin->board_label : "N/A",
		 pin->panel_label ? pin->panel_label : "N/A",
		 pin->package_label ? pin->package_label : "N/A",
		 pin->type, pin->ifname ? pin->ifname : "N/A",
		 pin->valid, pin->ready);
}

static void dpll_mon_pin_id_update(struct dpll_mon *dm, struct nlattr **tb)
{
	struct dpll_mon_pin *pin;

	STAILQ_FOREACH(pin, &dm->pins, list) {
		if (pin && pin->id_requested)
			if (tb[DPLL_A_PIN_ID]) {
				pin->id = nla_get_u32(tb[DPLL_A_PIN_ID]);
				pin->ready = 1;
				pr_debug_pin("found pin", pin);
				break;
			}
	}
}

static struct dpll_mon_pin
*find_pin_by_if_index(struct dpll_mon *dm, int if_index)
{
	struct dpll_mon_pin *pin;

	STAILQ_FOREACH(pin, &dm->pins, list)
		if (if_index == pin->if_index)
			return pin;

	return NULL;
}

static struct dpll_mon_pin *find_pin(struct dpll_mon *dm, uint32_t pin_id)
{
	struct dpll_mon_pin *pin;

	STAILQ_FOREACH(pin, &dm->pins, list)
		if (pin_id == pin->id)
			return pin;

	return NULL;
}

static struct dpll_mon_pin *pin_create(void)
{
	struct dpll_mon_pin *pin = calloc(1, sizeof(*pin));

	if (!pin) {
		pr_err("%s failed", __func__);
		return NULL;
	}
	pr_debug("%s %p", __func__, pin);
	pin->parent_used_by = PARENT_NOT_USED;
	pin->id = -1;
	STAILQ_INIT(&pin->parents);

	return pin;
}

static void pin_destroy(struct dpll_mon_pin *pin)
{
	struct parent_pin *parent;

	while ((parent = STAILQ_FIRST(&pin->parents))) {
		STAILQ_REMOVE_HEAD(&pin->parents, list);
		free(parent);
	}
	free(pin);
}

void remove_no_ifname_pin(struct dpll_mon *dm, uint32_t pin_id, struct dpll_mon_pin *except)
{
	struct dpll_mon_pin *pin;

	STAILQ_FOREACH(pin, &dm->pins, list)
		if (pin && pin != except && pin_id == pin->id && pin->ifname == NULL) {
			pr_debug_pin("removed duplicated pin", pin);
			STAILQ_REMOVE(&dm->pins, pin, dpll_mon_pin, list);
			pin_destroy(pin);
			pin = NULL;
			return;
		}
}

static void update_pin(struct dpll_mon *dm, uint32_t pin_id, struct nlattr *a,
		       int exist, int notify)
{
	int dpll_id_valid = 0, pin_state_valid = 0, prio_valid = 0, rem;
	uint32_t dpll_id, pin_state, prio;
	struct dpll_mon_pin *pin;
	struct nlattr *an;

	pin = find_pin(dm, pin_id);
	if (!exist && !pin)
		return;
	if (notify && ((pin && !pin->ready) || !pin))
		return;
	nla_for_each_nested(an, a, rem) {
		switch (nla_type(an)) {
		case DPLL_A_PIN_PARENT_ID:
			dpll_id = nla_get_u32(an);
			if (dpll_id != dm->dpll_id)
				continue;
			dpll_id_valid = 1;
			break;
		case DPLL_A_PIN_STATE:
			pin_state = nla_get_u32(an);
			pin_state_valid = 1;
			break;
		case DPLL_A_PIN_PRIO:
			prio = nla_get_u32(an);
			prio_valid = 1;
			break;
		default:
			break;
		}
	}

	if (!dpll_id_valid)
		return;
	if (!pin) {
		pin = pin_create();
		if (!pin)
			return;
		pin->id = pin_id;
		STAILQ_INSERT_TAIL(&dm->pins, pin, list);
	}

	if (!exist)
		pin->ready = 0;
	else
		pin->ready = 1;

	if (pin_state_valid  && pin->state != pin_state) {
		pr_debug("new pin state %u for pin_id:%u", pin_state, pin_id);
		pin->state = pin_state;

		if (pin->valid && pin->state == DPLL_PIN_STATE_DISCONNECTED)
			nl_dpll_pin_state_set(dm->dev_sk, dm->family,
					      pin->id, dm->dpll_id,
					      DPLL_PIN_STATE_SELECTABLE);
	}
	if (prio_valid) {
		pin->prio_valid = 1;
		if (pin->prio != prio) {
			pr_debug("new pin prio %u for pin_id:%u", prio, pin_id);
			pin->prio = prio;
		}
	}
}

static int parent_add(struct dpll_mon_pin *pin, struct dpll_mon_pin *parent)
{
	struct parent_pin *pp;

	STAILQ_FOREACH(pp, &pin->parents, list)
		if (pp->id == parent->id)
			return 0;
	pp = calloc(1, sizeof(*pp));
	if (!pp)
		return -ENOMEM;
	pp->id = parent->id;
	STAILQ_INSERT_TAIL(&pin->parents, pp, list);

	return 0;
}

static void parent_state_set(struct dpll_mon_pin *pin, uint32_t parent_id,
			     enum dpll_pin_state state)
{
	struct parent_pin *pp;

	STAILQ_FOREACH(pp, &pin->parents, list)
		if (pp->id == parent_id && pp->state != state) {
			pp->state = state;
			pr_debug("new pin state %u for pin_id:%u on parent_id:%u",
				 state, pin->id, parent_id);
			return;
		}
}

static void update_muxed_pin(struct dpll_mon *dm, uint32_t pin_id,
			     struct nlattr *a, int exist, int notify)
{
	int parent_pin_id_valid = 0, pin_state_valid = 0, rem;
	uint32_t parent_pin_id = 0, pin_state = 0;
	struct dpll_mon_pin *pin, *parent;
	struct nlattr *an;

	pin = find_pin(dm, pin_id);
	if (!exist && !pin)
		return;
	if (notify && ((pin && !pin->ready) || !pin))
		return;
	nla_for_each_nested(an, a, rem) {
		switch (nla_type(an)) {
		case DPLL_A_PIN_PARENT_ID:
			parent_pin_id = nla_get_u32(an);
			parent_pin_id_valid = 1;
			break;
		case DPLL_A_PIN_STATE:
			pin_state = nla_get_u32(an);
			pin_state_valid = 1;
			break;
		default:
			break;
		}
	}

	if (!parent_pin_id_valid)
		return;
	parent = find_pin(dm, parent_pin_id);
	if (!parent)
		return;
	if (!pin) {
		pin = pin_create();
		if (!pin)
			return;
		pin->id = pin_id;
		STAILQ_INSERT_TAIL(&dm->pins, pin, list);
	}
	pin->muxed = 1;
	parent_add(pin, parent);
	if (!exist)
		pin->ready = 0;
	else
		pin->ready = 1;
	if (pin->valid) {
		parent->valid = PARENT_VALID;
		if (parent->state != DPLL_PIN_STATE_SELECTABLE)
			nl_dpll_pin_state_set(dm->dev_sk, dm->family,
					      parent->id, dm->dpll_id,
					      DPLL_PIN_STATE_SELECTABLE);
	}
	if (pin_state_valid)
		parent_state_set(pin, parent_pin_id, pin_state);
}

static void dpll_mon_pin_update(struct dpll_mon *dm, struct nlattr **tb,
				int exist, int notify, struct genlmsghdr *gnlh)
{
	struct nlattr *a;
	uint32_t pin_id;
	int rem;

	if (!tb[DPLL_A_PIN_ID])
		return;
	pin_id = nla_get_u32(tb[DPLL_A_PIN_ID]);

	nla_for_each_attr(a, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), rem) {
		if (nla_type(a) == DPLL_A_PIN_PARENT_DEVICE)
			update_pin(dm, pin_id, a, exist, notify);
		else if (nla_type(a) == DPLL_A_PIN_PARENT_PIN)
			update_muxed_pin(dm, pin_id, a, exist, notify);
	}
}

static void dpll_mon_device_update(struct dpll_mon *dm, struct nlattr **tb)
{
	dpll_mon_device_id_update(dm, tb);
	if (tb[DPLL_A_MODE]) {
		dm->dpll_mode = nla_get_u32(tb[DPLL_A_MODE]);
		pr_debug("mode:%u received on %s", dm->dpll_mode, dm->name);
	}
	if (tb[DPLL_A_LOCK_STATUS]) {
		dm->lock_status = nla_get_u32(tb[DPLL_A_LOCK_STATUS]);
		pr_debug("lock status:%u received on %s", dm->lock_status,
			 dm->name);
	}
}

static int dpll_mon_device_owner(struct dpll_mon *dm, struct nlattr **tb)
{
	if (tb[DPLL_A_CLOCK_ID] && tb[DPLL_A_MODULE_NAME] && tb[DPLL_A_TYPE])
		if (nla_get_u64(tb[DPLL_A_CLOCK_ID]) == dm->clock_id &&
		    !nla_strcmp(tb[DPLL_A_MODULE_NAME],
				dm->module_name) &&
		    nla_get_u32(tb[DPLL_A_TYPE]) == DPLL_TYPE_EEC)
			return 1;

	return 0;
}

static int pins_ready(struct dpll_mon *dm)
{
	struct dpll_mon_pin *pin;

	STAILQ_FOREACH(pin, &dm->pins, list) {
		if (!pin->ready) {
			pr_debug_pin("pin not ready", pin);
			return 0;
		}
	}

	return 1;
}

static int pins_dnu(struct dpll_mon *dm)
{
	struct dpll_mon_pin *pin;

	STAILQ_FOREACH(pin, &dm->pins, list) {
		if (pin->prio_valid && pin->prio != dm->dev_dnu_prio) {
			pr_debug("not expected pin id:%u prio: %u",
				 pin->id, pin->prio);
			return 0;
		}
	}

	return 1;
}

static void invalidate_pins(struct dpll_mon *dm)
{
	struct dpll_mon_pin *pin;

	STAILQ_FOREACH(pin, &dm->pins, list)
		pin->ready = 0;
}

static int dpll_mon_ntf_recv(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[MAX_ATTR + 1];
	struct dpll_mon *dm = arg;
	struct genlmsghdr *gnlh;
	int ret;

	gnlh = nlmsg_data(nlmsg_hdr(msg));
	if (!gnlh) {
		pr_err("failed parse gnl header");
		return -EINVAL;
	}
	ret = genlmsg_parse(nlmsg_hdr(msg), 0, tb, MAX_ATTR, NULL);
	if (ret) {
		pr_err("genlsmg_parse err:%d", ret);
		return ret;
	}
	lock_mutex(dm, __func__);
	switch (gnlh->cmd) {
	case DPLL_CMD_DEVICE_CREATE_NTF:
		if ((dm->state == DPLL_MON_STATE_INIT_READY ||
		     dm->state == DPLL_MON_STATE_DEV_GET_WAIT) &&
		    dpll_mon_device_owner(dm, tb)) {
			dpll_mon_device_update(dm, tb);
			dpll_mon_state_set(dm, DPLL_MON_STATE_DEV_INITED);
		}
		break;
	case DPLL_CMD_DEVICE_CHANGE_NTF:
		if (dpll_mon_device_owner(dm, tb))
			dpll_mon_device_update(dm, tb);
		break;
	case DPLL_CMD_DEVICE_DELETE_NTF:
		if (dpll_mon_device_owner(dm, tb))
			dpll_mon_state_set(dm, DPLL_MON_STATE_DPLL_REINIT);
		break;
	case DPLL_CMD_PIN_DELETE_NTF:
		dpll_mon_pin_update(dm, tb, 0, 1, gnlh);
		break;
	case DPLL_CMD_PIN_CREATE_NTF:
	case DPLL_CMD_PIN_CHANGE_NTF:
		dpll_mon_pin_update(dm, tb, 1, 1, gnlh);
		break;
	default:
		break;
	}
	unlock_mutex(dm, __func__);

	return NL_OK;
}

static int dpll_rt_recv(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[IFLA_MAX + 1], *an[DPLL_A_PIN_ID + 1];
	struct sk_arg *args = arg;
	struct dpll_mon_pin *pin;
	struct ifinfomsg *info;
	struct nlmsghdr *nlh;
	struct dpll_mon *dm;
	uint32_t pin_id;
	int ret;

	dm = args->arg;
	nlh = nlmsg_hdr(msg);
	if (!nlh) {
		pr_err("fail missing nl header");
		return -EINVAL;
	}
	ret = nlmsg_parse(nlh, sizeof(*info), tb, IFLA_MAX, NULL);
	if (ret) {
		pr_err("rt nlsmg_parse err:%d", ret);
		return ret;
	}
	info = nlmsg_data(nlh);
	lock_mutex(dm, __func__);
	pin = find_pin_by_if_index(dm, info->ifi_index);
	if (!tb[IFLA_DPLL_PIN])
		goto unlock;
	nla_parse_nested(an, DPLL_A_PIN_ID, tb[IFLA_DPLL_PIN], NULL);
	if (!an[DPLL_A_PIN_ID])
		goto unlock;
	pin_id = nla_get_u32(an[DPLL_A_PIN_ID]);
	if (pin) {
		remove_no_ifname_pin(dm, pin_id, pin);
		pin->id = pin_id;
		pr_debug_pin("pin assigned id", pin);
	} else {
		pin = find_pin(dm, pin_id);
		if (pin) {
			pin->if_index = info->ifi_index;
			pr_debug_pin("pin assigned if_index", pin);
		}
	}

unlock:
	unlock_mutex(dm, __func__);

	return NL_OK;
}

static int dpll_mon_recv(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[MAX_ATTR + 1];
	struct sk_arg *args = arg;
	struct genlmsghdr *gnlh;
	struct dpll_mon *dm;
	int ret;

	dm = args->arg;
	gnlh = nlmsg_data(nlmsg_hdr(msg));
	if (!gnlh) {
		pr_err("fail missing gnl header");
		return -EINVAL;
	}
	ret = genlmsg_parse(nlmsg_hdr(msg), 0, tb, MAX_ATTR, NULL);
	if (ret) {
		pr_err("genlsmg_parse err:%d", ret);
		return ret;
	}
	lock_mutex(dm, __func__);
	switch (gnlh->cmd) {
	case DPLL_CMD_DEVICE_ID_GET:
		if (dm->state == DPLL_MON_STATE_INIT_READY)
			dpll_mon_device_id_update(dm, tb);
		break;
	case DPLL_CMD_DEVICE_GET:
		if (dm->state == DPLL_MON_STATE_DEV_GET_WAIT &&
		    dpll_mon_device_owner(dm, tb)) {
			dpll_mon_device_update(dm, tb);
			dpll_mon_state_set(dm, DPLL_MON_STATE_DEV_INITED);
		}
		break;
	case DPLL_CMD_PIN_ID_GET:
		dpll_mon_pin_id_update(dm, tb);
		break;
	case DPLL_CMD_PIN_GET:
		dpll_mon_pin_update(dm, tb, 1, 0, gnlh);
		break;

	default:
		break;
	}
	unlock_mutex(dm, __func__);

	return NL_OK;
}

static int init_pins(struct dpll_mon *dm)
{
	struct dpll_mon_pin *pin;
	int ret;

	ret = nl_rt_dump_links(dm->rt_sk, &dm->rt_args);
	if (ret < 0) {
		pr_err("RT link dump request failed");
		return ret;
	}
	pr_debug("RT link dump requested");
	STAILQ_FOREACH(pin, &dm->pins, list) {
		if (!pin->ifname && pin->valid == PIN_VALID) {
			pin->id_requested = 1;
			ret = nl_dpll_pin_id_get(dm->dev_sk, &dm->dev_args,
						 dm->family, dm->clock_id,
						 dm->module_name,
						 pin->board_label,
						 pin->panel_label,
						 pin->package_label, pin->type);
			pin->id_requested = 0;
			if (ret < 0) {
				pr_debug_pin("get id failed", pin);
				return ret;
			}
		}
	}
	ret = nl_dpll_pin_dump(dm->dev_sk, &dm->dev_args, dm->family);
	if (ret < 0)
		pr_err("dpll pin dump request failed");
	else
		pr_debug("dpll pin dump requested");

	return ret;
}

int sockets_init(struct dpll_mon *dm)
{
	dm->dev_args.arg = dm;
	dm->dev_sk = nl_dpll_sk_create(dpll_mon_recv, &dm->dev_args);
	if (dm->dev_sk) {
		pr_debug("dev socket created for %s device", dm->name);
	} else {
		pr_err("dev socket failed for %s device", dm->name);
		return -EINVAL;
	}
	dm->family = nl_dpll_family_resolve(dm->dev_sk);
	if (dm->family < 0)
		pr_err("nl dpll family not found for %s device", dm->name);

	dm->rt_args.arg = dm;
	dm->rt_sk = nl_rt_sk_create(dpll_rt_recv, &dm->rt_args);
	if (!dm->rt_sk) {
		pr_err("rt socket failed for %s device", dm->name);
		return -EINVAL;
	}
	return 0;
}

void sockets_deinit(struct dpll_mon *dm)
{
	if (dm->dev_sk) {
		nl_dpll_sk_destroy(dm->dev_sk);
		dm->dev_sk = NULL;
	}
	if (dm->rt_sk) {
		nl_dpll_sk_destroy(dm->rt_sk);
		dm->rt_sk = NULL;
	}
}

int sockets_reinit(struct dpll_mon *dm)
{
	sockets_deinit(dm);

	return sockets_init(dm);
}

static int need_reinit(struct dpll_mon *dm)
{
	dm->init_err++;

	return dm->init_err % PIN_READY_TRIES == 0;
}

static void state_step(struct dpll_mon *dm)
{
	int ret;

	switch (dm->state) {
	case DPLL_MON_STATE_INIT_READY:
		ret = nl_dpll_device_id_get(dm->dev_sk, &dm->dev_args,
					    dm->family, dm->clock_id,
					    dm->module_name);
		if (ret) {
			if (need_reinit(dm))
				dpll_mon_state_set(dm,
						   DPLL_MON_STATE_DPLL_REINIT);
			pr_debug("dpll get dev id request failed");
		} else {
			dpll_mon_state_set(dm, DPLL_MON_STATE_DEV_ID_READY);
			pr_debug("dpll get dev id requested");
		}
		break;
	case DPLL_MON_STATE_DEV_ID_READY:
		dpll_mon_state_set(dm, DPLL_MON_STATE_DEV_GET_WAIT);
		ret = nl_dpll_device_get(dm->dev_sk, &dm->dev_args,
					 dm->family, dm->dpll_id);
		if (ret)
			pr_debug("dpll get dev request failed");
		else
			pr_debug("dpll get dev requested");
		break;
	case DPLL_MON_STATE_DEV_INITED:
		ret = init_pins(dm);
		if (ret && need_reinit(dm))
			dpll_mon_state_set(dm, DPLL_MON_STATE_DPLL_REINIT);
		else
			dpll_mon_state_set(dm, DPLL_MON_STATE_PIN_DUMP_WAIT);
		break;
	case DPLL_MON_STATE_PIN_DUMP_WAIT:
		if (pins_ready(dm))
			dpll_mon_state_set(dm, DPLL_MON_STATE_PINS_VALID);
		else if (need_reinit(dm))
			dpll_mon_state_set(dm, DPLL_MON_STATE_DPLL_REINIT);
		break;
	case DPLL_MON_STATE_PINS_VALID:
		ret = dpll_mon_pins_prio_dnu_set(dm);
		if (!ret)
			dpll_mon_state_set(dm, DPLL_MON_STATE_PINS_INITED);
		break;
	case DPLL_MON_STATE_PINS_INITED:
		if (pins_dnu(dm)) {
			dpll_mon_state_set(dm, DPLL_MON_STATE_RUNNING);
			pr_info("dpll device for %s - init successful", dm->name);
		} else if (need_reinit(dm)) {
			dpll_mon_state_set(dm, DPLL_MON_STATE_DPLL_REINIT);
		}
		break;
	case DPLL_MON_STATE_DPLL_REINIT:
		pr_info("dpll device for %s - reinit requested", dm->name);
		ret = sockets_reinit(dm);
		if (ret)
			pr_err("unable to reinit dpll_mon sockets for %s ret:%d",
			       dm->name, ret);
		invalidate_pins(dm);
		dpll_mon_state_set(dm, DPLL_MON_STATE_INIT_READY);
		break;
	default:
		break;
	}
}

int dpll_mon_dev_running(struct dpll_mon *dm)
{
	state_step(dm);

	return dm->state == DPLL_MON_STATE_RUNNING;
}

static int dpll_mon_thread_create(void *data)
{
	char thread_name[TASK_COMM_LEN];
	struct dpll_mon *dm = data;
	pthread_t *thread_id;
	pthread_attr_t attr;
	const char *name;
	int err;

	name = dm->name;
	thread_id = &dm->thread_id;
	err = pthread_attr_init(&attr);
	if (err) {
		pr_err("init dpll_mon thread attr failed for %s", name);
		goto err_attr;
	}

	err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (err) {
		pr_err("set dpll_mon thread detached failed for %s err=%d",
		       name, err);
		goto err_attr;
	}

	err = pthread_attr_setstacksize(&attr, SYNCE_THREAD_STACK_SIZE);
	if (err) {
		pr_err("set dpll_mon thread stack failed for %s err=%d",
		       name, err);
		goto err_attr;
	}

	err = pthread_create(thread_id, &attr, dpll_mon_thread, data);
	if (err) {
		pr_err("create dpll_mon thread failed for %s err=%d",
		       name, err);
		goto err_attr;
	}

	snprintf(thread_name, TASK_COMM_LEN, "dpll_mon-%s", name);
	err = pthread_setname_np(*thread_id, thread_name);
	if (err)
		pr_info("failed to set dpll_mon thread's name for %s", name);

	pthread_attr_destroy(&attr);
	return 0;

err_attr:
	pthread_attr_destroy(&attr);
	return -ECHILD;
}

void dpll_mon_destroy(struct dpll_mon *dm)
{
	struct dpll_mon_pin *pin;

	if (dm->dev_sk)
		nl_dpll_sk_destroy(dm->dev_sk);
	if (dm->mon_sk)
		nl_dpll_sk_destroy(dm->mon_sk);
	if (dm->rt_sk)
		nl_dpll_sk_destroy(dm->rt_sk);
#ifdef UNIT_TESTS
	dpll_mon_state_set(dm, DPLL_MON_STATE_STOPPED);
#else
	dpll_mon_state_set(dm, DPLL_MON_STATE_STOPPING);
#endif
	while (dm->state == DPLL_MON_STATE_STOPPING)
		usleep(THREAD_STOP_SLEEP_USEC);
	while ((pin = STAILQ_FIRST(&dm->pins))) {
		STAILQ_REMOVE_HEAD(&dm->pins, list);
		pin_destroy(pin);
	}
	pthread_mutex_destroy(&dm->lock);

	free(dm);
}

int dpll_mon_init(struct dpll_mon *dm)
{
	int ret;

	if (dm->state != DPLL_MON_STATE_CREATED) {
		pr_debug("%s wrong dpll monitor state for %s device",
			 __func__, dm->name);
		return -ENODEV;
	}

	dm->mon_sk = nl_dpll_mon_socket_create(dpll_mon_ntf_recv, dm);
	if (dm->mon_sk) {
		pr_debug("monitor socket created");
	} else {
		pr_debug("failed to create monitor socket");
		return -EINVAL;
	}
	ret = sockets_init(dm);
	if (ret)
		return ret;
	STAILQ_INIT(&dm->pins);
	dpll_mon_state_set(dm, DPLL_MON_STATE_INIT_READY);
	ret = dpll_mon_thread_create(dm);
	if (ret) {
		dpll_mon_destroy(dm);
		return ret;
	}
	if (pthread_mutex_init(&dm->lock, NULL)) {
		pr_err("%s: dpll_mon mutex init failure", dm->name);
		return -EFAULT;
	}

	return 0;
}

int dpll_mon_mode_get(struct dpll_mon *dm, enum dpll_mode *mode)
{
	*mode = dm->dpll_mode;

	return 0;
}

int dpll_mon_lock_state_get(struct dpll_mon *dm, enum eec_state *state)
{
	*state = lock_status_to_state[dm->lock_status];

	return 0;
}

struct dpll_mon_pin
*dpll_mon_add_pin(struct dpll_mon *dm, const char *board_label,
		  const char *panel_label, const char *package_label,
		  enum dpll_pin_type type)
{
	struct dpll_mon_pin *pin = pin_create();

	if (!pin)
		return NULL;
	pin->board_label = board_label;
	pin->package_label = package_label;
	pin->panel_label = panel_label;
	pin->type = type;
	pin->valid = PIN_VALID;
	STAILQ_INSERT_TAIL(&dm->pins, pin, list);
	pr_debug_pin("adding valid pin", pin);

	return pin;
}

struct dpll_mon_pin
*dpll_mon_add_port_pin(struct dpll_mon *dm, const char *ifname)
{
	struct dpll_mon_pin *pin = pin_create();
	int fd;

	if (!pin)
		return NULL;
	pin->ifname = ifname;
	fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, PF_UNIX);
	if (fd < 0) {
		pr_err("create socket for %s failed: %m", ifname);
		if (fd == -EPERM)
			pr_err("try running as root");
		goto error;
	}
	pin->if_index = sk_interface_index(fd, ifname);
	if (pin->if_index < 0) {
		pr_err("sk_interface_index for %s failed: %m", ifname);
		close(fd);
		goto error;
	}
	close(fd);
	pin->type = DPLL_PIN_TYPE_SYNCE_ETH_PORT;
	pin->valid = PIN_VALID;
	STAILQ_INSERT_TAIL(&dm->pins, pin, list);
	pr_debug_pin("adding valid pin", pin);

	return pin;
error:
	free(pin);
	return NULL;
}

int dpll_mon_pin_is_active(struct dpll_mon *dm, struct dpll_mon_pin *pin)
{
	struct dpll_mon_pin *parent;
	struct parent_pin *pp;

	if (!pin->muxed)
		return pin->state == DPLL_PIN_STATE_CONNECTED;
	STAILQ_FOREACH(pp, &pin->parents, list)
		if (pp->state == DPLL_PIN_STATE_CONNECTED) {
			parent = find_pin(dm, pp->id);
			if (parent->state == DPLL_PIN_STATE_CONNECTED)
				return 1;
		}
	return 0;
}

int disconnect_parent(struct dpll_mon *dm, uint32_t pin_id, uint32_t parent_id)
{
	return nl_dpll_pin_parent_state_set(dm->dev_sk, dm->family, pin_id,
					    parent_id,
					    DPLL_PIN_STATE_DISCONNECTED);
}

int connect_parent(struct dpll_mon *dm, uint32_t pin_id, uint32_t parent_id)
{
	return nl_dpll_pin_parent_state_set(dm->dev_sk, dm->family, pin_id,
					    parent_id,
					    DPLL_PIN_STATE_CONNECTED);
}

int set_prio(struct dpll_mon *dm, uint32_t pin_id, uint32_t prio)
{
	pr_debug("trying set prio=%u for pin:%u on %s", prio, pin_id, dm->name);
	return nl_dpll_pin_prio_set(dm->dev_sk, dm->family, pin_id,
				    dm->dpll_id, prio);
}

int dpll_mon_pin_prio_clear(struct dpll_mon *dm, struct dpll_mon_pin *pin)
{
	struct dpll_mon_pin *parent;
	struct parent_pin *pp;
	int ret;

	if (pin->prio_valid)
		return set_prio(dm, pin->id, dm->dev_dnu_prio);
	STAILQ_FOREACH(pp, &pin->parents, list) {
		if (pp->state == DPLL_PIN_STATE_CONNECTED) {
			parent = find_pin(dm, pp->id);
			parent->parent_used_by = PARENT_NOT_USED;
			ret = disconnect_parent(dm, pin->id, parent->id);
			if (ret < 0)
				return ret;
			ret = set_prio(dm, parent->id, dm->dev_dnu_prio);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

int dpll_mon_pin_prio_get(struct dpll_mon *dm, struct dpll_mon_pin *pin,
			  uint32_t *prio)
{
	struct dpll_mon_pin *parent;
	struct parent_pin *pp;

	if (pin->prio_valid) {
		*prio = pin->prio;
		return 0;
	}
	STAILQ_FOREACH(pp, &pin->parents, list) {
		parent = find_pin(dm, pp->id);
		if (parent->parent_used_by == pin->id) {
			*prio = parent->prio;
			return 0;
		}
	}

	return -EINVAL;
}

int dpll_mon_pin_prio_set(struct dpll_mon *dm, struct dpll_mon_pin *pin,
			  uint32_t prio)
{
	struct dpll_mon_pin *parent;
	struct parent_pin *pp;
	int ret;

	if (prio == dm->dev_dnu_prio) {
		pr_err("setting prio to DNU not allowed");
		return -EINVAL;
	}
	if (pin->prio_valid)
		return set_prio(dm, pin->id, prio);

	STAILQ_FOREACH(pp, &pin->parents, list) {
		parent = find_pin(dm, pp->id);
		if (parent->parent_used_by == pin->id) {
			pr_debug("parent present(id:%u) prio=%u for pin:%u on %s",
				 parent->id, parent->prio, pin->id, dm->name);
			if (parent->prio != prio)
				return set_prio(dm, parent->id, prio);
			return 0;
		}
	}
	STAILQ_FOREACH(pp, &pin->parents, list) {
		parent = find_pin(dm, pp->id);
		if (parent->parent_used_by != PARENT_NOT_USED)
			continue;
		ret = connect_parent(dm, pin->id, parent->id);
		if (ret < 0) {
			pr_debug("failed to send connect request for pin:%u with parent: %u on %s",
				 pin->id, parent->id, dm->name);
			return ret;
		}
		ret = set_prio(dm, parent->id, prio);
		if (ret < 0) {
			pr_debug("failed to send set prio=%u for pin:%u on parent: %u on %s",
				 prio, pin->id, parent->id, dm->name);
			return ret;
		}
		parent->parent_used_by = pin->id;
		return 0;
	}
	pr_debug("unused parent not available for pin:%u for priority set on %s",
		 pin->id, dm->name);

	return 0;
}

int dpll_mon_pins_prio_dnu_set(struct dpll_mon *dm)
{
	struct dpll_mon_pin *pin;
	int ret;

	STAILQ_FOREACH(pin, &dm->pins, list) {
		if (!(pin->muxed || pin->prio_valid))
			continue;
		ret = dpll_mon_pin_prio_clear(dm, pin);
		if (ret < 0)
			return ret;
	}

	return 0;
}
