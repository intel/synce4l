/**
 * @file nl_dpll.c
 * @brief Implements a netlink dpll communication class
 * @note SPDX-FileCopyrightText: Copyright 2023 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <inttypes.h>
#include "nl_dpll.h"
#include "print.h"

#define MSG_DONE	0
int err_handler(__attribute__((unused))struct sockaddr_nl *nla,
		struct nlmsgerr *err, void *arg)
{
	int *ret = (int *)arg;
	*ret = err->error;

	return NL_STOP;
}

int fin_handler(__attribute__((unused))struct nl_msg *msg, void *arg)
{
	int *ret = (int *)arg;
	*ret = MSG_DONE;

	return NL_SKIP;
}

int ack_handler(__attribute__((unused))struct nl_msg *msg, void *arg)
{
	int *ret = (int *)arg;
	*ret = MSG_DONE;

	return NL_OK;
}

struct nl_sock *nl_dpll_sk_create(nl_recvmsg_msg_cb_t cb, struct sk_arg *arg)
{
	struct nl_sock *sk;
	int ret;

	sk = nl_socket_alloc();
	if (!sk) {
		pr_err("failed to allocate global socket");
		return NULL;
	}

	ret = genl_connect(sk);
	if (ret) {
		pr_err("could not connect the global socket: %s",
		       nl_geterror(ret));
		goto error;
	}

	ret = genl_ctrl_resolve(sk, DPLL_FAMILY_NAME);
	if (ret < 0)
		pr_err("could not resolve dpll netlink family: %s",
		       nl_geterror(ret));
	if (nl_socket_set_nonblocking(sk))
		goto error;
	nl_socket_modify_err_cb(sk, NL_CB_CUSTOM, err_handler, &arg->err);
	nl_socket_modify_cb(sk, NL_CB_FINISH, NL_CB_CUSTOM, fin_handler,
			    &arg->done);
	nl_socket_modify_cb(sk, NL_CB_ACK, NL_CB_CUSTOM, ack_handler,
			    &arg->done);
	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, cb, arg);
	nl_socket_set_buffer_size(sk, 1024*127, 1024*127);

	return sk;
error:
	nl_socket_free(sk);
	return NULL;
}

void nl_dpll_sk_destroy(struct nl_sock *sk)
{
	nl_close(sk);
	nl_socket_free(sk);
}

int nl_dpll_family_resolve(struct nl_sock *sk)
{
	return genl_ctrl_resolve(sk, DPLL_FAMILY_NAME);
}

int nl_dpll_device_id_get(struct nl_sock *sk, struct sk_arg *arg,
			  int family, uint64_t clock_id,
			  const char *module_name)
{
	struct request_hdr *hdr;
	struct nl_msg *msg;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg) {
		pr_err("%s: out of memory", __func__);
		return ret;
	}
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			  0, 0, DPLL_CMD_DEVICE_ID_GET, 1);
	if (!hdr) {
		pr_debug("%s: failed build request", __func__);
		goto msg_free;
	}
	ret = -EMSGSIZE;
	if (nla_put_u64(msg, DPLL_A_CLOCK_ID, clock_id))
		goto msg_free;
	if (nla_put_string(msg, DPLL_A_MODULE_NAME, module_name))
		goto msg_free;
	if (nla_put_u32(msg, DPLL_A_TYPE, DPLL_TYPE_EEC))
		goto msg_free;
	ret = nl_send_auto(sk, msg);
	if (ret < 0) {
		pr_err("%s: failed to send request", __func__);
		goto msg_free;
	}
	pr_debug("DEVICE_ID_GET request sent dpll id: %" PRIu64 " %s, ret:%d",
		 clock_id, module_name, ret);

	arg->err = 0;
	arg->done = !MSG_DONE;
	while (arg->err == 0 && arg->done != MSG_DONE)
		nl_recvmsgs_default(sk);
	ret = arg->err;
msg_free:
	nlmsg_free(msg);

	return ret;
}

int nl_dpll_device_get(struct nl_sock *sk, struct sk_arg *arg,
		       int family, uint32_t dpll_id)
{
	struct request_hdr *hdr;
	struct nl_msg *msg;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg) {
		pr_err("%s: out of memory", __func__);
		return ret;
	}
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			  0, NLM_F_REQUEST, DPLL_CMD_DEVICE_GET, 1);
	if (!hdr) {
		pr_debug("%s: failed build request", __func__);
		goto msg_free;
	}

	ret = -EMSGSIZE;
	if (nla_put_u32(msg, DPLL_A_ID, dpll_id))
		goto msg_free;
	ret = nl_send_auto(sk, msg);
	if (ret < 0) {
		pr_err("%s: failed to send request", __func__);
		goto msg_free;
	}
	pr_debug("DEVICE_GET request sent dpll_id:%u, ret:%d", dpll_id, ret);

	arg->err = 0;
	arg->done = !MSG_DONE;
	while (arg->err == 0 && arg->done != MSG_DONE)
		nl_recvmsgs_default(sk);
	ret = arg->err;
msg_free:
	nlmsg_free(msg);

	return ret;
}

int nl_dpll_pin_id_get(struct nl_sock *sk, struct sk_arg *arg,
		       int family, uint64_t clock_id, const char *module_name,
		       const char *board_label, const char *panel_label,
		       const char *package_label, enum dpll_pin_type type)
{
	struct request_hdr *hdr;
	struct nl_msg *msg;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg) {
		pr_err("%s: out of memory", __func__);
		return ret;
	}
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			  0, NLM_F_REQUEST, DPLL_CMD_PIN_ID_GET, 1);
	if (!hdr) {
		pr_debug("%s: failed build request", __func__);
		goto msg_free;
	}

	ret = -EMSGSIZE;
	if (nla_put_u64(msg, DPLL_A_PIN_CLOCK_ID, clock_id))
		goto msg_free;
	if (nla_put_string(msg, DPLL_A_PIN_MODULE_NAME, module_name))
		goto msg_free;
	if (board_label)
		if (nla_put_string(msg, DPLL_A_PIN_BOARD_LABEL, board_label))
			goto msg_free;
	if (panel_label)
		if (nla_put_string(msg, DPLL_A_PIN_PANEL_LABEL, panel_label))
			goto msg_free;
	if (package_label)
		if (nla_put_string(msg, DPLL_A_PIN_PACKAGE_LABEL,
				   package_label))
			goto msg_free;
	if (type)
		if (nla_put_u32(msg, DPLL_A_PIN_TYPE, type))
			goto msg_free;

	ret = nl_send_auto(sk, msg);
	if (ret < 0) {
		pr_err("%s: failed to send request", __func__);
		goto msg_free;
	}
	pr_debug("PIN_ID_GET request sent ret:%d", ret);

	arg->err = 0;
	arg->done = !MSG_DONE;
	while (arg->err == 0 && arg->done != MSG_DONE)
		nl_recvmsgs_default(sk);
	ret = arg->err;
msg_free:
	nlmsg_free(msg);

	return ret;
}

int nl_dpll_pin_get(struct nl_sock *sk, struct sk_arg *arg,
		    int family, uint32_t pin_id)
{
	struct request_hdr *hdr;
	struct nl_msg *msg;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg) {
		pr_err("%s: out of memory", __func__);
		return ret;
	}
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			  0, NLM_F_REQUEST, DPLL_CMD_PIN_GET, 1);
	if (!hdr) {
		pr_debug("%s: failed build request", __func__);
		goto msg_free;
	}

	ret = -EMSGSIZE;
	if (nla_put_u32(msg, DPLL_A_PIN_ID, pin_id))
		goto msg_free;
	ret = nl_send_auto(sk, msg);
	if (ret < 0) {
		pr_err("%s: failed to send request", __func__);
		goto msg_free;
	}
	pr_debug("PIN_GET request sent pin_id:%u ret:%d", pin_id, ret);

	arg->err = 0;
	arg->done = !MSG_DONE;
	while (arg->err == 0 && arg->done != MSG_DONE)
		nl_recvmsgs_default(sk);
	ret = arg->err;
msg_free:
	nlmsg_free(msg);

	return ret;
}

int nl_dpll_pin_dump(struct nl_sock *sk, struct sk_arg *arg,
		     int family)
{
	struct request_hdr *hdr;
	struct nl_msg *msg;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg) {
		pr_err("%s: out of memory", __func__);
		return ret;
	}
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			  0, NLM_F_REQUEST | NLM_F_DUMP, DPLL_CMD_PIN_GET, 1);
	if (!hdr) {
		pr_err("%s: failed build request", __func__);
		goto msg_free;
	}

	ret = nl_send_auto(sk, msg);
	if (ret < 0) {
		pr_err("%s: failed to send request", __func__);
		return ret;
	}
	pr_debug("PIN_GET dump request sent ret:%d", ret);

	arg->err = 0;
	arg->done = !MSG_DONE;
	while (arg->err == 0 && arg->done != MSG_DONE)
		nl_recvmsgs_default(sk);
	ret = arg->err;
msg_free:
	nlmsg_free(msg);

	return ret;
}

int nl_dpll_pin_parent_state_set(struct nl_sock *sk, int family,
				 uint32_t pin_id, uint32_t parent_id,
				 enum dpll_pin_state state)
{
	struct request_hdr *hdr;
	struct nlattr *nest;
	struct nl_msg *msg;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg) {
		pr_err("%s: out of memory", __func__);
		return ret;
	}
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			  0, NLM_F_REQUEST, DPLL_CMD_PIN_SET, 1);
	if (!hdr) {
		pr_debug("%s: failed build request", __func__);
		goto msg_free;
	}

	ret = -EMSGSIZE;
	if (nla_put_u32(msg, DPLL_A_PIN_ID, pin_id))
		goto msg_free;
	nest = nla_nest_start(msg, DPLL_A_PIN_PARENT_PIN);
	if (!nest)
		goto msg_free;
	if (nla_put_u32(msg, DPLL_A_PIN_PARENT_ID, parent_id))
		goto nest_cancel;
	if (nla_put_u32(msg, DPLL_A_PIN_STATE, state))
		goto nest_cancel;
	nla_nest_end(msg, nest);
	ret = nl_send_auto(sk, msg);
	nlmsg_free(msg);
	if (ret < 0)
		pr_err("%s: failed to send request", __func__);
	pr_debug("PIN_SET request sent state:%u, pin:%u parent:%u ret:%d",
		 state, pin_id, parent_id, ret);

	return ret;

nest_cancel:
	nla_nest_cancel(msg, nest);
msg_free:
	nlmsg_free(msg);
	return ret;
}

int nl_dpll_pin_prio_set(struct nl_sock *sk, int family,
			 uint32_t pin_id, uint32_t dev_id,
			 uint32_t prio)
{
	struct request_hdr *hdr;
	struct nlattr *nest;
	struct nl_msg *msg;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg) {
		pr_err("%s: out of memory", __func__);
		return ret;
	}
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			  0, NLM_F_REQUEST, DPLL_CMD_PIN_SET, 1);
	if (!hdr) {
		pr_debug("%s: failed build request", __func__);
		goto msg_free;
	}

	ret = -EMSGSIZE;
	if (nla_put_u32(msg, DPLL_A_PIN_ID, pin_id))
		goto msg_free;
	nest = nla_nest_start(msg, DPLL_A_PIN_PARENT_DEVICE);
	if (!nest)
		goto msg_free;
	if (nla_put_u32(msg, DPLL_A_PIN_PARENT_ID, dev_id))
		goto nest_cancel;
	if (nla_put_u32(msg, DPLL_A_PIN_PRIO, prio))
		goto nest_cancel;
	nla_nest_end(msg, nest);
	ret = nl_send_auto(sk, msg);
	nlmsg_free(msg);
	if (ret < 0)
		pr_err("%s: failed to send request", __func__);
	pr_debug("PIN_SET request sent prio:%u, pin:%u dpll:%u ret: %d",
		 prio, pin_id, dev_id, ret);

	return ret;
nest_cancel:
	nla_nest_cancel(msg, nest);
msg_free:
	nlmsg_free(msg);
	return ret;
}

int nl_dpll_pin_state_set(struct nl_sock *sk, int family, uint32_t pin_id,
			  uint32_t dev_id, enum dpll_pin_state state)
{
	struct request_hdr *hdr;
	struct nlattr *nest;
	struct nl_msg *msg;
	int ret = -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg) {
		pr_err("%s: out of memory", __func__);
		return ret;
	}
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family,
			  0, NLM_F_REQUEST, DPLL_CMD_PIN_SET, 1);
	if (!hdr) {
		pr_debug("%s: failed build request", __func__);
		goto msg_free;
	}

	ret = -EMSGSIZE;
	if (nla_put_u32(msg, DPLL_A_PIN_ID, pin_id))
		goto msg_free;
	nest = nla_nest_start(msg, DPLL_A_PIN_PARENT_DEVICE);
	if (!nest)
		goto msg_free;
	if (nla_put_u32(msg, DPLL_A_PIN_PARENT_ID, dev_id))
		goto nest_cancel;
	if (nla_put_u32(msg, DPLL_A_PIN_STATE, state))
		goto nest_cancel;
	nla_nest_end(msg, nest);
	ret = nl_send_auto(sk, msg);
	nlmsg_free(msg);
	if (ret < 0)
		pr_err("%s: failed to send request", __func__);
	pr_debug("PIN_SET request sent state:%d, pin:%u dpll:%u ret: %d",
		 state, pin_id, dev_id, ret);

	return ret;
nest_cancel:
	nla_nest_cancel(msg, nest);
msg_free:
	nlmsg_free(msg);
	return ret;
}

struct nl_sock *nl_dpll_mon_socket_create(nl_recvmsg_msg_cb_t cb, void *arg)
{
	struct nl_sock *mon_sk;
	int ret, grp;

	mon_sk = nl_socket_alloc();
	if (!mon_sk) {
		pr_err("failed to allocate monitor socket");
		return NULL;
	}
	nl_socket_disable_seq_check(mon_sk);
	if (nl_socket_modify_cb(mon_sk, NL_CB_VALID, NL_CB_CUSTOM, cb, arg))
		goto error;
	ret = genl_connect(mon_sk);
	if (ret) {
		pr_err("could not connect the mon socket: %s",
		       nl_geterror(ret));
		goto error;
	}
	grp = genl_ctrl_resolve_grp(mon_sk, DPLL_FAMILY_NAME,
				    DPLL_MCGRP_MONITOR);
	if (nl_socket_add_memberships(mon_sk, grp, 0)) {
		pr_err("could not join MONITOR group");
		goto error;
	}
	if (nl_socket_set_nonblocking(mon_sk))
		goto error;

	return mon_sk;
error:
	nl_socket_free(mon_sk);
	return NULL;
}

struct nl_sock *nl_rt_sk_create(nl_recvmsg_msg_cb_t cb, struct sk_arg *arg)
{
	struct nl_sock *sk;
	int ret;

	sk = nl_socket_alloc();
	if (!sk) {
		pr_err("failed to allocate rtnl socket");
		return NULL;
	}

	ret = nl_connect(sk, NETLINK_ROUTE);
	if (ret) {
		pr_err("could not connect the rtnl socket: %s",
		       nl_geterror(ret));
		goto error;
	}
	nl_socket_modify_err_cb(sk, NL_CB_CUSTOM, err_handler, &arg->err);
	nl_socket_modify_cb(sk, NL_CB_FINISH, NL_CB_CUSTOM, fin_handler,
			    &arg->done);
	nl_socket_modify_cb(sk, NL_CB_ACK, NL_CB_CUSTOM, ack_handler,
			    &arg->done);
	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, cb, arg);

	if (nl_socket_set_nonblocking(sk))
		goto error;

	return sk;
error:
	nl_socket_free(sk);
	return NULL;
}

int nl_rt_dump_links(struct nl_sock *rt_sk, struct sk_arg *arg)
{
	struct rtgenmsg rt_hdr = {
		.rtgen_family = AF_NETLINK,
	};
	int ret = nl_send_simple(rt_sk, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP,
				 &rt_hdr, sizeof(rt_hdr));

	if (ret < 0) {
		pr_err("%s: failed to send request", __func__);
		return ret;
	}
	arg->err = 0;
	arg->done = !MSG_DONE;
	while (arg->err == 0 && arg->done != MSG_DONE)
		nl_recvmsgs_default(rt_sk);

	return arg->err;
}
