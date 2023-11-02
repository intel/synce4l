/**
 * @file synce_port_ctrl.c
 * @brief Interface between synce port and socket handling theads, used
 * for controling data on the wire. Allows acquire incoming data and
 * submit new outgoing data.
 * TX thread is always present, RX only if required (line input mode).
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <net/if.h>
#include <errno.h>
#include <stdbool.h>
#include "print.h"
#include "config.h"
#include "synce_port_ctrl.h"
#include "synce_transport.h"
#include "synce_msg.h"
#include "synce_thread_common.h"

#define RX_THREAD		0
#define TX_THREAD		1

struct ql {
	STAILQ_ENTRY(ql) list;
	uint8_t value;
};

struct thread_common_data {
	int heartbeat_usec;
	int state;
	uint8_t ql;
	int extended;
	struct synce_msg_ext_ql ext_ql;
	struct synce_transport *transport;
	struct synce_pdu *pdu;
	char *name;
	int enabled;
	pthread_mutex_t lock;
};

struct synce_port_tx {
	struct thread_common_data cd;
	int rebuild_tlv;
};

struct synce_port_rx {
	struct thread_common_data cd;
	uint8_t last_ql;
	struct synce_msg_ext_ql last_ext_ql;
	int ql_failed;
	struct timespec last_recv_ts;
	struct timespec first_valid_ts;
	uint64_t n_recv;
	int recover_time;
	int ext_tlv_recvd;
	uint8_t ql_dnu_val;
	uint8_t ext_ql_dnu_val;

	STAILQ_HEAD(allowed_qls_head, ql) allowed_qls;
	STAILQ_HEAD(allowed_ext_qls_head, ql) allowed_ext_qls;
};

struct synce_port_ctrl {
	char name[IF_NAMESIZE];
	struct synce_port_tx tx;
	struct synce_port_rx rx;
	pthread_t tx_thread_id;
	pthread_t rx_thread_id;
	struct synce_transport *transport;
	const uint16_t *priority_list;
	int priority_list_count;
};

enum thread_state {
	THREAD_NOT_STARTED = 0,
	THREAD_STARTED,
	THREAD_STOPPING,
	THREAD_STOPPED,
	THREAD_FAILED,
};

static int lock_mutex(struct thread_common_data *cd, const char *func)
{
	int ret = pthread_mutex_lock(&cd->lock);

	if (ret) {
		pr_err("%s: lock mutex failed err: %d on %s",
		       func, ret, cd->name);
	}

	return ret;
}

static int unlock_mutex(struct thread_common_data *cd, const char *func)
{
	int ret = pthread_mutex_unlock(&cd->lock);

	if (ret) {
		pr_err("%s: lock mutex failed err: %d on %s",
		       func, ret, cd->name);
	}

	return ret;
}

static int tx_rebuild_tlv(struct synce_port_tx *tx)
{
	struct thread_common_data *cd;
	int ret = -ENXIO;

	if (!tx) {
		pr_err("synce_port_tx is NULL");
		return ret;
	}

	cd = &tx->cd;
	if (!cd) {
		pr_err("%s cd is NULL", __func__);
		return ret;
	}

	if (!cd->pdu) {
		pr_err("tx pdu is NULL");
		return ret;
	}

	synce_msg_reset_tlvs(cd->pdu);

	ret = synce_msg_attach_ql_tlv(cd->pdu, cd->ql);
	if (ret) {
		pr_err("attach QL=0x%x TLV failed on %s", cd->ql, cd->name);
		goto err;
	} else {
		pr_info("%s: attached new TLV, QL=0x%x on %s",
			__func__, cd->ql, cd->name);
	}

	if (cd->extended) {
		ret = synce_msg_attach_extended_ql_tlv(cd->pdu,
						       &cd->ext_ql);
		if (ret) {
			pr_err("attach EXT_QL TLV failed on %s", cd->name);
			goto err;
		} else {
			pr_info("%s: attached new extended TLV, EXT_QL=0x%x on %s",
				__func__, cd->ext_ql.enhancedSsmCode,
				cd->name);
		}
	}

	tx->rebuild_tlv = 0;

	return ret;
err:
	cd->state = THREAD_FAILED;
	return ret;
}

static void *tx_thread(void *data)
{
	struct synce_port_tx *tx = (struct synce_port_tx *) data;
	struct thread_common_data *cd;
	volatile int *state;

	if (!tx) {
		pr_err("%s tx data is NULL", __func__);
		pthread_exit(NULL);
	}

	cd = &tx->cd;
	state = &cd->state;

	if (lock_mutex(cd, __func__) == 0) {
		if (*state != THREAD_NOT_STARTED) {
			pr_err("tx wrong state");
			goto unlock_out;
		}
	} else {
		goto out;
	}

	pr_debug("tx thread started on port %s", cd->name);
	*state = THREAD_STARTED;
	while (*state == THREAD_STARTED) {

		/* any errors are traced inside */
		if (cd->enabled) {
			if (tx->rebuild_tlv) {
				if (tx_rebuild_tlv(tx)) {
					pr_err("tx rebuild failed");
					cd->enabled = 0;
				}
			}
			if (synce_transport_send_pdu(cd->transport, cd->pdu))
				synce_transport_reinit(cd->transport);
		}
		unlock_mutex(cd, __func__);
		usleep(cd->heartbeat_usec);
		if (lock_mutex(cd, __func__) != 0) {
			goto out;
		}
	};

unlock_out:
	unlock_mutex(cd, __func__);
out:
	*state = (*state == THREAD_STOPPING) ? THREAD_STOPPED : *state;
	pr_debug("tx thread exit state %d=%s port %s", *state,
		 *state == THREAD_STOPPED ? "OK" : "failed", cd->name);
	pthread_exit(NULL);
}

static int diff_sec(struct timespec now, struct timespec before)
{
	return (now.tv_sec - before.tv_sec);
}

static void update_ql(struct thread_common_data *cd, int ext_tlv_recvd,
		      uint8_t ql, const struct synce_msg_ext_ql *ext_ql)
{
	cd->ql = ql;

	if (ext_tlv_recvd == 1) {
		memcpy(&cd->ext_ql, ext_ql, sizeof(cd->ext_ql));
	}
}

static int is_ql_allowed(struct allowed_qls_head *qls_stailq_head, uint8_t ql)
{
	struct ql *checked_ql;

	if (STAILQ_EMPTY(qls_stailq_head)) {
		/* no filter list - accept all */
		return 1;
	}

	STAILQ_FOREACH(checked_ql, qls_stailq_head, list) {
		if (checked_ql->value == ql) {
			return 1;
		}
	}

	return 0;
}

static int get_rx_qls(struct synce_port_rx *rx, uint8_t *ql,
		      struct synce_msg_ext_ql *ext_ql)
{
	struct thread_common_data *cd = &rx->cd;

	if (synce_msg_get_ql_tlv(cd->pdu, ql)) {
		return -EAGAIN;
	}

	pr_debug("QL=0x%x found on %s", *ql, cd->name);

	if (!is_ql_allowed(&rx->allowed_qls, *ql)) {
		pr_debug("Received not allowed QL: 0x%x, discarding", *ql);
		return -EBADMSG;
	}

	if (cd->extended) {
		if (synce_msg_get_extended_ql_tlv(cd->pdu, ext_ql)) {
			rx->ext_tlv_recvd = 0;

			/* only extended missing - not an error */
			return 0;
		}
		pr_debug("extended QL=0x%x found on %s",
			 ext_ql->enhancedSsmCode, cd->name);

		if (!is_ql_allowed((struct allowed_qls_head *)
				   &rx->allowed_ext_qls,
				   ext_ql->enhancedSsmCode)) {
			pr_debug("Received not allowed ext_QL: 0x%x, discarding",
				 ext_ql->enhancedSsmCode);
			rx->ext_tlv_recvd = 0;
			return -EBADMSG;
		}

		rx->ext_tlv_recvd = 1;
	}

	return 0;
}

static int rx_act(struct synce_port_rx *rx)
{
	struct thread_common_data *cd = &rx->cd;
	struct synce_msg_ext_ql ext_ql;
	struct timespec now;
	uint8_t ql;
	int err;

	/* read socket for ESMC and fill pdu */
	err = synce_transport_recv_pdu(cd->transport, cd->pdu);
	if (!err) {
		rx->n_recv++;
	}

	/* wait for first frame received before starting any logic */
	if (!rx->n_recv) {
		return -EAGAIN;
	}

	err = get_rx_qls(rx, &ql, &ext_ql);
	if (err) {
		/* go to ql_failed state if continue missing frames */
		if (rx->ql_failed == 0) {
			clock_gettime(CLOCK_REALTIME, &now);
			if (diff_sec(now, rx->last_recv_ts) >=
			    QL_FAILED_PERIOD_SEC) {
				pr_info("QL not received on %s within %d s",
					cd->name, QL_FAILED_PERIOD_SEC);
				rx->ql_failed = 1;
				/* clear first_valid_ts so we can recover from
				 * ql_failed state
				 */
				memset(&rx->first_valid_ts, 0,
				       sizeof(rx->first_valid_ts));
			}
		}
	} else {
		clock_gettime(CLOCK_REALTIME, &rx->last_recv_ts);
		now.tv_sec = rx->last_recv_ts.tv_sec;
		if (rx->ql_failed == 1) {
			if (rx->first_valid_ts.tv_sec == 0) {
				clock_gettime(CLOCK_REALTIME,
					      &rx->first_valid_ts);
			} else {
			/* May be required to add counter for number
			 * of received frames before exit ql_failed
			 */
				if (diff_sec(now, rx->first_valid_ts) >=
					     rx->recover_time) {
					update_ql(cd, rx->ext_tlv_recvd,
						  ql, &ext_ql);
					rx->ql_failed = 0;
					pr_info("QL-failed recovered on %s",
						cd->name);
				}
			}
		} else {
			update_ql(cd, rx->ext_tlv_recvd, ql, &ext_ql);
			pr_debug("QL=0x%x received on %s", cd->ql, cd->name);
		}
	}

	return 0;
}

static void *rx_thread(void *data)
{
	struct synce_port_rx *rx = (struct synce_port_rx *) data;
	struct thread_common_data *cd;
	volatile int *state;

	if (!rx) {
		pr_err("%s rx data NULL", __func__);
		pthread_exit(NULL);
	}

	cd = &rx->cd;
	state = &cd->state;

	if (lock_mutex(cd, __func__) == 0) {
		if (*state != THREAD_NOT_STARTED) {
			pr_err("rx wrong state on %s", cd->name);
			goto unlock_out;
		}
	} else {
		goto out;
	}

	pr_debug("rx thread started on port %s", cd->name);
	*state = THREAD_STARTED;
	while (*state == THREAD_STARTED) {
		rx_act(rx);
		unlock_mutex(cd, __func__);
		usleep(cd->heartbeat_usec);
		if (lock_mutex(cd, __func__) != 0) {
			goto out;
		}
	};

unlock_out:
	unlock_mutex(cd, __func__);
out:
	*state = (*state == THREAD_STOPPING) ? THREAD_STOPPED : *state;
	pr_debug("rx thread exit state %d=%s port %s", *state,
		 *state == THREAD_STOPPED ? "OK" : "failed", cd->name);
	pthread_exit(NULL);
}

static int tx_init(struct synce_port_tx *tx, int heartbeat_msec,
		   int extended_tlv, struct synce_transport *transport,
		   char *name)
{
	struct thread_common_data *cd;

	if (!tx) {
		pr_err("%s tx NULL", __func__);
		return -EFAULT;
	}

	if (!transport) {
		pr_err("%s transport NULL", __func__);
		return -EFAULT;
	}

	if (!name) {
		pr_err("%s name NULL", __func__);
		return -EFAULT;
	}

	cd = &tx->cd;
	memset(tx, 0, sizeof(*tx));

	if (extended_tlv) {
		memset(&cd->ext_ql, 0, sizeof(cd->ext_ql));
		cd->extended = extended_tlv;
	}
	cd->heartbeat_usec = MSEC_TO_USEC(heartbeat_msec);
	cd->name = name;
	cd->pdu = synce_msg_create(cd->name);
	cd->transport = transport;
	cd->state = THREAD_NOT_STARTED;
	tx->rebuild_tlv = 0;
	cd->enabled = 0;
	if (pthread_mutex_init(&cd->lock, NULL)) {
		pr_err("%s: TX thread mutex init failure", name);
		return -EFAULT;
	}

	return 0;
}

static void free_allowed_qls(struct allowed_qls_head *head)
{
	struct ql *q;

	while ((q = STAILQ_FIRST(head))) {
		STAILQ_REMOVE_HEAD(head, list);
		free(q);
	}
}

#define QL_STR_MAX_LEN	256
static int init_ql_str(struct allowed_qls_head *qls_stailq_head,
		       const char *allowed_qls)
{
	char buf[QL_STR_MAX_LEN], *ptr, *next;

	if (allowed_qls == NULL) {
		return 0;
	}

	if ((unsigned long)snprintf(buf, sizeof (buf), "%s", allowed_qls) >=
			sizeof (buf)) {
		pr_err("QLs list string too long (max %i)", QL_STR_MAX_LEN);
		return -E2BIG;
	}

	for (ptr = buf; ptr && *ptr; ptr = next) {
		enum parser_result r;
		unsigned int value;
		struct ql *newql;

		next = strchr(ptr, ',');
		if (next)
			*next++ = '\0';

		r = get_ranged_uint(ptr, &value, 0, UCHAR_MAX);
		if (r == MALFORMED) {
			pr_err("QL list item read failed - please verify");
			free_allowed_qls(qls_stailq_head);
			return -EINVAL;
		}
		if (r == OUT_OF_RANGE) {
			pr_err("QL list item outside of range - please verify");
			free_allowed_qls(qls_stailq_head);
			return -EINVAL;
		}

		newql = malloc(sizeof(struct ql));
		if (!newql) {
			pr_err("could not alloc ql");
			return -EINVAL;
		}

		newql->value = value;
		STAILQ_INSERT_HEAD(qls_stailq_head, newql, list);
	}

	return 0;
}

static int init_allowed_qls(struct synce_port_rx *rx, struct config *cfg,
			    const char *name)
{
	const char *allowed_qls;

	STAILQ_INIT(&rx->allowed_qls);

	allowed_qls = config_get_string(cfg, name, "allowed_qls");
	if (allowed_qls == NULL) {
		pr_warning("No allowed QLs list found - filtering disabled");
		return 0;
	}

	return init_ql_str(&rx->allowed_qls, allowed_qls);
}

static int init_allowed_ext_qls(struct synce_port_rx *rx, struct config *cfg,
				const char *name)
{
	const char *allowed_qls;

	STAILQ_INIT(&rx->allowed_ext_qls);

	allowed_qls = config_get_string(cfg, name, "allowed_ext_qls");

	if (allowed_qls == NULL) {
		pr_warning("No allowed ext_QLs list found - filtering disabled");
		return 0;
	}

	return init_ql_str((struct allowed_qls_head *)&rx->allowed_ext_qls,
			    allowed_qls);
}

static int rx_init(struct synce_port_rx *rx, int heartbeat_msec,
		   int extended_tlv, int recover_time,
		   struct synce_transport *transport, char *name,
		   struct config *cfg, int network_option)
{
	struct thread_common_data *cd;

	if (!rx) {
		pr_err("%s rx NULL", __func__);
		return -EFAULT;
	}

	if (!transport) {
		pr_err("%s transport NULL", __func__);
		return -EFAULT;
	}

	if (!name) {
		pr_err("%s name NULL", __func__);
		return -EFAULT;
	}

	cd = &rx->cd;
	memset(rx, 0, sizeof(*rx));

	if (extended_tlv) {
		memset(&cd->ext_ql, 0, sizeof(cd->ext_ql));
		memcpy(&rx->last_ext_ql, &cd->ext_ql, sizeof(rx->last_ext_ql));
		cd->extended = extended_tlv;
	}
	cd->heartbeat_usec = MSEC_TO_USEC(heartbeat_msec);
	cd->name = name;
	cd->pdu = synce_msg_create(cd->name);
	cd->transport = transport;
	cd->state = THREAD_NOT_STARTED;
	rx->ql_dnu_val = synce_get_dnu_value(network_option, false);
	rx->ext_ql_dnu_val = synce_get_dnu_value(network_option, true);
	rx->last_ql = rx->ql_dnu_val;
	rx->ql_failed = 1;
	memset(&rx->last_recv_ts, 0, sizeof(rx->last_recv_ts));
	memset(&rx->first_valid_ts, 0, sizeof(rx->first_valid_ts));
	rx->n_recv = 0;
	rx->recover_time = recover_time;
	cd->enabled = 1;
	if (pthread_mutex_init(&cd->lock, NULL)) {
		pr_err("%s: RX thread mutex init failure", name);
		return -EFAULT;
	}


	init_allowed_qls(rx, cfg, name);
	init_allowed_ext_qls(rx, cfg, name);

	return 0;
}

static int thread_stop_wait(struct thread_common_data *cd)
{
	int cnt = (cd->heartbeat_usec / THREAD_STOP_SLEEP_USEC) + 1;
	int ret = lock_mutex(cd, __func__);

	if (ret)
		return ret;

	if (cd->state == THREAD_STARTED) {
		cd->state = THREAD_STOPPING;
	} else {
		unlock_mutex(cd, __func__);
		return -ESRCH;
	}

	do {
		unlock_mutex(cd, __func__);
		usleep(THREAD_STOP_SLEEP_USEC);
		ret = lock_mutex(cd, __func__);
		if (ret) {
			return ret;
		}
	} while (cnt-- && cd->state != THREAD_STOPPED);

	ret = (cd->state == THREAD_STOPPED ? 0 : -ENXIO);
	unlock_mutex(cd, __func__);

	return ret;
}

static int thread_start_wait(struct thread_common_data *cd)
{
	int cnt = (cd->heartbeat_usec / THREAD_START_SLEEP_USEC) + 1;
	int ret = lock_mutex(cd, __func__);

	if (ret)
		return ret;

	if (cd->state == THREAD_STARTED) {
		pr_debug("THREAD_STARTED");
		unlock_mutex(cd, __func__);
		return 0;
	}

	do {
		unlock_mutex(cd, __func__);
		usleep(THREAD_START_SLEEP_USEC);
		ret = lock_mutex(cd, __func__);
		if (ret) {
			return ret;
		}
	} while (cnt-- && cd->state != THREAD_STARTED);

	ret = (cd->state == THREAD_STARTED ? 0 : -ESRCH);
	unlock_mutex(cd, __func__);

	if (ret) {
		pr_err("THREAD_FAILED");
	} else {
		pr_debug("THREAD_STARTED");
	}

	return ret;
}

static int synce_port_ctrl_thread_create(char *name, void *data, int tx,
					 pthread_t *thread_id)
{
	char thread_name[TASK_COMM_LEN];
	pthread_attr_t attr;
	int err;

	err = pthread_attr_init(&attr);
	if (err) {
		pr_err("init %s thread attr failed for %s",
		       tx ? "tx" : "rx", name);
		goto err_attr;
	}

	err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (err) {
		pr_err("set %s thread detached failed for %s err=%d",
		       tx ? "tx" : "rx", name, err);
		goto err_attr;
	}

	err = pthread_attr_setstacksize(&attr, SYNCE_THREAD_STACK_SIZE);
	if (err) {
		pr_err("set %s thread stack failed for %s err=%d",
		       tx ? "tx" : "rx", name, err);
		goto err_attr;
	}

	if (tx) {
		err = pthread_create(thread_id, &attr, tx_thread, data);
	} else {
		err = pthread_create(thread_id, &attr, rx_thread, data);
	}
	if (err) {
		pr_err("create %s thread failed for %s err=%d",
		       tx ? "tx" : "rx", name, err);
		goto err_attr;
	}

	snprintf(thread_name, TASK_COMM_LEN, "%s-%s",
		 tx ? "tx" : "rx", name);
	err = pthread_setname_np(*thread_id, thread_name);
	if (err) {
		pr_info("failed to set %s thread's name for %s",
			tx ? "tx" : "rx", name);
	}

	pthread_attr_destroy(&attr);
	return 0;

err_attr:
	pthread_attr_destroy(&attr);
	return -ECHILD;
}

uint16_t get_priority_params(struct synce_port_ctrl *pc,
			     const uint16_t **priority_list)
{
	if (!pc || !pc->priority_list)
		return 0;
	*priority_list = pc->priority_list;

	return pc->priority_list_count;
}

uint16_t get_ql_priority(struct synce_port_ctrl *pc)
{
	if (pc->rx.cd.extended) {
		return QL_PRIORITY(pc->rx.cd.ql,
				   pc->rx.cd.ext_ql.enhancedSsmCode);
	} else {
		return QL_PRIORITY(pc->rx.cd.ql,
				   QL_OTHER_CLOCK_TYPES_ENHSSM);
	}
}

struct synce_port_ctrl *is_valid_source(struct synce_port_ctrl *pc)
{
	uint16_t ql_priority;
	int i, err;

	if (!pc) {
		pr_debug("pc is NULL");
		return NULL;
	}

	ql_priority = get_ql_priority(pc);

	err = lock_mutex(&pc->rx.cd, __func__);
	if (err) {
		pr_err("mutex fatal error on %s", pc->name);
		return NULL;
	}

	if (pc->rx.n_recv > 0 && !pc->rx.ql_failed) {
		for (i = 0; i < pc->priority_list_count; i++) {
			if (ql_priority == pc->priority_list[i]) {
				unlock_mutex(&pc->rx.cd, __func__);
				return pc;
			}
		}
	}
	unlock_mutex(&pc->rx.cd, __func__);
	pr_debug("not valid source: %s", pc->name);

	return NULL;
}

int synce_port_ctrl_running(struct synce_port_ctrl *pc)
{
	int state, ret;

	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return -EFAULT;
	}

	ret = lock_mutex(&pc->tx.cd, __func__);
	if (ret)
		return ret;

	state = (pc->tx.cd.state == THREAD_STARTED);
	unlock_mutex(&pc->tx.cd, __func__);

	if (pc->rx.cd.enabled) {
		ret = lock_mutex(&pc->rx.cd, __func__);
		if (ret)
			return ret;

		state = state && (pc->rx.cd.state == THREAD_STARTED);
		unlock_mutex(&pc->rx.cd, __func__);
	}

	return state;
}

int synce_port_ctrl_destroy(struct synce_port_ctrl *pc)
{
	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return -EFAULT;
	}
	pr_debug("%s on %s", __func__, pc->name);

	if (!pc->transport)
		return 0;

	thread_stop_wait(&pc->tx.cd);
	if (pc->tx.cd.pdu) {
		synce_msg_delete(pc->tx.cd.pdu);
	}
	pthread_mutex_destroy(&pc->tx.cd.lock);

	if (pc->rx.cd.enabled) {
		thread_stop_wait(&pc->rx.cd);
		if (pc->tx.cd.pdu) {
			synce_msg_delete(pc->rx.cd.pdu);
		}
		pthread_mutex_destroy(&pc->rx.cd.lock);

		free_allowed_qls(&pc->rx.allowed_qls);
		free_allowed_qls((struct allowed_qls_head *)&pc->rx.allowed_ext_qls);
	}

	if (pc->transport) {
		synce_transport_delete(pc->transport);
	}
	memset(pc, 0, sizeof(*pc));

	return 0;
}

int synce_port_ctrl_rx_ql_failed(struct synce_port_ctrl *pc)
{
	int ret = -EFAULT;

	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return ret;
	}

	ret = lock_mutex(&pc->rx.cd, __func__);
	if (ret)
		return ret;

	ret = (pc->rx.ql_failed != 0);
	unlock_mutex(&pc->rx.cd, __func__);

	return ret;
}

int synce_port_ctrl_rx_dnu(struct synce_port_ctrl *pc, uint8_t dnu_val)
{
	int ret = -EFAULT;

	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return ret;
	}

	ret = lock_mutex(&pc->rx.cd, __func__);
	if (ret)
		return ret;

	ret = pc->rx.n_recv && !pc->rx.ql_failed ?
	      pc->rx.cd.ql == dnu_val : -EAGAIN;
	unlock_mutex(&pc->rx.cd, __func__);

	return ret;
}

int synce_port_ctrl_rx_ql_changed(struct synce_port_ctrl *pc)
{
	struct thread_common_data *cd;
	int ret = -EFAULT;

	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return ret;
	}

	cd = &pc->rx.cd;
	ret = lock_mutex(cd, __func__);
	if (ret)
		return ret;

	if (!pc->rx.ext_tlv_recvd) {
		ret = (cd->ql != pc->rx.last_ql);
		pc->rx.last_ql = cd->ql;
	} else {
		ret = (cd->ql != pc->rx.last_ql) ||
		      (memcmp(&cd->ext_ql,
			      &pc->rx.last_ext_ql,
			      sizeof(cd->ext_ql)) != 0);
		pc->rx.last_ql = cd->ql;
		memcpy(&pc->rx.last_ext_ql, &cd->ext_ql, sizeof(pc->rx.last_ext_ql));
	}
	unlock_mutex(cd, __func__);

	if (ret) {
		pr_debug("%s on %s", __func__, pc->name);
	}

	return ret;
}

int synce_port_ctrl_rx_ext_tlv(struct synce_port_ctrl *pc)
{
	int ret = -EFAULT;

	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return ret;
	}

	ret = lock_mutex(&pc->rx.cd, __func__);
	if (ret)
		return ret;

	ret = pc->rx.ext_tlv_recvd;
	unlock_mutex(&pc->rx.cd, __func__);

	return ret;
}

int synce_port_ctrl_get_rx_ql(struct synce_port_ctrl *pc, uint8_t *ql)
{
	int ret = -EFAULT;

	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return ret;
	}

	if (!ql) {
		pr_err("%s ql is NULL", __func__);
		return ret;
	}

	ret = lock_mutex(&pc->rx.cd, __func__);
	if (ret)
		return ret;

	*ql = pc->rx.cd.ql;
	unlock_mutex(&pc->rx.cd, __func__);

	return ret;
}

int synce_port_ctrl_get_rx_ext_ql(struct synce_port_ctrl *pc,
				  struct synce_msg_ext_ql *ext_ql)
{
	int ret = -EFAULT;

	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return ret;
	}

	if (!ext_ql) {
		pr_err("%s ext_ql is NULL", __func__);
		return ret;
	}

	if (!pc->rx.cd.extended) {
		pr_err("ext_ql was not enabled for %s", pc->name);
		return ret;
	}

	ret = lock_mutex(&pc->rx.cd, __func__);
	if (ret)
		return ret;

	memcpy(ext_ql, &pc->rx.cd.ext_ql, sizeof(*ext_ql));
	unlock_mutex(&pc->rx.cd, __func__);

	return ret;
}

int synce_port_ctrl_set_tx_ql(struct synce_port_ctrl *pc, uint8_t ql)
{
	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return -EFAULT;
	}

	pc->tx.cd.ql = ql;

	return 0;
}

int synce_port_ctrl_set_tx_ext_ql(struct synce_port_ctrl *pc,
				  struct synce_msg_ext_ql *ext_ql)
{
	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return -EFAULT;
	}

	if (!ext_ql) {
		pr_err("%s ext_ql is NULL", __func__);
		return -EFAULT;
	}

	memcpy(&pc->tx.cd.ext_ql, ext_ql, sizeof(pc->tx.cd.ext_ql));

	return 0;
}

int synce_port_ctrl_rebuild_tx(struct synce_port_ctrl *pc)
{
	int ret = -EFAULT;

	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return ret;
	}

	ret = lock_mutex(&pc->tx.cd, __func__);
	if (ret)
		return ret;

	pc->tx.rebuild_tlv = 1;
	unlock_mutex(&pc->tx.cd, __func__);

	return ret;
}

int synce_port_ctrl_enable_tx(struct synce_port_ctrl *pc)
{
	int ret;

	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return -EFAULT;
	}

	ret = lock_mutex(&pc->tx.cd, __func__);
	if (ret)
		return ret;

	pc->tx.cd.enabled = 1;
	unlock_mutex(&pc->tx.cd, __func__);

	return 0;
}

int synce_port_ctrl_init(struct synce_port_ctrl *pc, struct config *cfg,
			 int rx_enabled, int extended_tlv, int recover_time,
			 int network_option)
{
	if (!pc) {
		pr_err("%s pc is NULL", __func__);
		return -ENODEV;
	}

	if (!cfg) {
		pr_err("%s cfg is NULL", __func__);
		return -ENXIO;
	}
	pc->transport = synce_transport_create(pc->name);
	if (!pc->transport) {
		pr_err("init synce_transport failed for port %s", pc->name);
		return -ENXIO;
	}

	tx_init(&pc->tx,
		config_get_int(cfg, pc->name, "tx_heartbeat_msec"),
		extended_tlv, pc->transport, pc->name);
	if (synce_port_ctrl_thread_create(pc->tx.cd.name, &pc->tx, TX_THREAD,
					  &pc->tx_thread_id)) {
		pr_err("tx thread create failed on port %s", pc->name);
		goto transport_err;
	}

	if (thread_start_wait(&pc->tx.cd)) {
		pr_err("tx thread start wait failed for %s", pc->name);
		goto transport_err;
	}

	switch (network_option)	{
	case SYNCE_NETWORK_OPT_1:
		pc->priority_list = O1N_priority;
		pc->priority_list_count = O1N_PRIORITY_COUNT;
		break;
	case SYNCE_NETWORK_OPT_2:
		pc->priority_list = O2N_priority;
		pc->priority_list_count = O2N_PRIORITY_COUNT;
		break;
	default:
		pr_err("wrong network option - only 1 and 2 supported");
		goto transport_err;
	}

	if (rx_enabled) {
		rx_init(&pc->rx,
			config_get_int(cfg, pc->name, "rx_heartbeat_msec"),
			extended_tlv, recover_time, pc->transport, pc->name,
			cfg, network_option);

		if (synce_port_ctrl_thread_create(pc->rx.cd.name,
						  &pc->rx, RX_THREAD,
						  &pc->rx_thread_id)) {
			pr_err("rx thread create failed on port %s", pc->name);
			goto rx_err;
		}
		if (thread_start_wait(&pc->rx.cd)) {
			pr_err("rx thread start wait failed for %s", pc->name);
			goto rx_err;
		}
	} else {
		pc->rx.cd.enabled = 0;
		pr_debug("rx thread not needed on port %s", pc->name);
	}

	return 0;
rx_err:
	thread_stop_wait(&pc->tx.cd);
transport_err:
	synce_transport_delete(pc->transport);

	return -ECHILD;
}

struct synce_port_ctrl *synce_port_ctrl_create(const char *name)
{
	struct synce_port_ctrl *p = NULL;

	if (!name) {
		pr_err("name not profided in %s", __func__);
		return NULL;
	}

	p = malloc(sizeof(struct synce_port_ctrl));
	if (!p) {
		pr_err("could not alloc synce_port_ctrl for %s", name);
		return NULL;
	}

	memset(p, 0, sizeof(*p));
	memcpy(p->name, name, sizeof(p->name));

	return p;
}

void synce_port_ctrl_invalidate_rx_ql(struct synce_port_ctrl *pc)
{
	if (lock_mutex(&pc->rx.cd, __func__) != 0)
		return;

	pc->rx.last_ql = pc->rx.ql_dnu_val;
	pc->rx.cd.ql = pc->rx.ql_dnu_val;
	if (pc->rx.cd.extended) {
		pc->rx.cd.ext_ql.enhancedSsmCode = pc->rx.ext_ql_dnu_val;
		pc->rx.last_ext_ql.enhancedSsmCode = pc->rx.ext_ql_dnu_val;
	}
	unlock_mutex(&pc->rx.cd, __func__);
}
