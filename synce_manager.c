/**
 * @file synce_manager.c
 * @brief Interface for managing QL for external clock sources
 * @note SPDX-FileCopyrightText: Copyright 2023 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <net/if.h>
#include <ctype.h>
#include <errno.h>
#include "print.h"
#include "config.h"
#include "synce_dev.h"
#include "synce_clock.h"
#include "synce_manager.h"
#include "synce_thread_common.h"
#include "synce_external_api.h"

struct synce_clock;

static void synce_manager_generate_err_tlv(struct synce_manager_tlv **err_tlv,
					   char *err_str)
{
	*err_tlv = malloc(sizeof(struct synce_manager_tlv));
	if (!*err_tlv) {
		pr_err("Failed allocating error synce_manager_tlv");
		return;
	}

	(*err_tlv)->type = MSG_ERR_MSG;
	(*err_tlv)->length = strlen(err_str);
	(*err_tlv)->value = malloc((*err_tlv)->length);
	if (!(*err_tlv)->value) {
		pr_err("Failed allocating error synce_manager_tlv msg");
		return;
	}
	memcpy((*err_tlv)->value, err_str, (*err_tlv)->length);
}

int synce_manager_parse_input(const uint8_t *input, int bytes_read,
			      struct synce_manager_tlv **tlv_array,
			      int *tlv_num, char *dev_name,
			      char *ext_src_name,
			      struct synce_manager_tlv **err_tlv)
{
	char err_response[MAX_ERR_RESPONSE_STR_SIZE];
	struct synce_manager_tlv new_tlv;
	int index = 0;

	*tlv_num = 0;
	*tlv_array = NULL;

	while (index < bytes_read) {
		memset(&new_tlv, 0, sizeof(struct synce_manager_tlv));

		if (index + (int)(2 * sizeof(uint16_t)) > bytes_read) {
			sprintf(err_response, "Command size exceeds %d",
				MAX_COMMAND_SIZE);
			synce_manager_generate_err_tlv(err_tlv, err_response);
			return -1;
		}
		new_tlv.type = *(uint16_t *)(input + index);
		index += sizeof(uint16_t);

		if (new_tlv.type == MSG_END_MARKER)
			return 0;

		new_tlv.length = *(uint16_t *)(input + index);
		index += sizeof(uint16_t);
		if (new_tlv.length + index > bytes_read) {
			sprintf(err_response, "Command size exceeds %d",
				bytes_read);
			synce_manager_generate_err_tlv(err_tlv, err_response);
			return -1;
		}

		if (new_tlv.length > 0 &&
		    new_tlv.length <= bytes_read - index) {
			new_tlv.value = malloc(new_tlv.length);
			if (!new_tlv.value) {
				synce_manager_generate_err_tlv(err_tlv, "Internal parsing error");
				pr_err("%s Failed allocating memory", __func__);
				return -1;
			}

			memcpy(new_tlv.value, input + index, new_tlv.length);
			index += new_tlv.length;
		} else {
			new_tlv.value = NULL;
		}

		*tlv_array = realloc(*tlv_array, (*tlv_num + 1) *
				     sizeof(struct synce_manager_tlv));
		if (!*tlv_array) {
			synce_manager_generate_err_tlv(err_tlv, "Internal parsing error");
			pr_err("%s Failed reallocating memory", __func__);
			return -1;
		}

		(*tlv_array)[*tlv_num] = new_tlv;
		(*tlv_num)++;
		if (new_tlv.type == MSG_DEV_NAME) {
			if (new_tlv.length < IF_NAMESIZE && new_tlv.value) {
				memcpy(dev_name, new_tlv.value, new_tlv.length);
				dev_name[new_tlv.length] = '\0';
			} else {
				sprintf(err_response, "Dev name size exceeds %d",
					IF_NAMESIZE);
				synce_manager_generate_err_tlv(err_tlv,
							       err_response);
				return -1;
			}
		} else if (new_tlv.type == MSG_SRC_NAME) {
			if (new_tlv.length < IF_NAMESIZE && new_tlv.value) {
				memcpy(ext_src_name, new_tlv.value,
				       new_tlv.length);
				ext_src_name[new_tlv.length] = '\0';
			} else {
				sprintf(err_response, "External source name size exceeds %d",
					IF_NAMESIZE);
				synce_manager_generate_err_tlv(err_tlv,
							       err_response);
				return -1;
			}
		}
	}

	synce_manager_generate_err_tlv(err_tlv, "END_MARKER missing from command");
	return -1;
}

void synce_manager_execute_tlv_array(struct synce_manager_tlv *tlv_array,
				     int tlv_num, struct synce_dev *dev,
				     char *ext_src_name,
				     struct synce_manager_tlv **err_tlv)
{
	uint8_t val;
	int i;

	for (i = 0; i < tlv_num; i++) {
		switch (tlv_array[i].type) {
		case MSG_DEV_NAME:
		case MSG_SRC_NAME:
			break;
		case MSG_GET_QL:
			synce_dev_get_ql(dev, &val);
			tlv_array[i].length = sizeof(uint8_t);
			tlv_array[i].value = malloc(sizeof(uint8_t));
			if (!tlv_array[i].value) {
				synce_manager_generate_err_tlv(err_tlv, "Internal parsing error");
				pr_err("%s Failed allocating memory", __func__);
				return;
			}
			memcpy(tlv_array[i].value, &val, sizeof(uint8_t));
			break;
		case MSG_GET_EXT_QL:
			synce_dev_get_ext_ql(dev, &val);
			tlv_array[i].length = sizeof(uint8_t);
			tlv_array[i].value = malloc(sizeof(uint8_t));
			if (!tlv_array[i].value) {
				synce_manager_generate_err_tlv(err_tlv, "Internal parsing error");
				pr_err("%s Failed allocating memory", __func__);
				return;
			}
			memcpy(tlv_array[i].value, &val, sizeof(uint8_t));
			break;
		case MSG_SET_QL:
			if (!*ext_src_name) {
				synce_manager_generate_err_tlv(err_tlv, "missing ext_src name");
				return;
			}
			if (tlv_array[i].length > sizeof(uint8_t)) {
				synce_manager_generate_err_tlv(err_tlv, "Bad QL value");
				return;
			}
			memcpy(&val, tlv_array[i].value, sizeof(uint8_t));
			synce_dev_set_ext_src_ql(dev, ext_src_name, 0, val);
			break;
		case MSG_SET_EXT_QL:
			if (!*ext_src_name) {
				synce_manager_generate_err_tlv(err_tlv, "missing ext_src name");
				return;
			}
			if (tlv_array[i].length > sizeof(uint8_t)) {
				synce_manager_generate_err_tlv(err_tlv, "Bad QL value");
				return;
			}
			memcpy(&val, tlv_array[i].value, sizeof(uint8_t));
			synce_dev_set_ext_src_ql(dev, ext_src_name, 1, val);
			break;
		default:
			synce_manager_generate_err_tlv(err_tlv, "Bad command");
			return;
		}
	}
}

int synce_manager_generate_response(struct synce_manager_tlv *resp_tlv,
				    int tlv_num, uint8_t *response,
				    int *resp_len)
{
	int i;

	*resp_len = 0;
	for (i = 0; i < tlv_num; i++) {
		if (*resp_len + 2 * sizeof(uint16_t) + resp_tlv[i].length >
		    MAX_RESPONSE_SIZE_WO_MARKER) {
			pr_err("response message too big");
			return -1;
		}

		if (!resp_tlv[i].value) {
			pr_err("bad TLV for response");
			return -1;
		}

		*(uint16_t *)(response + *resp_len) = resp_tlv[i].type;
		*resp_len += sizeof(uint16_t);

		*(uint16_t *)(response + *resp_len) = resp_tlv[i].length;
		*resp_len += sizeof(uint16_t);

		memcpy(response + *resp_len, resp_tlv[i].value,
		       resp_tlv[i].length);
		*resp_len += resp_tlv[i].length;
	}
	*(uint16_t *)(response + *resp_len) = MSG_END_MARKER;
	*resp_len += sizeof(uint16_t);
	*(uint16_t *)(response + *resp_len) = 0;
	*resp_len += sizeof(uint16_t);

	return 0;
}

static void *synce_manager_server_thread(void *arg)
{
	struct synce_clock *clk = (struct synce_clock *)arg;
	int tlv_num = 0, ret, i, resp_len, bytes_read;
	uint8_t response[MAX_RESPONSE_SIZE];
	struct synce_manager_tlv *tlv_array;
	struct synce_manager_tlv *err_tlv;
	struct sockaddr_un server, client;
	uint8_t command[MAX_COMMAND_SIZE];
	char ext_src_name[IF_NAMESIZE];
	int addrlen = sizeof(server);
	char dev_name[IF_NAMESIZE];
	int server_fd, new_socket;
	struct synce_dev *dev;

	server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_fd <= 0) {
		pr_err("%s Socket creation failed", __func__);
		exit(EXIT_FAILURE);
	}

	server.sun_family = AF_UNIX;
	snprintf(server.sun_path, sizeof(server.sun_path), "%s",
		 synce_clock_get_socket_path(clk));

	if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		pr_err("%s Bind failed", __func__);
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, 3) < 0) {
		pr_err("%s Listen failed", __func__);
		exit(EXIT_FAILURE);
	}

	while (1) {
		memset(ext_src_name, 0, sizeof(ext_src_name));
		memset(dev_name, 0, sizeof(dev_name));
		memset(response, 0, sizeof(response));
		memset(command, 0, sizeof(command));
		tlv_array = NULL;
		err_tlv = NULL;

		new_socket = accept(server_fd, (struct sockaddr *)&client,
				    (socklen_t *)&addrlen);
		if (new_socket < 0) {
			pr_err("%s Accept failed", __func__);
			exit(EXIT_FAILURE);
		}

		// Read the client's command
		bytes_read = recv(new_socket, command, MAX_COMMAND_SIZE, 0);
		if (bytes_read <= 0) {
			synce_manager_generate_err_tlv(&err_tlv, "NULL command");
			ret = -1;
			goto return_response;
		} else if (bytes_read > MAX_COMMAND_SIZE) {
			synce_manager_generate_err_tlv(&err_tlv,
						       "Command size exceeds MAX_COMMAND_SIZE");
			ret = -1;
			goto return_response;
		}
		ret = synce_manager_parse_input(command, bytes_read, &tlv_array,
						&tlv_num, dev_name,
						ext_src_name, &err_tlv);
		if (ret)
			goto return_response;

		ret = synce_clock_get_dev(clk, dev_name, &dev);
		if (ret) {
			synce_manager_generate_err_tlv(&err_tlv, "Device not found");
			goto return_response;
		}

		if (*ext_src_name) {
			ret = synce_dev_check_ext_src_name(dev, ext_src_name);
			if (ret) {
				synce_manager_generate_err_tlv(&err_tlv, "External clock source not found");
				goto return_response;
			}
		}

		synce_manager_execute_tlv_array(tlv_array, tlv_num, dev,
						ext_src_name, &err_tlv);

return_response:
		if (err_tlv) {
			ret = synce_manager_generate_response(err_tlv, 1,
							      response,
							      &resp_len);
			if (err_tlv->value)
				free(err_tlv->value);
			free((void *)err_tlv);
		} else if (tlv_array) {
			ret = synce_manager_generate_response(tlv_array,
							      tlv_num,
							      response,
							      &resp_len);
		}

		for (i = 0; i < tlv_num; i++) {
			if (tlv_array && tlv_array[i].value)
				free(tlv_array[i].value);
		}
		if (tlv_array)
			free((void *)tlv_array);

		if (!ret && write(new_socket, response, resp_len) != resp_len)
			ret = -1;
		close(new_socket);
	}

	return NULL;
}

int synce_manager_start_thread(struct synce_clock *clk)
{
	char thread_name[TASK_COMM_LEN];
	pthread_t server_tid;
	pthread_attr_t attr;
	int err;

	err = pthread_attr_init(&attr);
	if (err) {
		pr_err("init thread attr failed for synce_manager");
		goto err_attr;
	}

	err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (err) {
		pr_err("set thread detached failed for synce_manager err=%d",
		       err);
		goto err_attr;
	}

	err = pthread_attr_setstacksize(&attr, SYNCE_THREAD_STACK_SIZE);
	if (err) {
		pr_err("set thread stack failed for synce_manager err=%d",
		       err);
		goto err_attr;
	}

	err = pthread_create(&server_tid, &attr, synce_manager_server_thread,
			     (void *)clk);
	if (err) {
		pr_err("create thread failed for synce_manager err=%d", err);
		goto err_attr;
	}

	snprintf(thread_name, TASK_COMM_LEN, "synce-manager");
	err = pthread_setname_np(server_tid, thread_name);
	if (err)
		pr_info("failed to set thread's name for synce_manager");

	pthread_attr_destroy(&attr);
	return 0;

err_attr:
	pthread_attr_destroy(&attr);
	return -ECHILD;
}

void synce_manager_close_socket(char *socket_path)
{
	unlink(socket_path);
}
