/**
 * @file synce_thread_common.h
 * @brief Header for synce thread's common defines
 * @note SPDX-FileCopyrightText: Copyright 2023 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */

#ifndef HAVE_SYNCE_THREAD_COMMON_H
#define HAVE_SYNCE_THREAD_COMMON_H

#define MSEC_TO_USEC(X)			(X * 1000)
#define THREAD_STOP_SLEEP_USEC		MSEC_TO_USEC(50)
#define THREAD_START_SLEEP_USEC		MSEC_TO_USEC(20)
#define SYNCE_THREAD_STACK_SIZE		0xffff
#define TASK_COMM_LEN			16

#endif /* HAVE_SYNCE_THREAD_COMMON_H */
