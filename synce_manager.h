/**
 * @file synce_manager.h
 * @brief Interface for managing synce4l while running
 * @note SPDX-FileCopyrightText: Copyright 2023 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SYNCE_MANAGER_H
#define HAVE_SYNCE_MANAGER_H

#define MAX_RESPONSE_SIZE_WO_MARKER	(MAX_RESPONSE_SIZE - 2 * sizeof(uint16_t))
#define MAX_ERR_RESPONSE_STR_SIZE	(MAX_RESPONSE_SIZE_WO_MARKER - 2 * sizeof(uint16_t))

/**
 * Starts synce_manager thread for handling external commands.
 *
 * @param clk		synce_clock instance
 * @return		0 on success or -1 on bad command
 */
int synce_manager_start_thread(struct synce_clock *clk);

/**
 * Removes local socket file.
 *
 * @param socket_path		socket_path name
 */
void synce_manager_close_socket(char *socket_path);

#endif
