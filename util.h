/**
 * @file util.h
 * @brief Various little utility functions that do not fit in elsewhere.
 * @note SPDX-FileCopyrightText: 2011 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 *
 * This code is based on the fragments from the linuxptp project.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef HAVE_UTIL_H
#define HAVE_UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "address.h"

#define xstr(s)	str(s)
#define str(s)	#s

#define UNUSED(var) (void)(var)

#define PACKED __attribute__((packed))

#define MAX_PRINT_BYTES 16
#define BIN_BUF_SIZE (MAX_PRINT_BYTES * 3 + 1)

#define EUI48		6
#define MAC_LEN		EUI48

static inline uint16_t align16(void *p)
{
	uint16_t v;
	memcpy(&v, p, sizeof(v));
	return v;
}

#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, tvar)                       \
        for ((var) = LIST_FIRST((head));                                \
            (var) && ((tvar) = LIST_NEXT((var), field), 1);             \
            (var) = (tvar))
#endif

//Source: ddt.h
struct ClockIdentity {
        uint8_t id[8];
};


/**
 * Scan a string containing a MAC address and convert it into binary form.
 *
 * @param s       String in human readable form.
 * @param mac     Pointer to a buffer to hold the result.
 * @return Zero on success, or -1 if the string is incorrectly formatted.
 */
int str2mac(const char *s, unsigned char mac[MAC_LEN]);

int sk_interface_index(int fd, const char *name);

int sk_interface_macaddr(const char *name, struct address *mac);

int generate_clock_identity(struct ClockIdentity *ci, const char *name);

/**
 * Values returned by get_ranged_*().
 */
enum parser_result {
	PARSED_OK,
	NOT_PARSED,
	BAD_VALUE,
	MALFORMED,
	OUT_OF_RANGE,
};

/**
 * Get an integer value from string with error checking and range
 * specification.
 *
 * @param str_val    String which contains an integer value.
 * @param result     Parsed value is stored in here.
 * @param min        Lower limit. Return OUT_OF_RANGE if parsed value
 *                   is less than min.
 * @param max        Upper Limit. Return OUT_OF_RANGE if parsed value
 *                   is bigger than max.
 * @return           PARSED_OK on success, MALFORMED if str_val is malformed,
 *                   OUT_OF_RANGE if str_val is out of range.
 */
enum parser_result get_ranged_int(const char *str_val, int *result,
				  int min, int max);

/**
 * Get an unsigned integer value from string with error checking and range
 * specification.
 *
 * @param str_val    String which contains an unsigned integer value.
 * @param result     Parsed value is stored in here.
 * @param min        Lower limit. Return OUT_OF_RANGE if parsed value
 *                   is less than min.
 * @param max        Upper Limit. Return OUT_OF_RANGE if parsed value
 *                   is bigger than max.
 * @return           PARSED_OK on success, MALFORMED if str_val is malformed,
 *                   OUT_OF_RANGE if str_val is out of range.
 */
enum parser_result get_ranged_uint(const char *str_val, unsigned int *result,
				   unsigned int min, unsigned int max);

/**
 * Get a double value from string with error checking and range
 * specification.
 *
 * @param str_val    String which contains a double value.
 * @param result     Parsed value is stored in here.
 * @param min        Lower limit. Return OUT_OF_RANGE if parsed value
 *                   is less than min.
 * @param max        Upper Limit. Return OUT_OF_RANGE if parsed value
 *                   is bigger than max.
 * @return           PARSED_OK on success, MALFORMED if str_val is malformed,
 *                   OUT_OF_RANGE if str_val is out of range.
 */
enum parser_result get_ranged_double(const char *str_val, double *result,
				     double min, double max);

/**
 * Common procedure to get an int value from argument.
 *
 * @param op     Character code of an option.
 * @param optarg Option argument string.
 * @param val    Parsed value is stored in here.
 * @param min    Lower limit. Return -1 if parsed value is less than min.
 * @param max    Upper limit. Return -1 if parsed value is bigger than max.
 * @return       0 on success, -1 if some error occurs.
 */
int get_arg_val_i(int op, const char *optarg, int *val, int min, int max);

/**
 * Common procedure to get an unsigned int value from argument.
 *
 * @param op     Character code of an option.
 * @param optarg Option argument string.
 * @param val    Parsed value is stored in here.
 * @param min    Lower limit. Return -1 if parsed value is less than min.
 * @param max    Upper limit. Return -1 if parsed value is bigger than max.
 * @return       0 on success, -1 if some error occurs.
 */
int get_arg_val_ui(int op, const char *optarg, unsigned int *val,
		   unsigned int min, unsigned int max);

/**
 * Common procedure to get a double value from argument.
 *
 * @param op     Character code of an option.
 * @param optarg Option argument string.
 * @param val    Parsed value is stored in here.
 * @param min    Lower limit. Return -1 if parsed value is less than min.
 * @param max    Upper limit. Return -1 if parsed value is bigger than max.
 * @return       0 on success, -1 if some error occurs.
 */
int get_arg_val_d(int op, const char *optarg, double *val,
		  double min, double max);

/**
 * Setup a handler for terminating signals (SIGINT, SIGQUIT, SIGTERM).
 *
 * @return       0 on success, -1 on error.
 */
int handle_term_signals(void);

/**
 * Check if a terminating signal was received.
 *
 * @return       1 if no terminating signal was received, 0 otherwise.
 */
int is_running(void);

/**
 * Acquire proper SynceE Do Not Use signal value basing on given arguments
 *
 * @param network_option	Type of the network
 * @param extended_tlv		If QL for extended tlv
 * @return			Do Not Use signal value
 */
uint8_t synce_get_dnu_value(int netwotk_option, int extended_tlv);
#endif
