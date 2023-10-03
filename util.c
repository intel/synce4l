/**
 * @file util.c
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
#include <arpa/inet.h>
#include <errno.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "address.h"
#include "ether.h"
#include "print.h"
#include "util.h"
#include "synce_msg.h"

#define NS_PER_SEC 1000000000LL
#define NS_PER_HOUR (3600 * NS_PER_SEC)
#define NS_PER_DAY (24 * NS_PER_HOUR)

static int running = 1;

int sk_interface_index(int fd, const char *name)
{
        struct ifreq ifreq;
        int err;

        memset(&ifreq, 0, sizeof(ifreq));
        strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name) - 1);
        err = ioctl(fd, SIOCGIFINDEX, &ifreq);
        if (err < 0) {
                pr_err("ioctl SIOCGIFINDEX failed: %m");
                return err;
        }
        return ifreq.ifr_ifindex;
}

int sk_available(const char *name)
{
	struct ifreq ifreq;
	int err, fd;

	fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, PF_UNIX);
	if (fd < 0)
		return fd;
	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name) - 1);
	err = ioctl(fd, SIOCGIFINDEX, &ifreq);
	close(fd);
	if (err < 0)
		return 0;
	return 1;
}

#ifndef UNIT_TESTS
int sk_interface_macaddr(const char *name, struct address *mac)
{
        struct ifreq ifreq;
        int err, fd;

        memset(&ifreq, 0, sizeof(ifreq));
        strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name) - 1);

        fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0) {
                pr_err("socket failed: %m");
                return -1;
        }

        err = ioctl(fd, SIOCGIFHWADDR, &ifreq);
        if (err < 0) {
                pr_err("ioctl SIOCGIFHWADDR failed: %m");
                close(fd);
                return -1;
        }

        close(fd);

	memcpy(mac->sll.sll_addr, &ifreq.ifr_hwaddr.sa_data, MAC_LEN);
	mac->sll.sll_halen = EUI48;
        mac->sll.sll_family = AF_PACKET;
        mac->len = sizeof(mac->sll);
        return 0;
}
#endif

int generate_clock_identity(struct ClockIdentity *ci, const char *name)
{
	struct address addr;

	if (sk_interface_macaddr(name, &addr))
		return -1;

	if (addr.sll.sll_halen != EUI48)
		return -1;
	
	ci->id[0] = addr.sll.sll_addr[0];
	ci->id[1] = addr.sll.sll_addr[1];
	ci->id[2] = addr.sll.sll_addr[2];
	ci->id[3] = 0xFF;
	ci->id[4] = 0xFE;
	ci->id[5] = addr.sll.sll_addr[3];
	ci->id[6] = addr.sll.sll_addr[4];
	ci->id[7] = addr.sll.sll_addr[5];

	return 0;
}

enum parser_result get_ranged_int(const char *str_val, int *result,
				  int min, int max)
{
	long parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtol(str_val, &endptr, 0);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

enum parser_result get_ranged_uint(const char *str_val, unsigned int *result,
				   unsigned int min, unsigned int max)
{
	unsigned long parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtoul(str_val, &endptr, 0);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

enum parser_result get_ranged_double(const char *str_val, double *result,
				     double min, double max)
{
	double parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtod(str_val, &endptr);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

int get_arg_val_i(int op, const char *optarg, int *val, int min, int max)
{
	enum parser_result r;
	r = get_ranged_int(optarg, val, min, max);
	if (r == MALFORMED) {
		fprintf(stderr,
			"-%c: %s is a malformed value\n", op, optarg);
		return -1;
	}
	if (r == OUT_OF_RANGE) {
		fprintf(stderr,
			"-%c: %s is out of range. Must be in the range %d to %d\n",
			op, optarg, min, max);
		return -1;
	}
	return 0;
}

int get_arg_val_ui(int op, const char *optarg, unsigned int *val,
		   unsigned int min, unsigned int max)
{
	enum parser_result r;
	r = get_ranged_uint(optarg, val, min, max);
	if (r == MALFORMED) {
		fprintf(stderr,
			"-%c: %s is a malformed value\n", op, optarg);
		return -1;
	}
	if (r == OUT_OF_RANGE) {
		fprintf(stderr,
			"-%c: %s is out of range. Must be in the range %u to %u\n",
			op, optarg, min, max);
		return -1;
	}
	return 0;
}

int get_arg_val_d(int op, const char *optarg, double *val,
		  double min, double max)
{
	enum parser_result r;
	r = get_ranged_double(optarg, val, min, max);
	if (r == MALFORMED) {
		fprintf(stderr,
			"-%c: %s is a malformed value\n", op, optarg);
		return -1;
	}
	if (r == OUT_OF_RANGE) {
		fprintf(stderr,
			"-%c: %s is out of range. Must be in the range %e to %e\n",
			op, optarg, min, max);
		return -1;
	}
	return 0;
}

static void handle_int_quit_term(int s)
{
	UNUSED(s);

	running = 0;
}

int handle_term_signals(void)
{
	if (SIG_ERR == signal(SIGINT, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGINT\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGQUIT, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGQUIT\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGTERM, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGTERM\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGHUP, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGHUP\n");
		return -1;
	}
	return 0;
}

int is_running(void)
{
	return running;
}

uint8_t synce_get_dnu_value(int network_option, int extended_tlv)
{
	uint8_t ret = O1N_QL_DNU_ENHSSM;

	if (extended_tlv) {
		if (network_option == SYNCE_NETWORK_OPT_1) {
			ret = O1N_QL_DNU_ENHSSM;
		} else if (network_option == SYNCE_NETWORK_OPT_2) {
			ret = O2N_QL_DUS_ENHSSM;
		}
	} else {
		if (network_option == SYNCE_NETWORK_OPT_1) {
			ret = O1N_QL_DNU_SSM;
		} else if (network_option == SYNCE_NETWORK_OPT_2) {
			ret = O2N_QL_DUS_SSM;
		}
	}

	return ret;
}
