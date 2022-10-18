/**
 * @file config.h
 * @brief Configuration file code
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
#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H

#include <getopt.h>
#include <sys/queue.h>

struct config {
	/* configured interfaces */
	STAILQ_HEAD(interfaces_head, interface) interfaces;
	int n_interfaces;

	/* for parsing command line options */
	struct option *opts;

	/* hash of all non-legacy items */
	struct hash *htab;
};

int config_read(const char *name, struct config *cfg);
struct interface *config_create_interface(const char *name, struct config *cfg);
void config_destroy(struct config *cfg);

/* New, hash table based methods: */

struct config *config_create(void);

struct config *config_create_synce();

double config_get_double(struct config *cfg, const char *section,
			 const char *option);

int config_get_int(struct config *cfg, const char *section,
		   const char *option);

char *config_get_string(struct config *cfg, const char *section,
			const char *option);

int config_harmonize_onestep(struct config *cfg);

static inline struct option *config_long_options(struct config *cfg)
{
	return cfg->opts;
}

int config_parse_option(struct config *cfg, const char *opt, const char *val);

int config_set_double(struct config *cfg, const char *option, double val);

int config_set_section_int(struct config *cfg, const char *section,
			   const char *option, int val);

static inline int config_set_int(struct config *cfg,
				 const char *option, int val)
{
	return config_set_section_int(cfg, NULL, option, val);
}

int config_set_string(struct config *cfg, const char *option,
		      const char *val);

#endif
