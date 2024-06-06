/**
 * @file config.c
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
#include <ctype.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#include "config.h"
#include "interface.h"
#include "hash.h"
#include "print.h"
#include "util.h"
#include "synce_thread_common.h"

struct interface {
	STAILQ_ENTRY(interface) list;
};

enum config_section {
	GLOBAL_SECTION,
	PORT_SECTION,
	DEVICE_SECTION,
	EXT_SECTION,
	SRC_SECTION,
	UNKNOWN_SECTION,
};

enum config_type {
	CFG_TYPE_INT,
	CFG_TYPE_U64,
	CFG_TYPE_DOUBLE,
	CFG_TYPE_ENUM,
	CFG_TYPE_STRING,
};

struct config_enum {
	const char *label;
	int value;
};

typedef union {
	int i;
	double d;
	char *s;
	uint64_t u64;
} any_t;

#define CONFIG_LABEL_SIZE 32

#define CFG_ITEM_STATIC	(1 << 0)  /* statically allocated, not to be freed */
#define CFG_ITEM_LOCKED	(1 << 1)  /* command line value, may not be changed */
#define CFG_ITEM_PORT	(1 << 2)  /* item may appear in port sections */
#define CFG_ITEM_DYNSTR	(1 << 4)  /* string value dynamically allocated */
#define CFG_ITEM_DEVICE	(1 << 8)  /* item may appear in device sections */
#define CFG_ITEM_EXT	(1 << 16) /* item may appear in external sections */

struct config_item {
	char label[CONFIG_LABEL_SIZE];
	enum config_type type;
	struct config_enum *tab;
	unsigned int flags;
	any_t val;
	any_t min;
	any_t max;
};

#define N_CONFIG_ITEMS_SYNCE (sizeof(config_tab_synce) / sizeof(config_tab_synce[0]))

#define PORT_TO_FLAG(_port) _port == PORT_SECTION ? CFG_ITEM_PORT : \
	_port == DEVICE_SECTION ? CFG_ITEM_DEVICE : \
	_port == EXT_SECTION ? CFG_ITEM_EXT : \
	_port == SRC_SECTION ? CFG_ITEM_PORT | CFG_ITEM_EXT : \
	CFG_ITEM_STATIC

#define CONFIG_ITEM_DBL(_label, _port, _default, _min, _max) {	\
	.label	= _label,				\
	.type	= CFG_TYPE_DOUBLE,			\
	.flags	= PORT_TO_FLAG(_port),			\
	.val.d	= _default,				\
	.min.d	= _min,					\
	.max.d	= _max,					\
}
#define CONFIG_ITEM_ENUM(_label, _port, _default, _table) { \
	.label	= _label,				\
	.type	= CFG_TYPE_ENUM,			\
	.flags	= PORT_TO_FLAG(_port),			\
	.tab	= _table,				\
	.val.i	= _default,				\
}
#define CONFIG_ITEM_INT(_label, _port, _default, _min, _max) {	\
	.label	= _label,				\
	.type	= CFG_TYPE_INT,				\
	.flags	= PORT_TO_FLAG(_port),			\
	.val.i	= _default,				\
	.min.i	= _min,					\
	.max.i	= _max,					\
}
#define CONFIG_ITEM_U64(_label, _port, _default, _min, _max) {	\
	.label	= _label,				\
	.type	= CFG_TYPE_U64,			\
	.flags	= PORT_TO_FLAG(_port),			\
	.val.u64 = _default,				\
	.min.u64 = _min,				\
	.max.u64 = _max,				\
}
#define CONFIG_ITEM_STRING(_label, _port, _default) {	\
	.label	= _label,				\
	.type	= CFG_TYPE_STRING,			\
	.flags	= PORT_TO_FLAG(_port),			\
	.val.s	= _default,				\
}

#define GLOB_ITEM_DBL(label, _default, min, max) \
	CONFIG_ITEM_DBL(label, GLOBAL_SECTION , _default, min, max)

#define GLOB_ITEM_ENU(label, _default, table) \
	CONFIG_ITEM_ENUM(label, GLOBAL_SECTION, _default, table)

#define GLOB_ITEM_INT(label, _default, min, max) \
	CONFIG_ITEM_INT(label, GLOBAL_SECTION, _default, min, max)

#define GLOB_ITEM_STR(label, _default) \
	CONFIG_ITEM_STRING(label, GLOBAL_SECTION, _default)

#define PORT_ITEM_DBL(label, _default, min, max) \
	CONFIG_ITEM_DBL(label, PORT_SECTION, _default, min, max)

#define PORT_ITEM_ENU(label, _default, table) \
	CONFIG_ITEM_ENUM(label, PORT_SECTION, _default, table)

#define PORT_ITEM_INT(label, _default, min, max) \
	CONFIG_ITEM_INT(label, PORT_SECTION, _default, min, max)

#define PORT_ITEM_STR(label, _default) \
	CONFIG_ITEM_STRING(label, PORT_SECTION, _default)

#define DEV_ITEM_INT(label, _default, min, max) \
	CONFIG_ITEM_INT(label, DEVICE_SECTION, _default, min, max)

#define DEV_ITEM_U64(label, _default, min, max) \
	CONFIG_ITEM_U64(label, DEVICE_SECTION, _default, min, max)

#define DEV_ITEM_STR(label, _default) \
	CONFIG_ITEM_STRING(label, DEVICE_SECTION, _default)

#define EXT_ITEM_INT(label, _default, min, max) \
	CONFIG_ITEM_INT(label, EXT_SECTION, _default, min, max)

#define EXT_ITEM_STR(label, _default) \
	CONFIG_ITEM_STRING(label, EXT_SECTION, _default)

#define SRC_ITEM_INT(label, _default, min, max) \
	CONFIG_ITEM_INT(label, SRC_SECTION, _default, min, max)

struct config_item config_tab_synce[] = {
	GLOB_ITEM_INT("logging_level", LOG_INFO, PRINT_LEVEL_MIN, PRINT_LEVEL_MAX),
	GLOB_ITEM_STR("message_tag", NULL),
	GLOB_ITEM_INT("poll_interval_msec", 20, CLOCK_POLL_INTERVAL_MIN,
		      CLOCK_POLL_INTERVAL_MAX),
	GLOB_ITEM_STR("smc_socket_path", "/run/synce4l_socket"),
	GLOB_ITEM_INT("use_syslog", 1, 0, 1),
	GLOB_ITEM_STR("userDescription", ""),
	GLOB_ITEM_INT("verbose", 0, 0, 1),
	DEV_ITEM_STR("input_mode", "line"),
	DEV_ITEM_INT("extended_tlv", 0, 0, 1),
	DEV_ITEM_INT("network_option", 1, 1, 2),
	DEV_ITEM_INT("recover_time", 300, 10, 720),
	DEV_ITEM_STR("eec_get_state_cmd", NULL),
	DEV_ITEM_STR("eec_holdover_value", NULL),
	DEV_ITEM_STR("eec_locked_ho_value", NULL),
	DEV_ITEM_STR("eec_locked_value", NULL),
	DEV_ITEM_STR("eec_freerun_value", NULL),
	DEV_ITEM_STR("eec_invalid_value", NULL),
	DEV_ITEM_U64("clock_id", 0, 0, 0xffffffffffffffff),
	DEV_ITEM_STR("module_name", NULL),
	DEV_ITEM_INT("dnu_prio", 15, 15, 0xffff),
	PORT_ITEM_STR("allowed_qls", NULL),
	PORT_ITEM_STR("allowed_ext_qls", NULL),
	PORT_ITEM_STR("recover_clock_enable_cmd", NULL),
	PORT_ITEM_STR("recover_clock_disable_cmd", NULL),
	PORT_ITEM_STR("board_label", NULL),
	PORT_ITEM_STR("panel_label", NULL),
	PORT_ITEM_STR("package_label", NULL),
	PORT_ITEM_INT("tx_heartbeat_msec", 1000, 100, 3000),
	PORT_ITEM_INT("rx_heartbeat_msec", 50, 10, 500),
	EXT_ITEM_INT("input_QL", 0, 0, 15),
	EXT_ITEM_INT("input_ext_QL", 0, 0, 255),
	EXT_ITEM_STR("external_enable_cmd", NULL),
	EXT_ITEM_STR("external_disable_cmd", NULL),
	SRC_ITEM_INT("internal_prio", 128, 0, 255),
};

static struct interface *__config_create_interface(const char *name, struct config *cfg,
						   const char *type);

static enum parser_result
parse_fault_interval(struct config *cfg, const char *section,
		     const char *option, const char *value);

static struct config_item *config_section_item(struct config *cfg,
					       const char *section,
					       const char *name)
{
	char buf[CONFIG_LABEL_SIZE + MAX_IFNAME_SIZE];

	if ((unsigned long)snprintf(buf, sizeof(buf), "%s.%s", section, name) >=
	    sizeof(buf))
		return NULL;
	return hash_lookup(cfg->htab, buf);
}

static struct config_item *config_global_item(struct config *cfg,
					      const char *name)
{
	return config_section_item(cfg, "global", name);
}

static struct config_item *config_find_item(struct config *cfg,
					    const char *section,
					    const char *name)
{
	struct config_item *ci;
	if (section) {
		ci = config_section_item(cfg, section, name);
		if (ci) {
			return ci;
		}
	}
	return config_global_item(cfg, name);
}

static struct config_item *config_item_alloc(struct config *cfg,
					     const char *section,
					     const char *name,
					     enum config_type type)
{
	struct config_item *ci;
	char buf[CONFIG_LABEL_SIZE + MAX_IFNAME_SIZE];

	ci = calloc(1, sizeof(*ci));
	if (!ci) {
		fprintf(stderr, "low memory\n");
		return NULL;
	}
	strncpy(ci->label, name, CONFIG_LABEL_SIZE - 1);
	ci->type = type;
	ci->val.s = NULL;
	ci->flags = 0;

	snprintf(buf, sizeof(buf), "%s.%s", section, ci->label);
	if (hash_insert(cfg->htab, buf, ci)) {
		fprintf(stderr, "low memory or duplicate item %s\n", name);
		free(ci);
		return NULL;
	}

	return ci;
}

static void config_item_free(void *ptr)
{
	struct config_item *ci = ptr;
	if (ci->type == CFG_TYPE_STRING && ci->flags & CFG_ITEM_DYNSTR
	    && ci->val.s != NULL) {
		free(ci->val.s);
		ci->val.s = NULL;
	}
	if (ci->flags & CFG_ITEM_STATIC)
		return;
	free(ci);
}

static enum parser_result parse_section_line(char *s, enum config_section *section)
{
	if (!strcasecmp(s, "[global]")) {
		*section = GLOBAL_SECTION;
	} else if (s[0] == '[') {
		char c;
		if (s[1] == '<')
			*section = DEVICE_SECTION;
		else if (s[1] == '{')
			*section = EXT_SECTION;
		else
			*section = PORT_SECTION;
		/* Replace brackets with white space. */
		while (0 != (c = *s)) {
			if (c == '[' || c == ']' || c == '<' || c == '>' ||
			    c == '{' || c == '}')
				*s = ' ';
			s++;
		}
	} else
		return NOT_PARSED;
	return PARSED_OK;
}

static enum parser_result parse_item(struct config *cfg,
				     int commandline,
				     const char *section,
				     const char *option,
				     const char *value)
{
	struct config_item *cgi, *dst;
	struct config_enum *cte;
	enum parser_result r;
	uint64_t u64 = 0;
	double df = 0.0;
	int val = 0;

	r = parse_fault_interval(cfg, section, option, value);
	if (r != NOT_PARSED)
		return r;

	r = BAD_VALUE;

	/* If there is no default value, then the option is bogus. */
	cgi = config_global_item(cfg, option);
	if (!cgi) {
		return NOT_PARSED;
	}

	switch (cgi->type) {
	case CFG_TYPE_INT:
		r = get_ranged_int(value, &val, cgi->min.i, cgi->max.i);
		break;
	case CFG_TYPE_U64:
		r = get_ranged_u64(value, &u64, cgi->min.u64, cgi->max.u64);
		break;
	case CFG_TYPE_DOUBLE:
		r = get_ranged_double(value, &df, cgi->min.d, cgi->max.d);
		break;
	case CFG_TYPE_ENUM:
		for (cte = cgi->tab; cte->label; cte++) {
			if (!strcasecmp(cte->label, value)) {
				val = cte->value;
				r = PARSED_OK;
				break;
			}
		}
		break;
	case CFG_TYPE_STRING:
		r = PARSED_OK;
		break;
	}
	if (r != PARSED_OK) {
		return r;
	}

	if (section) {
		if (!(cgi->flags & CFG_ITEM_PORT) &&
		    !(cgi->flags & CFG_ITEM_EXT) &&
		    !(cgi->flags & CFG_ITEM_DEVICE)) {
			return NOT_PARSED;
		}
		/* Create or update this port specific item. */
		dst = config_section_item(cfg, section, option);
		if (!dst) {
			dst = config_item_alloc(cfg, section, option, cgi->type);
			if (!dst) {
				return NOT_PARSED;
			}
		}
	} else if (!commandline && cgi->flags & CFG_ITEM_LOCKED) {
		/* This global option was set on the command line. */
		return PARSED_OK;
	} else {
		/* Update the global default value. */
		dst = cgi;
	}

	switch (dst->type) {
	case CFG_TYPE_INT:
	case CFG_TYPE_ENUM:
		dst->val.i = val;
		break;
	case CFG_TYPE_U64:
		dst->val.u64 = u64;
		break;
	case CFG_TYPE_DOUBLE:
		dst->val.d = df;
		break;
	case CFG_TYPE_STRING:
		if (dst->flags & CFG_ITEM_DYNSTR && dst->val.s != NULL) {
			free(dst->val.s);
			dst->val.s = NULL;
		}
		dst->val.s = strdup(value);
		if (!dst->val.s) {
			pr_err("low memory");
			return NOT_PARSED;
		}
		dst->flags |= CFG_ITEM_DYNSTR;
		break;
	}

	if (commandline) {
		dst->flags |= CFG_ITEM_LOCKED;
	}
	return PARSED_OK;
}

#define FRI_ASAP (-128)

static enum parser_result parse_fault_interval(struct config *cfg,
					       const char *section,
					       const char *option,
					       const char *value)
{
	int i, val;
	const char *str, *fault_options[2] = {
		"fault_badpeernet_interval",
		"fault_reset_interval",
	};
	int fault_values[2] = {
		0, FRI_ASAP,
	};

	if (strcasecmp("ASAP", value)) {
		return NOT_PARSED;
	}
	for (i = 0; i < 2; i++) {
		str = fault_options[i];
		val = fault_values[i];
		if (!strcmp(option, str)) {
			if (config_set_section_int(cfg, section, str, val)) {
				pr_err("bug: failed to set option %s!", option);
				exit(-1);
			}
			return PARSED_OK;
		}
	}
	return NOT_PARSED;
}

static enum parser_result parse_setting_line(char *line,
					     const char **option,
					     const char **value)
{
	*option = line;

	while (!isspace(line[0])) {
		if (line[0] == '\0')
			return NOT_PARSED;
		line++;
	}

	while (isspace(line[0])) {
		line[0] = '\0';
		line++;
	}

	*value = line;

	return PARSED_OK;
}

static struct option *config_alloc_longopts()
{
	struct config_item *ci, *ci_tab;
	struct option *opts;
	int i, n_items;

	ci_tab = &config_tab_synce[0];
	n_items = N_CONFIG_ITEMS_SYNCE;

	opts = calloc(1, (1 + n_items) * sizeof(*opts));
	if (!opts) {
		return NULL;
	}
	for (i = 0; i < n_items; i++) {
		ci = &ci_tab[i];
		opts[i].name = ci->label;
		opts[i].has_arg = required_argument;
		/* Avoid bug in detection of ambiguous options in glibc */
		opts[i].flag = &opts[i].val;
	}

	return opts;
}

int config_read(const char *name, struct config *cfg)
{
	enum config_section current_section = UNKNOWN_SECTION;
	enum parser_result parser_res;
	FILE *fp;
	char buf[1024], *line, *c;
	const char *option, *value;
	struct interface *current_device = NULL;
	struct interface *current_clk_src = NULL;
	int line_num;

	fp = 0 == strncmp(name, "-", 2) ? stdin : fopen(name, "r");

	if (!fp) {
		fprintf(stderr, "failed to open configuration file %s: %m\n", name);
		return -1;
	}

	for (line_num = 1; fgets(buf, sizeof(buf), fp); line_num++) {
		c = buf;

		/* skip whitespace characters */
		while (isspace(*c))
			c++;

		/* ignore empty lines and comments */
		if (*c == '#' || *c == '\n' || *c == '\0')
			continue;

		line = c;

		/* remove trailing whitespace characters and \n */
		c += strlen(line) - 1;
		while (c > line && (*c == '\n' || isspace(*c)))
			*c-- = '\0';

		if (parse_section_line(line, &current_section) == PARSED_OK) {
			if (current_section == PORT_SECTION ||
			    current_section == EXT_SECTION) {
				char clk_src[IF_NAMESIZE + 1];

				if (sscanf(line, " %16s", clk_src) != 1) {
					fprintf(stderr, "could not parse clk_src name on line %d\n",
							line_num);
					goto parse_error;
				}
				current_clk_src = config_create_interface(clk_src, cfg);
				if (!current_clk_src)
					goto parse_error;
				if (current_device) {
					interface_se_set_parent_dev(current_clk_src,
						interface_name(current_device));
					if (current_section == EXT_SECTION)
						interface_section_set_external_source(
							current_clk_src);
				} else {
					goto parse_error;
				}
			} else if (current_section == DEVICE_SECTION) {
				/* clear clk_src on new device found in config */
				current_clk_src = NULL;
				char device[IF_NAMESIZE + 1];
				if (1 != sscanf(line, " %16s", device)) {
					fprintf(stderr, "could not parse device name on line %d\n",
						line_num);
					goto parse_error;
				}
				current_device = __config_create_interface(device, cfg, "device");
				if (!current_device)
					goto parse_error;
			}
			continue;
		}

		if (current_section == UNKNOWN_SECTION) {
			fprintf(stderr, "line %d is not in a section\n", line_num);
			goto parse_error;
		}

		if (parse_setting_line(line, &option, &value)) {
			fprintf(stderr, "could not parse line %d in %s section\n",
				line_num, current_section == GLOBAL_SECTION ?
				"global" : interface_name(current_clk_src ?
							  current_clk_src : current_device));
			goto parse_error;
		}

		parser_res = parse_item(cfg, 0, current_section == GLOBAL_SECTION ?
					NULL : interface_name(current_clk_src ?
							      current_clk_src : current_device),
					option, value);
		switch (parser_res) {
		case PARSED_OK:
			break;
		case NOT_PARSED:
			fprintf(stderr, "unknown option %s at line %d in %s section\n",
				option, line_num,
				current_section == GLOBAL_SECTION ? "global" :
				interface_name(current_clk_src ?
					       current_clk_src : current_device));
			goto parse_error;
		case BAD_VALUE:
			fprintf(stderr, "%s is a bad value for option %s at line %d\n",
				value, option, line_num);
			goto parse_error;
		case MALFORMED:
			fprintf(stderr, "%s is a malformed value for option %s at line %d\n",
				value, option, line_num);
			goto parse_error;
		case OUT_OF_RANGE:
			fprintf(stderr, "%s is an out of range value for option %s at line %d\n",
				value, option, line_num);
			goto parse_error;
		}
	}

	fclose(fp);
	return 0;

parse_error:
	fprintf(stderr, "failed to parse configuration file %s\n", name);
	fclose(fp);
	return -2;
}

struct interface *__config_create_interface(const char *name, struct config *cfg, const char *type)
{
	struct interface *iface;
	const char *ifname;

	/* only create each interface once (by name) */
	STAILQ_FOREACH(iface, &cfg->interfaces, list) {
		ifname = interface_name(iface);
		if (0 == strncmp(name, ifname, MAX_IFNAME_SIZE))
			return iface;
	}

	iface = interface_create(name);
	if (!iface) {
		fprintf(stderr, "cannot allocate memory for a %s\n", type);
		return NULL;
	}
	STAILQ_INSERT_TAIL(&cfg->interfaces, iface, list);
	cfg->n_interfaces++;

	return iface;
}

struct interface *config_create_interface(const char *name, struct config *cfg)
{
	return __config_create_interface(name, cfg, "port");
}

struct config *config_create()
{
	char buf[CONFIG_LABEL_SIZE + 8];
	struct config_item *ci, *ci_tab;
	struct config *cfg;
	int i, end;

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg) {
		return NULL;
	}
	STAILQ_INIT(&cfg->interfaces);

	cfg->opts = config_alloc_longopts();
	if (!cfg->opts) {
		free(cfg);
		return NULL;
	}

	cfg->htab = hash_create();
	if (!cfg->htab) {
		free(cfg->opts);
		free(cfg);
		return NULL;
	}

	ci_tab = &config_tab_synce[0];
	end = N_CONFIG_ITEMS_SYNCE;

	/* Populate the hash table with global defaults. */
	for (i = 0; i < end; i++) {
		ci = &ci_tab[i];
		ci->flags |= CFG_ITEM_STATIC;
		if ((unsigned long)snprintf(buf, sizeof(buf), "global.%s",
					    ci->label) >= sizeof(buf)) {
			fprintf(stderr, "option %s too long\n", ci->label);
			goto fail;
		}
		if (hash_insert(cfg->htab, buf, ci)) {
			fprintf(stderr, "duplicate item %s\n", ci->label);
			goto fail;
		}
	}

	/* Perform a Built In Self Test.*/
	for (i = 0; i < end; i++) {
		ci = &ci_tab[i];
		ci = config_global_item(cfg, ci->label);
		if (ci != &ci_tab[i]) {
			fprintf(stderr, "config BIST failed at %s\n",
				ci_tab[i].label);
			goto fail;
		}
	}
	return cfg;
fail:
	hash_destroy(cfg->htab, NULL);
	free(cfg->opts);
	free(cfg);
	return NULL;
}

void config_destroy(struct config *cfg)
{
	struct interface *iface;

	while ((iface = STAILQ_FIRST(&cfg->interfaces))) {
		STAILQ_REMOVE_HEAD(&cfg->interfaces, list);
		interface_destroy(iface);
	}
	hash_destroy(cfg->htab, config_item_free);
	free(cfg->opts);
	free(cfg);
}

double config_get_double(struct config *cfg, const char *section,
			 const char *option)
{
	struct config_item *ci = config_find_item(cfg, section, option);

	if (!ci || ci->type != CFG_TYPE_DOUBLE) {
		pr_err("bug: config option %s missing or invalid!", option);
		exit(-1);
	}
	pr_debug("config item %s.%s is %f", section, option, ci->val.d);
	return ci->val.d;
}

int config_get_int(struct config *cfg, const char *section, const char *option)
{
	struct config_item *ci = config_find_item(cfg, section, option);

	if (!ci) {
		pr_err("bug: config option %s missing!", option);
		exit(-1);
	}
	switch (ci->type) {
	case CFG_TYPE_DOUBLE:
	case CFG_TYPE_STRING:
	case CFG_TYPE_U64:
		pr_err("bug: config option %s type mismatch!", option);
		exit(-1);
	case CFG_TYPE_INT:
	case CFG_TYPE_ENUM:
		break;
	}
	pr_debug("config item %s.%s is %d (0x%x)", section, option, ci->val.i, ci->val.i);
	return ci->val.i;
}

uint64_t
config_get_u64(struct config *cfg, const char *section, const char *option)
{
	struct config_item *ci = config_find_item(cfg, section, option);

	if (!ci) {
		pr_err("bug: config option %s missing!", option);
		exit(-1);
	}
	if (ci->type != CFG_TYPE_U64) {
		pr_err("bug: config option %s type mismatch!", option);
		exit(-1);
	}
	pr_debug("config item %s.%s is %"PRIu64" (0x%"PRIx64")", section, option,
		 ci->val.u64, ci->val.u64);
	return ci->val.u64;
}

char *config_get_string(struct config *cfg, const char *section,
			const char *option)
{
	struct config_item *ci = config_find_item(cfg, section, option);

	if (!ci || ci->type != CFG_TYPE_STRING) {
		pr_err("bug: config option %s missing or invalid!", option);
		exit(-1);
	}
	pr_debug("config item %s.%s is '%s'", section, option, ci->val.s);
	return ci->val.s;
}

int config_parse_option(struct config *cfg, const char *opt, const char *val)
{
	enum parser_result result;

	result = parse_item(cfg, 1, NULL, opt, val);

	switch (result) {
	case PARSED_OK:
		return 0;
	case NOT_PARSED:
		fprintf(stderr, "unknown option %s\n", opt);
		break;
	case BAD_VALUE:
		fprintf(stderr, "%s is a bad value for option %s\n", val, opt);
		break;
	case MALFORMED:
		fprintf(stderr, "%s is a malformed value for option %s\n",
			val, opt);
		break;
	case OUT_OF_RANGE:
		fprintf(stderr, "%s is an out of range value for option %s\n",
			val, opt);
		break;
	}
	return -1;
}

int config_set_double(struct config *cfg, const char *option, double val)
{
	struct config_item *ci = config_find_item(cfg, NULL, option);

	if (!ci || ci->type != CFG_TYPE_DOUBLE) {
		pr_err("bug: config option %s missing or invalid!", option);
		return -1;
	}
	ci->flags |= CFG_ITEM_LOCKED;
	ci->val.d = val;
	pr_debug("locked item global.%s as %f", option, ci->val.d);
	return 0;
}

int config_set_section_int(struct config *cfg, const char *section,
			   const char *option, int val)
{
	struct config_item *cgi, *dst;

	cgi = config_find_item(cfg, NULL, option);
	if (!cgi) {
		pr_err("bug: config option %s missing!", option);
		return -1;
	}
	switch (cgi->type) {
	case CFG_TYPE_DOUBLE:
	case CFG_TYPE_STRING:
	case CFG_TYPE_U64:
		pr_err("bug: config option %s type mismatch!", option);
		return -1;
	case CFG_TYPE_INT:
	case CFG_TYPE_ENUM:
		break;
	}
	if (!section) {
		cgi->flags |= CFG_ITEM_LOCKED;
		cgi->val.i = val;
		pr_debug("locked item global.%s as %d", option, cgi->val.i);
		return 0;
	}
	/* Create or update this port specific item. */
	dst = config_section_item(cfg, section, option);
	if (!dst) {
		dst = config_item_alloc(cfg, section, option, cgi->type);
		if (!dst) {
			return -1;
		}
	}
	dst->val.i = val;
	pr_debug("section item %s.%s now %d", section, option, dst->val.i);
	return 0;
}

int config_set_string(struct config *cfg, const char *option,
		      const char *val)
{
	struct config_item *ci = config_find_item(cfg, NULL, option);

	if (!ci || ci->type != CFG_TYPE_STRING) {
		pr_err("bug: config option %s missing or invalid!", option);
		return -1;
	}
	ci->flags |= CFG_ITEM_LOCKED;
	if (ci->flags & CFG_ITEM_DYNSTR && ci->val.s != NULL) {
		free(ci->val.s);
		ci->val.s = NULL;
	}
	ci->val.s = strdup(val);
	if (!ci->val.s) {
		pr_err("low memory");
		return -1;
	}
	ci->flags |= CFG_ITEM_DYNSTR;
	pr_debug("locked item global.%s as '%s'", option, ci->val.s);
	return 0;
}
