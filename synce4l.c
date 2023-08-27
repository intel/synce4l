/**
 * @file synce4l.c
 * @brief Synchronous Ethernet (SyncE) userspace client
 * @note SPDX-FileCopyrightText: Copyright 2022 Intel Corporation
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>
#include <errno.h>

#include "synce_clock.h"
#include "config.h"
#include "print.h"
#include "util.h"

static void usage(char *progname)
{
	fprintf(stderr,
		"\nusage: %s [options]\n\n"
		" \n\n"
		" options:\n\n"
		" -f [file] configuration file path (required)\n"
		"           (command line arguments takes precedence over config file)\n"
		" -l [num]  set the logging level to 'num'\n"
		"           (%d: least detailed, %d: most detailed)\n"
		" -p [num]  state poll interval in milliseconds (default 20 ms)\n"
		" -m        print messages to stdout\n"
		" -q        do not print messages to the syslog\n"
		" -v        print synce4l version and exit\n"
		" -h        print this message and exit\n"
		"\n",
		progname, PRINT_LEVEL_MIN, PRINT_LEVEL_MAX);
}

static void synce4l_cleanup(struct config *cfg)
{
	if (cfg)
		config_destroy(cfg);
}

static void version_show(void)
{
#ifndef VERSION
	#error VERSION macro not defined, failing compilation.
#endif
	printf("synce4l version: %s\n", xstr(VERSION));
}

int unused()
{
	return 5;
}

int main(int argc, char *argv[])
{
	int c, err = -EACCES, index, print_level, poll_interval_ms;
	char *config = NULL, *progname;
	struct synce_clock *clock;
	struct option *opts;
	struct config *cfg;

	if (handle_term_signals())
		return -EPERM;

	cfg = config_create();
	if (!cfg) {
		return -EINVAL;
	}
	opts = config_long_options(cfg);

	poll_interval_ms = -1;

	/* Process the command line arguments. */
	progname = strrchr(argv[0], '/');
	progname = progname ? 1+progname : argv[0];
	while (EOF != (c = getopt_long(argc, argv, "f:l:p:mqvh",
				       opts, &index))) {
		switch (c) {
		case 'f':
			config = optarg;
			break;
		case 'l':
			if (get_arg_val_i(c, optarg, &print_level,
					  PRINT_LEVEL_MIN, PRINT_LEVEL_MAX))
				goto out;
			config_set_int(cfg, "logging_level", print_level);
			break;
		case 'p':
			if (get_arg_val_i(c, optarg, &poll_interval_ms,
					1, INT_MAX))
				goto out;
			config_set_int(cfg, "poll_interval_ms", poll_interval_ms);
			break;
		case 'm':
			config_set_int(cfg, "verbose", 1);
			break;
		case 'q':
			config_set_int(cfg, "use_syslog", 0);
			break;
		case 'v':
			version_show();
			synce4l_cleanup(cfg);
			return 0;
		case 'h':
			usage(progname);
			synce4l_cleanup(cfg);
			return 0;
		case '?':
			usage(progname);
			goto out;
		default:
			usage(progname);
			goto out;
		}
	}

	if (config && (c = config_read(config, cfg))) {
		synce4l_cleanup(cfg);
		return c;
	}

	print_set_progname(progname);
	print_set_tag(config_get_string(cfg, NULL, "message_tag"));
	print_set_verbose(config_get_int(cfg, NULL, "verbose"));
	print_set_syslog(config_get_int(cfg, NULL, "use_syslog"));
	print_set_level(config_get_int(cfg, NULL, "logging_level"));

	if (STAILQ_EMPTY(&cfg->interfaces)) {
		fprintf(stderr, "%s", "no interface specified\n");
		usage(progname);
		goto out;
	}

	clock = synce_clock_create(cfg);
	if (!clock) {
		fprintf(stderr, "%s", "failed to create a synce clock\n");
		goto out;
	}

	while (is_running())
		if (synce_clock_poll(clock))
			break;

	synce_clock_destroy(clock);

	err = 0;
out:
	synce4l_cleanup(cfg);
	return err;
}
