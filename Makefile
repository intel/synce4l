#
# Copyright (C) 2022 Intel
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

ifeq ("$(wildcard .git)", "")
  VERSION = $(shell cat VERSION)
else
  VERSION = "$(shell git describe --abbrev=4 --dirty --always --tags)"
endif

LINUX_HDR_PATH   = /usr/include
ifneq ("$(wildcard $(LINUX_HDR_PATH)/linux/dpll.h)","")
  $(info Using linux/dpll.h header found in $(LINUX_HDR_PATH))
  DPLL = -DCONFIG_DPLL
else
  $(warning linux/dpll.h header not found - using backup file: headers/dpll.h)
endif

CC	= gcc
CFLAGS	= -Wall -Wextra -Werror $(EXTRA_CFLAGS) -pthread -DVERSION=$(VERSION) \
	$(DPLL) -I/usr/include/libnl3
LDLIBS	= -lm -lrt -pthread -lnl-genl-3 -lnl-3 $(EXTRA_LDFLAGS)

OBJS	= esmc_socket.o dpll_mon.o nl_dpll.o synce_clock.o synce_dev.o \
	  synce_dev_ctrl.o  synce_msg.o synce_port.o synce_port_ctrl.o \
	  synce_transport.o  synce_ext_src.o synce_clock_source.o config.o \
	  hash.o interface.o print.o util.o
HEADERS = $(OBJS:.o=.h)
BINARY 	= synce4l

SRC	= $(OBJS:.o=.c)

prefix	= /usr/local
sbindir	= $(prefix)/sbin
mandir	= $(prefix)/man
man8dir	= $(mandir)/man8

%.o: %c
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

$(BINARY): $(BINARY).c $(OBJS) $(HEADERS)
	$(CC) $(BINARY).c $(CFLAGS) $(OBJS) $(LDLIBS) -o $(BINARY)

install: $(BINARY)
	install -p -m 755 -d $(DESTDIR)$(sbindir) $(DESTDIR)$(man8dir)
	install $(BINARY) $(DESTDIR)$(sbindir)
	install -p -m 644 -t $(DESTDIR)$(man8dir) $(BINARY:%=%.8)

clean:
	rm -f $(OBJS) $(BINARY)
