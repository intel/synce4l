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

VERSION := "$(shell git describe --abbrev=4 --dirty --always --tags)"
ifndef VERSION
  $(error VERSION is unset)
endif
ifeq ($(VERSION), "")
  $(error VERSION is empty)
endif

CC	= gcc
CFLAGS	= -Wall -D_GNU_SOURCE -Wextra -Werror $(EXTRA_CFLAGS) -pthread -DVERSION=$(VERSION)
LDLIBS	= -lrt -pthread $(EXTRA_LDFLAGS)

OBJS	= esmc_socket.o synce_clock.o synce_dev.o synce_dev_ctrl.o \
 synce_msg.o synce_port.o synce_port_ctrl.o synce_transport.o \
 config.o hash.o interface.o print.o util.o
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
