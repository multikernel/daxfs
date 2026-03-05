# SPDX-License-Identifier: GPL-2.0

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
CFLAGS += -I../include

TARGETS = mkdaxfs daxfs-inspect

all: $(TARGETS)

mkdaxfs: mkdaxfs.c
	$(CC) $(CFLAGS) -o $@ $<

daxfs-inspect: daxfs-inspect.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

install: $(TARGETS)
	install -m 755 $(TARGETS) /usr/local/bin/

.PHONY: all clean install
