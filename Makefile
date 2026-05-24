# SPDX-License-Identifier: GPL-2.0

KDIR ?= /lib/modules/$(shell uname -r)/build

# Escape '#' as '\#' so GNU Make < 4.3 does not treat it as a comment
# inside $(shell ...) (sed's BRE matches '\#' as a literal '#' either way).
DAXFS_RELEASE := $(shell sed -n 's/^\#define DAXFS_RELEASE_STRING[[:space:]]*"\(.*\)".*/\1/p' include/daxfs_version.h)

all: daxfs tools

daxfs:
	$(MAKE) -C daxfs KDIR=$(KDIR)

tools:
	$(MAKE) -C tools

tests:
	$(MAKE) -C tests

clean:
	$(MAKE) -C daxfs clean
	$(MAKE) -C tools clean
	$(MAKE) -C tests clean

version:
	@echo $(DAXFS_RELEASE)

dist:
	git archive --format=tar.gz --prefix=daxfs-$(DAXFS_RELEASE)/ \
		-o daxfs-$(DAXFS_RELEASE).tar.gz HEAD
	@echo "Created daxfs-$(DAXFS_RELEASE).tar.gz"

.PHONY: all daxfs tools tests clean version dist
