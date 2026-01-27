# SPDX-License-Identifier: GPL-2.0

KDIR ?= /lib/modules/$(shell uname -r)/build

all: kernel mkdaxfs tools

kernel:
	$(MAKE) -C kernel KDIR=$(KDIR)

mkdaxfs:
	$(MAKE) -C mkdaxfs

tools:
	$(MAKE) -C tools

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C mkdaxfs clean
	$(MAKE) -C tools clean

.PHONY: all kernel mkdaxfs tools clean
