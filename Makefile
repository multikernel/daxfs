# SPDX-License-Identifier: GPL-2.0

KDIR ?= /lib/modules/$(shell uname -r)/build

all: kernel mkdaxfs

kernel:
	$(MAKE) -C kernel KDIR=$(KDIR)

mkdaxfs:
	$(MAKE) -C mkdaxfs

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C mkdaxfs clean

.PHONY: all kernel mkdaxfs clean
