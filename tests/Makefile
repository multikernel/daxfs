# SPDX-License-Identifier: GPL-2.0

CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g

TESTS = test_mmap

all: $(TESTS)

test_mmap: test_mmap.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TESTS)

# Run mmap tests (requires DAXFS mounted at /mnt/daxfs or specify MOUNTPOINT)
MOUNTPOINT ?= /mnt/daxfs

test-mmap: $(TESTS)
	@echo "Running mmap tests on $(MOUNTPOINT)..."
	@for t in $(TESTS); do ./$$t $(MOUNTPOINT) || exit 1; done

# Run full test suite (requires root, DMA heap)
test: $(TESTS)
	@echo "Running overlay & pcache tests (requires root)..."
	@sudo ./test_overlay.sh -v

.PHONY: all clean test test-mmap
