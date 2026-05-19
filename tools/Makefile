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

# Optional CUDA GPU mapping library
NVCC ?= nvcc
CUDA_PATH ?= /usr/local/cuda
CUDA_CFLAGS = -I../include -I$(CUDA_PATH)/include
CUDA_LDFLAGS = -L$(CUDA_PATH)/lib64 -lcuda

GPU_TARGETS = daxfs-gpu-map.o

gpu: $(GPU_TARGETS)

daxfs-gpu-map.o: daxfs-gpu-map.c daxfs-gpu-map.h ../include/daxfs_format.h
	$(CC) $(CFLAGS) $(CUDA_CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGETS) $(GPU_TARGETS)

install: $(TARGETS)
	install -m 755 $(TARGETS) /usr/local/bin/

.PHONY: all clean install gpu
