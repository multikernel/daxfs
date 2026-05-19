// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs-inspect - Inspection utility for daxfs
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * Read-only inspection of daxfs via physical memory (/dev/mem) or dma-buf.
 * Can parse mount point to automatically get phys/size from mountinfo.
 *
 * Usage:
 *   daxfs-inspect status -m /mnt/daxfs
 *   daxfs-inspect overlay -m /mnt/daxfs
 *   daxfs-inspect status -p 0x100000000 -s 256M
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <endian.h>

#include "daxfs_format.h"

/* Userspace endian conversion (kernel uses le32_to_cpu, etc.) */
#define le16_to_cpu(x)	le16toh(x)
#define le32_to_cpu(x)	le32toh(x)
#define le64_to_cpu(x)	le64toh(x)

static void *mem;
static size_t mem_size;
static int dmabuf_fd = -1;
static struct daxfs_super *super;

static int get_mount_size(const char *mount_point, size_t *size)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	int found = 0;
	char resolved_mount[PATH_MAX];

	if (!realpath(mount_point, resolved_mount)) {
		perror("realpath");
		return -1;
	}

	fp = fopen("/proc/self/mountinfo", "r");
	if (!fp) {
		perror("/proc/self/mountinfo");
		return -1;
	}

	while ((nread = getline(&line, &len, fp)) != -1) {
		char *mnt_path, *fs_type, *options;
		char *saveptr, *token;
		char *dash;

		token = strtok_r(line, " ", &saveptr);
		if (!token) continue;
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) continue;
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) continue;
		token = strtok_r(NULL, " ", &saveptr);
		if (!token) continue;
		mnt_path = strtok_r(NULL, " ", &saveptr);
		if (!mnt_path) continue;

		if (strcmp(mnt_path, resolved_mount) != 0)
			continue;

		dash = strstr(saveptr, " - ");
		if (!dash)
			continue;

		dash += 3;
		fs_type = strtok_r(dash, " ", &saveptr);
		if (!fs_type || strcmp(fs_type, "daxfs") != 0)
			continue;

		token = strtok_r(NULL, " ", &saveptr);
		if (!token) continue;

		options = strtok_r(NULL, "\n", &saveptr);
		if (!options) continue;

		char *opts_copy = strdup(options);
		char *opt_saveptr;
		char *opt = strtok_r(opts_copy, ",", &opt_saveptr);

		while (opt) {
			if (strncmp(opt, "size=", 5) == 0) {
				*size = strtoull(opt + 5, NULL, 0);
				found = 1;
				break;
			}
			opt = strtok_r(NULL, ",", &opt_saveptr);
		}
		free(opts_copy);
		break;
	}

	free(line);
	fclose(fp);

	if (!found) {
		fprintf(stderr, "Error: %s is not a daxfs mount or missing size\n",
			mount_point);
		return -1;
	}

	return 0;
}

static int open_mount(const char *mount_point)
{
	int fd;
	size_t size;

	if (get_mount_size(mount_point, &size) < 0)
		return -1;

	fd = open(mount_point, O_RDONLY);
	if (fd < 0) {
		perror(mount_point);
		return -1;
	}

	dmabuf_fd = ioctl(fd, DAXFS_IOC_GET_DMABUF);
	close(fd);

	if (dmabuf_fd < 0) {
		if (errno == ENOENT) {
			fprintf(stderr, "Error: %s is not a dma-buf backed mount\n",
				mount_point);
			fprintf(stderr, "Use -p/-s for phys-based mounts (requires root)\n");
		} else {
			perror("ioctl DAXFS_IOC_GET_DMABUF");
		}
		return -1;
	}

	mem_size = size;
	mem = mmap(NULL, size, PROT_READ, MAP_SHARED, dmabuf_fd, 0);

	if (mem == MAP_FAILED) {
		perror("mmap dma-buf");
		close(dmabuf_fd);
		dmabuf_fd = -1;
		return -1;
	}

	return 0;
}

static int open_phys(unsigned long long phys_addr, size_t size)
{
	int fd;

	fd = open("/dev/mem", O_RDONLY | O_SYNC);
	if (fd < 0) {
		perror("/dev/mem");
		fprintf(stderr, "Note: /dev/mem access may require root or CAP_SYS_RAWIO\n");
		return -1;
	}

	mem_size = size;
	mem = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, phys_addr);
	close(fd);

	if (mem == MAP_FAILED) {
		perror("mmap /dev/mem");
		return -1;
	}

	return 0;
}

static int validate_and_setup(void)
{
	super = mem;
	if (le32_to_cpu(super->magic) != DAXFS_SUPER_MAGIC) {
		fprintf(stderr, "Error: invalid magic 0x%x (expected 0x%x)\n",
			le32_to_cpu(super->magic), DAXFS_SUPER_MAGIC);
		munmap(mem, mem_size);
		return -1;
	}

	return 0;
}

static void close_mem(void)
{
	if (mem && mem != MAP_FAILED)
		munmap(mem, mem_size);
	if (dmabuf_fd >= 0) {
		close(dmabuf_fd);
		dmabuf_fd = -1;
	}
}

static int cmd_status(void)
{
	uint64_t total_size = le64_to_cpu(super->total_size);
	uint64_t base_offset = le64_to_cpu(super->base_offset);
	uint64_t base_size = le64_to_cpu(super->base_size);
	uint64_t overlay_offset = le64_to_cpu(super->overlay_offset);
	uint64_t overlay_size = le64_to_cpu(super->overlay_size);

	printf("DAXFS Memory Status\n");
	printf("===================\n\n");

	printf("Format:\n");
	printf("  Magic:           0x%x\n", le32_to_cpu(super->magic));
	printf("  Version:         %u\n", le32_to_cpu(super->version));
	printf("  Block size:      %u\n", le32_to_cpu(super->block_size));
	printf("  Total size:      %lu bytes (%.2f MB)\n",
	       total_size, (double)total_size / (1024 * 1024));

	if (base_offset) {
		uint32_t inode_count = le32_to_cpu(super->inode_count);
		uint32_t root_inode = le32_to_cpu(super->root_inode);

		printf("\nBase image:\n");
		printf("  Offset:          0x%lx\n", base_offset);
		printf("  Size:            %lu bytes (%.2f MB)\n",
		       base_size, (double)base_size / (1024 * 1024));
		printf("  Inode count:     %u\n", inode_count);
		printf("  Root inode:      %u\n", root_inode);
		printf("  Inode offset:    0x%lx (relative to base)\n",
		       (unsigned long)le64_to_cpu(super->inode_offset));
		printf("  Data offset:     0x%lx (relative to base)\n",
		       (unsigned long)le64_to_cpu(super->data_offset));
	} else {
		printf("\nBase image:        (none)\n");
	}

	/* Overlay region */
	if (overlay_offset) {
		uint32_t bucket_count = le32_to_cpu(super->overlay_bucket_count);

		printf("\nOverlay:\n");
		printf("  Offset:          0x%lx\n", overlay_offset);
		printf("  Size:            %lu bytes (%.2f MB)\n",
		       overlay_size, (double)overlay_size / (1024 * 1024));
		printf("  Bucket count:    %u\n", bucket_count);
		printf("  Bucket shift:    %u\n",
		       le32_to_cpu(super->overlay_bucket_shift));

		if (overlay_offset + sizeof(struct daxfs_overlay_header) <= mem_size) {
			struct daxfs_overlay_header *ohdr = mem + overlay_offset;

			if (le32_to_cpu(ohdr->magic) == DAXFS_OVERLAY_MAGIC) {
				uint64_t pool_size = le64_to_cpu(ohdr->pool_size);
				uint64_t pool_alloc = le64_to_cpu(ohdr->pool_alloc);
				uint64_t next_ino = le64_to_cpu(ohdr->next_ino);

				printf("  Pool size:       %lu bytes (%.2f MB)\n",
				       pool_size, (double)pool_size / (1024 * 1024));
				printf("  Pool allocated:  %lu bytes (%.2f MB, %.1f%%)\n",
				       pool_alloc, (double)pool_alloc / (1024 * 1024),
				       pool_size ? (double)pool_alloc * 100 / pool_size : 0);
				printf("  Next inode:      %lu\n", next_ino);
			}
		}
	} else {
		printf("\nOverlay:           (none - read-only)\n");
	}

	/* Page cache */
	uint64_t pcache_offset = le64_to_cpu(super->pcache_offset);
	if (pcache_offset) {
		uint64_t pcache_size = le64_to_cpu(super->pcache_size);
		uint32_t pcache_slots = le32_to_cpu(super->pcache_slot_count);

		printf("\nPage cache:\n");
		printf("  Offset:          0x%lx\n", pcache_offset);
		printf("  Size:            %lu bytes (%.2f MB)\n",
		       pcache_size, (double)pcache_size / (1024 * 1024));
		printf("  Slots:           %u\n", pcache_slots);
		printf("  Hash shift:      %u\n",
		       le32_to_cpu(super->pcache_hash_shift));

		if (pcache_offset + sizeof(struct daxfs_pcache_header) <= mem_size) {
			struct daxfs_pcache_header *phdr = mem + pcache_offset;

			if (le32_to_cpu(phdr->magic) == DAXFS_PCACHE_MAGIC) {
				uint32_t pending = le32_to_cpu(phdr->pending_count);
				uint64_t meta_off = le64_to_cpu(phdr->slot_meta_offset);

				printf("  Pending:         %u\n", pending);

				void *slot_base = mem + pcache_offset + meta_off;
				if (pcache_offset + meta_off +
				    (uint64_t)pcache_slots * sizeof(struct daxfs_pcache_slot) <= mem_size) {
					uint32_t free_count = 0, valid_count = 0, pending_count = 0;
					uint32_t ref_set_count = 0;

					for (uint32_t i = 0; i < pcache_slots; i++) {
						struct daxfs_pcache_slot *s = slot_base +
							i * sizeof(struct daxfs_pcache_slot);
						uint64_t st = le64_to_cpu(s->state_tag);

						switch (PCACHE_STATE(st)) {
						case PCACHE_STATE_FREE:
							free_count++;
							break;
						case PCACHE_STATE_PENDING:
							pending_count++;
							break;
						case PCACHE_STATE_VALID:
							valid_count++;
							if (le32_to_cpu(s->ref_bit))
								ref_set_count++;
							break;
						}
					}

					printf("  Slot states:     %u valid, %u free, %u pending\n",
					       valid_count, free_count, pending_count);
					if (pcache_slots > 0)
						printf("  Occupancy:       %.1f%%\n",
						       (double)valid_count * 100 / pcache_slots);

					printf("  Evict hand:      %u\n",
					       le32_to_cpu(phdr->evict_hand));
					if (valid_count > 0)
						printf("  Ref bits set:    %u / %u valid (%.1f%% hot)\n",
						       ref_set_count, valid_count,
						       (double)ref_set_count * 100 / valid_count);
					else
						printf("  Ref bits set:    0 / 0 valid\n");
				}
			}
		}
	}

	return 0;
}

static int cmd_overlay(void)
{
	uint64_t overlay_offset = le64_to_cpu(super->overlay_offset);
	struct daxfs_overlay_header *ohdr;
	uint32_t bucket_count, used_buckets = 0;
	uint32_t inode_count = 0, data_count = 0, dirent_count = 0, tombstone_count = 0;
	uint64_t bucket_offset, pool_offset, pool_size, pool_alloc, next_ino;
	void *bucket_base;

	if (!overlay_offset) {
		printf("No overlay region (read-only image)\n");
		return 0;
	}

	if (overlay_offset + sizeof(struct daxfs_overlay_header) > mem_size) {
		fprintf(stderr, "Error: overlay header out of bounds\n");
		return 1;
	}

	ohdr = mem + overlay_offset;

	if (le32_to_cpu(ohdr->magic) != DAXFS_OVERLAY_MAGIC) {
		fprintf(stderr, "Error: invalid overlay magic 0x%x (expected 0x%x)\n",
			le32_to_cpu(ohdr->magic), DAXFS_OVERLAY_MAGIC);
		return 1;
	}

	bucket_count = le32_to_cpu(super->overlay_bucket_count);
	bucket_offset = le64_to_cpu(ohdr->bucket_offset);
	pool_offset = le64_to_cpu(ohdr->pool_offset);
	pool_size = le64_to_cpu(ohdr->pool_size);
	pool_alloc = le64_to_cpu(ohdr->pool_alloc);
	next_ino = le64_to_cpu(ohdr->next_ino);

	printf("Overlay Hash Table\n");
	printf("==================\n\n");

	printf("Header:\n");
	printf("  Magic:           0x%x\n", le32_to_cpu(ohdr->magic));
	printf("  Version:         %u\n", le32_to_cpu(ohdr->version));
	printf("  Bucket count:    %u\n", bucket_count);
	printf("  Bucket shift:    %u\n",
	       le32_to_cpu(super->overlay_bucket_shift));
	printf("  Bucket offset:   0x%lx\n", bucket_offset);
	printf("  Pool offset:     0x%lx\n", pool_offset);
	printf("  Pool size:       %lu bytes (%.2f MB)\n",
	       pool_size, (double)pool_size / (1024 * 1024));
	printf("  Pool allocated:  %lu bytes (%.2f MB)\n",
	       pool_alloc, (double)pool_alloc / (1024 * 1024));
	printf("  Pool usage:      %.1f%%\n",
	       pool_size ? (double)pool_alloc * 100 / pool_size : 0);
	printf("  Next inode:      %lu\n", next_ino);

	/* Scan buckets */
	bucket_base = mem + overlay_offset + bucket_offset;
	if (overlay_offset + bucket_offset +
	    (uint64_t)bucket_count * sizeof(struct daxfs_overlay_bucket) > mem_size) {
		fprintf(stderr, "Warning: bucket array extends past memory\n");
		return 1;
	}

	for (uint32_t i = 0; i < bucket_count; i++) {
		struct daxfs_overlay_bucket *b = bucket_base +
			i * sizeof(struct daxfs_overlay_bucket);
		uint64_t state_key = le64_to_cpu(b->state_key);
		uint64_t value = le64_to_cpu(b->value);

		if (DAXFS_OVL_STATE(state_key) != DAXFS_OVL_USED)
			continue;

		used_buckets++;

		/*
		 * Classify entry. INODE/DIRLIST keys have unique
		 * sentinel pgoff values.  For other keys, read the
		 * pool entry type field: dirent/dirlist entries still
		 * have a type header; data pages (v2) do not, so any
		 * unrecognised type value means data.
		 */
		if (value < pool_alloc) {
			uint64_t key = DAXFS_OVL_KEY(state_key);
			uint64_t pgoff = DAXFS_OVL_KEY_PGOFF(key);

			if (pgoff == 0xFFFFF) {
				/* INODE sentinel */
				inode_count++;
			} else if (pgoff == 0xFFFFE) {
				/* DIRLIST sentinel */
			} else {
				/*
				 * Could be DATA or DIRENT. Check pool
				 * entry type: dirents have type header,
				 * data pages do not.
				 */
				void *entry = mem + overlay_offset +
					      pool_offset + value;
				if ((char *)entry + sizeof(uint32_t) <=
				    (char *)mem + mem_size &&
				    le32_to_cpu(*(uint32_t *)entry) ==
				    DAXFS_OVL_DIRENT) {
					struct daxfs_ovl_dirent_entry *de =
						entry;
					if (le32_to_cpu(de->flags) &
					    DAXFS_OVL_DIRENT_TOMBSTONE)
						tombstone_count++;
					else
						dirent_count++;
				} else {
					data_count++;
				}
			}
		}
	}

	printf("\nBucket utilization:\n");
	printf("  Used:            %u / %u (%.1f%%)\n",
	       used_buckets, bucket_count,
	       bucket_count ? (double)used_buckets * 100 / bucket_count : 0);
	printf("  Free:            %u\n", bucket_count - used_buckets);

	printf("\nEntry types:\n");
	printf("  Inodes:          %u\n", inode_count);
	printf("  Data pages:      %u\n", data_count);
	printf("  Dirents:         %u\n", dirent_count);
	printf("  Tombstones:      %u\n", tombstone_count);

	return 0;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <command> [options]\n", prog);
	fprintf(stderr, "\nCommands:\n");
	fprintf(stderr, "  status            Show memory layout and status\n");
	fprintf(stderr, "  overlay           Show overlay hash table details\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -m, --mount PATH  Mount point (uses ioctl, no root for dma-buf)\n");
	fprintf(stderr, "  -p, --phys ADDR   Physical memory address (via /dev/mem)\n");
	fprintf(stderr, "  -s, --size SIZE   Memory size (required with -p)\n");
	fprintf(stderr, "  -h, --help        Show this help\n");
	fprintf(stderr, "\nExamples:\n");
	fprintf(stderr, "  %s status -m /mnt/daxfs\n", prog);
	fprintf(stderr, "  %s overlay -m /mnt/daxfs\n", prog);
	fprintf(stderr, "  %s status -p 0x100000000 -s 256M\n", prog);
	fprintf(stderr, "\nNote: -m works without root for dma-buf backed mounts.\n");
	fprintf(stderr, "      -p requires root or CAP_SYS_RAWIO for /dev/mem.\n");
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"mount", required_argument, 0, 'm'},
		{"phys", required_argument, 0, 'p'},
		{"size", required_argument, 0, 's'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	char *mount_point = NULL;
	char *command = NULL;
	unsigned long long phys_addr = 0;
	size_t size = 0;
	int opt;
	int ret = 1;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	command = argv[1];
	optind = 2;

	while ((opt = getopt_long(argc, argv, "m:p:s:h", long_options, NULL)) != -1) {
		switch (opt) {
		case 'm':
			mount_point = optarg;
			break;
		case 'p':
			phys_addr = strtoull(optarg, NULL, 0);
			break;
		case 's':
			size = strtoull(optarg, NULL, 0);
			if (strchr(optarg, 'M') || strchr(optarg, 'm'))
				size *= 1024 * 1024;
			else if (strchr(optarg, 'G') || strchr(optarg, 'g'))
				size *= 1024 * 1024 * 1024;
			else if (strchr(optarg, 'K') || strchr(optarg, 'k'))
				size *= 1024;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (mount_point) {
		if (phys_addr || size) {
			fprintf(stderr, "Error: cannot use -m with -p/-s\n");
			print_usage(argv[0]);
			return 1;
		}
		if (open_mount(mount_point) < 0)
			return 1;
	} else if (phys_addr) {
		if (!size) {
			fprintf(stderr, "Error: -s/--size is required with -p/--phys\n");
			print_usage(argv[0]);
			return 1;
		}
		if (open_phys(phys_addr, size) < 0)
			return 1;
	} else {
		fprintf(stderr, "Error: -m/--mount or -p/--phys is required\n");
		print_usage(argv[0]);
		return 1;
	}

	if (validate_and_setup() < 0)
		return 1;

	if (strcmp(command, "status") == 0) {
		ret = cmd_status();
	} else if (strcmp(command, "overlay") == 0) {
		ret = cmd_overlay();
	} else if (strcmp(command, "help") == 0 || strcmp(command, "-h") == 0 ||
		   strcmp(command, "--help") == 0) {
		print_usage(argv[0]);
		ret = 0;
	} else {
		fprintf(stderr, "Error: unknown command '%s'\n", command);
		print_usage(argv[0]);
		ret = 1;
	}

	close_mem();
	return ret;
}
