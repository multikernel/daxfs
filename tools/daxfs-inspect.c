// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs-inspect - Inspection utility for daxfs
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * Read-only inspection of daxfs via physical memory (/dev/mem).
 * Can parse mount point to automatically get phys/size from mountinfo.
 *
 * Usage:
 *   daxfs-inspect list -m /mnt/daxfs
 *   daxfs-inspect list -p 0x100000000 -s 256M
 *   daxfs-inspect info -m /mnt/daxfs -b main
 *   daxfs-inspect status -m /mnt/daxfs
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
static int dmabuf_fd = -1;  /* Keep dma-buf fd open until munmap */
static struct daxfs_super *super;
static struct daxfs_branch *branch_table;

static const char *state_to_string(uint32_t state)
{
	switch (state) {
	case DAXFS_BRANCH_FREE:
		return "free";
	case DAXFS_BRANCH_ACTIVE:
		return "active";
	case DAXFS_BRANCH_COMMITTED:
		return "committed";
	case DAXFS_BRANCH_ABORTED:
		return "aborted";
	default:
		return "unknown";
	}
}

static struct daxfs_branch *find_branch_by_name(const char *name)
{
	uint32_t count = le32_to_cpu(super->branch_table_entries);

	for (uint32_t i = 0; i < count; i++) {
		struct daxfs_branch *b = &branch_table[i];
		uint32_t state = le32_to_cpu(b->state);

		if (state != DAXFS_BRANCH_FREE &&
		    strncmp(b->name, name, sizeof(b->name)) == 0)
			return b;
	}
	return NULL;
}

static struct daxfs_branch *find_branch_by_id(uint64_t id)
{
	uint32_t count = le32_to_cpu(super->branch_table_entries);

	for (uint32_t i = 0; i < count; i++) {
		struct daxfs_branch *b = &branch_table[i];
		uint32_t state = le32_to_cpu(b->state);

		if (state != DAXFS_BRANCH_FREE &&
		    le64_to_cpu(b->branch_id) == id)
			return b;
	}
	return NULL;
}

/*
 * Get size from /proc/self/mountinfo for a daxfs mount.
 * Returns 0 on success, -1 on failure.
 */
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

/*
 * Open memory via mount point.
 * First tries ioctl to get dma-buf fd (no root needed for dma-buf mounts).
 * Returns 0 on success, -1 on failure.
 */
static int open_mount(const char *mount_point)
{
	int fd;
	size_t size;

	/* Get size from mountinfo */
	if (get_mount_size(mount_point, &size) < 0)
		return -1;

	/* Open mount point and try ioctl */
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

	/* mmap the dma-buf - keep fd open until munmap */
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

	branch_table = mem + le64_to_cpu(super->branch_table_offset);
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

static int cmd_list(void)
{
	uint32_t count = le32_to_cpu(super->branch_table_entries);
	uint32_t active = 0;

	printf("%-4s  %-20s  %-10s  %-10s  %-8s  %-6s  %-12s  %s\n",
	       "ID", "NAME", "STATE", "PARENT", "REFCNT", "GEN", "DELTA_USED", "DELTA_CAP");
	printf("%-4s  %-20s  %-10s  %-10s  %-8s  %-6s  %-12s  %s\n",
	       "----", "--------------------", "----------", "----------",
	       "--------", "------", "------------", "------------");

	for (uint32_t i = 0; i < count; i++) {
		struct daxfs_branch *b = &branch_table[i];
		uint32_t state = le32_to_cpu(b->state);

		if (state == DAXFS_BRANCH_FREE)
			continue;

		active++;

		uint64_t id = le64_to_cpu(b->branch_id);
		uint64_t parent_id = le64_to_cpu(b->parent_id);
		uint32_t refcount = le32_to_cpu(b->refcount);
		uint32_t generation = le32_to_cpu(b->generation);
		uint64_t delta_used = le64_to_cpu(b->delta_log_size);
		uint64_t delta_cap = le64_to_cpu(b->delta_log_capacity);

		char parent_str[32];
		if (parent_id == 0) {
			snprintf(parent_str, sizeof(parent_str), "-");
		} else {
			struct daxfs_branch *p = find_branch_by_id(parent_id);
			if (p)
				snprintf(parent_str, sizeof(parent_str), "%s", p->name);
			else
				snprintf(parent_str, sizeof(parent_str), "id:%lu", parent_id);
		}

		printf("%-4lu  %-20s  %-10s  %-10s  %-8u  %-6u  %-12lu  %lu\n",
		       id, b->name, state_to_string(state), parent_str,
		       refcount, generation, delta_used, delta_cap);
	}

	printf("\nTotal: %u branches, %u slots available\n",
	       active, count - active);

	return 0;
}

static int cmd_info(const char *name)
{
	struct daxfs_branch *b = find_branch_by_name(name);
	if (!b) {
		fprintf(stderr, "Error: branch '%s' not found\n", name);
		return 1;
	}

	uint64_t id = le64_to_cpu(b->branch_id);
	uint64_t parent_id = le64_to_cpu(b->parent_id);
	uint32_t state = le32_to_cpu(b->state);
	uint32_t refcount = le32_to_cpu(b->refcount);
	uint32_t generation = le32_to_cpu(b->generation);
	uint64_t delta_offset = le64_to_cpu(b->delta_log_offset);
	uint64_t delta_used = le64_to_cpu(b->delta_log_size);
	uint64_t delta_cap = le64_to_cpu(b->delta_log_capacity);
	uint64_t next_ino = le64_to_cpu(b->next_local_ino);

	printf("Branch: %s\n", b->name);
	printf("  ID:              %lu\n", id);
	printf("  State:           %s\n", state_to_string(state));
	printf("  Generation:      %u\n", generation);

	if (parent_id == 0) {
		printf("  Parent:          (none - root branch)\n");
	} else {
		struct daxfs_branch *p = find_branch_by_id(parent_id);
		if (p)
			printf("  Parent:          %s (id:%lu)\n", p->name, parent_id);
		else
			printf("  Parent:          id:%lu (not found)\n", parent_id);
	}

	printf("  Reference count: %u\n", refcount);
	printf("  Next inode:      %lu\n", next_ino);
	printf("  Delta log:\n");
	printf("    Offset:        0x%lx\n", delta_offset);
	printf("    Used:          %lu bytes (%.2f KB)\n",
	       delta_used, (double)delta_used / 1024);
	printf("    Capacity:      %lu bytes (%.2f KB)\n",
	       delta_cap, (double)delta_cap / 1024);
	printf("    Usage:         %.1f%%\n",
	       delta_cap ? (double)delta_used * 100 / delta_cap : 0);

	/* Count delta entries */
	if (delta_used > 0) {
		void *delta_log = mem + delta_offset;
		uint64_t offset = 0;
		uint32_t entry_counts[9] = {0};

		while (offset < delta_used) {
			struct daxfs_delta_hdr *hdr = delta_log + offset;
			uint32_t type = le32_to_cpu(hdr->type);
			uint32_t size = le32_to_cpu(hdr->total_size);

			if (size == 0 || offset + size > delta_used)
				break;

			if (type < 9)
				entry_counts[type]++;

			offset += size;
		}

		printf("  Delta entries:\n");
		if (entry_counts[DAXFS_DELTA_WRITE])
			printf("    WRITE:     %u\n", entry_counts[DAXFS_DELTA_WRITE]);
		if (entry_counts[DAXFS_DELTA_CREATE])
			printf("    CREATE:    %u\n", entry_counts[DAXFS_DELTA_CREATE]);
		if (entry_counts[DAXFS_DELTA_DELETE])
			printf("    DELETE:    %u\n", entry_counts[DAXFS_DELTA_DELETE]);
		if (entry_counts[DAXFS_DELTA_TRUNCATE])
			printf("    TRUNCATE:  %u\n", entry_counts[DAXFS_DELTA_TRUNCATE]);
		if (entry_counts[DAXFS_DELTA_MKDIR])
			printf("    MKDIR:     %u\n", entry_counts[DAXFS_DELTA_MKDIR]);
		if (entry_counts[DAXFS_DELTA_RENAME])
			printf("    RENAME:    %u\n", entry_counts[DAXFS_DELTA_RENAME]);
		if (entry_counts[DAXFS_DELTA_SETATTR])
			printf("    SETATTR:   %u\n", entry_counts[DAXFS_DELTA_SETATTR]);
		if (entry_counts[DAXFS_DELTA_SYMLINK])
			printf("    SYMLINK:   %u\n", entry_counts[DAXFS_DELTA_SYMLINK]);
	}

	return 0;
}

static int cmd_status(void)
{
	uint64_t total_size = le64_to_cpu(super->total_size);
	uint64_t base_offset = le64_to_cpu(super->base_offset);
	uint64_t base_size = le64_to_cpu(super->base_size);
	uint64_t delta_region_offset = le64_to_cpu(super->delta_region_offset);
	uint64_t delta_region_size = le64_to_cpu(super->delta_region_size);
	uint64_t delta_alloc = le64_to_cpu(super->delta_alloc_offset);
	uint32_t branch_entries = le32_to_cpu(super->branch_table_entries);
	uint32_t active_branches = le32_to_cpu(super->active_branches);
	uint64_t next_inode = le64_to_cpu(super->next_inode_id);
	uint64_t next_branch = le64_to_cpu(super->next_branch_id);
	uint64_t commit_seq = le64_to_cpu(super->coord.commit_sequence);
	uint64_t last_committed = le64_to_cpu(super->coord.last_committed_id);

	printf("DAXFS Memory Status\n");
	printf("===================\n\n");

	printf("Format:\n");
	printf("  Magic:           0x%x\n", le32_to_cpu(super->magic));
	printf("  Version:         %u\n", le32_to_cpu(super->version));
	printf("  Block size:      %u\n", le32_to_cpu(super->block_size));
	printf("  Total size:      %lu bytes (%.2f MB)\n",
	       total_size, (double)total_size / (1024 * 1024));

	printf("\nBase image:\n");
	printf("  Offset:          0x%lx\n", base_offset);
	printf("  Size:            %lu bytes (%.2f MB)\n",
	       base_size, (double)base_size / (1024 * 1024));

	printf("\nBranch table:\n");
	printf("  Entries:         %u (max)\n", branch_entries);
	printf("  Active:          %u\n", active_branches);
	printf("  Next branch ID:  %lu\n", next_branch);

	printf("\nGlobal coordination:\n");
	printf("  Commit sequence: %lu\n", commit_seq);
	if (last_committed > 0) {
		struct daxfs_branch *b = find_branch_by_id(last_committed);
		if (b)
			printf("  Last committed:  %s (id:%lu)\n", b->name, last_committed);
		else
			printf("  Last committed:  id:%lu\n", last_committed);
	} else {
		printf("  Last committed:  (none)\n");
	}

	printf("\nDelta region:\n");
	printf("  Offset:          0x%lx\n", delta_region_offset);
	printf("  Total size:      %lu bytes (%.2f MB)\n",
	       delta_region_size, (double)delta_region_size / (1024 * 1024));
	printf("  Allocated:       %lu bytes (%.2f MB)\n",
	       delta_alloc - delta_region_offset,
	       (double)(delta_alloc - delta_region_offset) / (1024 * 1024));
	printf("  Free:            %lu bytes (%.2f MB)\n",
	       delta_region_offset + delta_region_size - delta_alloc,
	       (double)(delta_region_offset + delta_region_size - delta_alloc) / (1024 * 1024));

	printf("\nInodes:\n");
	printf("  Next inode ID:   %lu\n", next_inode);

	/* Page cache (backing store mode) */
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

		/* Read on-DAX pcache header for live stats */
		if (pcache_offset + sizeof(struct daxfs_pcache_header) <= mem_size) {
			struct daxfs_pcache_header *phdr = mem + pcache_offset;

			if (le32_to_cpu(phdr->magic) == DAXFS_PCACHE_MAGIC) {
				uint32_t pending = le32_to_cpu(phdr->pending_count);
				uint32_t hdr_slots = le32_to_cpu(phdr->slot_count);
				uint64_t meta_off = le64_to_cpu(phdr->slot_meta_offset);

				printf("  Pending:         %u\n", pending);

				/* Scan slot metadata for utilization */
				void *slot_base = mem + pcache_offset + meta_off;
				if (pcache_offset + meta_off +
				    (uint64_t)hdr_slots * sizeof(struct daxfs_pcache_slot) <= mem_size) {
					uint32_t free_count = 0, valid_count = 0, pending_count = 0;

					for (uint32_t i = 0; i < hdr_slots; i++) {
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
							break;
						}
					}

					printf("  Slot states:     %u valid, %u free, %u pending\n",
					       valid_count, free_count, pending_count);
					if (hdr_slots > 0)
						printf("  Occupancy:       %.1f%%\n",
						       (double)valid_count * 100 / hdr_slots);
				}
			}
		}
	}

	return 0;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <command> [options]\n", prog);
	fprintf(stderr, "\nCommands:\n");
	fprintf(stderr, "  list              List all branches\n");
	fprintf(stderr, "  info              Show branch details\n");
	fprintf(stderr, "  status            Show memory status\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -m, --mount PATH  Mount point (uses ioctl, no root for dma-buf)\n");
	fprintf(stderr, "  -p, --phys ADDR   Physical memory address (via /dev/mem)\n");
	fprintf(stderr, "  -s, --size SIZE   Memory size (required with -p)\n");
	fprintf(stderr, "  -b, --branch NAME Branch name (for info command)\n");
	fprintf(stderr, "  -h, --help        Show this help\n");
	fprintf(stderr, "\nExamples:\n");
	fprintf(stderr, "  %s list -m /mnt/daxfs\n", prog);
	fprintf(stderr, "  %s status -m /mnt/daxfs\n", prog);
	fprintf(stderr, "  %s info -m /mnt/daxfs -b main\n", prog);
	fprintf(stderr, "  %s list -p 0x100000000 -s 256M\n", prog);
	fprintf(stderr, "\nNote: -m works without root for dma-buf backed mounts.\n");
	fprintf(stderr, "      -p requires root or CAP_SYS_RAWIO for /dev/mem.\n");
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"mount", required_argument, 0, 'm'},
		{"phys", required_argument, 0, 'p'},
		{"size", required_argument, 0, 's'},
		{"branch", required_argument, 0, 'b'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	char *mount_point = NULL;
	char *branch_name = NULL;
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
	optind = 2;  /* Start parsing after command */

	while ((opt = getopt_long(argc, argv, "m:p:s:b:h", long_options, NULL)) != -1) {
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
		case 'b':
			branch_name = optarg;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	/* Handle mount point option - use ioctl to get dma-buf */
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

	if (strcmp(command, "list") == 0) {
		ret = cmd_list();
	} else if (strcmp(command, "info") == 0) {
		if (!branch_name) {
			fprintf(stderr, "Error: -b/--branch is required for info\n");
			ret = 1;
		} else {
			ret = cmd_info(branch_name);
		}
	} else if (strcmp(command, "status") == 0) {
		ret = cmd_status();
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
