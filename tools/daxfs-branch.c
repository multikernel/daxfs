// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs-branch - Branch management utility for mounted daxfs
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * Manages branches on mounted daxfs filesystems by wrapping mount operations.
 *
 * Usage:
 *   daxfs-branch list -m /mnt
 *   daxfs-branch create feature -m /mnt -p main
 *   daxfs-branch commit -m /mnt
 *   daxfs-branch abort -m /mnt
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <getopt.h>
#include <daxfs_format.h>

#define PROC_MOUNTS "/proc/mounts"

struct mount_info {
	char *mountpoint;
	char *source;
	char *fstype;
	char *options;
	/* Parsed options */
	char *branch;
	char *phys;
	char *size;
	char *dmabuf;
	char *name;
	bool writable;
};

static void free_mount_info(struct mount_info *mi)
{
	if (!mi)
		return;
	free(mi->mountpoint);
	free(mi->source);
	free(mi->fstype);
	free(mi->options);
	free(mi->branch);
	free(mi->phys);
	free(mi->size);
	free(mi->dmabuf);
	free(mi->name);
}

static char *parse_option(const char *options, const char *key)
{
	char *opts = strdup(options);
	char *token, *saveptr;
	char *result = NULL;
	size_t keylen = strlen(key);

	for (token = strtok_r(opts, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		if (strncmp(token, key, keylen) == 0 && token[keylen] == '=') {
			result = strdup(token + keylen + 1);
			break;
		}
	}

	free(opts);
	return result;
}

static bool has_option(const char *options, const char *key)
{
	char *opts = strdup(options);
	char *token, *saveptr;
	bool found = false;

	for (token = strtok_r(opts, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		if (strcmp(token, key) == 0) {
			found = true;
			break;
		}
	}

	free(opts);
	return found;
}

static int find_daxfs_mount(const char *mountpoint, struct mount_info *mi)
{
	FILE *fp;
	struct mntent *ent;
	int ret = -1;

	fp = setmntent(PROC_MOUNTS, "r");
	if (!fp) {
		perror("setmntent");
		return -1;
	}

	while ((ent = getmntent(fp)) != NULL) {
		if (strcmp(ent->mnt_type, "daxfs") != 0)
			continue;

		if (strcmp(ent->mnt_dir, mountpoint) != 0)
			continue;

		/* Found it */
		mi->mountpoint = strdup(ent->mnt_dir);
		mi->source = strdup(ent->mnt_fsname);
		mi->fstype = strdup(ent->mnt_type);
		mi->options = strdup(ent->mnt_opts);

		/* Parse interesting options */
		mi->branch = parse_option(mi->options, "branch");
		mi->phys = parse_option(mi->options, "phys");
		mi->size = parse_option(mi->options, "size");
		mi->dmabuf = parse_option(mi->options, "dmabuf");
		mi->name = parse_option(mi->options, "name");
		mi->writable = has_option(mi->options, "rw");

		ret = 0;
		break;
	}

	endmntent(fp);
	return ret;
}

static int list_daxfs_mounts(void)
{
	FILE *fp;
	struct mntent *ent;
	int count = 0;

	fp = setmntent(PROC_MOUNTS, "r");
	if (!fp) {
		perror("setmntent");
		return -1;
	}

	printf("%-20s  %-30s  %-8s  %s\n",
	       "MOUNTPOINT", "BRANCH PATH", "MODE", "BACKING");
	printf("%-20s  %-30s  %-8s  %s\n",
	       "--------------------", "------------------------------", "--------",
	       "--------------------");

	while ((ent = getmntent(fp)) != NULL) {
		if (strcmp(ent->mnt_type, "daxfs") != 0)
			continue;

		char *branch = parse_option(ent->mnt_opts, "branch");
		char *phys = parse_option(ent->mnt_opts, "phys");
		char *size = parse_option(ent->mnt_opts, "size");
		bool writable = has_option(ent->mnt_opts, "rw");

		char backing[64];
		if (phys && size)
			snprintf(backing, sizeof(backing), "phys=%s,size=%s", phys, size);
		else
			snprintf(backing, sizeof(backing), "dmabuf");

		printf("%-20s  %-30s  %-8s  %s\n",
		       ent->mnt_dir,
		       branch ? branch : "/main",
		       writable ? "rw" : "ro",
		       backing);

		free(branch);
		free(phys);
		free(size);
		count++;
	}

	endmntent(fp);

	if (count == 0)
		printf("(no daxfs mounts found)\n");

	return 0;
}

static int run_mount(char *const argv[])
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		/* Child */
		execvp("mount", argv);
		perror("execvp mount");
		_exit(127);
	}

	/* Parent */
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return -1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;

	return -1;
}

static int cmd_list(const char *mountpoint)
{
	if (mountpoint) {
		/* Show info for specific mount */
		struct mount_info mi = {0};

		if (find_daxfs_mount(mountpoint, &mi) < 0) {
			fprintf(stderr, "Error: no daxfs mount at '%s'\n", mountpoint);
			return 1;
		}

		printf("Mountpoint:  %s\n", mi.mountpoint);
		printf("Branch path: %s\n", mi.branch ? mi.branch : "/main");
		printf("Mode:        %s\n", mi.writable ? "read-write" : "read-only");
		if (mi.phys && mi.size)
			printf("Backing:     phys=%s, size=%s\n", mi.phys, mi.size);
		else
			printf("Backing:     dmabuf\n");

		free_mount_info(&mi);
		return 0;
	}

	/* List all daxfs mounts */
	return list_daxfs_mounts();
}

static int find_any_daxfs_mount(struct mount_info *mi)
{
	FILE *fp;
	struct mntent *ent;
	int ret = -1;

	fp = setmntent(PROC_MOUNTS, "r");
	if (!fp)
		return -1;

	while ((ent = getmntent(fp)) != NULL) {
		if (strcmp(ent->mnt_type, "daxfs") != 0)
			continue;

		mi->mountpoint = strdup(ent->mnt_dir);
		mi->source = strdup(ent->mnt_fsname);
		mi->fstype = strdup(ent->mnt_type);
		mi->options = strdup(ent->mnt_opts);
		mi->phys = parse_option(mi->options, "phys");
		mi->size = parse_option(mi->options, "size");
		mi->dmabuf = parse_option(mi->options, "dmabuf");
		ret = 0;
		break;
	}

	endmntent(fp);
	return ret;
}

/*
 * Get dmabuf fd from an existing daxfs mount via ioctl.
 * Returns fd on success, -1 on failure.
 */
static int get_dmabuf_fd(const char *existing_mount)
{
	int fd, dmabuf_fd;

	fd = open(existing_mount, O_RDONLY);
	if (fd < 0) {
		perror(existing_mount);
		return -1;
	}

	dmabuf_fd = ioctl(fd, DAXFS_IOC_GET_DMABUF);
	close(fd);

	return dmabuf_fd;
}

static int cmd_create(const char *mountpoint, const char *branch,
		      const char *parent)
{
	struct mount_info mi = {0};
	char options[512];
	int dmabuf_fd = -1;
	int ret;

	if (!branch) {
		fprintf(stderr, "Error: branch name required\n");
		return 1;
	}

	if (!parent) {
		fprintf(stderr, "Error: parent branch required (-p)\n");
		return 1;
	}

	if (!mountpoint) {
		fprintf(stderr, "Error: mountpoint required (-m)\n");
		return 1;
	}

	/* Find any existing daxfs mount to get backing store */
	if (find_any_daxfs_mount(&mi) < 0) {
		fprintf(stderr, "Error: no existing daxfs mount found\n");
		return 1;
	}

	printf("Creating branch '%s' from parent '%s'...\n", branch, parent);

	/* Try to get dmabuf fd from existing mount */
	dmabuf_fd = get_dmabuf_fd(mi.mountpoint);
	if (dmabuf_fd >= 0) {
		/* dmabuf-based mount */
		snprintf(options, sizeof(options), "dmabuf=%d,branch=%s,parent=%s",
			 dmabuf_fd, branch, parent);
	} else if (mi.phys && mi.size) {
		/* phys-based mount */
		snprintf(options, sizeof(options), "phys=%s,size=%s,branch=%s,parent=%s",
			 mi.phys, mi.size, branch, parent);
	} else {
		fprintf(stderr, "Error: cannot determine backing store\n");
		free_mount_info(&mi);
		return 1;
	}

	/* Note: dmabuf_fd is inherited by forked child, so fd number stays valid */
	char *argv[] = {"mount", "-t", "daxfs", "-o", options, "none",
			(char *)mountpoint, NULL};
	ret = run_mount(argv);

	if (dmabuf_fd >= 0)
		close(dmabuf_fd);

	if (ret < 0) {
		fprintf(stderr, "Error: failed to mount branch\n");
		free_mount_info(&mi);
		return 1;
	}

	printf("Branch '%s' mounted at '%s'\n", branch, mountpoint);
	free_mount_info(&mi);
	return 0;
}

static int cmd_commit(const char *mountpoint)
{
	struct mount_info mi = {0};
	int ret;

	if (find_daxfs_mount(mountpoint, &mi) < 0) {
		fprintf(stderr, "Error: no daxfs mount at '%s'\n", mountpoint);
		return 1;
	}

	if (!mi.writable) {
		fprintf(stderr, "Error: mount is read-only, cannot commit\n");
		free_mount_info(&mi);
		return 1;
	}

	/* Branch path is /main or /main/feature, check if it's just /main */
	if (!mi.branch || strcmp(mi.branch, "/main") == 0) {
		fprintf(stderr, "Error: cannot commit 'main' branch\n");
		free_mount_info(&mi);
		return 1;
	}

	printf("Committing branch chain to main...\n");

	char *argv[] = {"mount", "-o", "remount,commit", (char *)mountpoint, NULL};
	ret = run_mount(argv);
	if (ret < 0) {
		fprintf(stderr, "Error: commit failed\n");
		free_mount_info(&mi);
		return 1;
	}

	printf("Branch chain merged to main (all siblings invalidated)\n");
	free_mount_info(&mi);
	return 0;
}

static int cmd_abort(const char *mountpoint)
{
	struct mount_info mi = {0};
	int ret;

	if (find_daxfs_mount(mountpoint, &mi) < 0) {
		fprintf(stderr, "Error: no daxfs mount at '%s'\n", mountpoint);
		return 1;
	}

	/* Branch path is /main or /main/feature, check if it's just /main */
	if (!mi.branch || strcmp(mi.branch, "/main") == 0) {
		fprintf(stderr, "Error: cannot abort 'main' branch\n");
		free_mount_info(&mi);
		return 1;
	}

	printf("Aborting entire branch chain...\n");

	char *argv[] = {"mount", "-o", "remount,abort", (char *)mountpoint, NULL};
	ret = run_mount(argv);
	if (ret < 0) {
		fprintf(stderr, "Error: abort failed\n");
		free_mount_info(&mi);
		return 1;
	}

	printf("Branch chain aborted (back to main)\n");
	free_mount_info(&mi);
	return 0;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <command> [options]\n", prog);
	fprintf(stderr, "\nCommands:\n");
	fprintf(stderr, "  list              List daxfs mounts or show mount info\n");
	fprintf(stderr, "  create NAME       Create a new branch and mount it\n");
	fprintf(stderr, "  commit            Commit entire branch chain to main\n");
	fprintf(stderr, "  abort             Abort entire branch chain (discard all changes)\n");
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -m, --mount PATH  Mountpoint for the branch\n");
	fprintf(stderr, "  -p, --parent NAME Parent branch name (required for create)\n");
	fprintf(stderr, "  -h, --help        Show this help\n");
	fprintf(stderr, "\nExamples:\n");
	fprintf(stderr, "  %s list\n", prog);
	fprintf(stderr, "  %s list -m /mnt/main\n", prog);
	fprintf(stderr, "  %s create feature -m /mnt/feature -p main\n", prog);
	fprintf(stderr, "  %s commit -m /mnt/feature\n", prog);
	fprintf(stderr, "  %s abort -m /mnt/feature\n", prog);
	fprintf(stderr, "\nSpeculative execution semantics:\n");
	fprintf(stderr, "  commit  - Merges entire chain to main, invalidates all siblings\n");
	fprintf(stderr, "  abort   - Discards entire chain back to main\n");
	fprintf(stderr, "  umount  - Discards only current branch (use to backtrack one level)\n");
	fprintf(stderr, "\nNote: Use 'daxfs-inspect' to inspect raw image files.\n");
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"mount", required_argument, 0, 'm'},
		{"parent", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	char *mountpoint = NULL;
	char *parent = NULL;
	char *command = NULL;
	char *branch_name = NULL;
	int opt;
	int ret = 1;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	command = argv[1];

	/* Check if second arg is a branch name (not starting with -) */
	if (argc > 2 && argv[2][0] != '-') {
		branch_name = argv[2];
		optind = 3;
	} else {
		optind = 2;
	}

	while ((opt = getopt_long(argc, argv, "m:p:h", long_options, NULL)) != -1) {
		switch (opt) {
		case 'm':
			mountpoint = optarg;
			break;
		case 'p':
			parent = optarg;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (strcmp(command, "list") == 0) {
		ret = cmd_list(mountpoint);
	} else if (strcmp(command, "create") == 0) {
		ret = cmd_create(mountpoint, branch_name, parent);
	} else if (strcmp(command, "commit") == 0) {
		if (!mountpoint) {
			fprintf(stderr, "Error: -m/--mount is required\n");
			return 1;
		}
		ret = cmd_commit(mountpoint);
	} else if (strcmp(command, "abort") == 0) {
		if (!mountpoint) {
			fprintf(stderr, "Error: -m/--mount is required\n");
			return 1;
		}
		ret = cmd_abort(mountpoint);
	} else if (strcmp(command, "help") == 0 || strcmp(command, "-h") == 0 ||
		   strcmp(command, "--help") == 0) {
		print_usage(argv[0]);
		ret = 0;
	} else {
		fprintf(stderr, "Error: unknown command '%s'\n", command);
		print_usage(argv[0]);
		ret = 1;
	}

	return ret;
}
