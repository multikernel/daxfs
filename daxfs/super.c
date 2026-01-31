// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs superblock operations
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include "daxfs.h"

enum daxfs_param {
	Opt_phys,
	Opt_size,
	Opt_name,
	Opt_dmabuf,
	Opt_branch,
	Opt_parent,
	Opt_commit,
	Opt_abort,
	Opt_validate,
};

static const struct fs_parameter_spec daxfs_fs_parameters[] = {
	fsparam_u64("phys", Opt_phys),
	fsparam_u64("size", Opt_size),
	fsparam_string("name", Opt_name),
	fsparam_fd("dmabuf", Opt_dmabuf),
	fsparam_string("branch", Opt_branch),
	fsparam_string("parent", Opt_parent),
	fsparam_flag("commit", Opt_commit),
	fsparam_flag("abort", Opt_abort),
	fsparam_flag("validate", Opt_validate),
	{}
};

struct daxfs_fs_context {
	phys_addr_t phys_addr;
	size_t size;
	char *name;
	struct file *dmabuf_file;	/* dma-buf file from FSCONFIG_SET_FD */
	char *branch_name;		/* branch name */
	char *parent_name;		/* parent branch name */
	bool commit;			/* remount commit flag */
	bool do_abort;			/* remount abort flag */
	bool validate;			/* validate image on mount */
};

static int daxfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct daxfs_fs_context *ctx = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, daxfs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_phys:
		ctx->phys_addr = result.uint_64;
		break;
	case Opt_size:
		ctx->size = result.uint_64;
		break;
	case Opt_name:
		kfree(ctx->name);
		ctx->name = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->name)
			return -ENOMEM;
		break;
	case Opt_dmabuf:
		if (ctx->dmabuf_file)
			fput(ctx->dmabuf_file);
		ctx->dmabuf_file = get_file(param->file);
		break;
	case Opt_branch:
		kfree(ctx->branch_name);
		ctx->branch_name = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->branch_name)
			return -ENOMEM;
		break;
	case Opt_parent:
		kfree(ctx->parent_name);
		ctx->parent_name = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->parent_name)
			return -ENOMEM;
		break;
	case Opt_commit:
		ctx->commit = true;
		break;
	case Opt_abort:
		ctx->do_abort = true;
		break;
	case Opt_validate:
		ctx->validate = true;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int daxfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct daxfs_fs_context *ctx = fc->fs_private;
	struct daxfs_info *info;
	struct daxfs_branch_ctx *branch;
	struct inode *root_inode;
	u32 magic;
	int ret = -EINVAL;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	atomic_set(&info->open_files, 0);

	/* Initialize memory mapping via storage layer */
	if (ctx->dmabuf_file) {
		ret = daxfs_mem_init_dmabuf(info, ctx->dmabuf_file);
		if (ret)
			goto err_free;
	} else if (ctx->phys_addr && ctx->size) {
		ret = daxfs_mem_init_phys(info, ctx->phys_addr, ctx->size);
		if (ret)
			goto err_free;
	} else {
		pr_err("daxfs: need dmabuf fd or phys/size options\n");
		ret = -EINVAL;
		goto err_free;
	}

	/* Copy name for identification */
	if (ctx->name) {
		info->name = kstrdup(ctx->name, GFP_KERNEL);
		if (!info->name) {
			ret = -ENOMEM;
			goto err_unmap;
		}
	}

	sb->s_fs_info = info;
	info->sb = sb;
	sb->s_time_gran = 1;

	/* Validate magic */
	magic = le32_to_cpu(*((__le32 *)daxfs_mem_ptr(info, 0)));
	if (magic != DAXFS_SUPER_MAGIC) {
		pr_err("daxfs: invalid magic 0x%x (expected 0x%x)\n",
		       magic, DAXFS_SUPER_MAGIC);
		ret = -EINVAL;
		goto err_unmap;
	}

	info->super = daxfs_mem_ptr(info, 0);

	/* Validate version */
	if (le32_to_cpu(info->super->version) != DAXFS_VERSION) {
		pr_err("daxfs: unsupported version %u\n",
		       le32_to_cpu(info->super->version));
		ret = -EINVAL;
		goto err_unmap;
	}

	/* Initialize structures using storage layer */
	info->branch_table_entries =
		le32_to_cpu(info->super->branch_table_entries);

	spin_lock_init(&info->alloc_lock);
	mutex_init(&info->branch_lock);
	INIT_LIST_HEAD(&info->active_branches);

	/* Validate overall image structure bounds (if requested) */
	if (ctx->validate) {
		ret = daxfs_validate_super(info);
		if (ret)
			goto err_unmap;
	}

	/* Load base image if present */
	if (le64_to_cpu(info->super->base_offset)) {
		u64 base_off = le64_to_cpu(info->super->base_offset);

		info->base_super = daxfs_mem_ptr(info, base_off);
		info->base_inodes = daxfs_mem_ptr(info,
			base_off + le64_to_cpu(info->base_super->inode_offset));
		info->base_data_offset = base_off +
			le64_to_cpu(info->base_super->data_offset);
		info->base_inode_count =
			le32_to_cpu(info->base_super->inode_count);

		/* Validate base image structure (if requested) */
		if (ctx->validate) {
			ret = daxfs_validate_base_image(info);
			if (ret)
				goto err_unmap;
		}
	}

	sb->s_op = &daxfs_super_ops;
	sb->s_magic = DAXFS_SUPER_MAGIC;

	/*
	 * Static image (no branch table) - read-only, no branching
	 */
	if (info->branch_table_entries == 0) {
		sb->s_flags |= SB_RDONLY;
		info->static_image = true;
		info->current_branch = NULL;

		pr_info("daxfs: mounted static image read-only\n");
		goto get_root;
	}

	/* Initialize branch table and delta region pointers */
	info->branch_table = daxfs_mem_ptr(info,
		le64_to_cpu(info->super->branch_table_offset));
	info->delta_alloc_offset =
		le64_to_cpu(info->super->delta_alloc_offset);

	/* Initialize coordination pointer (embedded in superblock) */
	info->coord = &info->super->coord;

	/* First mount initializes coordination */
	if (le64_to_cpu(info->coord->commit_sequence) == 0)
		info->coord->commit_sequence = cpu_to_le64(1);

	info->cached_commit_seq = le64_to_cpu(info->coord->commit_sequence);

	/* Initialize or find branch */
	if (ctx->branch_name && ctx->parent_name) {
		/* Create new named branch - writable */
		ret = daxfs_branch_create(info, ctx->branch_name,
					  ctx->parent_name, &branch);
		if (ret)
			goto err_unmap;
	} else if (ctx->branch_name) {
		/* Mount existing branch (loads from on-DAX if needed) */
		branch = daxfs_load_branch(info, ctx->branch_name);
		if (!branch) {
			pr_err("daxfs: branch '%s' not found\n",
			       ctx->branch_name);
			ret = -ENOENT;
			goto err_unmap;
		}
		if (IS_ERR(branch)) {
			ret = PTR_ERR(branch);
			goto err_unmap;
		}
	} else {
		/* Default: mount "main" branch (read-only) */
		ret = daxfs_init_main_branch(info);
		if (ret)
			goto err_unmap;
		branch = daxfs_find_branch_by_name(info, "main");
		if (!branch) {
			ret = -EINVAL;
			goto err_unmap;
		}
		atomic_inc(&branch->refcount);
	}

	/*
	 * Main branch is always read-only. Only child branches
	 * (created with branch=name,parent=...) are writable.
	 */
	if (!branch->parent)
		sb->s_flags |= SB_RDONLY;

	info->current_branch = branch;

	/* Build delta index for current branch chain */
	ret = daxfs_delta_build_index(branch);
	if (ret)
		goto err_branch;

get_root:
	/* Get root inode */
	root_inode = daxfs_iget(sb, DAXFS_ROOT_INO);
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		goto err_branch;
	}

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto err_branch;
	}

	if (branch)
		pr_info("daxfs: mounted branch '%s' (id=%llu) %s\n",
			branch->name, branch->branch_id,
			(sb->s_flags & SB_RDONLY) ? "read-only" : "read-write");

	return 0;

err_branch:
	if (branch) {
		if (ctx->branch_name && ctx->parent_name)
			daxfs_branch_abort(info, branch);
		else
			atomic_dec(&branch->refcount);
	}
err_unmap:
	daxfs_mem_exit(info);
	kfree(info->name);
err_free:
	sb->s_fs_info = NULL;
	kfree(info);
	return ret;
}

static int daxfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, daxfs_fill_super);
}

static void daxfs_free_fc(struct fs_context *fc)
{
	struct daxfs_fs_context *ctx = fc->fs_private;

	if (ctx) {
		if (ctx->dmabuf_file)
			fput(ctx->dmabuf_file);
		kfree(ctx->name);
		kfree(ctx->branch_name);
		kfree(ctx->parent_name);
		kfree(ctx);
	}
}

static int daxfs_reconfigure(struct fs_context *fc)
{
	struct daxfs_fs_context *ctx = fc->fs_private;
	struct super_block *sb = fc->root->d_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	int ret = 0;

	if (ctx->commit) {
		/* Commit current branch to parent and switch to main */
		struct daxfs_branch_ctx *branch = info->current_branch;
		struct daxfs_branch_ctx *main_branch;

		if (!branch->parent) {
			pr_err("daxfs: cannot commit main branch\n");
			return -EINVAL;
		}

		main_branch = daxfs_find_branch_by_name(info, "main");
		if (!main_branch) {
			pr_err("daxfs: main branch not found\n");
			return -EINVAL;
		}

		/* Sync all dirty pages before commit */
		sync_filesystem(sb);

		ret = daxfs_branch_commit(info, branch);
		if (ret) {
			pr_err("daxfs: commit failed: %d\n", ret);
		} else {
			/* Switch to main after successful commit */
			atomic_inc(&main_branch->refcount);
			info->current_branch = main_branch;
			pr_info("daxfs: committed and switched to main branch\n");
		}
	} else if (ctx->do_abort) {
		/* Abort current branch (discard changes) and switch to main */
		struct daxfs_branch_ctx *branch = info->current_branch;
		struct daxfs_branch_ctx *main_branch;

		if (!branch->parent) {
			pr_err("daxfs: cannot abort main branch\n");
			return -EINVAL;
		}

		main_branch = daxfs_find_branch_by_name(info, "main");
		if (!main_branch) {
			pr_err("daxfs: main branch not found\n");
			return -EINVAL;
		}

		/*
		 * Sync dirty pages before abort. Note: these writes go to
		 * the current branch which we're about to discard. This
		 * ensures the page cache is clean before we switch branches.
		 */
		sync_filesystem(sb);

		/* Switch to main first */
		atomic_inc(&main_branch->refcount);
		info->current_branch = main_branch;

		/*
		 * Invalidate page cache - cached data is from the old branch.
		 * Since EBUSY check passed, no files are open, so all inodes
		 * can be evicted along with their cached pages.
		 */
		shrink_dcache_sb(sb);
		evict_inodes(sb);

		/* Now abort the old branch */
		ret = daxfs_branch_abort(info, branch);
		if (ret)
			pr_err("daxfs: abort failed: %d\n", ret);
		else
			pr_info("daxfs: aborted and switched to main branch\n");
	}

	return ret;
}

static const struct fs_context_operations daxfs_context_ops = {
	.parse_param	= daxfs_parse_param,
	.get_tree	= daxfs_get_tree,
	.reconfigure	= daxfs_reconfigure,
	.free		= daxfs_free_fc,
};

static int daxfs_init_fs_context(struct fs_context *fc)
{
	struct daxfs_fs_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	fc->fs_private = ctx;
	fc->ops = &daxfs_context_ops;
	return 0;
}

static void daxfs_kill_sb(struct super_block *sb)
{
	struct daxfs_info *info = DAXFS_SB(sb);

	/*
	 * If this is a non-main branch and it wasn't committed,
	 * abort it (discard changes). This is the default umount behavior.
	 */
	if (info && info->current_branch) {
		struct daxfs_branch_ctx *branch = info->current_branch;

		if (strcmp(branch->name, "main") != 0 && !branch->committed) {
			pr_info("daxfs: aborting branch '%s' on umount\n",
				branch->name);
			daxfs_branch_abort_single(info, branch);
		} else {
			/* Just decrement refcount for main or committed */
			atomic_dec(&branch->refcount);
		}
		info->current_branch = NULL;
	}

	kill_anon_super(sb);

	if (info) {
		daxfs_mem_exit(info);
		kfree(info->name);
		kfree(info);
	}
}

static int daxfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct daxfs_info *info = DAXFS_SB(dentry->d_sb);

	buf->f_type = DAXFS_SUPER_MAGIC;
	buf->f_bsize = DAXFS_BLOCK_SIZE;
	buf->f_blocks = info->size / DAXFS_BLOCK_SIZE;

	if (info->static_image) {
		/* Static image is read-only, no free space */
		buf->f_bfree = 0;
		buf->f_bavail = 0;
		buf->f_files = info->base_inode_count;
		buf->f_ffree = 0;
	} else {
		u64 delta_used = info->delta_alloc_offset -
			le64_to_cpu(info->super->delta_region_offset);
		u64 delta_total = le64_to_cpu(info->super->delta_region_size);

		buf->f_bfree = (delta_total - delta_used) / DAXFS_BLOCK_SIZE;
		buf->f_bavail = buf->f_bfree;
		buf->f_files = le64_to_cpu(info->super->next_inode_id);
		buf->f_ffree = UINT_MAX;	/* Effectively unlimited */
	}
	buf->f_namelen = 255;
	return 0;
}

static void daxfs_show_branch_path(struct seq_file *m,
				   struct daxfs_branch_ctx *branch)
{
	if (branch->parent)
		daxfs_show_branch_path(m, branch->parent);
	seq_printf(m, "/%s", branch->name);
}

static int daxfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct daxfs_info *info = DAXFS_SB(root->d_sb);

	if (info->name)
		seq_printf(m, ",name=%s", info->name);
	if (info->dmabuf)
		seq_puts(m, ",source=dmabuf");
	else
		seq_printf(m, ",phys=0x%llx", (unsigned long long)info->phys_addr);
	seq_printf(m, ",size=%zu", info->size);
	if (info->static_image) {
		seq_puts(m, ",static");
	} else if (info->current_branch) {
		seq_puts(m, ",branch=");
		daxfs_show_branch_path(m, info->current_branch);
	}
	return 0;
}

const struct super_operations daxfs_super_ops = {
	.alloc_inode	= daxfs_alloc_inode,
	.free_inode	= daxfs_free_inode,
	.statfs		= daxfs_statfs,
	.show_options	= daxfs_show_options,
};

static struct file_system_type daxfs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "daxfs",
	.init_fs_context	= daxfs_init_fs_context,
	.parameters		= daxfs_fs_parameters,
	.kill_sb		= daxfs_kill_sb,
};

static int __init daxfs_init(void)
{
	int err;

	err = daxfs_inode_cache_init();
	if (err)
		return err;

	err = register_filesystem(&daxfs_fs_type);
	if (err) {
		daxfs_inode_cache_destroy();
		return err;
	}

	return 0;
}

static void __exit daxfs_exit(void)
{
	unregister_filesystem(&daxfs_fs_type);
	daxfs_inode_cache_destroy();
}

module_init(daxfs_init);
module_exit(daxfs_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cong Wang <cwang@multikernel.io>");
MODULE_DESCRIPTION("DAX-based filesystem for shared memory");
MODULE_IMPORT_NS("DMA_BUF");
