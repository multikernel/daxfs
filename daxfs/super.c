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
	Opt_validate,
	Opt_backing,
	Opt_export,
};

static const struct fs_parameter_spec daxfs_fs_parameters[] = {
	fsparam_u64("phys", Opt_phys),
	fsparam_u64("size", Opt_size),
	fsparam_string("name", Opt_name),
	fsparam_fd("dmabuf", Opt_dmabuf),
	fsparam_flag("validate", Opt_validate),
	fsparam_string("backing", Opt_backing),
	fsparam_string("export", Opt_export),
	{}
};

struct daxfs_fs_context {
	phys_addr_t phys_addr;
	size_t size;
	char *name;
	struct file *dmabuf_file;	/* dma-buf file from FSCONFIG_SET_FD */
	char *backing_path;		/* backing file path for pcache */
	char *export_path;		/* directory to export into namespace */
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
	case Opt_validate:
		ctx->validate = true;
		break;
	case Opt_backing:
		kfree(ctx->backing_path);
		ctx->backing_path = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->backing_path)
			return -ENOMEM;
		break;
	case Opt_export:
		kfree(ctx->export_path);
		ctx->export_path = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->export_path)
			return -ENOMEM;
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
	struct inode *root_inode;
	u32 magic;
	int ret = -EINVAL;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

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

	if (ctx->backing_path && ctx->export_path) {
		pr_err("daxfs: 'backing' and 'export' are mutually exclusive\n");
		ret = -EINVAL;
		goto err_unmap;
	}

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
		pr_err("daxfs: unsupported version %u (expected %u)\n",
		       le32_to_cpu(info->super->version), DAXFS_VERSION);
		ret = -EINVAL;
		goto err_unmap;
	}

	/* Validate block_size matches native page size */
	info->block_size = le32_to_cpu(info->super->block_size);
	if (info->block_size != PAGE_SIZE) {
		pr_err("daxfs: block_size %u does not match PAGE_SIZE %lu\n",
		       info->block_size, PAGE_SIZE);
		ret = -EINVAL;
		goto err_unmap;
	}

	/* Validate overall image structure bounds (if requested) */
	if (ctx->validate) {
		ret = daxfs_validate_super(info);
		if (ret)
			goto err_unmap;
	}

	/* Load base image if present */
	if (le64_to_cpu(info->super->base_offset)) {
		u64 base_off = le64_to_cpu(info->super->base_offset);
		struct daxfs_super *s = info->super;

		info->base_inodes = daxfs_mem_ptr(info,
			base_off + le64_to_cpu(s->inode_offset));
		info->base_data_offset = base_off +
			le64_to_cpu(s->data_offset);
		info->base_inode_count = le32_to_cpu(s->inode_count);

		/* Validate base image structure (if requested) */
		if (ctx->validate) {
			ret = daxfs_validate_base_image(info);
			if (ret)
				goto err_unmap;
		}
	}

	/* Validate export prerequisites */
	if (ctx->export_path) {
		if (!le64_to_cpu(info->super->pcache_offset)) {
			pr_err("daxfs: 'export' requires a pcache region\n");
			ret = -EINVAL;
			goto err_unmap;
		}
		if (!le64_to_cpu(info->super->base_offset)) {
			pr_err("daxfs: 'export' requires a base image\n");
			ret = -EINVAL;
			goto err_unmap;
		}
	}

	/* Initialize page cache if present */
	if (le64_to_cpu(info->super->pcache_offset)) {
		if (ctx->export_path) {
			ret = daxfs_pcache_init(info, NULL);
			if (ret)
				goto err_unmap;
			ret = daxfs_pcache_init_export(info, ctx->export_path);
			if (ret)
				goto err_pcache;
			info->export_mode = true;
		} else {
			ret = daxfs_pcache_init(info, ctx->backing_path);
			if (ret)
				goto err_unmap;
		}
	}

	/* Initialize overlay if present */
	if (le64_to_cpu(info->super->overlay_offset)) {
		ret = daxfs_overlay_init(info);
		if (ret)
			goto err_pcache;
	}

	sb->s_op = &daxfs_super_ops;
	sb->s_magic = DAXFS_SUPER_MAGIC;

	/* Read-only unless overlay is present */
	if (!info->overlay)
		sb->s_flags |= SB_RDONLY;

	/* Get root inode */
	root_inode = daxfs_iget(sb, DAXFS_ROOT_INO);
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		goto err_overlay;
	}

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto err_overlay;
	}

	pr_info("daxfs: mounted %s\n",
		info->overlay ? "read-write (overlay)" : "read-only");

	return 0;

err_overlay:
	daxfs_overlay_exit(info);
err_pcache:
	daxfs_pcache_exit(info);
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
		kfree(ctx->backing_path);
		kfree(ctx->export_path);
		kfree(ctx);
	}
}

static const struct fs_context_operations daxfs_context_ops = {
	.parse_param	= daxfs_parse_param,
	.get_tree	= daxfs_get_tree,
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

	kill_anon_super(sb);

	if (info) {
		daxfs_overlay_exit(info);
		daxfs_pcache_exit(info);
		daxfs_mem_exit(info);
		kfree(info->name);
		kfree(info);
	}
}

static int daxfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct daxfs_info *info = DAXFS_SB(dentry->d_sb);

	buf->f_type = DAXFS_SUPER_MAGIC;
	buf->f_bsize = info->block_size;
	buf->f_blocks = info->size / info->block_size;
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_files = info->base_inode_count;
	buf->f_ffree = 0;

	if (info->overlay) {
		/* Estimate free space from overlay pool */
		struct daxfs_overlay *ovl = info->overlay;
		u64 pool_used = le64_to_cpu(ovl->header->pool_alloc);
		u64 pool_size = le64_to_cpu(ovl->header->pool_size);

		if (pool_size > pool_used) {
			buf->f_bfree = (pool_size - pool_used) / info->block_size;
			buf->f_bavail = buf->f_bfree;
		}
		buf->f_ffree = UINT_MAX;
	}

	buf->f_namelen = 255;
	return 0;
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
	if (info->overlay)
		seq_puts(m, ",overlay");
	if (info->export_mode)
		seq_puts(m, ",export");
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
