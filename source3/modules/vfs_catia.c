/*
 * Catia VFS module
 *
 * Implement a fixed mapping of forbidden NT characters in filenames that are
 * used a lot by the CAD package Catia.
 *
 * Catia V4 on AIX uses characters like "<*$ a *lot*, all forbidden under
 * Windows...
 *
 * Copyright (C) Volker Lendecke, 2005
 * Copyright (C) Aravind Srinivasan, 2009
 * Copyright (C) Guenter Kukkukk, 2013
 * Copyright (C) Ralph Boehme, 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "includes.h"
#include "smbd/smbd.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"
#include "string_replace.h"

static int vfs_catia_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_catia_debug_level

struct share_mapping_entry {
	int snum;
	struct share_mapping_entry *next;
	struct char_mappings **mappings;
};

struct catia_cache {
	bool is_fsp_ext;
	const struct catia_cache * const *busy;
	char *orig_fname;
	char *fname;
	char *orig_base_fname;
	char *base_fname;
};

static struct share_mapping_entry *srt_head = NULL;

static struct share_mapping_entry *get_srt(connection_struct *conn,
					   struct share_mapping_entry **global)
{
	struct share_mapping_entry *share;

	for (share = srt_head; share != NULL; share = share->next) {
		if (share->snum == GLOBAL_SECTION_SNUM)
			(*global) = share;

		if (share->snum == SNUM(conn))
			return share;
	}

	return share;
}

static struct share_mapping_entry *add_srt(int snum, const char **mappings)
{
	struct share_mapping_entry *sme = NULL;

	sme = talloc_zero(NULL, struct share_mapping_entry);
	if (sme == NULL)
		return sme;

	sme->snum = snum;
	sme->next = srt_head;
	srt_head = sme;

	if (mappings == NULL) {
		sme->mappings = NULL;
		return sme;
	}

	sme->mappings = string_replace_init_map(sme, mappings);

	return sme;
}

static bool init_mappings(connection_struct *conn,
			  struct share_mapping_entry **selected_out)
{
	const char **mappings = NULL;
	struct share_mapping_entry *share_level = NULL;
	struct share_mapping_entry *global = NULL;

	/* check srt cache */
	share_level = get_srt(conn, &global);
	if (share_level) {
		*selected_out = share_level;
		return (share_level->mappings != NULL);
	}

	/* see if we have a global setting */
	if (!global) {
		/* global setting */
		mappings = lp_parm_string_list(-1, "catia", "mappings", NULL);
		global = add_srt(GLOBAL_SECTION_SNUM, mappings);
	}

	/* no global setting - what about share level ? */
	mappings = lp_parm_string_list(SNUM(conn), "catia", "mappings", NULL);
	share_level = add_srt(SNUM(conn), mappings);

	if (share_level->mappings) {
		(*selected_out) = share_level;
		return True;
	}
	if (global->mappings) {
		share_level->mappings = global->mappings;
		(*selected_out) = share_level;
		return True;
	}

	return False;
}

static int catia_string_replace_allocate(
	connection_struct *conn,
	const char *name_in,
	char **mapped_name,
	enum vfs_translate_direction direction)
{
	struct share_mapping_entry *selected;
	int ret;

	if (!init_mappings(conn, &selected)) {
		/* No mappings found. Just use the old name */
		*mapped_name = talloc_strdup(talloc_tos(), name_in);
		if (!*mapped_name) {
			return ENOMEM;
		}
		return 0;
	}

	ret = string_replace_allocate(conn,
				      name_in,
				      selected->mappings,
				      talloc_tos(),
				      mapped_name,
				      direction);
	return ret;
}

static int catia_connect(struct vfs_handle_struct *handle,
			 const char *service,
			 const char *user)
{
	/*
	 * Unless we have an async implementation of get_dos_attributes turn
	 * this off.
	 */
	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");

	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

/*
 * TRANSLATE_NAME call which converts the given name to
 * "WINDOWS displayable" name
 */
static NTSTATUS catia_translate_name(struct vfs_handle_struct *handle,
				     const char *orig_name,
				     enum vfs_translate_direction direction,
				     TALLOC_CTX *mem_ctx,
				     char **pmapped_name)
{
	char *name = NULL;
	char *mapped_name;
	NTSTATUS ret;
	int rc;

	/*
	 * Copy the supplied name and free the memory for mapped_name,
	 * already allocated by the caller.
	 * We will be allocating new memory for mapped_name in
	 * catia_string_replace_allocate
	 */
	name = talloc_strdup(talloc_tos(), orig_name);
	if (!name) {
		errno = ENOMEM;
		return NT_STATUS_NO_MEMORY;
	}
	rc = catia_string_replace_allocate(handle->conn,
					   name,
					   &mapped_name,
					   direction);

	TALLOC_FREE(name);
	if (rc != 0) {
		return map_nt_error_from_unix(rc);
	}

	ret = SMB_VFS_NEXT_TRANSLATE_NAME(handle, mapped_name, direction,
					  mem_ctx, pmapped_name);

	if (NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED)) {
		*pmapped_name = talloc_move(mem_ctx, &mapped_name);
		/* we need to return the former translation result here */
		ret = NT_STATUS_OK;
	} else {
		TALLOC_FREE(mapped_name);
	}

	return ret;
}

#define CATIA_DEBUG_CC(lvl, cc, fsp) \
	catia_debug_cc((lvl), (cc), (fsp), __location__);

static void catia_debug_cc(int lvl,
			   struct catia_cache *cc,
			   files_struct *fsp,
			   const char *location)
{
	DEBUG(lvl, ("%s: cc [%p] cc->busy [%p] "
		    "is_fsp_ext [%s] "
		    "fsp [%p] fsp name [%s] "
		    "orig_fname [%s] "
		    "fname [%s] "
		    "orig_base_fname [%s] "
		    "base_fname [%s]\n",
		    location,
		    cc, cc->busy,
		    cc->is_fsp_ext ? "yes" : "no",
		    fsp, fsp_str_dbg(fsp),
		    cc->orig_fname, cc->fname,
		    cc->orig_base_fname, cc->base_fname));
}

static void catia_free_cc(struct catia_cache **_cc,
			  vfs_handle_struct *handle,
			  files_struct *fsp)
{
	struct catia_cache *cc = *_cc;

	if (cc->is_fsp_ext) {
		VFS_REMOVE_FSP_EXTENSION(handle, fsp);
		cc = NULL;
	} else {
		TALLOC_FREE(cc);
	}

	*_cc = NULL;
}

static struct catia_cache *catia_validate_and_apply_cc(
				       vfs_handle_struct *handle,
				       files_struct *fsp,
				       const struct catia_cache * const *busy,
				       bool *make_tmp_cache)
{
	struct catia_cache *cc = NULL;

	*make_tmp_cache = false;

	cc = (struct catia_cache *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (cc == NULL) {
		return NULL;
	}

	if (cc->busy != NULL) {
		if (cc->busy == busy) {
			/* This should never happen */
			CATIA_DEBUG_CC(0, cc, fsp);
			smb_panic(__location__);
		}

		/*
		 * Recursion. Validate names, the names in the fsp's should be
		 * the translated names we had set.
		 */

		if ((cc->fname != fsp->fsp_name->base_name)
		    ||
		    (fsp_is_alternate_stream(fsp) &&
		     (cc->base_fname != fsp->base_fsp->fsp_name->base_name)))
		{
			CATIA_DEBUG_CC(10, cc, fsp);

			/*
			 * Names changed. Setting don't expose the cache on the
			 * fsp and ask the caller to create a temporary cache.
			 */
			*make_tmp_cache = true;
			return NULL;
		}

		/*
		 * Ok, a validated cache while in a recursion, just let the
		 * caller detect that cc->busy is != busy and there's
		 * nothing else to do.
		 */
		CATIA_DEBUG_CC(10, cc, fsp);
		return cc;
	}

	/* Not in a recursion */

	if ((cc->orig_fname != fsp->fsp_name->base_name)
	    ||
	    (fsp_is_alternate_stream(fsp) &&
	     (cc->orig_base_fname != fsp->base_fsp->fsp_name->base_name)))
	{
		/*
		 * fsp names changed, this can happen in an rename op.
		 * Trigger recreation as a full fledged fsp extension.
		 */

		CATIA_DEBUG_CC(10, cc, fsp);
		catia_free_cc(&cc, handle, fsp);
		return NULL;
	}


	/*
	 * Ok, we found a valid cache entry, no recursion. Just set translated
	 * names from the cache and mark the cc as busy.
	 */
	fsp->fsp_name->base_name = cc->fname;
	if (fsp_is_alternate_stream(fsp)) {
		fsp->base_fsp->fsp_name->base_name = cc->base_fname;
	}

	cc->busy = busy;
	CATIA_DEBUG_CC(10, cc, fsp);
	return cc;
}

#define CATIA_FETCH_FSP_PRE_NEXT(mem_ctx, handle, fsp, _cc) \
	catia_fetch_fsp_pre_next((mem_ctx), (handle), (fsp), (_cc), __func__);

static int catia_fetch_fsp_pre_next(TALLOC_CTX *mem_ctx,
				    vfs_handle_struct *handle,
				    files_struct *fsp,
				    struct catia_cache **_cc,
				    const char *function)
{
	const struct catia_cache * const *busy =
		(const struct catia_cache * const *)_cc;
	struct catia_cache *cc = NULL;
	bool make_tmp_cache = false;
	int ret;

	*_cc = NULL;

	DBG_DEBUG("Called from [%s]\n", function);

	cc = catia_validate_and_apply_cc(handle,
					 fsp,
					 busy,
					 &make_tmp_cache);
	if (cc != NULL) {
		if (cc->busy != busy) {
			return 0;
		}
		*_cc = cc;
		return 0;
	}

	if (!make_tmp_cache) {
		cc = VFS_ADD_FSP_EXTENSION(
			handle, fsp, struct catia_cache, NULL);
		if (cc == NULL) {
			return -1;
		}
		*cc = (struct catia_cache) {
			.is_fsp_ext = true,
		};

		mem_ctx = VFS_MEMCTX_FSP_EXTENSION(handle, fsp);
		if (mem_ctx == NULL) {
			DBG_ERR("VFS_MEMCTX_FSP_EXTENSION failed\n");
			catia_free_cc(&cc, handle, fsp);
			return -1;
		}
	} else {
		cc = talloc_zero(mem_ctx, struct catia_cache);
		if (cc == NULL) {
			return -1;
		}
		mem_ctx = cc;
	}

	ret = catia_string_replace_allocate(handle->conn,
					    fsp->fsp_name->base_name,
					    &cc->fname,
					    vfs_translate_to_unix);
	if (ret != 0) {
		catia_free_cc(&cc, handle, fsp);
		errno = ret;
		return -1;
	}
	talloc_steal(mem_ctx, cc->fname);

	if (fsp_is_alternate_stream(fsp)) {
		ret = catia_string_replace_allocate(
			handle->conn,
			fsp->base_fsp->fsp_name->base_name,
			&cc->base_fname,
			vfs_translate_to_unix);
		if (ret != 0) {
			catia_free_cc(&cc, handle, fsp);
			errno = ret;
			return -1;
		}
		talloc_steal(mem_ctx, cc->base_fname);
	}

	cc->orig_fname = fsp->fsp_name->base_name;
	fsp->fsp_name->base_name = cc->fname;

	if (fsp_is_alternate_stream(fsp)) {
		cc->orig_base_fname = fsp->base_fsp->fsp_name->base_name;
		fsp->base_fsp->fsp_name->base_name = cc->base_fname;
	}

	cc->busy = busy;
	CATIA_DEBUG_CC(10, cc, fsp);

	*_cc = cc;

	return 0;
}

#define CATIA_FETCH_FSP_POST_NEXT(_cc, fsp) do { \
	int catia_saved_errno = errno; \
	catia_fetch_fsp_post_next((_cc), (fsp), __func__); \
	errno = catia_saved_errno; \
} while(0)

static void catia_fetch_fsp_post_next(struct catia_cache **_cc,
				      files_struct *fsp,
				      const char *function)
{
	const struct catia_cache * const *busy =
		(const struct catia_cache * const *)_cc;
	struct catia_cache *cc = *_cc;

	DBG_DEBUG("Called from [%s]\n", function);

	if (cc == NULL) {
		/*
		 * This can happen when recursing in the VFS on the fsp when the
		 * pre_next func noticed the recursion and set out cc pointer to
		 * NULL.
		 */
		return;
	}

	if (cc->busy != busy) {
		CATIA_DEBUG_CC(0, cc, fsp);
		smb_panic(__location__);
		return;
	}

	cc->busy = NULL;
	*_cc = NULL;

	fsp->fsp_name->base_name = cc->orig_fname;
	if (fsp_is_alternate_stream(fsp)) {
		fsp->base_fsp->fsp_name->base_name = cc->orig_base_fname;
	}

	CATIA_DEBUG_CC(10, cc, fsp);

	if (!cc->is_fsp_ext) {
		TALLOC_FREE(cc);
	}

	return;
}

static int catia_openat(vfs_handle_struct *handle,
			const struct files_struct *dirfsp,
			const struct smb_filename *smb_fname_in,
			files_struct *fsp,
			const struct vfs_open_how *how)
{
	struct smb_filename *smb_fname = NULL;
	struct catia_cache *cc = NULL;
	char *mapped_name = NULL;
	int ret;
	int saved_errno = 0;

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname_in->base_name,
					    &mapped_name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		TALLOC_FREE(mapped_name);
		return ret;
	}

	smb_fname = cp_smb_filename(talloc_tos(), smb_fname_in);
	if (smb_fname == NULL) {
		TALLOC_FREE(mapped_name);
		errno = ENOMEM;
		return -1;
	}
	smb_fname->base_name = mapped_name;

	ret = SMB_VFS_NEXT_OPENAT(handle,
				  dirfsp,
				  smb_fname,
				  fsp,
				  how);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(smb_fname);
	TALLOC_FREE(mapped_name);
	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int catia_renameat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst,
			const struct vfs_rename_how *how)
{
	TALLOC_CTX *ctx = talloc_tos();
	struct smb_filename *smb_fname_src_tmp = NULL;
	struct smb_filename *smb_fname_dst_tmp = NULL;
	char *src_name_mapped = NULL;
	char *dst_name_mapped = NULL;
	int ret = -1;

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname_src->base_name,
					    &src_name_mapped,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname_dst->base_name,
					    &dst_name_mapped,
					    vfs_translate_to_unix);
	if (ret != 0) {
		TALLOC_FREE(src_name_mapped);
		errno = ret;
		ret = -1;
		goto out;
	}

	/* Setup temporary smb_filename structs. */
	smb_fname_src_tmp = cp_smb_filename(ctx, smb_fname_src);
	if (smb_fname_src_tmp == NULL) {
		errno = ENOMEM;
		ret = -1;
		goto out;
	}

	smb_fname_dst_tmp = cp_smb_filename(ctx, smb_fname_dst);
	if (smb_fname_dst_tmp == NULL) {
		errno = ENOMEM;
		ret = -1;
		goto out;
	}

	smb_fname_src_tmp->base_name = src_name_mapped;
	smb_fname_dst_tmp->base_name = dst_name_mapped;
	DEBUG(10, ("converted old name: %s\n",
				smb_fname_str_dbg(smb_fname_src_tmp)));
	DEBUG(10, ("converted new name: %s\n",
				smb_fname_str_dbg(smb_fname_dst_tmp)));

	ret = SMB_VFS_NEXT_RENAMEAT(handle,
			srcfsp,
			smb_fname_src_tmp,
			dstfsp,
			smb_fname_dst_tmp,
			how);

out:
	TALLOC_FREE(src_name_mapped);
	TALLOC_FREE(dst_name_mapped);
	TALLOC_FREE(smb_fname_src_tmp);
	TALLOC_FREE(smb_fname_dst_tmp);
	return ret;
}

static int catia_fstatat(struct vfs_handle_struct *handle,
			 const struct files_struct *dirfsp,
			 const struct smb_filename *smb_fname,
			 SMB_STRUCT_STAT *sbuf,
			 int flags)
{
	struct smb_filename *tmp = NULL;
	int ret;

	tmp = cp_smb_filename(talloc_tos(), smb_fname);
	if (tmp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname->base_name,
					    &tmp->base_name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		TALLOC_FREE(tmp);
		errno = ret;
		return -1;
	}

	ret = SMB_VFS_NEXT_FSTATAT(handle, dirfsp, tmp, sbuf, flags);

	{
		int err = errno;
		TALLOC_FREE(tmp);
		errno = err;
	}

	return ret;
}

static int catia_stat(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	char *name = NULL;
	char *tmp_base_name;
	int ret;

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname->base_name,
					    &name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = name;

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	smb_fname->base_name = tmp_base_name;

	TALLOC_FREE(name);
	return ret;
}

static int catia_lstat(vfs_handle_struct *handle,
		       struct smb_filename *smb_fname)
{
	char *name = NULL;
	char *tmp_base_name;
	int ret;

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname->base_name,
					    &name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	tmp_base_name = smb_fname->base_name;
	smb_fname->base_name = name;

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	smb_fname->base_name = tmp_base_name;
	TALLOC_FREE(name);

	return ret;
}

static int catia_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	struct catia_cache *cc = NULL;
	struct smb_filename *smb_fname_tmp = NULL;
	char *name = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, dirfsp, &cc);
	if (ret != 0) {
		return ret;
	}

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname->base_name,
					    &name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		goto out;
	}

	/* Setup temporary smb_filename structs. */
	smb_fname_tmp = cp_smb_filename(talloc_tos(), smb_fname);
	if (smb_fname_tmp == NULL) {
		errno = ENOMEM;
		goto out;
	}

	smb_fname_tmp->base_name = name;
	smb_fname_tmp->fsp = smb_fname->fsp;

	ret = SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp,
			smb_fname_tmp,
			flags);
	TALLOC_FREE(smb_fname_tmp);
	TALLOC_FREE(name);

out:
	CATIA_FETCH_FSP_POST_NEXT(&cc, dirfsp);
	return ret;
}

static int catia_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	char *name = NULL;
	int ret;
	int saved_errno;
	struct smb_filename *catia_smb_fname = NULL;

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname->base_name,
					    &name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}
	catia_smb_fname = synthetic_smb_fname(talloc_tos(),
					name,
					NULL,
					&smb_fname->st,
					smb_fname->twrp,
					smb_fname->flags);
	if (catia_smb_fname == NULL) {
		TALLOC_FREE(name);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_LCHOWN(handle, catia_smb_fname, uid, gid);
	saved_errno = errno;
	TALLOC_FREE(name);
	TALLOC_FREE(catia_smb_fname);
	errno = saved_errno;
	return ret;
}

static int catia_mkdirat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	char *name = NULL;
	int ret;
	struct smb_filename *catia_smb_fname = NULL;

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname->base_name,
					    &name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}
	catia_smb_fname = synthetic_smb_fname(talloc_tos(),
					name,
					NULL,
					&smb_fname->st,
					smb_fname->twrp,
					smb_fname->flags);
	if (catia_smb_fname == NULL) {
		TALLOC_FREE(name);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_MKDIRAT(handle,
			dirfsp,
			catia_smb_fname,
			mode);
	TALLOC_FREE(name);
	TALLOC_FREE(catia_smb_fname);

	return ret;
}

static int catia_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	char *name = NULL;
	struct smb_filename *catia_smb_fname = NULL;
	int ret;

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname->base_name,
					    &name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	catia_smb_fname = synthetic_smb_fname(talloc_tos(),
					name,
					NULL,
					&smb_fname->st,
					smb_fname->twrp,
					smb_fname->flags);
	if (catia_smb_fname == NULL) {
		TALLOC_FREE(name);
		errno = ENOMEM;
		return -1;
	}
	ret = SMB_VFS_NEXT_CHDIR(handle, catia_smb_fname);
	TALLOC_FREE(name);
	TALLOC_FREE(catia_smb_fname);

	return ret;
}

static int catia_fntimes(vfs_handle_struct *handle,
			 files_struct *fsp,
			 struct smb_file_time *ft)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	ret = SMB_VFS_NEXT_FNTIMES(handle, fsp, ft);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

static struct smb_filename *
catia_realpath(vfs_handle_struct *handle,
		TALLOC_CTX *ctx,
		const struct smb_filename *smb_fname)
{
	char *mapped_name = NULL;
	struct smb_filename *catia_smb_fname = NULL;
	struct smb_filename *return_fname = NULL;
	int ret;

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname->base_name,
					    &mapped_name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return NULL;
	}

	catia_smb_fname = synthetic_smb_fname(talloc_tos(),
					mapped_name,
					NULL,
					&smb_fname->st,
					smb_fname->twrp,
					smb_fname->flags);
	if (catia_smb_fname == NULL) {
		TALLOC_FREE(mapped_name);
		errno = ENOMEM;
		return NULL;
	}
	return_fname = SMB_VFS_NEXT_REALPATH(handle, ctx, catia_smb_fname);
	TALLOC_FREE(mapped_name);
	TALLOC_FREE(catia_smb_fname);
	return return_fname;
}

static NTSTATUS
catia_fstreaminfo(struct vfs_handle_struct *handle,
		 struct files_struct *fsp,
		 TALLOC_CTX *mem_ctx,
		 unsigned int *_num_streams,
		 struct stream_struct **_streams)
{
	char *mapped_name = NULL;
	NTSTATUS status;
	unsigned int i;
	struct smb_filename *catia_smb_fname = NULL;
	struct smb_filename *smb_fname = NULL;
	unsigned int num_streams = 0;
	struct stream_struct *streams = NULL;
	int ret;

	smb_fname = fsp->fsp_name;
	*_num_streams = 0;
	*_streams = NULL;

	ret = catia_string_replace_allocate(handle->conn,
					    smb_fname->base_name,
					    &mapped_name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		return map_nt_error_from_unix(ret);
	}

	status = synthetic_pathref(talloc_tos(),
					handle->conn->cwd_fsp,
					mapped_name,
					NULL,
					&smb_fname->st,
					smb_fname->twrp,
					smb_fname->flags,
					&catia_smb_fname);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(mapped_name);
		return status;
	}

	status = SMB_VFS_NEXT_FSTREAMINFO(handle,
					  catia_smb_fname->fsp,
					  mem_ctx,
					  &num_streams,
					  &streams);
	TALLOC_FREE(mapped_name);
	TALLOC_FREE(catia_smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Translate stream names just like the base names
	 */
	for (i = 0; i < num_streams; i++) {
		/*
		 * Strip ":" prefix and ":$DATA" suffix to get a
		 * "pure" stream name and only translate that.
		 */
		void *old_ptr = streams[i].name;
		char *stream_name = streams[i].name + 1;
		char *stream_type = strrchr_m(stream_name, ':');

		if (stream_type != NULL) {
			*stream_type = '\0';
			stream_type += 1;
		}

		ret = catia_string_replace_allocate(handle->conn,
						    stream_name,
						    &mapped_name,
						    vfs_translate_to_windows);
		if (ret != 0) {
			TALLOC_FREE(streams);
			return map_nt_error_from_unix(ret);
		}

		if (stream_type != NULL) {
			streams[i].name = talloc_asprintf(streams,
							  ":%s:%s",
							  mapped_name,
							  stream_type);
		} else {
			streams[i].name = talloc_asprintf(streams,
							  ":%s",
							  mapped_name);
		}
		TALLOC_FREE(mapped_name);
		TALLOC_FREE(old_ptr);
		if (streams[i].name == NULL) {
			TALLOC_FREE(streams);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*_num_streams = num_streams;
	*_streams = streams;
	return NT_STATUS_OK;
}

static int catia_fstat(vfs_handle_struct *handle,
		       files_struct *fsp,
		       SMB_STRUCT_STAT *sbuf)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

static ssize_t catia_pread(vfs_handle_struct *handle,
			   files_struct *fsp, void *data,
			   size_t n, off_t offset)
{
	struct catia_cache *cc = NULL;
	ssize_t result;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	result = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return result;
}

static ssize_t catia_pwrite(vfs_handle_struct *handle,
			    files_struct *fsp, const void *data,
			    size_t n, off_t offset)
{
	struct catia_cache *cc = NULL;
	ssize_t result;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	result = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return result;
}

static int catia_ftruncate(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   off_t offset)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	ret = SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

static int catia_fallocate(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   uint32_t mode,
			   off_t offset,
			   off_t len)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	ret = SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

static ssize_t catia_fgetxattr(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       const char *name,
			       void *value,
			       size_t size)
{
	char *mapped_xattr_name = NULL;
	ssize_t result;
	int ret;

	ret = catia_string_replace_allocate(handle->conn,
					    name,
					    &mapped_xattr_name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	result = SMB_VFS_NEXT_FGETXATTR(handle, fsp, mapped_xattr_name,
					value, size);

	TALLOC_FREE(mapped_xattr_name);

	return result;
}

static ssize_t catia_flistxattr(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				char *list,
				size_t size)
{
	struct catia_cache *cc = NULL;
	ssize_t result;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	result = SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return result;
}

static int catia_fremovexattr(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      const char *name)
{
	char *mapped_name = NULL;
	int ret;

	ret = catia_string_replace_allocate(handle->conn,
					    name,
					    &mapped_name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	ret = SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, mapped_name);

	TALLOC_FREE(mapped_name);

	return ret;
}

static int catia_fsetxattr(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   const char *name,
			   const void *value,
			   size_t size,
			   int flags)
{
	char *mapped_xattr_name = NULL;
	int ret;

	ret = catia_string_replace_allocate(handle->conn,
					    name,
					    &mapped_xattr_name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		errno = ret;
		return -1;
	}

	ret = SMB_VFS_NEXT_FSETXATTR(handle, fsp, mapped_xattr_name,
				     value, size, flags);

	TALLOC_FREE(mapped_xattr_name);

	return ret;
}

static SMB_ACL_T catia_sys_acl_get_fd(vfs_handle_struct *handle,
				      files_struct *fsp,
				      SMB_ACL_TYPE_T type,
				      TALLOC_CTX *mem_ctx)
{
	struct catia_cache *cc = NULL;
	struct smb_acl_t *result = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return NULL;
	}

	result = SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, type, mem_ctx);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return result;
}

static int catia_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				     files_struct *fsp,
				     TALLOC_CTX *mem_ctx,
				     char **blob_description,
				     DATA_BLOB *blob)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	ret = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx,
					       blob_description, blob);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

static int catia_sys_acl_set_fd(vfs_handle_struct *handle,
				files_struct *fsp,
				SMB_ACL_TYPE_T type,
				SMB_ACL_T theacl)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	ret = SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, type, theacl);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

static NTSTATUS catia_fget_nt_acl(vfs_handle_struct *handle,
				  files_struct *fsp,
				  uint32_t security_info,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor **ppdesc)
{
	struct catia_cache *cc = NULL;
	NTSTATUS status;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	status = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
					  mem_ctx, ppdesc);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return status;
}

static NTSTATUS catia_fset_nt_acl(vfs_handle_struct *handle,
				  files_struct *fsp,
				  uint32_t security_info_sent,
				  const struct security_descriptor *psd)
{
	struct catia_cache *cc = NULL;
	NTSTATUS status;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return status;
}

static NTSTATUS catia_fset_dos_attributes(struct vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  uint32_t dosmode)
{
	struct catia_cache *cc = NULL;
	NTSTATUS status;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	status = SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle, fsp, dosmode);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return status;
}

static NTSTATUS catia_fget_dos_attributes(struct vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  uint32_t *dosmode)
{
	struct catia_cache *cc = NULL;
	NTSTATUS status;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	status = SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle, fsp, dosmode);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return status;
}

static int catia_fchown(vfs_handle_struct *handle,
			files_struct *fsp,
			uid_t uid,
			gid_t gid)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	ret = SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

static int catia_fchmod(vfs_handle_struct *handle,
			files_struct *fsp,
			mode_t mode)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return ret;
	}

	ret = SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

struct catia_pread_state {
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
	struct files_struct *fsp;
	struct catia_cache *cc;
};

static void catia_pread_done(struct tevent_req *subreq);

static struct tevent_req *catia_pread_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   void *data,
					   size_t n,
					   off_t offset)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct catia_pread_state *state = NULL;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct catia_pread_state);
	if (req == NULL) {
		return NULL;
	}
	state->fsp = fsp;

	ret = CATIA_FETCH_FSP_PRE_NEXT(state, handle, fsp, &state->cc);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data,
					 n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, catia_pread_done, req);

	return req;
}

static void catia_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct catia_pread_state *state = tevent_req_data(
		req, struct catia_pread_state);

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	CATIA_FETCH_FSP_POST_NEXT(&state->cc, state->fsp);

	tevent_req_done(req);
}

static ssize_t catia_pread_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct catia_pread_state *state = tevent_req_data(
		req, struct catia_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

struct catia_pwrite_state {
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
	struct files_struct *fsp;
	struct catia_cache *cc;
};

static void catia_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *catia_pwrite_send(struct vfs_handle_struct *handle,
					    TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct files_struct *fsp,
					    const void *data,
					    size_t n,
					    off_t offset)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct catia_pwrite_state *state = NULL;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct catia_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	state->fsp = fsp;

	ret = CATIA_FETCH_FSP_PRE_NEXT(state, handle, fsp, &state->cc);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data,
					  n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, catia_pwrite_done, req);

	return req;
}

static void catia_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct catia_pwrite_state *state = tevent_req_data(
		req, struct catia_pwrite_state);

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	CATIA_FETCH_FSP_POST_NEXT(&state->cc, state->fsp);

	tevent_req_done(req);
}

static ssize_t catia_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct catia_pwrite_state *state = tevent_req_data(
		req, struct catia_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static off_t catia_lseek(vfs_handle_struct *handle,
			 files_struct *fsp,
			 off_t offset,
			 int whence)
{
	struct catia_cache *cc = NULL;
	ssize_t result;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return -1;
	}

	result = SMB_VFS_NEXT_LSEEK(handle, fsp, offset, whence);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return result;
}

struct catia_fsync_state {
	int ret;
	struct vfs_aio_state vfs_aio_state;
	struct files_struct *fsp;
	struct catia_cache *cc;
};

static void catia_fsync_done(struct tevent_req *subreq);

static struct tevent_req *catia_fsync_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct catia_fsync_state *state = NULL;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct catia_fsync_state);
	if (req == NULL) {
		return NULL;
	}
	state->fsp = fsp;

	ret = CATIA_FETCH_FSP_PRE_NEXT(state, handle, fsp, &state->cc);
	if (ret != 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	subreq = SMB_VFS_NEXT_FSYNC_SEND(state, ev, handle, fsp);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, catia_fsync_done, req);

	return req;
}

static void catia_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct catia_fsync_state *state = tevent_req_data(
		req, struct catia_fsync_state);

	state->ret = SMB_VFS_FSYNC_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);

	CATIA_FETCH_FSP_POST_NEXT(&state->cc, state->fsp);

	tevent_req_done(req);
}

static int catia_fsync_recv(struct tevent_req *req,
			    struct vfs_aio_state *vfs_aio_state)
{
	struct catia_fsync_state *state = tevent_req_data(
		req, struct catia_fsync_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static bool catia_lock(vfs_handle_struct *handle,
		       files_struct *fsp,
		       int op,
		       off_t offset,
		       off_t count,
		       int type)
{
	struct catia_cache *cc = NULL;
	bool ok;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return false;
	}

	ok = SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ok;
}

static int catia_filesystem_sharemode(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      uint32_t share_access,
				      uint32_t access_mask)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return -1;
	}

	ret = SMB_VFS_NEXT_FILESYSTEM_SHAREMODE(handle,
						fsp,
						share_access,
						access_mask);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

static int catia_linux_setlease(vfs_handle_struct *handle,
				files_struct *fsp,
				int leasetype)
{
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return -1;
	}

	ret = SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ret;
}

static bool catia_getlock(vfs_handle_struct *handle,
			  files_struct *fsp,
			  off_t *poffset,
			  off_t *pcount,
			  int *ptype,
			  pid_t *ppid)
{
	struct catia_cache *cc = NULL;
	int ret;
	bool ok;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return false;
	}

	ok = SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset, pcount, ptype, ppid);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ok;
}

static bool catia_strict_lock_check(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    struct lock_struct *plock)
{
	struct catia_cache *cc = NULL;
	int ret;
	bool ok;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return false;
	}

	ok = SMB_VFS_NEXT_STRICT_LOCK_CHECK(handle, fsp, plock);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return ok;
}

static NTSTATUS catia_fsctl(struct vfs_handle_struct *handle,
			    struct files_struct *fsp,
			    TALLOC_CTX *ctx,
			    uint32_t function,
			    uint16_t req_flags,
			    const uint8_t *_in_data,
			    uint32_t in_len,
			    uint8_t **_out_data,
			    uint32_t max_out_len,
			    uint32_t *out_len)
{
	NTSTATUS result;
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	result = SMB_VFS_NEXT_FSCTL(handle,
				fsp,
				ctx,
				function,
				req_flags,
				_in_data,
				in_len,
				_out_data,
				max_out_len,
				out_len);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return result;
}

static NTSTATUS catia_fget_compression(vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      struct files_struct *fsp,
				      uint16_t *_compression_fmt)
{
	NTSTATUS result;
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	result = SMB_VFS_NEXT_FGET_COMPRESSION(handle,
					mem_ctx,
					fsp,
					_compression_fmt);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return result;
}

static NTSTATUS catia_set_compression(vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      struct files_struct *fsp,
				      uint16_t compression_fmt)
{
	NTSTATUS result;
	struct catia_cache *cc = NULL;
	int ret;

	ret = CATIA_FETCH_FSP_PRE_NEXT(talloc_tos(), handle, fsp, &cc);
	if (ret != 0) {
		return map_nt_error_from_unix(errno);
	}

	result = SMB_VFS_NEXT_SET_COMPRESSION(handle, mem_ctx, fsp,
					      compression_fmt);

	CATIA_FETCH_FSP_POST_NEXT(&cc, fsp);

	return result;
}

static NTSTATUS catia_create_dfs_pathat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			const struct referral *reflist,
			size_t referral_count)
{
	char *mapped_name = NULL;
	const char *path = smb_fname->base_name;
	struct smb_filename *mapped_smb_fname = NULL;
	NTSTATUS status;
	int ret;

	ret = catia_string_replace_allocate(handle->conn,
					    path,
					    &mapped_name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		return map_nt_error_from_unix(ret);
	}
	mapped_smb_fname = synthetic_smb_fname(talloc_tos(),
					mapped_name,
					NULL,
					&smb_fname->st,
					smb_fname->twrp,
					smb_fname->flags);
	if (mapped_smb_fname == NULL) {
		TALLOC_FREE(mapped_name);
		return NT_STATUS_NO_MEMORY;
	}

	status = SMB_VFS_NEXT_CREATE_DFS_PATHAT(handle,
					dirfsp,
					mapped_smb_fname,
					reflist,
					referral_count);
	TALLOC_FREE(mapped_name);
	TALLOC_FREE(mapped_smb_fname);
	return status;
}

static NTSTATUS catia_read_dfs_pathat(struct vfs_handle_struct *handle,
			TALLOC_CTX *mem_ctx,
			struct files_struct *dirfsp,
			struct smb_filename *smb_fname,
			struct referral **ppreflist,
			size_t *preferral_count)
{
	char *mapped_name = NULL;
	const char *path = smb_fname->base_name;
	struct smb_filename *mapped_smb_fname = NULL;
	NTSTATUS status;
	int ret;

	ret = catia_string_replace_allocate(handle->conn,
					    path,
					    &mapped_name,
					    vfs_translate_to_unix);
	if (ret != 0) {
		return map_nt_error_from_unix(ret);
	}
	mapped_smb_fname = synthetic_smb_fname(talloc_tos(),
					mapped_name,
					NULL,
					&smb_fname->st,
					smb_fname->twrp,
					smb_fname->flags);
	if (mapped_smb_fname == NULL) {
		TALLOC_FREE(mapped_name);
		return NT_STATUS_NO_MEMORY;
	}

	status = SMB_VFS_NEXT_READ_DFS_PATHAT(handle,
					mem_ctx,
					dirfsp,
					mapped_smb_fname,
					ppreflist,
					preferral_count);
	if (NT_STATUS_IS_OK(status)) {
		/* Return any stat(2) info. */
		smb_fname->st = mapped_smb_fname->st;
	}

	TALLOC_FREE(mapped_name);
	TALLOC_FREE(mapped_smb_fname);
	return status;
}

static struct vfs_fn_pointers vfs_catia_fns = {
	.connect_fn = catia_connect,

	/* Directory operations */
	.mkdirat_fn = catia_mkdirat,

	/* File operations */
	.openat_fn = catia_openat,
	.pread_fn = catia_pread,
	.pread_send_fn = catia_pread_send,
	.pread_recv_fn = catia_pread_recv,
	.pwrite_fn = catia_pwrite,
	.pwrite_send_fn = catia_pwrite_send,
	.pwrite_recv_fn = catia_pwrite_recv,
	.lseek_fn = catia_lseek,
	.renameat_fn = catia_renameat,
	.fsync_send_fn = catia_fsync_send,
	.fsync_recv_fn = catia_fsync_recv,
	.stat_fn = catia_stat,
	.fstat_fn = catia_fstat,
	.fstatat_fn = catia_fstatat,
	.lstat_fn = catia_lstat,
	.unlinkat_fn = catia_unlinkat,
	.fchmod_fn = catia_fchmod,
	.fchown_fn = catia_fchown,
	.lchown_fn = catia_lchown,
	.chdir_fn = catia_chdir,
	.fntimes_fn = catia_fntimes,
	.ftruncate_fn = catia_ftruncate,
	.fallocate_fn = catia_fallocate,
	.lock_fn = catia_lock,
	.filesystem_sharemode_fn = catia_filesystem_sharemode,
	.linux_setlease_fn = catia_linux_setlease,
	.getlock_fn = catia_getlock,
	.realpath_fn = catia_realpath,
	.fstreaminfo_fn = catia_fstreaminfo,
	.strict_lock_check_fn = catia_strict_lock_check,
	.translate_name_fn = catia_translate_name,
	.fsctl_fn = catia_fsctl,
	.get_dos_attributes_send_fn = vfs_not_implemented_get_dos_attributes_send,
	.get_dos_attributes_recv_fn = vfs_not_implemented_get_dos_attributes_recv,
	.fset_dos_attributes_fn = catia_fset_dos_attributes,
	.fget_dos_attributes_fn = catia_fget_dos_attributes,
	.fget_compression_fn = catia_fget_compression,
	.set_compression_fn = catia_set_compression,
	.create_dfs_pathat_fn = catia_create_dfs_pathat,
	.read_dfs_pathat_fn = catia_read_dfs_pathat,

	/* NT ACL operations. */
	.fget_nt_acl_fn = catia_fget_nt_acl,
	.fset_nt_acl_fn = catia_fset_nt_acl,

	/* POSIX ACL operations. */
	.sys_acl_get_fd_fn = catia_sys_acl_get_fd,
	.sys_acl_blob_get_fd_fn = catia_sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = catia_sys_acl_set_fd,

	/* EA operations. */
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = catia_fgetxattr,
	.flistxattr_fn = catia_flistxattr,
	.fremovexattr_fn = catia_fremovexattr,
	.fsetxattr_fn = catia_fsetxattr,
};

static_decl_vfs;
NTSTATUS vfs_catia_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

        ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "catia",
				&vfs_catia_fns);
	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_catia_debug_level = debug_add_class("catia");
	if (vfs_catia_debug_level == -1) {
		vfs_catia_debug_level = DBGC_VFS;
		DEBUG(0, ("vfs_catia: Couldn't register custom debugging "
			  "class!\n"));
	} else {
		DEBUG(10, ("vfs_catia: Debug class number of "
			   "'catia': %d\n", vfs_catia_debug_level));
	}

	return ret;

}
