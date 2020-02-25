/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "eacces-error.h"
#include "fdatasync-path.h"
#include "mkdir-parents.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "fs-api.h"
#include "dbox-attachment.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"

#include <stdio.h>
#include <utime.h>

static void sdbox_file_init_paths(struct sdbox_file *file, const char *fname)
{
	FUNC_START();
	struct mailbox *box = &file->mbox->box;
	const char *alt_path;

	i_free(file->file.primary_path);
	i_free(file->file.alt_path);
	file->file.primary_path =
		i_strdup_printf("%s/%s", mailbox_get_path(box), fname);
	file->file.cur_path = file->file.primary_path;

	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_ALT_MAILBOX,
				&alt_path) > 0)
		file->file.alt_path = i_strdup_printf("%s/%s", alt_path, fname);
}

struct dbox_file *sdbox_file_init(struct sdbox_mailbox *mbox, uint32_t uid)
{
	FUNC_START();
	struct sdbox_file *file;
	const char *fname;

	file = i_new(struct sdbox_file, 1);
	file->file.storage = &mbox->storage->storage;
	file->mbox = mbox;
	T_BEGIN {
		if (uid != 0) {
			fname = t_strdup_printf(SDBOX_MAIL_FILE_FORMAT, uid);
			sdbox_file_init_paths(file, fname);
			file->uid = uid;
		} else {
			sdbox_file_init_paths(file, dbox_generate_tmp_filename());
		}
	} T_END;
	dbox_file_init(&file->file);
	return &file->file;
}

struct dbox_file *sdbox_file_create(struct sdbox_mailbox *mbox)
{
	FUNC_START();
	struct dbox_file *file;

	file = sdbox_file_init(mbox, 0);
	file->fs_file = file->storage->v.
		file_init_fs_file(file, file->primary_path, FALSE);
	return file;
}

void sdbox_file_free(struct dbox_file *file)
{
	FUNC_START();
	struct sdbox_file *sfile = (struct sdbox_file *)file;

	pool_unref(&sfile->attachment_pool);
	dbox_file_free(file);
}

int sdbox_file_get_attachments(struct dbox_file *file, const char **extrefs_r)
{
	FUNC_START();
	const char *line;
	bool deleted;
	int ret;

	*extrefs_r = NULL;

	/* read the metadata */
	ret = dbox_file_open(file, &deleted);
	if (ret > 0) {
		if (deleted)
			return 0;
		if ((ret = dbox_file_seek(file, 0)) > 0)
			ret = dbox_file_metadata_read(file);
	}
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		/* corrupted file. we're deleting it anyway. */
		line = NULL;
	} else {
		line = dbox_file_metadata_get(file, DBOX_METADATA_EXT_REF);
	}
	if (line == NULL) {
		/* no attachments */
		return 0;
	}
	*extrefs_r = line;
	return 1;
}

const char *
sdbox_file_attachment_relpath(struct sdbox_file *file, const char *srcpath)
{
	FUNC_START();
	const char *p;

	p = strchr(srcpath, '-');
	if (p == NULL) {
		mailbox_set_critical(&file->mbox->box,
			"sdbox attachment path in invalid format: %s", srcpath);
	} else {
		p = strchr(p+1, '-');
	}
	return t_strdup_printf("%s-%s-%u",
			p == NULL ? srcpath : t_strdup_until(srcpath, p),
			guid_128_to_string(file->mbox->mailbox_guid),
			file->uid);
}

static int sdbox_file_rename_attachments(struct sdbox_file *file)
{
	FUNC_START();
	struct dbox_storage *storage = file->file.storage;
	struct fs_file *src_file, *dest_file;
	const char *const *pathp, *src, *dest;
	int ret = 0;

	array_foreach(&file->attachment_paths, pathp) T_BEGIN {
		src = t_strdup_printf("%s/%s", storage->attachment_dir, *pathp);
		dest = t_strdup_printf("%s/%s", storage->attachment_dir,
				sdbox_file_attachment_relpath(file, *pathp));
		src_file = fs_file_init(storage->attachment_fs, src,
					FS_OPEN_MODE_READONLY);
		dest_file = fs_file_init(storage->attachment_fs, dest,
					FS_OPEN_MODE_READONLY);
		if (fs_rename(src_file, dest_file) < 0) {
			mailbox_set_critical(&file->mbox->box, "%s",
				fs_file_last_error(dest_file));
			ret = -1;
		}
		fs_file_deinit(&src_file);
		fs_file_deinit(&dest_file);
	} T_END;
	return ret;
}

int sdbox_file_assign_uid(struct sdbox_file *file, uint32_t uid,
			  bool ignore_if_exists)
{
	FUNC_START();
	const char *p, *old_path, *dir, *new_fname, *new_path;
	struct stat st;

	i_assert(file->uid == 0);
	i_assert(uid != 0);

	old_path = file->file.cur_path;
	p = strrchr(old_path, '/');
	i_assert(p != NULL);
	dir = t_strdup_until(old_path, p);

	new_fname = t_strdup_printf(SDBOX_MAIL_FILE_FORMAT, uid);
	new_path = t_strdup_printf("%s/%s", dir, new_fname);

	if (!ignore_if_exists && stat(new_path, &st) == 0) {
		mailbox_set_critical(&file->mbox->box,
			"sdbox: %s already exists, rebuilding index", new_path);
		sdbox_set_mailbox_corrupted(&file->mbox->box);
		return -1;
	}
	if (rename(old_path, new_path) < 0) {
		mailbox_set_critical(&file->mbox->box,
				     "rename(%s, %s) failed: %m",
				     old_path, new_path);
		return -1;
	}
	sdbox_file_init_paths(file, new_fname);
	file->uid = uid;

	if (array_is_created(&file->attachment_paths)) {
		if (sdbox_file_rename_attachments(file) < 0)
			return -1;
	}
	return 0;
}

static int sdbox_file_unlink_aborted_save_attachments(struct sdbox_file *file)
{
	FUNC_START();
	struct dbox_storage *storage = file->file.storage;
	struct fs *fs = storage->attachment_fs;
	struct fs_file *fs_file;
	const char *const *pathp, *path;
	int ret = 0;

	array_foreach(&file->attachment_paths, pathp) T_BEGIN {
		/* we don't know if we aborted before renaming this attachment,
		   so try deleting both source and dest path. the source paths
		   point to temporary files (not to source messages'
		   attachment paths), so it's safe to delete them. */
		path = t_strdup_printf("%s/%s", storage->attachment_dir,
				       *pathp);
		fs_file = fs_file_init(fs, path, FS_OPEN_MODE_READONLY);
		if (fs_delete(fs_file) < 0 &&
		    errno != ENOENT) {
			mailbox_set_critical(&file->mbox->box, "%s",
					     fs_file_last_error(fs_file));
			ret = -1;
		}
		fs_file_deinit(&fs_file);

		path = t_strdup_printf("%s/%s", storage->attachment_dir,
				sdbox_file_attachment_relpath(file, *pathp));
		fs_file = fs_file_init(fs, path, FS_OPEN_MODE_READONLY);
		if (fs_delete(fs_file) < 0 &&
		    errno != ENOENT) {
			mailbox_set_critical(&file->mbox->box, "%s",
					     fs_file_last_error(fs_file));
			ret = -1;
		}
		fs_file_deinit(&fs_file);
	} T_END;
	return ret;
}

int sdbox_file_unlink_aborted_save(struct sdbox_file *file)
{
	FUNC_START();
	int ret = 0;

	if (unlink(file->file.cur_path) < 0) {
		mailbox_set_critical(&file->mbox->box,
			"unlink(%s) failed: %m", file->file.cur_path);
		ret = -1;
	}
	if (array_is_created(&file->attachment_paths)) {
		if (sdbox_file_unlink_aborted_save_attachments(file) < 0)
			ret = -1;
	}
	return ret;
}

struct fs_file *sdbox_file_init_fs_file(struct dbox_file *file, const char *path, bool parents)
{
	FUNC_START();
	struct sdbox_file *sfile = (struct sdbox_file *)file;
	struct mailbox *box = &sfile->mbox->box;
	const struct mailbox_permissions *perm = mailbox_get_permissions(box);
	const char *p, *dir;
	mode_t old_mask;
	struct fs_file *fs_file;

	old_mask = umask(0666 & ~perm->file_create_mode);
	fs_file = fs_file_init(file->storage->mail_fs, path, FS_OPEN_MODE_REPLACE);
	umask(old_mask);
	if (fs_file == NULL) {
		mailbox_set_critical(box, "fs_file_init(%s, FS_OPEN_MODE_REPLACE) failed: %m", path);
	}
	return fs_file;
}

int sdbox_file_move(struct dbox_file *file, bool alt_path)
{
	FUNC_START();
	struct mail_storage *storage = &file->storage->storage;
	struct ostream *output;
	const char *dest_dir, *temp_path, *dest_path, *p;
	struct stat st;
	bool deleted;
	struct fs_file *out_file;
	struct fs_file *dest_file;
	int ret = 0;

	i_assert(file->input != NULL);

	if (dbox_file_is_in_alt(file) == alt_path)
		return 0;
	if (file->alt_path == NULL)
		return 0;

	if (stat(file->cur_path, &st) < 0 && errno == ENOENT) {
		/* already expunged/moved by another session */
		return 0;
	}

	dest_path = !alt_path ? file->primary_path : file->alt_path;

	i_assert(dest_path != NULL);

	p = strrchr(dest_path, '/');
	i_assert(p != NULL);
	dest_dir = t_strdup_until(dest_path, p);
	temp_path = t_strdup_printf("%s/%s", dest_dir,
				    dbox_generate_tmp_filename());

	/* first copy the file. make sure to catch every possible error
	   since we really don't want to break the file. */
	out_file = file->storage->v.file_init_fs_file(file, dest_path, TRUE);
	if (out_file == NULL)
		return -1;

	output = fs_write_stream(out_file);
	i_stream_seek(file->input, 0);
	o_stream_nsend_istream(output, file->input);
	if (fs_write_stream_finish(file->fs_file, &output) < 0) {
		mail_storage_set_critical(storage, "write(%s) failed: %s",
			temp_path, o_stream_get_error(output));
		ret = -1;
	}

	fs_file_deinit(&dest_file);
	if (fs_delete(file->fs_file) < 0) {
		dbox_file_set_syscall_error(file, "fs_delete()");
		/* who knows what happened to the file. keep both just to be
		   sure both won't get deleted. */
		return -1;
	}

	/* file was successfully moved - reopen it */
	dbox_file_close(file);
	if (dbox_file_open(file, &deleted) <= 0) {
		mail_storage_set_critical(storage,
			"dbox_file_move(%s): reopening file failed", dest_path);
		return -1;
	}
	return 0;
}

static int
sdbox_unlink_attachments(struct sdbox_file *sfile,
			 const ARRAY_TYPE(mail_attachment_extref) *extrefs)
{
	FUNC_START();
	struct dbox_storage *storage = sfile->file.storage;
	const struct mail_attachment_extref *extref;
	const char *path;
	int ret = 0;

	array_foreach(extrefs, extref) T_BEGIN {
		path = sdbox_file_attachment_relpath(sfile, extref->path);
		if (index_attachment_delete(&storage->storage,
					    storage->attachment_fs, path) < 0)
			ret = -1;
	} T_END;
	return ret;
}

int sdbox_file_unlink_with_attachments(struct sdbox_file *sfile)
{
	FUNC_START();
	ARRAY_TYPE(mail_attachment_extref) extrefs;
	const char *extrefs_line;
	pool_t pool;
	int ret;

	ret = sdbox_file_get_attachments(&sfile->file, &extrefs_line);
	if (ret < 0)
		return -1;
	if (ret == 0) {
		/* no attachments */
		return dbox_file_unlink(&sfile->file);
	}

	pool = pool_alloconly_create("sdbox attachments unlink", 1024);
	p_array_init(&extrefs, pool, 16);
	if (!index_attachment_parse_extrefs(extrefs_line, pool, &extrefs)) {
		i_warning("%s: Ignoring corrupted extref: %s",
			  sfile->file.cur_path, extrefs_line);
		array_clear(&extrefs);
	}

	/* try to delete the file first, so if it fails we don't have
	   missing attachments */
	if ((ret = dbox_file_unlink(&sfile->file)) >= 0)
		(void)sdbox_unlink_attachments(sfile, &extrefs);
	pool_unref(&pool);
	return ret;
}
