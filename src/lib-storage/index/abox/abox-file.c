/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "eacces-error.h"
#include "fdatasync-path.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "fs-api.h"
#include "fs-api-private.h"
#include "abox-storage.h"
#include "abox-file.h"

#include <stdio.h>
#include <utime.h>

#define ABOX_READ_BLOCK_SIZE IO_BLOCK_SIZE

void abox_file_set_corrupted(struct abox_file *file, const char *reason, ...)
{
	FUNC_START();
	va_list args;

	va_start(args, reason);
	mail_storage_set_critical(&file->storage->storage,
		"Corrupted abox file %s (around offset=%"PRIuUOFF_T"): %s",
		file->cur_path, file->input == NULL ? 0 : file->input->v_offset,
		t_strdup_vprintf(reason, args));
	va_end(args);

	abox_set_mailbox_corrupted(&file->mbox->box);
}

void abox_file_set_syscall_error(struct abox_file *file, const char *function)
{
	FUNC_START();
	mail_storage_set_critical(&file->storage->storage,
				  "%s failed for file %s: %m",
				  function, file->cur_path);
}

char *abox_file_make_path(struct abox_file *file, const char *fname)
{
	FUNC_START();
	return i_strdup_printf("/%s/%s/%s",
		file->mbox->box.storage->user->username,
		guid_128_to_string(file->mbox->mailbox_guid),
		fname);
}

struct abox_file *abox_file_init(struct abox_mailbox *mbox, guid_128_t guid)
{
	FUNC_START();
	struct abox_file *file;
	const char *fname;

	file = i_new(struct abox_file, 1);
	file->storage = mbox->storage;
	file->mbox = mbox;
	T_BEGIN {
		if (guid_128_is_empty(guid)) {
			guid_128_generate(file->guid);
		} else {
			// we will generate guid later in abox_save_mail_write_metadata
			guid_128_copy(file->guid, guid);
		}

		fname = guid_128_to_string(file->guid);
		i_free(file->primary_path);
		file->cur_path =
			file->primary_path =
				abox_file_make_path(file, fname);
	} T_END;

	file->refcount = 1;
	file->fs_file = fs_file_init(file->storage->mail_fs,
								 file->primary_path, FS_OPEN_MODE_REPLACE);
	if (file->fs_file == NULL) {
		mailbox_set_critical(&mbox->box,
			"fs_file_init(%s, FS_OPEN_MODE_REPLACE) failed: %m",
			file->primary_path);
	}
	file->cur_offset = (uoff_t)-1;
	file->cur_path = file->primary_path;

	return file;
}

int abox_file_open(struct abox_file *file, bool *notfound_r)
{
	FUNC_START();
	*notfound_r = FALSE;
	if (file->input != NULL)
		return 1;

	if (file->fs_file == NULL) {
		T_BEGIN {
			file->fs_file = fs_file_init(file->storage->mail_fs,
								file->primary_path, FS_OPEN_MODE_READONLY);
		} T_END;
	}

	file->input = fs_read_stream(file->fs_file, ABOX_READ_BLOCK_SIZE);
	// (void)i_stream_read(file->input);
	if (file->input->stream_errno != 0) {
		i_debug("abox_file_open: stream_errno=%u", file->input->stream_errno);
		if (file->input->stream_errno == ENOENT) {
			*notfound_r = TRUE;
			FUNC_END_RET_INT(1);
			return 1;
		}
		mail_storage_set_critical(&file->storage->storage,
						"open(%s) failed: %s %m", file->primary_path,
						i_stream_get_error(file->input));
		FUNC_END_RET_INT(-1);
		return -1;
	}
	FUNC_END_RET_INT(1);
	return 1;
}

int abox_file_stat(struct abox_file *file, struct stat *st_r)
{
	FUNC_START();

	if (abox_file_is_open(file)) {
		if (fs_stat(file->fs_file, st_r) < 0) {
			mail_storage_set_critical(&file->storage->storage,
				"fstat(%s) failed: %m", file->cur_path);
			return -1;
		}
		return 0;
	}

	file->fs_file = fs_file_init(file->storage->mail_fs,
							file->primary_path, FS_OPEN_MODE_READONLY);
	if (fs_stat(file->fs_file, st_r) < 0) {
		FUNC_IN();
		if (errno != ENOENT) {
			mail_storage_set_critical(&file->storage->storage,
						  "fs_stat(%s) failed: %m", file->primary_path);
			return -1;
		}
	}
	fs_file_deinit(&file->fs_file);

	return 0;
}

void abox_file_unlock(struct abox_file *file)
{
	FUNC_START();
	i_assert(!file->appending || file->fs_lock == NULL);

	if (file->fs_lock != NULL)
		fs_unlock(&file->fs_lock);

	if (file->input != NULL)
		i_stream_sync(file->input);
}

void abox_file_close(struct abox_file *file)
{
	FUNC_START();
	abox_file_unlock(file);
	fs_file_deinit(&file->fs_file);
	file->cur_offset = (uoff_t)-1;
}

void abox_file_free(struct abox_file *file)
{
	FUNC_START();

	i_assert(file->refcount == 0);

	abox_file_close(file);
	i_free(file->primary_path);
	i_free(file->alt_path);
	i_free(file);
}

void abox_file_unref(struct abox_file **_file)
{
	FUNC_START();
	struct abox_file *file = *_file;

	*_file = NULL;

	i_assert(file->refcount > 0);
	if (--file->refcount == 0)
		abox_file_free(file);
}

int abox_file_unlink_aborted_save(struct abox_file *file)
{
	FUNC_START();
	int ret = 0;

	i_assert(file->fs_file != NULL);

	if (fs_delete(file->fs_file) < 0) {
		mailbox_set_critical(&file->mbox->box,
			"fs_delete(%s) failed: %m", file->cur_path);
		ret = -1;
	}
	FUNC_END_RET_INT(ret);
	return ret;
}

int abox_file_unlink(struct abox_file *file)
{
	FUNC_START();
	i_assert(file->fs_file != NULL);

	if (fs_delete(file->fs_file) < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"fs_delete(%s) failed: %m", file->primary_path);
		FUNC_END_RET_INT(-1);
		return -1;
	}
	FUNC_END_RET_INT(1);
	return 1;
}

int abox_file_seek(struct abox_file *file, uoff_t offset)
{
	FUNC_START();
	struct stat st;

	i_assert(file->input != NULL);

	if (offset == 0)
		offset = file->file_header_size;

	if (offset != file->cur_offset) {
		fs_stat(file->fs_file, &st);
		file->cur_offset = offset;
		file->cur_physical_size = st.st_size;
	}
	i_stream_seek(file->input, offset + file->msg_header_size);
	return 1;
}

struct abox_file_append_context *abox_file_append_init(struct abox_file *file)
{
	FUNC_START();
	struct abox_file_append_context *ctx;

	i_assert(!file->appending);

	file->appending = TRUE;

	ctx = i_new(struct abox_file_append_context, 1);
	ctx->file = file;
	if (file->fs_file != NULL) {
		FUNC_IN();
		ctx->output = fs_write_stream(file->fs_file);
	}
	return ctx;
}

int abox_file_append_commit(struct abox_file_append_context **_ctx)
{
	FUNC_START();
	struct abox_file_append_context *ctx = *_ctx;
	int ret;

	i_assert(ctx->file->appending);

	*_ctx = NULL;

	ret = fs_write_stream_finish(ctx->file->fs_file, &ctx->output);
	ctx->file->appending = FALSE;
	i_free(ctx);
	return ret;
}

void abox_file_append_rollback(struct abox_file_append_context **_ctx)
{
	FUNC_START();
	struct abox_file_append_context *ctx = *_ctx;
	struct abox_file *file = ctx->file;
	bool close_file = FALSE;

	i_assert(ctx->file->appending);

	*_ctx = NULL;
	if (ctx->first_append_offset == 0) {
		/* nothing changed */
	} else if (ctx->first_append_offset == file->file_header_size) {
		/* rolling back everything */
		if (fs_delete(file->fs_file) < 0)
			abox_file_set_syscall_error(file, "fs_delete()");
		close_file = TRUE;
	}
	fs_write_stream_abort_error(file->fs_file, &ctx->output, "rollback");
	i_free(ctx);

	if (close_file)
		abox_file_close(file);
	file->appending = FALSE;
}

int abox_file_append_flush(struct abox_file_append_context *ctx)
{
	FUNC_START();
	if (ctx->last_flush_offset == ctx->output->offset &&
	    ctx->last_checkpoint_offset == ctx->output->offset)
		return 0;

	if (fs_write_stream_finish(ctx->file->fs_file, &ctx->output) < 0)
	{
		abox_file_set_syscall_error(ctx->file, "fs_write_stream_finish()");
		return -1;
	}

	ctx->last_flush_offset = ctx->output->offset;
	return 0;
}

void abox_file_append_checkpoint(struct abox_file_append_context *ctx)
{
	ctx->last_checkpoint_offset = ctx->output->offset;
}

int abox_file_get_append_stream(struct abox_file_append_context *ctx,
				struct ostream **output_r)
{
	FUNC_START();

	if (ctx->output == NULL) {
		/* file creation had failed */
		FUNC_END_RET_INT(-1);
		return -1;
	}

	*output_r = ctx->output;
	FUNC_END_RET_INT(1);
	return 1;
}

const char *abox_file_metadata_get(struct abox_file *file, const char * key)
{
	FUNC_START();
	const char *value = NULL;
	fs_lookup_metadata(file->fs_file, key, &value);
	FUNC_END_RET(value);
	return value;
}

uoff_t abox_file_get_plaintext_size(struct abox_file *file)
{
	FUNC_START();
	const char *value;
	uintmax_t size;
	struct stat st;

	/* see if we have it in metadata */
	value = abox_file_metadata_get(file, ABOX_METADATA_PHYSICAL_SIZE);
	if (value == NULL ||
	    str_to_uintmax(value, &size) < 0 ||
	    size > (uoff_t)-1) {
		FUNC_IN();
		/* no. that means we can use the size from fs_stat */
		if (fs_stat(file->fs_file, &st) < 0) {
			i_error("abox_file_get_plaintext_size: fs_stat failed");
		}
		FUNC_END_RET_INT(st.st_size);
		return (uoff_t)st.st_size;
	}
	FUNC_END_RET_INT(st.st_size);
	return (uoff_t)size;
}

