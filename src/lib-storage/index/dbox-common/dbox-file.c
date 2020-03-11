/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hex-dec.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "istream.h"
#include "ostream.h"
#include "fs-api.h"
#include "file-lock.h"
#include "file-dotlock.h"
#include "mkdir-parents.h"
#include "eacces-error.h"
#include "str.h"
#include "dbox-storage.h"
#include "dbox-file.h"

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>

#define DBOX_READ_BLOCK_SIZE IO_BLOCK_SIZE

#ifndef DBOX_FILE_LOCK_METHOD_FLOCK
static const struct dotlock_settings dotlock_set = {
	.stale_timeout = 60*10,
	.use_excl_lock = TRUE
};
#endif

const char *dbox_generate_tmp_filename(void)
{
	FUNC_START();
	static unsigned int create_count = 0;

	return t_strdup_printf(DBOX_TEMP_FILE_PREFIX"%"PRIdTIME_T".P%sQ%uM%u.%s",
			       ioloop_timeval.tv_sec, my_pid,
			       create_count++,
			       (unsigned int)ioloop_timeval.tv_usec,
			       my_hostname);
}

void dbox_file_set_syscall_error(struct dbox_file *file, const char *function)
{
	FUNC_START();
	mail_storage_set_critical(&file->storage->storage,
				  "%s failed for file %s: %m",
				  function, file->cur_path);
}

void dbox_file_set_corrupted(struct dbox_file *file, const char *reason, ...)
{
	FUNC_START();
	va_list args;

	va_start(args, reason);
	mail_storage_set_critical(&file->storage->storage,
		"Corrupted dbox file %s (around offset=%"PRIuUOFF_T"): %s",
		file->cur_path, file->input == NULL ? 0 : file->input->v_offset,
		t_strdup_vprintf(reason, args));
	va_end(args);

	file->storage->v.set_file_corrupted(file);
}

void dbox_file_init(struct dbox_file *file)
{
	FUNC_START();
	file->refcount = 1;
	file->fs_file = file->storage->v.file_init_fs_file(file,
									file->primary_path, TRUE);
	file->cur_offset = (uoff_t)-1;
	file->cur_path = file->primary_path;
}

void dbox_file_free(struct dbox_file *file)
{
	FUNC_START();
	i_assert(file->refcount == 0);

	pool_unref(&file->metadata_pool);
	dbox_file_close(file);
	i_free(file->primary_path);
	i_free(file->alt_path);
	i_free(file);
}

void dbox_file_unref(struct dbox_file **_file)
{
	FUNC_START();
	struct dbox_file *file = *_file;

	*_file = NULL;

	i_assert(file->refcount > 0);
	if (--file->refcount == 0)
		file->storage->v.file_free(file);
}

static int dbox_file_parse_header(struct dbox_file *file, const char *line)
{
	FUNC_START();
	const char *const *tmp, *value;
	unsigned int pos;
	enum dbox_header_key key;

	file->file_version = *line - '0';
	if (!i_isdigit(line[0]) || line[1] != ' ' ||
	    (file->file_version != 1 && file->file_version != DBOX_VERSION)) {
		dbox_file_set_corrupted(file, "Invalid dbox version");
		return -1;
	}
	line += 2;
	pos = 2;

	file->msg_header_size = 0;

	for (tmp = t_strsplit(line, " "); *tmp != NULL; tmp++) {
		uintmax_t time;
		key = **tmp;
		value = *tmp + 1;

		switch (key) {
		case DBOX_HEADER_OLDV1_APPEND_OFFSET:
			break;
		case DBOX_HEADER_MSG_HEADER_SIZE:
			if (str_to_uint_hex(value, &file->msg_header_size) < 0) {
				dbox_file_set_corrupted(file, "Invalid message header size");
				return -1;
			}
			break;
		case DBOX_HEADER_CREATE_STAMP:
			if (str_to_uintmax_hex(value, &time) < 0) {
				dbox_file_set_corrupted(file, "Invalid create time stamp");
				return -1;
			}
			file->create_time = (time_t)time;
			break;
		}
		pos += strlen(value) + 2;
	}

	if (file->msg_header_size == 0) {
		dbox_file_set_corrupted(file, "Missing message header size");
		return -1;
	}
	return 0;
}

static int dbox_file_read_header(struct dbox_file *file)
{
	FUNC_START();
	const char *line;
	unsigned int hdr_size;
	int ret;

	i_stream_seek(file->input, 0);
	line = i_stream_read_next_line(file->input);
	if (line == NULL) {
		if (file->input->stream_errno == 0) {
			dbox_file_set_corrupted(file,
				"EOF while reading file header");
			return 0;
		}

		dbox_file_set_syscall_error(file, "read()");
		return -1;
	}
	hdr_size = file->input->v_offset;
	T_BEGIN {
		ret = dbox_file_parse_header(file, line) < 0 ? 0 : 1;
	} T_END;
	if (ret > 0)
		file->file_header_size = hdr_size;
	return ret;
}

static int dbox_file_open_fd(struct dbox_file *file, bool try_altpath ATTR_UNUSED)
{
	FUNC_START();
	// const char *path;
	int flags = FS_OPEN_MODE_REPLACE;
	// bool alt = FALSE;

	file->fs_file = fs_file_init(file->storage->mail_fs,
								 file->primary_path, flags);

	if (errno == EACCES && flags == FS_OPEN_MODE_REPLACE) {
		flags = FS_OPEN_MODE_READONLY;
	}

	file->cur_path = file->primary_path;
	return 1;
}

static int dbox_file_open_full(struct dbox_file *file, bool try_altpath,
			       bool *notfound_r)
{
	FUNC_START();
	int ret;

	*notfound_r = FALSE;
	if (file->input != NULL)
		return 1;

	if (file->fs_file == NULL) {
		T_BEGIN {
			ret = dbox_file_open_fd(file, try_altpath);
		} T_END;
		if (ret <= 0) {
			if (ret < 0)
				return -1;
			*notfound_r = TRUE;
			return 1;
		}
	}

	file->input = fs_read_stream(file->fs_file, DBOX_READ_BLOCK_SIZE);
	return 1;
}

int dbox_file_open(struct dbox_file *file, bool *deleted_r)
{
	FUNC_START();
	return dbox_file_open_full(file, TRUE, deleted_r);
}

int dbox_file_open_primary(struct dbox_file *file, bool *notfound_r)
{
	FUNC_START();
	return dbox_file_open_full(file, FALSE, notfound_r);
}

int dbox_file_stat(struct dbox_file *file, struct stat *st_r)
{
	FUNC_START();
	const char *path;
	bool alt = FALSE;

	if (dbox_file_is_open(file)) {
		if (fs_stat(file->fs_file, st_r) < 0) {
			mail_storage_set_critical(&file->storage->storage,
				"fstat(%s) failed: %m", file->cur_path);
			return -1;
		}
		return 0;
	}

	/* try the primary path first */
	path = file->primary_path;
	file->fs_file = fs_file_init(file->storage->mail_fs, path, FS_OPEN_MODE_READONLY);
	while (fs_stat(file->fs_file, st_r) < 0)
	{
		if (errno != ENOENT) {
			mail_storage_set_critical(&file->storage->storage,
						  "stat(%s) failed: %m", path);
			return -1;
		}

		if (file->alt_path == NULL || alt) {
			/* not found */
			return -1;
		}

		/* try the alternative path */
		path = file->alt_path;
		file->fs_file = fs_file_init(file->storage->mail_fs, path, FS_OPEN_MODE_READONLY);
		alt = TRUE;
	}
	fs_file_deinit(&file->fs_file);
	file->cur_path = path;
	return 0;
}

int dbox_file_header_write(struct dbox_file *file, struct ostream *output)
{
	FUNC_START();
	string_t *hdr;

	hdr = t_str_new(128);
	str_printfa(hdr, "%u %c%x %c%x\n", DBOX_VERSION,
		    DBOX_HEADER_MSG_HEADER_SIZE,
		    (unsigned int)sizeof(struct dbox_message_header),
		    DBOX_HEADER_CREATE_STAMP, (unsigned int)ioloop_time);

	file->file_version = DBOX_VERSION;
	file->file_header_size = str_len(hdr);
	file->msg_header_size = sizeof(struct dbox_message_header);
	return o_stream_send(output, str_data(hdr), str_len(hdr));
}

void dbox_file_close(struct dbox_file *file)
{
	FUNC_START();
	dbox_file_unlock(file);
	if (file->input != NULL) {
		i_stream_unref(&file->input);
	}
	fs_file_deinit(&file->fs_file);
	file->cur_offset = (uoff_t)-1;
}

int dbox_file_try_lock(struct dbox_file *file)
{
	FUNC_START();
	int ret;

	i_assert(file->fs_file != NULL);

	ret = fs_lock(file->fs_file, 10, &file->fs_lock);
	if (ret < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"file_try_lock(%s) failed: %m", file->cur_path);
	}

	return ret;
}

void dbox_file_unlock(struct dbox_file *file)
{
	FUNC_START();
	i_assert(!file->appending || file->fs_lock == NULL);

	if (file->fs_lock != NULL)
		fs_unlock(&file->fs_lock);

	if (file->input != NULL)
		i_stream_sync(file->input);
}

int dbox_file_read_mail_header(struct dbox_file *file, uoff_t *physical_size_r)
{
	FUNC_START();
	struct dbox_message_header hdr;
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_bytes(file->input, &data, &size,
				  file->msg_header_size);
	if (ret <= 0) {
		if (file->input->stream_errno == 0) {
			/* EOF, broken offset or file truncated */
			dbox_file_set_corrupted(file, "EOF reading msg header "
						"(got %"PRIuSIZE_T"/%u bytes)",
						size, file->msg_header_size);
			return 0;
		}
		dbox_file_set_syscall_error(file, "read()");
		return -1;
	}
	memcpy(&hdr, data, I_MIN(sizeof(hdr), file->msg_header_size));
	if (memcmp(hdr.magic_pre, DBOX_MAGIC_PRE, sizeof(hdr.magic_pre)) != 0) {
		/* probably broken offset */
		dbox_file_set_corrupted(file, "msg header has bad magic value");
		return 0;
	}

	if (data[file->msg_header_size-1] != '\n') {
		dbox_file_set_corrupted(file, "msg header doesn't end with LF");
		return 0;
	}

	*physical_size_r = hex2dec(hdr.message_size_hex,
				   sizeof(hdr.message_size_hex));
	return 1;
}

int dbox_file_seek(struct dbox_file *file, uoff_t offset)
{
	FUNC_START();
	// uoff_t size;
	// int ret;
	struct stat st;

	i_assert(file->input != NULL);

	if (offset == 0)
		offset = file->file_header_size;

	if (offset != file->cur_offset) {
		/* TODO: don't use msg header
		i_stream_seek(file->input, offset);
		ret = dbox_file_read_mail_header(file, &size);
		if (ret <= 0)
			return ret;
		*/
		fs_stat(file->fs_file, &st);
		file->cur_offset = offset;
		file->cur_physical_size = st.st_size;
	}
	i_stream_seek(file->input, offset + file->msg_header_size);
	return 1;
}

static int
dbox_file_seek_next_at_metadata(struct dbox_file *file, uoff_t *offset)
{
	FUNC_START();
	const char *line;
	size_t buf_size;
	int ret;

	i_stream_seek(file->input, *offset);
	if ((ret = dbox_file_metadata_skip_header(file)) <= 0)
		return ret;

	/* skip over the actual metadata */
	buf_size = i_stream_get_max_buffer_size(file->input);
	i_stream_set_max_buffer_size(file->input, (size_t)-1);
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == DBOX_METADATA_OLDV1_SPACE || *line == '\0') {
			/* end of metadata */
			break;
		}
	}
	i_stream_set_max_buffer_size(file->input, buf_size);
	*offset = file->input->v_offset;
	return 1;
}

void dbox_file_seek_rewind(struct dbox_file *file)
{
	FUNC_START();
	file->cur_offset = (uoff_t)-1;
}

int dbox_file_seek_next(struct dbox_file *file, uoff_t *offset_r, bool *last_r)
{
	FUNC_START();
	uoff_t offset;
	int ret;

	i_assert(file->input != NULL);

	if (file->cur_offset == (uoff_t)-1) {
		/* first mail. we may not have read the file at all yet,
		   so set the offset afterwards. */
		offset = 0;
	} else {
		offset = file->cur_offset + file->msg_header_size +
			file->cur_physical_size;
		if ((ret = dbox_file_seek_next_at_metadata(file, &offset)) <= 0) {
			*offset_r = file->cur_offset;
			return ret;
		}
		if (i_stream_read_eof(file->input)) {
			*last_r = TRUE;
			return 0;
		}
	}
	*offset_r = offset;

	*last_r = FALSE;

	ret = dbox_file_seek(file, offset);
	if (*offset_r == 0)
		*offset_r = file->file_header_size;
	return ret;
}

struct dbox_file_append_context *dbox_file_append_init(struct dbox_file *file)
{
	FUNC_START();
	struct dbox_file_append_context *ctx;

	i_assert(!file->appending);

	file->appending = TRUE;

	ctx = i_new(struct dbox_file_append_context, 1);
	ctx->file = file;
	if (file->fs_file != NULL) {
		ctx->output = fs_write_stream(file->fs_file);
	}
	return ctx;
}

int dbox_file_append_commit(struct dbox_file_append_context **_ctx)
{
	FUNC_START();
	struct dbox_file_append_context *ctx = *_ctx;
	int ret;

	i_assert(ctx->file->appending);

	*_ctx = NULL;

	ret = fs_write_stream_finish(ctx->file->fs_file, &ctx->output);
	ctx->file->appending = FALSE;
	i_free(ctx);
	return ret;
}

void dbox_file_append_rollback(struct dbox_file_append_context **_ctx)
{
	FUNC_START();
	struct dbox_file_append_context *ctx = *_ctx;
	struct dbox_file *file = ctx->file;
	bool close_file = FALSE;

	i_assert(ctx->file->appending);

	*_ctx = NULL;
	if (ctx->first_append_offset == 0) {
		/* nothing changed */
	} else if (ctx->first_append_offset == file->file_header_size) {
		/* rolling back everything */
		if (fs_delete(file->fs_file) < 0)
			dbox_file_set_syscall_error(file, "fs_delete()");
		close_file = TRUE;
	}
	fs_write_stream_abort_error(file->fs_file, &ctx->output, "rollback");
	i_free(ctx);

	if (close_file)
		dbox_file_close(file);
	file->appending = FALSE;
}

int dbox_file_append_flush(struct dbox_file_append_context *ctx)
{
	FUNC_START();
	if (ctx->last_flush_offset == ctx->output->offset &&
	    ctx->last_checkpoint_offset == ctx->output->offset)
		return 0;

	if (fs_write_stream_finish(ctx->file->fs_file, &ctx->output) < 0)
	{
		dbox_file_set_syscall_error(ctx->file, "fs_write_stream_finish()");
		return -1;
	}

	if (ctx->last_checkpoint_offset != ctx->output->offset) {
		/* TODO: is this needed with fs-api?
		if (ftruncate(ctx->file->fd, ctx->last_checkpoint_offset) < 0) {
			dbox_file_set_syscall_error(ctx->file, "ftruncate()");
			return -1;
		}
		*/
		if (o_stream_seek(ctx->output, ctx->last_checkpoint_offset) < 0) {
			dbox_file_set_syscall_error(ctx->file, "lseek()");
			return -1;
		}
	}

	/* TODO: is this needed with fs-api?
	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER) {
		if (fdatasync(ctx->file->fd) < 0) {
			dbox_file_set_syscall_error(ctx->file, "fdatasync()");
			return -1;
		}
	}
	*/
	ctx->last_flush_offset = ctx->output->offset;
	return 0;
}

void dbox_file_append_checkpoint(struct dbox_file_append_context *ctx)
{
	ctx->last_checkpoint_offset = ctx->output->offset;
}

int dbox_file_get_append_stream(struct dbox_file_append_context *ctx,
				struct ostream **output_r)
{
	FUNC_START();
	struct dbox_file *file = ctx->file;
	struct stat st;

	if (ctx->output == NULL) {
		/* file creation had failed */
		return -1;
	}
	if (ctx->last_checkpoint_offset != ctx->output->offset) {
		/* a message was aborted. don't try appending to this
		   file anymore. */
		return -1;
	}

	if (file->file_version == 0) {
		/* newly created file, write the file header */
		/*
		if (dbox_file_header_write(file, ctx->output) < 0) {
			dbox_file_set_syscall_error(file, "write()");
			return -1;
		}
		*/
		*output_r = ctx->output;
		return 1;
	}

	/* file has existing mails */
	if (file->file_version != DBOX_VERSION ||
	    file->msg_header_size != sizeof(struct dbox_message_header)) {
		/* created by an incompatible version, can't append */
		return 0;
	}

	if (ctx->output->offset == 0) {
		/* first append to existing file. seek to eof first. */
		if (fs_stat(file->fs_file, &st) < 0) {
			dbox_file_set_syscall_error(file, "fstat()");
			return -1;
		}
		if (st.st_size < file->msg_header_size) {
			dbox_file_set_corrupted(file,
				"dbox file size too small");
			return 0;
		}
		if (o_stream_seek(ctx->output, st.st_size) < 0) {
			dbox_file_set_syscall_error(file, "lseek()");
			return -1;
		}
	}
	*output_r = ctx->output;
	return 1;
}

int dbox_file_metadata_skip_header(struct dbox_file *file)
{
	FUNC_START();
	struct dbox_metadata_header metadata_hdr;
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_bytes(file->input, &data, &size,
				  sizeof(metadata_hdr));
	if (ret <= 0) {
		if (file->input->stream_errno == 0) {
			/* EOF, broken offset */
			dbox_file_set_corrupted(file,
				"Unexpected EOF while reading metadata header");
			return 0;
		}
		dbox_file_set_syscall_error(file, "read()");
		return -1;
	}
	memcpy(&metadata_hdr, data, sizeof(metadata_hdr));
	if (memcmp(metadata_hdr.magic_post, DBOX_MAGIC_POST,
		   sizeof(metadata_hdr.magic_post)) != 0) {
		/* probably broken offset */
		dbox_file_set_corrupted(file,
			"metadata header has bad magic value");
		return 0;
	}
	i_stream_skip(file->input, sizeof(metadata_hdr));
	return 1;
}

static int
dbox_file_metadata_read_at(struct dbox_file *file, uoff_t metadata_offset)
{
	FUNC_START();
	const char *line;
	size_t buf_size;
	int ret;

	if (file->metadata_pool != NULL)
		p_clear(file->metadata_pool);
	else {
		file->metadata_pool =
			pool_alloconly_create("dbox metadata", 1024);
	}
	p_array_init(&file->metadata, file->metadata_pool, 16);

	i_stream_seek(file->input, metadata_offset);
	if ((ret = dbox_file_metadata_skip_header(file)) <= 0)
		return ret;

	ret = 0;
	buf_size = i_stream_get_max_buffer_size(file->input);
	/* use unlimited line length for metadata */
	i_stream_set_max_buffer_size(file->input, (size_t)-1);
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == DBOX_METADATA_OLDV1_SPACE || *line == '\0') {
			/* end of metadata */
			ret = 1;
			break;
		}
		line = p_strdup(file->metadata_pool, line);
		array_push_back(&file->metadata, &line);
	}
	i_stream_set_max_buffer_size(file->input, buf_size);
	if (ret == 0)
		dbox_file_set_corrupted(file, "missing end-of-metadata line");
	return ret;
}

int dbox_file_metadata_read(struct dbox_file *file)
{
	FUNC_START();
	uoff_t metadata_offset;
	int ret;

	i_assert(file->cur_offset != (uoff_t)-1);

	if (file->metadata_read_offset == file->cur_offset)
		return 1;

	metadata_offset = file->cur_offset + file->msg_header_size +
		file->cur_physical_size;
	ret = dbox_file_metadata_read_at(file, metadata_offset);
	if (ret <= 0)
		return ret;

	file->metadata_read_offset = file->cur_offset;
	return 1;
}

const char *dbox_file_metadata_get(struct dbox_file *file,
				   enum dbox_metadata_key key)
{
	FUNC_START();
	const char *value = NULL;
	const char *key_c;
	struct stat st;

	switch (key) {
	case DBOX_METADATA_POP3_ORDER:
		key_c = SDBOX_METADATA_POP3_ORDER;
		break;
	case DBOX_METADATA_POP3_UIDL:
		key_c = SDBOX_METADATA_POP3_UIDL;
		break;
	case DBOX_METADATA_RECEIVED_TIME:
		key_c = SDBOX_METADATA_RECEIVED_TIME;
		break;
	case DBOX_METADATA_EXT_REF:
		key_c = SDBOX_METADATA_EXT_REF;
		break;
	case DBOX_METADATA_ORIG_MAILBOX:
		key_c = SDBOX_METADATA_ORIG_MAILBOX;
		break;
	case DBOX_METADATA_GUID:
		key_c = SDBOX_METADATA_GUID;
		break;
	case DBOX_METADATA_VIRTUAL_SIZE:
		key_c = SDBOX_METADATA_VIRTUAL_SIZE;
		if (fs_stat(file->fs_file, &st) >= 0) {
			value = i_strdup_printf("%llx", st.st_size);
		}
		break;
	case DBOX_METADATA_PHYSICAL_SIZE:
		key_c = SDBOX_METADATA_PHYSICAL_SIZE;
		break;
	default:
		i_unreached();
	}
	if (value == NULL) {
		fs_lookup_metadata(file->fs_file, key_c, &value);
	}
	return value;
}

uoff_t dbox_file_get_plaintext_size(struct dbox_file *file)
{
	FUNC_START();
	const char *value;
	uintmax_t size;
	struct stat st;

	/* see if we have it in metadata */
	value = dbox_file_metadata_get(file, DBOX_METADATA_PHYSICAL_SIZE);
	if (value == NULL ||
	    str_to_uintmax_hex(value, &size) < 0 ||
	    size > (uoff_t)-1) {
		/* no. that means we can use the size from fs_stat */
		if (fs_stat(file->fs_file, &st) < 0) {
			i_error("");
		}
		return (uoff_t)st.st_size;
	}
	return (uoff_t)size;
}

void dbox_msg_header_fill(struct dbox_message_header *dbox_msg_hdr,
			  uoff_t message_size)
{
	FUNC_START();
	memset(dbox_msg_hdr, ' ', sizeof(*dbox_msg_hdr));
	memcpy(dbox_msg_hdr->magic_pre, DBOX_MAGIC_PRE,
	       sizeof(dbox_msg_hdr->magic_pre));
	dbox_msg_hdr->type = DBOX_MESSAGE_TYPE_NORMAL;
	dec2hex(dbox_msg_hdr->message_size_hex, message_size,
		sizeof(dbox_msg_hdr->message_size_hex));
	dbox_msg_hdr->save_lf = '\n';
}

int dbox_file_unlink(struct dbox_file *file)
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
