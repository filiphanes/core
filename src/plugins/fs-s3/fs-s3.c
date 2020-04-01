/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "guid.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "fs-api-private.h"
#include "http-url.h"
#include "http-client.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#define FS_HTTP_META_PREFIX "x-amz-meta-"

extern const struct fs fs_class_s3;

struct http_client *fs_s3_http_client = NULL;

struct http_fs {
	struct fs fs;
	char *root_path;
	char *path_prefix;
	struct http_url *url;

	unsigned int slow_warn_msec;
	bool no_trace_headers;
	bool have_dirs;
};

struct s3_fs_file {
	struct fs_file file;
	pool_t pool;
	struct http_client_request *request;
	struct http_url *url;
	struct istream *payload;
	struct io *io;
	struct stat *st;
	enum fs_open_mode open_mode;

	buffer_t *buffer;
	int err;
	fs_file_async_callback_t *callback;
	void *callback_ctx;
};

struct http_fs_iter {
	struct fs_iter iter;
	char *path;
	int err;
};

static struct fs *fs_s3_alloc(void)
{
	FUNC_START();
	struct http_fs *fs;

	fs = i_new(struct http_fs, 1);
	fs->fs = fs_class_s3;
	return &fs->fs;
}

static int
fs_s3_init(struct fs *_fs, const char *args, const struct fs_settings *set,
	      const char **error_r)
{
	FUNC_START();
	struct http_fs *fs = container_of(_fs, struct http_fs, fs);
	struct http_client_settings http_set;
	const char *error;
	const char *const *tmp;
	const char *const *query_params;
	const char *arg;
	unsigned int uint;

	fs->fs.set.root_path = fs->root_path;

	if (http_url_parse(args, NULL, HTTP_URL_ALLOW_USERINFO_PART,
						default_pool, &fs->url, &error) < 0) {
		*error_r = t_strdup_printf("http_fs error while parsing settings url"
					" '%s': %s", args, error);
		return -1;
	}

	query_params = t_strsplit_spaces(
		fs->url->enc_query != NULL ? fs->url->enc_query : "", "&");

	for (tmp = query_params; *tmp != NULL; tmp++) {
		arg = *tmp;
		if (str_begins(arg, "prefix=")) {
			i_free(fs->path_prefix);
			fs->path_prefix = i_strdup(arg + 7);
		} else if (str_begins(arg, "no_trace_headers=")) {
			fs->no_trace_headers = (arg[6] == 'y' || arg[6] == '1');
		} else if (str_begins(arg, "slow_warn=")) {
			/* TODO: implement warning about slow requests */
			if (str_parse_uint(arg+10, &uint, NULL) < 0) {
				*error_r = t_strdup_printf("Invalid uint '%s'", arg);
				return -1;
			}
			fs->slow_warn_msec = uint * 1000;
		}
	}

	if (fs_s3_http_client != NULL)
		return 0;

	/* Setup http client settings */
	i_zero(&http_set);
	http_set.event_parent = set->event;
	http_set.max_idle_time_msecs = 5 * 1000;
	http_set.max_parallel_connections = 10;
	http_set.max_pipelined_requests = 10;
	http_set.ssl = set->ssl_client_set;
	http_set.dns_client = set->dns_client;

	for (tmp = query_params; *tmp != NULL; tmp++) {
		arg = *tmp;
		if (str_begins(arg, "rawlog_dir=")){
			http_set.rawlog_dir = i_strdup(arg + 11);
		} else if (str_begins(arg, "debug=") == 0) {
			http_set.debug = (arg[6] == 'y' || arg[6] == '1');
		} else if (str_begins(arg, "timeout=")) {
			if (str_parse_uint(arg+8, &uint, NULL) < 0) {
				*error_r = t_strdup_printf("Invalid uint '%s'", arg);
				return -1;
			}
			http_set.request_timeout_msecs = uint * 1000;
		} else if (str_begins(arg, "absolute_timeout=")) {
			if (str_parse_uint(arg+17, &uint, NULL) < 0) {
				*error_r = t_strdup_printf("Invalid uint '%s'", arg);
				return -1;
			}
			http_set.request_absolute_timeout_msecs = uint * 1000;
		} else if (str_begins(arg, "connect_timeout=")) {
			if (str_parse_uint(arg+16, &uint, NULL) < 0) {
				*error_r = t_strdup_printf("Invalid uint '%s'", arg);
				return -1;
			}
			http_set.connect_timeout_msecs = uint * 1000;
		} else if (str_begins(arg, "request_timeout=")) {
			if (str_parse_uint(arg+16, &uint, NULL) < 0) {
				*error_r = t_strdup_printf("Invalid uint '%s'", arg);
				return -1;
			}
			http_set.request_timeout_msecs = uint * 1000;
		} else if (str_begins(arg, "max_retries=")) {
			if (str_parse_uint(arg+12, &uint, NULL) < 0) {
				*error_r = t_strdup_printf("Invalid uint '%s'", arg);
				return -1;
			}
			http_set.max_attempts = uint * 1000;
		}
	}
	fs_s3_http_client = http_client_init(&http_set);

	return 0;
}

static void fs_s3_deinit(struct fs *_fs)
{
	FUNC_START();
	struct http_fs *fs = container_of(_fs, struct http_fs, fs);

	i_free(fs->url);
	i_free(fs->path_prefix);
	i_free(fs->root_path);
	i_free(fs);

	http_client_deinit(&fs_s3_http_client);
}

static enum fs_properties fs_s3_get_properties(struct fs *_fs)
{
	FUNC_START();
	struct http_fs *fs = container_of(_fs, struct http_fs, fs);
	enum fs_properties props =
		FS_PROPERTY_LOCKS | FS_PROPERTY_FASTCOPY | FS_PROPERTY_RENAME |
		FS_PROPERTY_STAT | FS_PROPERTY_ITER | FS_PROPERTY_RELIABLEITER;

	/* FS_PROPERTY_DIRECTORIES is not returned normally because fs_delete()
	   automatically rmdir()s parents. For backwards compatibility
	   (especially with SIS code) we'll do it that way, but optionally with
	   "dirs" parameter enable them. This is especially important to be
	   able to use doveadm fs commands to delete empty directories. */
	if (fs->have_dirs)
		props |= FS_PROPERTY_DIRECTORIES;
	return props;
}

static struct fs_file *fs_s3_file_alloc(void)
{
	FUNC_START();
	struct s3_fs_file *file;
	pool_t pool;

	pool = pool_alloconly_create("fs http file", 1024);
	file = p_new(pool, struct s3_fs_file, 1);
	file->pool = pool;
	return &file->file;
}

static void
fs_s3_file_init(struct fs_file *_file, const char *path,
		   enum fs_open_mode mode, enum fs_open_flags flags ATTR_UNUSED)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);
	struct http_fs *fs = container_of(_file->fs, struct http_fs, fs);
	guid_128_t guid;

	if (mode == FS_OPEN_MODE_APPEND || mode == FS_OPEN_MODE_CREATE) {
		fs_set_error(_file->event, ENOTSUP, "APPEND or CREATE not supported");
		return;
	}

	if (mode == FS_OPEN_MODE_CREATE_UNIQUE_128) {
		guid_128_generate(guid);
		_file->path = p_strdup_printf(file->pool, "%s/%s", path,
									  guid_128_to_string(guid));
	} else {
		_file->path = p_strdup(file->pool, path);
	}

	file->url = p_memdup(file->pool, fs->url, sizeof(struct http_url));
	file->url->enc_query = NULL;
	file->url->enc_fragment = NULL;
	file->url->path = fs->path_prefix == NULL ?
		p_strdup(file->pool, _file->path) :
		p_strconcat(file->pool, fs->path_prefix, _file->path, NULL);
	file->open_mode = mode;
	file->st = p_new(file->pool, struct stat, 1);
}

static void fs_s3_file_deinit(struct fs_file *_file)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);

	i_assert(_file->output == NULL);

	if (file->buffer != NULL) {
		buffer_free(&file->buffer);
	}
	fs_file_free(_file);
	pool_unref(&file->pool);
	FUNC_END();
}

static void fs_s3_file_close(struct fs_file *_file)
{
	FUNC_START();
	struct s3_fs_file *file = container_of(_file, struct s3_fs_file, file);
	if (file->payload != NULL) {
		// i_stream_destroy(&file->payload);
	}
	FUNC_END();
}

static void
fs_s3_set_async_callback(struct fs_file *_file,
		fs_file_async_callback_t *callback, void *context)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);
	file->callback = callback;
	file->callback_ctx = context;
}

static void
fs_s3_wait_async(struct fs *_fs ATTR_UNUSED)
{
	FUNC_START();
	http_client_wait(fs_s3_http_client);
}

static void
fs_s3_add_trace_headers(struct fs_file *_file)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);
	struct http_fs *fs =
		container_of(_file->fs, struct http_fs, fs);

	if (fs->no_trace_headers)
		return;

	http_client_request_add_header(file->request, "X-Dovecot-Username",
								   _file->fs->username);
	http_client_request_add_header(file->request, "X-Dovecot-Session-Id",
			_file->fs->session_id);
	/* TODO: somehow get reason from box->reason, maybe via metadata
	const char *val = NULL;
	if (fs_lookup_metadata(_file, FS_METADATA_REASON, &val) >= 0 && val != NULL) {
		http_client_request_add_header(file->request, "X-Dovecot-Reason", val);
	}
	*/
}

static void
fs_s3_add_metadata_headers(struct fs_file *_file)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);
	const struct fs_metadata *metadata;
	const char *val = NULL;
	string_t *hdrkey = str_new(file->pool, 64);
	str_append(hdrkey, FS_HTTP_META_PREFIX);

	array_foreach(&_file->metadata, metadata) {
		if (str_begins(metadata->key, FS_METADATA_INTERNAL_PREFIX))
			continue;
		/* truncate to keep prefix */
		buffer_set_used_size(hdrkey, strlen(FS_HTTP_META_PREFIX));
		// TODO: escape metadata->key
		str_append(hdrkey, metadata->key);
		http_client_request_add_header(file->request,
			str_c(hdrkey), metadata->value);
	}

	if (fs_lookup_metadata(_file, FS_METADATA_OBJECTID, &val) >= 0) {
		if (val != NULL) {
			http_client_request_add_header(file->request, "X-ObjectID", val);
		}
	} else if (errno == ENOTSUP) {
		i_debug("Metadata not supported!");
	} // TODO: else if (errno == EAGAIN){

	str_free(&hdrkey);
}

/* Used for reading error response data for debugging */
static void
read_response_payload(struct s3_fs_file *file)
{
	FUNC_START();
	const unsigned char *data;
	size_t size;
	int ret;

	if (file->payload == NULL) {
		FUNC_END_RET("payload == NULL");
		return;
	}
	FUNC_IN();
	if (file->buffer == NULL) {
		file->buffer = buffer_create_dynamic(file->pool, 64*1024);
	}
	FUNC_IN();
	if (file->io == NULL){
		buffer_set_used_size(file->buffer, 0);
		i_stream_ref(file->payload);
		file->io = io_add_istream(file->payload, read_response_payload, file);
	}
	FUNC_IN();
	/* read payload */
	while ((ret = i_stream_read_more(file->payload, &data, &size)) >= 0) {
		buffer_append(file->buffer, data, size);
		i_stream_skip(file->payload, size);
	}

	if (ret == 0) {
		FUNC_IN();
		/* we will be called again for more data */
	} else {
		FUNC_IN();
		if (file->payload->stream_errno != 0) {
			i_assert(ret < 0);
			i_error("fs_s3: failed to read HTTP payload: %s",
				i_stream_get_error(file->payload));
		}
		io_remove(&file->io);
		i_stream_unref(&file->payload);
	}
	FUNC_END();
}

static void
fs_s3_response_callback(const struct http_response *response,
		    		 struct fs_file *_file)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);
	const struct http_header_field *field;
	const ARRAY_TYPE(http_header_field) *header_fields;
	const char *name;

	i_debug("HTTP %u %s", response->status, response->reason);
	switch (response->status) {
	case 200: /* OK, usually on GET */
	case 201: /* Created, usually on PUT */
	case 202: /* Accepted, on DELETE */
	case 204: /* No Content, PUT without change */
	case 206: /* Partial Content, GET with range */
		FUNC_IN();
		file->err = 0;
		break;
	case 403: /* Forbidden */
		file->err = EPERM;
		break;
	case 404: /* Not found */
		file->err = ENOENT;
		break;
	case 405: /* Method Not Allowed */
		file->err = ENOTSUP;
		break;
	default:
		file->err = EIO;
		break;
	}
	if (file->err > 0) {
		fs_set_error(_file->event, file->err, "%u %s",
					 response->status, response->reason);
	}
	FUNC_IN();

	// Read metadata and st_size
	header_fields = http_response_header_get_fields(response);
	array_foreach(header_fields, field) {
		if (str_begins(field->name, FS_HTTP_META_PREFIX)) {
			name = field->name + strlen(FS_HTTP_META_PREFIX);
			fs_default_set_metadata(&file->file, name, field->value);
		} else if (strcasecmp(field->name, "Content-Length") == 0) {
			if (str_to_int64(field->value, &file->st->st_size) < 0) {
				i_error("fs_s3: Content-Length not int64: %s", field->value);
			}
		} else if (strcasecmp(field->name, "X-ObjectID") == 0) {
			fs_default_set_metadata(&file->file,
							FS_METADATA_OBJECTID, field->value);
		}
	}

	FUNC_IN();
	/* Read payload to response->buffer */
	i_assert(file->payload == NULL);
	file->payload = response->payload;
	read_response_payload(file);

	file->request = NULL;
	FUNC_END();
}

static int fs_s3_open_for_read(struct fs_file *_file)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);

	i_assert(_file->output == NULL);

	if (file->request != NULL) {
		return 0;
	}
	file->err = -1;
	file->request = http_client_request_url(fs_s3_http_client,
			"GET", file->url, fs_s3_response_callback, _file);

	fs_s3_add_trace_headers(_file);
	http_client_request_submit(file->request);

	FUNC_END_RET_INT(0);
	return 0;
}

static bool fs_s3_prefetch(struct fs_file *_file, uoff_t length ATTR_UNUSED)
{
	FUNC_START();
	return TRUE;
}

static struct istream *
fs_s3_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);

	fs_s3_open_for_read(_file);
	FUNC_IN();
	http_client_wait(fs_s3_http_client);

	i_assert(file->payload == NULL);

	if (file->err > 0) {
		i_debug("fs_s3_read_stream: status=%d", file->err);
		file->payload = i_stream_create_error(file->err);
	} else if (file->buffer == NULL) {
		i_debug("fs_s3_read_stream: file->buffer == NULL");
		file->payload = i_stream_create_error(file->err);
	} else {
		FUNC_IN();
		file->payload = i_stream_create_from_buffer(file->buffer);
		i_stream_set_max_buffer_size(file->payload, max_buffer_size);
		i_stream_set_name(file->payload, file->url->path);
		FUNC_END_RET(file->url->path);
	}

	FUNC_END();
	return file->payload;
}

static void fs_s3_write_rename_if_needed(struct s3_fs_file *file)
{
	FUNC_START();
	struct fs_file *_file = &file->file;
	struct http_fs *fs = container_of(_file->fs, struct http_fs, fs);
	const char *new_fname;

	if (fs_lookup_metadata(_file, FS_METADATA_WRITE_FNAME, &new_fname) < 0) {
		if (errno == ENOTSUP)
			i_debug("Metadata not supported.");
	}
	FUNC_IN();
	if (new_fname == NULL)
		return;
	FUNC_IN();

	p_free(file->pool, _file->path);
	_file->path = p_strdup(file->pool, new_fname);
	FUNC_IN();

	p_free(file->pool, file->url->path);
	file->url->path = fs->path_prefix == NULL ?
		p_strdup(file->pool, _file->path) :
		p_strconcat(file->pool, fs->path_prefix, _file->path, NULL);
	FUNC_END();
}

static void fs_s3_write_stream(struct fs_file *_file)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);

	i_assert(_file->output == NULL);

	file->buffer = buffer_create_dynamic(file->pool, 64*1024);
	_file->output = o_stream_create_buffer(file->buffer);

	o_stream_set_name(_file->output, _file->path);
}

static int fs_s3_write_stream_finish(struct fs_file *_file, bool success)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);
	int ret = success ? 0 : -1;

	if (file->request == NULL) {
		i_assert(file->open_mode != FS_OPEN_MODE_READONLY);
		fs_s3_write_rename_if_needed(file);
		o_stream_destroy(&_file->output);

		/* Create and submit request */
		file->err = -1;
		file->request = http_client_request_url(fs_s3_http_client,
			"PUT", file->url, fs_s3_response_callback, _file);
		fs_s3_add_trace_headers(_file);
		fs_s3_add_metadata_headers(_file);

		http_client_request_set_payload_data(file->request,
				file->buffer->data, file->buffer->used);
		http_client_request_submit(file->request);
		buffer_free(&file->buffer);
	}

	while (file->err < 0) {
		if ((_file->flags & FS_OPEN_FLAG_ASYNC) != 0) {
			errno = EAGAIN;
			return -1;
		}
		/* block */
		http_client_wait(fs_s3_http_client);
	}

	if (file->err > 0) {
		fs_set_error(_file->event, file->err, "PUT %s returned %s %s",
				file->url->path, fs_file_last_error(_file),
				str_c(file->buffer));
		return -1;
	}

	return ret < 0 ? -1 : 1;
}

static int fs_s3_stat(struct fs_file *_file, struct stat *st_r)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);

	i_assert(_file->output == NULL);

	/* Fire request if we don't know size or request is not created */
	if (file->st->st_size == NULL && file->request == NULL) {
		FUNC_IN();
		file->err = -1;
		file->request = http_client_request_url(fs_s3_http_client,
				"HEAD", file->url, fs_s3_response_callback, _file);
		FUNC_IN();
		fs_s3_add_trace_headers(_file);
		FUNC_IN();
		http_client_request_submit(file->request);
	}

	while (file->err < 0) {
		if ((_file->flags & FS_OPEN_FLAG_ASYNC) != 0) {
			FUNC_IN();
			errno = EAGAIN;
			return -1;
		}
		/* block */
		http_client_wait(fs_s3_http_client);
	}

	if (file->err > 0) {
		fs_set_error(_file->event, file->err, "HEAD %s returned %s",
				file->url->path, fs_file_last_error(_file));
		FUNC_END_RET_INT(-1);
		return -1;
	}
	i_zero(st_r);
	st_r->st_size = file->st->st_size;
	FUNC_END_RET_INT(0);
	return 0;
}

static int fs_s3_delete(struct fs_file *_file)
{
	FUNC_START();
	struct s3_fs_file *file =
		container_of(_file, struct s3_fs_file, file);

	if (file->request == NULL) {
		file->err = -1;
		file->request = http_client_request_url(fs_s3_http_client,
				"DELETE", file->url, fs_s3_response_callback, _file);
		fs_s3_add_trace_headers(_file);
		http_client_request_submit(file->request);
	}

	while (file->err < 0) {
		if ((_file->flags & FS_OPEN_FLAG_ASYNC) != 0) {
			errno = EAGAIN;
			FUNC_END_RET_INT(-1);
			return -1;
		}
		/* block */
		http_client_wait(fs_s3_http_client);
	}

	if (file->err > 0) {
		fs_set_error(_file->event, file->err, "DELETE %s returned %s %s",
				file->url->path, fs_file_last_error(_file),
				str_c(file->buffer));
		FUNC_END_RET_INT(-1);
		return -1;
	}

	FUNC_END_RET_INT(0);
	return 0;
}

static struct fs_iter *fs_s3_iter_alloc(void)
{
	FUNC_START();
	struct http_fs_iter *iter = i_new(struct http_fs_iter, 1);
	return &iter->iter;
}

// TODO: implement
static void
fs_s3_iter_init(struct fs_iter *_iter, const char *path,
		   enum fs_iter_flags flags ATTR_UNUSED)
{
	FUNC_START();
/*
	struct http_fs_iter *iter =
		container_of(_iter, struct http_fs_iter, iter);

	iter->path = i_strdup(path);
	if (iter->path[0] == '\0') {
		i_free(iter->path);
		iter->path = i_strdup(".");
	}
	iter->dir = opendir(iter->path);
	if (iter->dir == NULL && errno != ENOENT) {
		iter->err = errno;
		fs_set_error_errno(_iter->event,
				   "opendir(%s) failed: %m", iter->path);
	}
*/
}

// TODO: implement
static bool fs_s3_iter_want(struct http_fs_iter *iter, const char *fname)
{
	FUNC_START();
	bool ret;

	T_BEGIN {
/*
		const char *path = t_strdup_printf("%s/%s", iter->path, fname);
		struct stat st;

		if (stat(path, &st) < 0 &&
		    lstat(path, &st) < 0)
			ret = FALSE;
		else if (!S_ISDIR(st.st_mode))
			ret = (iter->iter.flags & FS_ITER_FLAG_DIRS) == 0;
		else
			ret = (iter->iter.flags & FS_ITER_FLAG_DIRS) != 0;
*/
	} T_END;
	return ret;
}

// TODO: implement
static const char *fs_s3_iter_next(struct fs_iter *_iter)
{
	FUNC_START();
/*
	struct http_fs_iter *iter =
		container_of(_iter, struct http_fs_iter, iter);

	if (iter->dir == NULL)
		return NULL;

	errno = 0;
	for (; (d = readdir(iter->dir)) != NULL; errno = 0) {
		if (strcmp(d->d_name, ".") == 0 ||
		    strcmp(d->d_name, "..") == 0)
			continue;
		if (fs_s3_iter_want(iter, d->d_name))
			return d->d_name;
	}
	if (errno != 0) {
		iter->err = errno;
		fs_set_error_errno(_iter->event,
				   "readdir(%s) failed: %m", iter->path);
	}
*/
	return NULL;
}

static int fs_s3_iter_deinit(struct fs_iter *_iter)
{
	FUNC_START();
	struct http_fs_iter *iter =
		container_of(_iter, struct http_fs_iter, iter);
	int ret = 0;

/*
	if (iter->dir != NULL && closedir(iter->dir) < 0 && iter->err == 0) {
		iter->err = errno;
		fs_set_error_errno(_iter->event,
				   "closedir(%s) failed: %m", iter->path);
	}
	if (iter->err != 0) {
		errno = iter->err;
		ret = -1;
	}
*/
	i_free(iter->path);
	return ret;
}

const struct fs fs_class_s3 = {
	.name = "s3",
	.v = {
		fs_s3_alloc,
		fs_s3_init,
		fs_s3_deinit,
		fs_s3_get_properties,
		fs_s3_file_alloc,
		fs_s3_file_init,
		fs_s3_file_deinit,
		fs_s3_file_close,
		NULL /* get_path */,
		fs_s3_set_async_callback,
		fs_s3_wait_async,
		fs_default_set_metadata,
		NULL /* get_metadata */,
		fs_s3_prefetch,
		NULL /* read */,
		fs_s3_read_stream,
		NULL /* write */,
		fs_s3_write_stream,
		fs_s3_write_stream_finish,
		NULL /* lock */,
		NULL /* unlock */,
		NULL /* exists */,
		fs_s3_stat,
		fs_default_copy,
		NULL /* rename */,
		fs_s3_delete,
		fs_s3_iter_alloc,
		fs_s3_iter_init,
		fs_s3_iter_next,
		fs_s3_iter_deinit,
		NULL,
		NULL,
	}
};
