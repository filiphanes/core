/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "guid.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "fs-api-private.h"
#include "http-url.h"
#include "http-client.h"

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_MKDIR_RETRY_COUNT 5
#define FS_HTTP_META_PREFIX "X-Meta-"


struct http_client *fs_http_client = NULL;

struct http_fs {
	struct fs fs;
	char *root_path;
	char *path_prefix;
	struct http_url *url;

	unsigned int slow_warn_msec;
	bool no_trace_headers;
	bool have_dirs;
};

struct http_fs_file {
	struct fs_file file;
	pool_t pool;
	struct http_client_request *request;
	struct http_url *url;
	struct istream *i_payload;
	struct stat *st;
	enum fs_open_mode open_mode;

	buffer_t *write_buf;
	int response_status;
	string_t *response_data;
	fs_file_async_callback_t *callback;
	void *callback_ctx;
};

struct http_fs_iter {
	struct fs_iter iter;
	char *path;
	DIR *dir;
	int err;
};

static struct fs *fs_http_alloc(void)
{
	FUNC_START();
	struct http_fs *fs;

	fs = i_new(struct http_fs, 1);
	fs->fs = fs_class_http;
	return &fs->fs;
}

static int
fs_http_init(struct fs *_fs, const char *args, const struct fs_settings *set,
	      const char **error_r)
{
	FUNC_START();
	struct http_fs *fs = container_of(_fs, struct http_fs, fs);
	struct http_client_settings http_set;
	const char *error;
	const char *const *tmp;
	unsigned int uint;

	fs->fs.set.root_path = fs->root_path;

	if (http_url_parse(args, NULL, HTTP_URL_ALLOW_USERINFO_PART,
						default_pool, &fs->url, &error) < 0) {
		*error_r = t_strdup_printf("http_fs error while parsing settings url"
					" '%s': %s", args, error);
		return -1;
	}

	i_zero(&http_set);
	http_set.event_parent = set->event;

	tmp = t_strsplit_spaces(fs->url->enc_query, "&");
	for (; *tmp != NULL; tmp++) {
		const char *arg = *tmp;
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
		} else if (str_begins(arg, "rawlog_dir=")) {
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

	if (fs_http_client == NULL) {
		http_set.max_idle_time_msecs = 5*1000;
		http_set.max_parallel_connections = 10;
		http_set.max_pipelined_requests = 10;
		http_set.max_redirects = 1;
		http_set.max_attempts = 3;
		http_set.connect_timeout_msecs = 5*1000;
		http_set.ssl = set->ssl_client_set;
		http_set.dns_client = set->dns_client;
		fs_http_client = http_client_init(&http_set);
	}

	return 0;
}

static void fs_http_deinit(struct fs *_fs)
{
	FUNC_START();
	struct http_fs *fs = container_of(_fs, struct http_fs, fs);

	i_free(fs->url);
	i_free(fs->path_prefix);
	i_free(fs->root_path);
	i_free(fs);

	http_client_deinit(&fs_http_client);
}

static enum fs_properties fs_http_get_properties(struct fs *_fs)
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

static struct fs_file *fs_http_file_alloc(void)
{
	FUNC_START();
	struct http_fs_file *file;
	pool_t pool;

	pool = pool_alloconly_create("fs http file", 1024);
	file = p_new(pool, struct http_fs_file, 1);
	file->pool = pool;
	return &file->file;
}

static void
fs_http_file_init(struct fs_file *_file, const char *path,
		   enum fs_open_mode mode, enum fs_open_flags flags ATTR_UNUSED)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);
	struct http_fs *fs = container_of(_file->fs, struct http_fs, fs);
	guid_128_t guid;

	i_assert(mode != FS_OPEN_MODE_APPEND); /* not supported */
	i_assert(mode != FS_OPEN_MODE_CREATE); /* not supported */

	if (mode != FS_OPEN_MODE_CREATE_UNIQUE_128)
		file->file.path = p_strdup(file->pool, path);
	else {
		guid_128_generate(guid);
		file->file.path = p_strdup_printf(file->pool, "%s/%s", path,
						  guid_128_to_string(guid));
	}

	file->url = p_memdup(file->pool, fs->url, sizeof(struct http_url));
	file->url->enc_query = NULL;
	file->url->enc_fragment = NULL;
	file->url->path = fs->path_prefix == NULL ?
		p_strdup(file->pool, file->file.path) :
		p_strconcat(file->pool, fs->path_prefix, file->file.path, NULL);
	file->response_data = str_new(file->pool, 256);
	file->open_mode = mode;
	file->st = p_new(file->pool, struct stat, 1);
}

static void fs_http_file_deinit(struct fs_file *_file)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);

	i_assert(_file->output == NULL);

	fs_file_free(_file);
	FUNC_IN();
	pool_unref(&file->pool);
	FUNC_END();
}

static void
fs_http_set_async_callback(struct fs_file *_file,
		fs_file_async_callback_t *callback, void *context)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);
	file->callback = callback;
	file->callback_ctx = context;
}

static void
fs_http_wait_async(struct fs *_fs ATTR_UNUSED)
{
	FUNC_START();
	http_client_wait(fs_http_client);
}

static void
fs_http_add_trace_headers(struct fs_file *_file)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);
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
fs_http_add_metadata_headers(struct fs_file *_file)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);
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

static void
fs_http_response_callback(const struct http_response *response,
		    		 struct http_fs_file *file)
{
	FUNC_START();
	const struct http_header_field *field;
	const ARRAY_TYPE(http_header_field) *header_fields;
	const unsigned char *data;
	const char *name;
	size_t size;

	file->response_status = response->status;
	if (response->status / 100 != 2) {
		i_error("HTTP Response status: %u %s", response->status, response->reason);
		return;
	}

	// Read metadata and st_size
	header_fields = http_response_header_get_fields(response);
	array_foreach(header_fields, field) {
		if (str_begins(field->name, FS_HTTP_META_PREFIX)) {
			name = field->name + strlen(FS_HTTP_META_PREFIX);
			fs_default_set_metadata(&file->file,
							name, field->value);
		} else if (strcasecmp(field->name, "Content-Length") == 0) {
			if (str_to_int64(field->value, &file->st->st_size) < 0) {
				i_error("fs_http: Content-Length is not int: %s",
						field->value);
			}
		} else if (strcasecmp(field->name, "X-ObjectID") == 0) {
			fs_default_set_metadata(&file->file,
							FS_METADATA_OBJECTID, field->value);
		}
	}

	str_truncate(file->response_data, 0);

	if (response->payload == NULL) {
		return;
	}

	file->response_data = buffer_create_dynamic(file->pool, 256);
	while ((i_stream_read_more(response->payload, &data, &size)) > 0) {
		str_append_data(file->response_data, data, size);
		i_stream_skip(response->payload, size);
	}

	if (file->callback != NULL) {
		file->callback(file->callback_ctx);
	}
	file->request = NULL;
	FUNC_END();
}

static int fs_http_open_for_read(struct fs_file *_file)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);

	i_assert(_file->output == NULL);

	if (file->request != NULL)
		return 0;

	file->response_status = 0;
	file->request = http_client_request_url(fs_http_client,
			"GET", file->url, fs_http_response_callback, file);

	fs_http_add_trace_headers(_file);
	http_client_request_submit(file->request);

	return 0;
}

static bool fs_http_prefetch(struct fs_file *_file, uoff_t length ATTR_UNUSED)
{
	FUNC_START();
	return fs_http_open_for_read(_file) < 0;
}

static struct istream *
fs_http_read_stream(struct fs_file *_file, size_t max_buffer_size)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);

	fs_http_open_for_read(_file);
	// TODO: return non-blocking stream from http response
	http_client_wait(fs_http_client);

	if (file->response_status / 100 == 2) {
		file->i_payload = i_stream_create_from_buffer(file->response_data);
	} else {
		file->i_payload = i_stream_create_error_str(errno, "%s",
								fs_file_last_error(_file));
	}

	i_stream_set_max_buffer_size(file->i_payload, max_buffer_size);
	i_stream_set_name(file->i_payload, file->url->path);
	return file->i_payload;
}

static void fs_http_write_rename_if_needed(struct http_fs_file *file)
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

static void fs_http_write_stream(struct fs_file *_file)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);

	i_assert(_file->output == NULL);

	// TODO: stream directly to http i_stream payload if possible
	file->write_buf = buffer_create_dynamic(file->pool, 64*1024);
	_file->output = o_stream_create_buffer(file->write_buf);

	o_stream_set_name(_file->output, file->url->path);
	file->response_status = 0;
}

static int fs_http_write_stream_finish(struct fs_file *_file, bool success)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);
	int ret = success ? 0 : -1;

	if (file->request == NULL) {
		i_assert(file->open_mode != FS_OPEN_MODE_READONLY);

		fs_http_write_rename_if_needed(file);

		/* Create and submit request */
		o_stream_destroy(&_file->output);

		file->response_status = 0;
		file->request = http_client_request_url(fs_http_client,
			"PUT", file->url, fs_http_response_callback, file);
		fs_http_add_trace_headers(_file);
		fs_http_add_metadata_headers(_file);
		// TODO: maybe implement 100 Continue
		http_client_request_set_payload_data(file->request,
				file->write_buf->data, file->write_buf->used);
		http_client_request_submit(file->request);
		buffer_free(&file->write_buf);
	}

	while (file->response_status <= 0) {
		if ((_file->flags & FS_OPEN_FLAG_ASYNC) != 0) {
			errno = EAGAIN;
			return -1;
		}
		/* block */
		http_client_wait(fs_http_client);
	}

	if (file->response_status / 100 == 2) {
		ret = 1;
	} else {
		ret = -1;
		fs_set_error(_file->event, EIO, "PUT %s returned status %d: %s",
				file->url->path, file->response_status, str_c(file->response_data));
	}

	return ret < 0 ? -1 : 1;
}

static int fs_http_stat(struct fs_file *_file, struct stat *st_r)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);
	int ret = 0;

	i_assert(_file->output == NULL);

	/* Fire request if we don't know size or request is not created */
	if (file->st->st_size == 0 && file->request == NULL) {
		FUNC_IN();
		file->response_status = 0;
		file->request = http_client_request_url(fs_http_client,
				"HEAD", file->url, fs_http_response_callback, file);
		FUNC_IN();
		fs_http_add_trace_headers(_file);
		FUNC_IN();
		http_client_request_submit(file->request);
	}

	while (file->response_status <= 0) {
		if ((_file->flags & FS_OPEN_FLAG_ASYNC) != 0) {
			FUNC_IN();
			errno = EAGAIN;
			return -1;
		}
		/* block */
		http_client_wait(fs_http_client);
	}

	if (file->response_status / 100 != 2) {
		ret = -1;
		fs_set_error(_file->event, EIO, "HEAD %s returned status %d",
				file->url->path, file->response_status);
	} else {
		FUNC_IN();
		i_zero(st_r);
		st_r->st_size = file->st->st_size;
	}
	FUNC_END();

	return ret;
}

static int fs_http_delete(struct fs_file *_file)
{
	FUNC_START();
	struct http_fs_file *file =
		container_of(_file, struct http_fs_file, file);

	if (file->request == NULL) {
		file->response_status = 0;
		file->request = http_client_request_url(fs_http_client,
				"DELETE", file->url, fs_http_response_callback, file);
		fs_http_add_trace_headers(_file);
		http_client_request_submit(file->request);
	}

	while (file->response_status <= 0) {
		if ((_file->flags & FS_OPEN_FLAG_ASYNC) != 0) {
			errno = EAGAIN;
			return -1;
		}
		/* block */
		http_client_wait(fs_http_client);
	}

	if (file->response_status / 100 != 2) {
		fs_set_error(_file->event, EIO, "HEAD %s returned status %d: %s",
				file->url->path, file->response_status, str_c(file->response_data));
		return -1;
	}

	return 0;
}

static struct fs_iter *fs_http_iter_alloc(void)
{
	FUNC_START();
	struct http_fs_iter *iter = i_new(struct http_fs_iter, 1);
	return &iter->iter;
}

static void
fs_http_iter_init(struct fs_iter *_iter, const char *path,
		   enum fs_iter_flags flags ATTR_UNUSED)
{
	FUNC_START();
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
}

static bool fs_http_iter_want(struct http_fs_iter *iter, const char *fname)
{
	FUNC_START();
	bool ret;

	T_BEGIN {
		const char *path = t_strdup_printf("%s/%s", iter->path, fname);
		struct stat st;

		if (stat(path, &st) < 0 &&
		    lstat(path, &st) < 0)
			ret = FALSE;
		else if (!S_ISDIR(st.st_mode))
			ret = (iter->iter.flags & FS_ITER_FLAG_DIRS) == 0;
		else
			ret = (iter->iter.flags & FS_ITER_FLAG_DIRS) != 0;
	} T_END;
	return ret;
}

static const char *fs_http_iter_next(struct fs_iter *_iter)
{
	FUNC_START();
	struct http_fs_iter *iter =
		container_of(_iter, struct http_fs_iter, iter);
	struct dirent *d;

	if (iter->dir == NULL)
		return NULL;

	errno = 0;
	for (; (d = readdir(iter->dir)) != NULL; errno = 0) {
		if (strcmp(d->d_name, ".") == 0 ||
		    strcmp(d->d_name, "..") == 0)
			continue;
		if (fs_http_iter_want(iter, d->d_name))
			return d->d_name;
	}
	if (errno != 0) {
		iter->err = errno;
		fs_set_error_errno(_iter->event,
				   "readdir(%s) failed: %m", iter->path);
	}
	return NULL;
}

static int fs_http_iter_deinit(struct fs_iter *_iter)
{
	FUNC_START();
	struct http_fs_iter *iter =
		container_of(_iter, struct http_fs_iter, iter);
	int ret = 0;

	if (iter->dir != NULL && closedir(iter->dir) < 0 && iter->err == 0) {
		iter->err = errno;
		fs_set_error_errno(_iter->event,
				   "closedir(%s) failed: %m", iter->path);
	}
	if (iter->err != 0) {
		errno = iter->err;
		ret = -1;
	}
	i_free(iter->path);
	return ret;
}

const struct fs fs_class_http = {
	.name = "http",
	.v = {
		fs_http_alloc,
		fs_http_init,
		fs_http_deinit,
		fs_http_get_properties,
		fs_http_file_alloc,
		fs_http_file_init,
		fs_http_file_deinit,
		NULL /* file_close */,
		NULL /* get_path */,
		fs_http_set_async_callback,
		fs_http_wait_async,
		fs_default_set_metadata,
		NULL /* get_metadata */,
		fs_http_prefetch,
		NULL /* read */,
		fs_http_read_stream,
		NULL /* write */,
		fs_http_write_stream,
		fs_http_write_stream_finish,
		NULL /* lock */,
		NULL /* unlock */,
		NULL /* exists */,
		fs_http_stat,
		fs_default_copy,
		NULL /* rename */,
		fs_http_delete,
		fs_http_iter_alloc,
		fs_http_iter_init,
		fs_http_iter_next,
		fs_http_iter_deinit,
		NULL,
		NULL,
	}
};
