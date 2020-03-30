/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "index-mail.h"
#include "index-pop3-uidl.h"
#include "index-storage.h"
#include "abox-mail.h"
#include "abox-storage.h"
#include "abox-file.h"

#include <sys/stat.h>

struct mail *
abox_mail_alloc(struct mailbox_transaction_context *t,
		enum mail_fetch_field wanted_fields,
		struct mailbox_header_lookup_ctx *wanted_headers)
{
	FUNC_START();
	struct abox_mail *mail;
	pool_t pool;

	pool = pool_alloconly_create("mail", 2048);
	mail = p_new(pool, struct abox_mail, 1);
	mail->imail.mail.pool = pool;

	index_mail_init(&mail->imail, t, wanted_fields, wanted_headers);
	return &mail->imail.mail.mail;
}

void abox_mail_close(struct mail *_mail)
{
	FUNC_START();
	struct abox_mail *mail = ABOX_MAIL(_mail);

	index_mail_close(_mail);
	/* close the abox file only after index is closed, since it may still
	   try to read from it. */
	if (mail->open_file != NULL)
		abox_file_unref(&mail->open_file);
}

static void abox_mail_set_expunged(struct abox_mail *mail)
{
	FUNC_START();
	struct mail *_mail = &mail->imail.mail.mail;

	mail_index_refresh(_mail->box->index);
	if (mail_index_is_expunged(_mail->transaction->view, _mail->seq)) {
		mail_set_expunged(_mail);
		return;
	}

	mail_set_critical(_mail, "abox: Unexpectedly lost uid");
	abox_set_mailbox_corrupted(_mail->box);
}

static int abox_mail_file_set(struct abox_mail *mail)
{
	FUNC_START();
	struct mail *_mail = &mail->imail.mail.mail;
	struct abox_mailbox *mbox = ABOX_MAILBOX(_mail->box);
	bool deleted;
	const void *guid;
	int ret;

	if (mail->open_file != NULL) {
		/* already set */
		return 0;
	} else if (!_mail->saving) {
		mail_index_lookup_ext(_mail->transaction->view, _mail->seq,
					mbox->guid_ext_id, &guid, &deleted);
		mail->open_file = abox_file_init(mbox, guid);
		return 0;
	} else {
		/* mail is being saved in this transaction */
		mail->open_file =
			abox_save_file_get_file(_mail->transaction,
						 _mail->seq);
		mail->open_file->refcount++;

		ret = abox_file_open(mail->open_file, &deleted);
		if (ret <= 0) {
			mail_set_critical(_mail,
				"abox: Unexpectedly lost mail being saved");
			abox_set_mailbox_corrupted(_mail->box);
			return -1;
		}
		return 1;
	}
}

static int
abox_mail_metadata_get(struct abox_mail *mail, const char *key,
		       const char **value_r)
{
	FUNC_START();
	struct abox_file *file;

	if (abox_mail_open(mail, &file) < 0){
		FUNC_END_RET_INT(-1);
		return -1;
	}
	*value_r = abox_file_metadata_get(file, key);
	FUNC_END_RET_INT(0);
	return 0;
}

int abox_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	FUNC_START();
	struct abox_mail *mail = ABOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	const char *value;
	uintmax_t time;

	if (index_mail_get_received_date(_mail, date_r) == 0)
		return 0;

	if (abox_mail_metadata_get(mail, ABOX_METADATA_RECEIVED_TIME,
				   &value) < 0)
		return -1;

	time = 0;
	if (value != NULL && str_to_uintmax(value, &time) < 0)
		return -1;

	data->received_date = (time_t)time;
	*date_r = data->received_date;
	return 0;
}

int abox_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	FUNC_START();
	struct abox_mail *mail = ABOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	struct abox_file *file;
	struct stat st;

 	if (index_mail_get_save_date(_mail, date_r) == 0)
		return 0;

	if (abox_mail_open(mail, &file) < 0)
		return -1;

	_mail->transaction->stats.fstat_lookup_count++;
	if (abox_file_stat(file, &st) < 0) {
		if (errno == ENOENT)
			mail_set_expunged(_mail);
		return -1;
	}
	*date_r = data->save_date = st.st_ctime;
	return 0;
}

int abox_mail_get_virtual_size(struct mail *_mail, uoff_t *size_r)
{
	FUNC_START();
	struct abox_mail *mail = ABOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	const char *value;
	uintmax_t size;

	if (index_mail_get_cached_virtual_size(&mail->imail, size_r)) {
		FUNC_END_RET_INT(0);
		return 0;
	}
	if (abox_mail_metadata_get(mail,
							   ABOX_METADATA_VIRTUAL_SIZE, &value) < 0) {
		FUNC_END_RET_INT(-1);
		return -1;
	}
	if (value == NULL) {
		FUNC_END();
		return index_mail_get_virtual_size(_mail, size_r);
	}
	if (str_to_uintmax(value, &size) < 0 || size > (uoff_t)-1) {
		i_warning("Error "ABOX_METADATA_VIRTUAL_SIZE"=%s is not uint", value);
		return -1;
	}
	*size_r = data->virtual_size = (uoff_t)size;
	FUNC_END_RET_INT(0);
	return 0;
}

int abox_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	FUNC_START();
	struct abox_mail *mail = ABOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	struct abox_file *file;

	if (index_mail_get_physical_size(_mail, size_r) == 0) {
		FUNC_END_RET_INT(0);
		return 0;
	}
	if (abox_mail_open(mail, &file) < 0) {
		FUNC_END_RET_INT(-1);
		return -1;
	}

	data->physical_size = abox_file_get_plaintext_size(file);
	*size_r = data->physical_size;
	FUNC_END_RET_INT(0);
	return 0;
}

static int
abox_get_cached_metadata(struct abox_mail *mail, const char *key,
			 enum index_cache_field cache_field,
			 const char **value_r)
{
	FUNC_START();
	struct index_mail *imail = &mail->imail;
	struct index_mailbox_context *ibox =
		INDEX_STORAGE_CONTEXT(imail->mail.mail.box);
	const char *value;
	string_t *str;
	uint32_t order;

	str = str_new(imail->mail.data_pool, 64);
	if (mail_cache_lookup_field(imail->mail.mail.transaction->cache_view,
				    str, imail->mail.mail.seq,
				    ibox->cache_fields[cache_field].idx) > 0) {
		if (cache_field == MAIL_CACHE_POP3_ORDER) {
			i_assert(str_len(str) == sizeof(order));
			memcpy(&order, str_data(str), sizeof(order));
			str_truncate(str, 0);
			if (order != 0)
				str_printfa(str, "%u", order);
			else {
				/* order=0 means it doesn't exist. we don't
				   want to return "0" though, because then the
				   mails get ordered to beginning, while
				   nonexistent are supposed to be ordered at
				   the end. */
			}
		}
		*value_r = str_c(str);
		return 0;
	}

	if (abox_mail_metadata_get(mail, key, &value) < 0)
		return -1;

	if (value == NULL)
		value = "";
	if (cache_field != MAIL_CACHE_POP3_ORDER) {
		index_mail_cache_add_idx(imail, ibox->cache_fields[cache_field].idx,
					 value, strlen(value));
	} else {
		if (str_to_uint(value, &order) < 0)
			order = 0;
		index_mail_cache_add_idx(imail, ibox->cache_fields[cache_field].idx,
					 &order, sizeof(order));
	}

	/* don't return pointer to abox metadata directly, since it may
	   change unexpectedly */
	str_truncate(str, 0);
	str_append(str, value);
	*value_r = str_c(str);
	return 0;
}

int
abox_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		       const char **value_r)
{
	FUNC_START();
	struct abox_mailbox *mbox = ABOX_MAILBOX(_mail->box);
	struct abox_mail *mail = ABOX_MAIL(_mail);
	struct stat st;
	int ret;

	switch (field) {
	case MAIL_FETCH_REFCOUNT:
		if (abox_mail_file_set(mail) < 0)
			return -1;

		_mail->transaction->stats.fstat_lookup_count++;
		if (abox_file_stat(mail->open_file, &st) < 0) {
			if (errno == ENOENT)
				mail_set_expunged(_mail);
			return -1;
		}
		*value_r = p_strdup_printf(mail->imail.mail.data_pool, "%lu",
					   (unsigned long)st.st_nlink);
		return 0;
	case MAIL_FETCH_REFCOUNT_ID:
		if (abox_mail_file_set(mail) < 0)
			return -1;

		_mail->transaction->stats.fstat_lookup_count++;
		if (abox_file_stat(mail->open_file, &st) < 0) {
			if (errno == ENOENT)
				mail_set_expunged(_mail);
			return -1;
		}
		*value_r = p_strdup_printf(mail->imail.mail.data_pool, "%llu",
					   (unsigned long long)st.st_ino);
		return 0;
	case MAIL_FETCH_UIDL_BACKEND:
		if (!abox_header_have_flag(&mbox->box, mbox->hdr_ext_id,
				offsetof(struct abox_index_header, flags),
				ABOX_INDEX_HEADER_FLAG_HAVE_POP3_UIDLS)) {
			*value_r = "";
			return 0;
		}
		if (!index_pop3_uidl_can_exist(_mail)) {
			*value_r = "";
			return 0;
		}
		ret = abox_get_cached_metadata(mail, ABOX_METADATA_POP3_UIDL,
					       MAIL_CACHE_POP3_UIDL, value_r);
		if (ret == 0) {
			index_pop3_uidl_update_exists(&mail->imail.mail.mail,
						      (*value_r)[0] != '\0');
		}
		return ret;
		break;
	case MAIL_FETCH_POP3_ORDER:
		if (!abox_header_have_flag(&mbox->box, mbox->hdr_ext_id,
				offsetof(struct abox_index_header, flags),
				ABOX_INDEX_HEADER_FLAG_HAVE_POP3_ORDERS)) {
			*value_r = "";
			return 0;
		}
		if (!index_pop3_uidl_can_exist(_mail)) {
			/* assuming if there's a POP3 order, there's also a UIDL */
			*value_r = "";
			return 0;
		}
		return abox_get_cached_metadata(mail, ABOX_METADATA_POP3_ORDER,
						MAIL_CACHE_POP3_ORDER, value_r);
		break;
	case MAIL_FETCH_GUID:
		return abox_get_cached_metadata(mail, ABOX_METADATA_GUID,
						MAIL_CACHE_GUID, value_r);
	default:
		break;
	}

	return index_mail_get_special(_mail, field, value_r);
}

int abox_mail_open(struct abox_mail *mail, struct abox_file **file_r)
{
	FUNC_START();
	struct mail *_mail = &mail->imail.mail.mail;
	bool deleted;
	int ret;

	if (_mail->lookup_abort != MAIL_LOOKUP_ABORT_NEVER) {
		mail_set_aborted(_mail);
		FUNC_END_RET_INT(-1);
		return -1;
	}
	_mail->mail_stream_opened = TRUE;

	ret = abox_mail_file_set(mail);
	if (ret < 0) {
		FUNC_END_RET_INT(-1);
		return -1;
	}
	if (ret == 0) {
		if (!abox_file_is_open(mail->open_file))
			_mail->transaction->stats.open_lookup_count++;
		if (abox_file_open(mail->open_file, &deleted) <= 0) {
			FUNC_END_RET_INT(-1);
			return -1;
		}
		if (deleted) {
			abox_mail_set_expunged(mail);
			FUNC_END_RET_INT(-1);
			return -1;
		}
	}

	*file_r = mail->open_file;
	FUNC_END_RET_INT(0);
	return 0;
}

static int
get_mail_stream(struct abox_mail *mail, struct istream **stream_r)
{
	FUNC_START();
	struct mail_private *pmail = &mail->imail.mail;

	*stream_r = mail->open_file->input;
	if (pmail->v.istream_opened != NULL) {
		if (pmail->v.istream_opened(&pmail->mail, stream_r) < 0)
			return -1;
	}

	return 1;
}

int abox_mail_get_stream(struct mail *_mail, bool get_body ATTR_UNUSED,
			 struct message_size *hdr_size,
			 struct message_size *body_size,
			 struct istream **stream_r)
{
	FUNC_START();
	struct abox_mail *mail = ABOX_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	struct istream *input;
	int ret;

	if (data->stream == NULL) {
		if (abox_mail_open(mail, &mail->open_file) < 0)
			return -1;

		ret = get_mail_stream(mail, &input);
		if (ret <= 0) {
			if (ret < 0)
				return -1;
			abox_file_set_corrupted(mail->open_file,
				"uid=%u points to broken data at offset=", _mail->uid);
			i_stream_unref(&input);
			return -1;
		}
		data->stream = input;
		index_mail_set_read_buffer_size(_mail, input);
	}

	return index_mail_init_stream(&mail->imail, hdr_size, body_size,
				      stream_r);
}

struct mail_vfuncs abox_mail_vfuncs = {
	abox_mail_close,
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,
	index_mail_set_uid_cache_updates,
	index_mail_prefetch,
	index_mail_precache,
	index_mail_add_temp_wanted_fields,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	index_mail_get_pvt_modseq,
	index_mail_get_parts,
	index_mail_get_date,
	abox_mail_get_received_date,
	abox_mail_get_save_date,
	abox_mail_get_virtual_size,
	abox_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	abox_mail_get_stream,
	index_mail_get_binary_stream,
	abox_mail_get_special,
	index_mail_get_backend_mail,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	index_mail_update_pvt_modseq,
	NULL,
	index_mail_expunge,
	index_mail_set_cache_corrupted,
	index_mail_opened,
};
