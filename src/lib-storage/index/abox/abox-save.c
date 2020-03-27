/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "fdatasync-path.h"
#include "hex-binary.h"
#include "hex-dec.h"
#include "str.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "write-full.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "index-pop3-uidl.h"
#include "abox-save.h"
#include "abox-storage.h"
#include "abox-file.h"
#include "abox-sync.h"
#include "fs-api.h"

struct abox_file *
abox_save_file_get_file(struct mailbox_transaction_context *t, uint32_t seq)
{
	FUNC_START();
	struct abox_save_context *ctx = ABOX_SAVECTX(t->save_ctx);
	struct abox_file *const *files, *file;
	unsigned int count;

	i_assert(seq >= ctx->first_saved_seq);

	files = array_get(&ctx->files, &count);
	i_assert(count > 0);
	i_assert(seq - ctx->first_saved_seq < count);

	file = files[seq - ctx->first_saved_seq];
	i_assert(((struct abox_file *)file)->written_to_disk);
	return file;
}

struct mail_save_context *
abox_save_alloc(struct mailbox_transaction_context *t)
{
	FUNC_START();
	struct abox_mailbox *mbox = ABOX_MAILBOX(t->box);
	struct abox_save_context *ctx = ABOX_SAVECTX(t->save_ctx);

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (ctx != NULL) {
		/* use the existing allocated structure */
		ctx->cur_file = NULL;
		ctx->failed = FALSE;
		ctx->finished = FALSE;
		ctx->abox_output = NULL;
		return &ctx->ctx;
	}

	ctx = i_new(struct abox_save_context, 1);
	ctx->ctx.transaction = t;
	ctx->trans = t->itrans;
	ctx->mbox = mbox;
	i_array_init(&ctx->files, 32);
	t->save_ctx = &ctx->ctx;
	return t->save_ctx;
}

void abox_save_add_file(struct mail_save_context *_ctx, struct abox_file *file)
{
	FUNC_START();
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);
	struct abox_file *const *files;
	unsigned int count;

	if (ctx->first_saved_seq == 0)
		ctx->first_saved_seq = ctx->seq;

	files = array_get(&ctx->files, &count);
	if (count > 0) {
		/* a plugin may leave a previously saved file open.
		   we'll close it here to avoid eating too many fds. */
		abox_file_close(files[count-1]);
	}
	array_push_back(&ctx->files, &file);
}

int abox_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	FUNC_START();
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);
	struct mail_storage *_storage = _ctx->transaction->box->storage;
	struct abox_storage *storage = ABOX_STORAGE(_storage);
	struct istream *crlf_input;
	struct abox_file *file;
	guid_128_t guid;
	int ret;

	file = abox_file_init(ctx->mbox, guid);
	ctx->append_ctx = abox_file_append_init(file);
	ret = abox_file_get_append_stream(ctx->append_ctx, &ctx->abox_output);
	if (ret <= 0) {
		i_assert(ret != 0);
		abox_file_append_rollback(&ctx->append_ctx);
		abox_file_unref(&file);
		ctx->failed = TRUE;
		return -1;
	}
	ctx->cur_file = file;

	abox_save_add_to_index(ctx);

	mail_set_seq_saving(_ctx->dest_mail, ctx->seq);

	crlf_input = i_stream_create_lf(input);
	/* crlf_input = i_stream_create_crlf_full(input,
			ctx->mbox->storage->storage.set->mail_save_crlf); */
	ctx->input = index_mail_cache_parse_init(_ctx->dest_mail, crlf_input);
	i_stream_unref(&crlf_input);

	o_stream_cork(ctx->abox_output);
	_ctx->data.output = ctx->abox_output;

	if (_ctx->data.received_date == (time_t)-1)
		_ctx->data.received_date = ioloop_time;

	abox_save_add_file(_ctx, file);
	return ctx->failed ? -1 : 0;
}

int abox_save_continue(struct mail_save_context *_ctx)
{
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);

	if (ctx->failed)
		return -1;

	if (index_storage_save_continue(_ctx, ctx->input,
					_ctx->dest_mail) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

void abox_save_end(struct abox_save_context *ctx)
{
	struct mail_save_data *mdata = &ctx->ctx.data;
	struct ostream *abox_output = ctx->abox_output;
	int ret;

	i_assert(mdata->output != NULL);

	if (mdata->output != abox_output) {
		/* e.g. zlib plugin had changed this. make sure we
		   successfully write the trailer. */
		ret = o_stream_finish(mdata->output);
	} else {
		/* no plugins - flush the output so far */
		ret = o_stream_flush(mdata->output);
	}
	if (ret < 0) {
		mail_set_critical(ctx->ctx.dest_mail,
				  "write(%s) failed: %s",
				  o_stream_get_name(mdata->output),
				  o_stream_get_error(mdata->output));
		ctx->failed = TRUE;
	}
	if (mdata->output != abox_output) {
		o_stream_ref(abox_output);
		o_stream_destroy(&mdata->output);
		mdata->output = abox_output;
	}
	index_mail_cache_parse_deinit(ctx->ctx.dest_mail,
				      ctx->ctx.data.received_date,
				      !ctx->failed);
	if (!ctx->failed)
		index_mail_cache_pop3_data(ctx->ctx.dest_mail,
					   mdata->pop3_uidl,
					   mdata->pop3_order);
}

void abox_save_update_header_flags(struct abox_save_context *ctx,
				   struct mail_index_view *sync_view,
				   uint32_t ext_id,
				   unsigned int flags_offset)
{
	const void *data;
	size_t data_size;
	uint8_t old_flags = 0, flags;

	mail_index_get_header_ext(sync_view, ext_id, &data, &data_size);
	if (flags_offset < data_size)
		old_flags = *((const uint8_t *)data + flags_offset);
	else {
		/* grow old abox header */
		mail_index_ext_resize_hdr(ctx->trans, ext_id, flags_offset+1);
	}

	flags = old_flags;
	if (ctx->have_pop3_uidls)
		flags |= ABOX_INDEX_HEADER_FLAG_HAVE_POP3_UIDLS;
	if (ctx->have_pop3_orders)
		flags |= ABOX_INDEX_HEADER_FLAG_HAVE_POP3_ORDERS;
	if (flags != old_flags) {
		/* flags changed, update them */
		mail_index_update_header_ext(ctx->trans, ext_id,
					     flags_offset, &flags, 1);
	}
}

static void abox_save_set_fs_metadata(struct mail_save_context *_ctx,
			struct abox_file *file,
			uoff_t output_msg_size ATTR_UNUSED,
			const char *orig_mailbox_name,
			guid_128_t guid_128)
{
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);
	struct mail_save_data *mdata = &ctx->ctx.data;
	const char *guid;
	uoff_t vsize;

	fs_set_metadata(file->fs_file, ABOX_METADATA_RECEIVED_TIME,
					i_strdup_printf("%zu", mdata->received_date));
	if (mail_get_virtual_size(_ctx->dest_mail, &vsize) < 0)
		i_unreached();
	fs_set_metadata(file->fs_file, ABOX_METADATA_VIRTUAL_SIZE,
					i_strdup_printf("%llu", (unsigned long long)vsize));
	if (mdata->pop3_uidl != NULL) {
		i_assert(strchr(mdata->pop3_uidl, '\n') == NULL);
		fs_set_metadata(file->fs_file, ABOX_METADATA_POP3_UIDL,
						mdata->pop3_uidl);
		ctx->have_pop3_uidls = TRUE;
		ctx->highest_pop3_uidl_seq =
			I_MAX(ctx->highest_pop3_uidl_seq, ctx->seq);
	}
	if (mdata->pop3_order != 0) {
		fs_set_metadata(file->fs_file, ABOX_METADATA_POP3_ORDER,
						i_strdup_printf("%u", mdata->pop3_order));
		ctx->have_pop3_orders = TRUE;
		ctx->highest_pop3_uidl_seq =
			I_MAX(ctx->highest_pop3_uidl_seq, ctx->seq);
	}

	guid = mdata->guid;
	if (guid != NULL) {
		i_debug("mdata->guid: %s", guid);
		mail_generate_guid_128_hash(guid, guid_128);
	} else {
		guid_128_generate(guid_128);
		guid = guid_128_to_string(guid_128);
	}
	fs_set_metadata(file->fs_file, FS_METADATA_WRITE_FNAME,
			(const char*) abox_file_make_path(file, guid));

	if (orig_mailbox_name != NULL &&
	    strchr(orig_mailbox_name, '\r') == NULL &&
	    strchr(orig_mailbox_name, '\n') == NULL) {
		/* save the original mailbox name so if mailbox indexes get
		   corrupted we can place at least some (hopefully most) of
		   the messages to correct mailboxes. */
		fs_set_metadata(file->fs_file,
					ABOX_METADATA_ORIG_MAILBOX, orig_mailbox_name);
	}
}

static int abox_save_mail_write_metadata(struct mail_save_context *_ctx,
					 struct abox_file *file)
{
	FUNC_START();
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);
	uoff_t message_size;
	guid_128_t guid_128;

	message_size = ctx->abox_output->offset -
		file->msg_header_size - file->file_header_size;

	abox_save_set_fs_metadata(_ctx, file,
				 message_size, ctx->mbox->box.name, guid_128);

	/* save the 128bit GUID to index so we can quickly find the message */
	mail_index_update_ext(ctx->trans, ctx->seq,
						  ctx->mbox->guid_ext_id, guid_128, NULL);
	FUNC_IN();
	// bool expunged;
	// mail_index_lookup_ext(ctx->trans, ctx->seq,
	// 					     ctx->mbox->guid_ext_id, &guid_128, &expunged);

	file->written_to_disk = TRUE;

	return 0;
}

static int abox_save_finish_write(struct mail_save_context *_ctx)
{
	FUNC_START();
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);
	struct abox_file **files;

	ctx->finished = TRUE;
	if (ctx->abox_output == NULL)
		return -1;

	if (_ctx->data.save_date != (time_t)-1) {
		/* we can't change ctime, but we can add the date to cache */
		struct index_mail *mail = (struct index_mail *)_ctx->dest_mail;
		uint32_t t = _ctx->data.save_date;

		index_mail_cache_add(mail, MAIL_CACHE_SAVE_DATE, &t, sizeof(t));
	}
	abox_save_end(ctx);

	files = array_back_modifiable(&ctx->files);
	if (!ctx->failed) T_BEGIN {
		if (abox_save_mail_write_metadata(_ctx, *files) < 0)
			ctx->failed = TRUE;
	} T_END;

	if (ctx->failed) {
		index_storage_save_abort_last(&ctx->ctx, ctx->seq);
		abox_file_append_rollback(&ctx->append_ctx);
		abox_file_unlink(*files);
		abox_file_unref(files);
		array_pop_back(&ctx->files);
	} else {
		abox_file_append_checkpoint(ctx->append_ctx);
		if (abox_file_append_commit(&ctx->append_ctx) < 0)
			ctx->failed = TRUE;
		abox_file_close(*files);
	}

	i_stream_unref(&ctx->input);
	ctx->abox_output = NULL;

	return ctx->failed ? -1 : 0;
}

int abox_save_finish(struct mail_save_context *ctx)
{
	FUNC_START();
	int ret;

	ret = abox_save_finish_write(ctx);
	index_save_context_free(ctx);
	return ret;
}

void abox_save_cancel(struct mail_save_context *_ctx)
{
	FUNC_START();
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);

	ctx->failed = TRUE;
	(void)abox_save_finish(_ctx);
}

static void abox_save_unref_files(struct abox_save_context *ctx)
{
	FUNC_START();
	struct abox_file **files;
	unsigned int i, count;

	files = array_get_modifiable(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (ctx->failed) {
			(void)abox_file_unlink_aborted_save(files[i]);
		}
		abox_file_unref(&files[i]);
	}
	array_free(&ctx->files);
}

void abox_save_add_to_index(struct abox_save_context *ctx)
{
	struct mail_save_data *mdata = &ctx->ctx.data;
	enum mail_flags save_flags;

	save_flags = mdata->flags & ~MAIL_RECENT;
	mail_index_append(ctx->trans, mdata->uid, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
				save_flags);
	if (mdata->keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, mdata->keywords);
	}
	if (mdata->min_modseq != 0) {
		mail_index_update_modseq(ctx->trans, ctx->seq,
					 mdata->min_modseq);
	}
}

int abox_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	FUNC_START();
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);
	struct mailbox_transaction_context *_t = _ctx->transaction;
	const struct mail_index_header *hdr;

	i_assert(ctx->finished);

	if (array_count(&ctx->files) == 0) {
		/* the mail must be freed in the commit_pre() */
		return 0;
	}

	if (abox_sync_begin(ctx->mbox, ABOX_SYNC_FLAG_FORCE |
			     ABOX_SYNC_FLAG_FSYNC, &ctx->sync_ctx) < 0) {
		abox_transaction_save_rollback(_ctx);
		return -1;
	}

	/* update abox header flags */
	abox_save_update_header_flags(ctx, ctx->sync_ctx->sync_view,
		ctx->mbox->hdr_ext_id, offsetof(struct abox_index_header, flags));

	/* assign UIDs for new messages */
	hdr = mail_index_get_header(ctx->sync_ctx->sync_view);

	// TODO: move uid assignment to abox_save_begin by setting FS_METADATA_WRITE_FNAME
	/* assign UIDs for new messages */
	mail_index_append_finish_uids(ctx->trans, hdr->next_uid,
						&_t->changes->saved_uids);

	_t->changes->uid_validity = hdr->uid_validity;
	return 0;
}

void abox_transaction_save_commit_post(struct mail_save_context *_ctx,
					struct mail_index_transaction_commit_result *result)
{
	FUNC_START();
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);

	_ctx->transaction = NULL; /* transaction is already freed */

	if (array_count(&ctx->files) == 0) {
		abox_transaction_save_rollback(_ctx);
		return;
	}

	mail_index_sync_set_commit_result(ctx->sync_ctx->index_sync_ctx,
					  result);

	if (abox_sync_finish(&ctx->sync_ctx, TRUE) < 0)
		ctx->failed = TRUE;

	i_assert(ctx->finished);
	abox_save_unref_files(ctx);
	i_free(ctx);
}

void abox_transaction_save_rollback(struct mail_save_context *_ctx)
{
	FUNC_START();
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);

	ctx->failed = TRUE;
	if (!ctx->finished)
		abox_save_cancel(_ctx);
	abox_save_unref_files(ctx);

	if (ctx->sync_ctx != NULL)
		(void)abox_sync_finish(&ctx->sync_ctx, FALSE);
	i_free(ctx);
}
