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
#include "dbox-attachment.h"
#include "dbox-save.h"
#include "sdbox-storage.h"
#include "sdbox-file.h"
#include "sdbox-sync.h"
#include "fs-api.h"


struct sdbox_save_context {
	struct dbox_save_context ctx;

	struct sdbox_mailbox *mbox;
	struct sdbox_sync_context *sync_ctx;

	struct dbox_file *cur_file;
	struct dbox_file_append_context *append_ctx;

	uint32_t first_saved_seq;
	ARRAY(struct dbox_file *) files;
};

#define SDBOX_SAVECTX(s)	container_of(DBOX_SAVECTX(s), struct sdbox_save_context, ctx)

struct dbox_file *
sdbox_save_file_get_file(struct mailbox_transaction_context *t, uint32_t seq)
{
	FUNC_START();
	struct sdbox_save_context *ctx = SDBOX_SAVECTX(t->save_ctx);
	struct dbox_file *const *files, *file;
	unsigned int count;

	i_assert(seq >= ctx->first_saved_seq);

	files = array_get(&ctx->files, &count);
	i_assert(count > 0);
	i_assert(seq - ctx->first_saved_seq < count);

	file = files[seq - ctx->first_saved_seq];
	i_assert(((struct sdbox_file *)file)->written_to_disk);
	return file;
}

struct mail_save_context *
sdbox_save_alloc(struct mailbox_transaction_context *t)
{
	FUNC_START();
	struct sdbox_mailbox *mbox = SDBOX_MAILBOX(t->box);
	struct sdbox_save_context *ctx = SDBOX_SAVECTX(t->save_ctx);

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (ctx != NULL) {
		/* use the existing allocated structure */
		ctx->cur_file = NULL;
		ctx->ctx.failed = FALSE;
		ctx->ctx.finished = FALSE;
		ctx->ctx.dbox_output = NULL;
		return &ctx->ctx.ctx;
	}

	ctx = i_new(struct sdbox_save_context, 1);
	ctx->ctx.ctx.transaction = t;
	ctx->ctx.trans = t->itrans;
	ctx->mbox = mbox;
	i_array_init(&ctx->files, 32);
	t->save_ctx = &ctx->ctx.ctx;
	return t->save_ctx;
}

void sdbox_save_add_file(struct mail_save_context *_ctx, struct dbox_file *file)
{
	FUNC_START();
	struct sdbox_save_context *ctx = SDBOX_SAVECTX(_ctx);
	struct dbox_file *const *files;
	unsigned int count;

	if (ctx->first_saved_seq == 0)
		ctx->first_saved_seq = ctx->ctx.seq;

	files = array_get(&ctx->files, &count);
	if (count > 0) {
		/* a plugin may leave a previously saved file open.
		   we'll close it here to avoid eating too many fds. */
		dbox_file_close(files[count-1]);
	}
	array_push_back(&ctx->files, &file);
}

int sdbox_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	FUNC_START();
	struct sdbox_save_context *ctx = SDBOX_SAVECTX(_ctx);
	struct dbox_file *file;
	guid_128_t guid;
	int ret;

	file = sdbox_file_init(ctx->mbox, guid);
	file->fs_file = sdbox_file_init_fs_file(file, file->primary_path, FALSE);
	ctx->append_ctx = dbox_file_append_init(file);
	ret = dbox_file_get_append_stream(ctx->append_ctx,
					  &ctx->ctx.dbox_output);
	if (ret <= 0) {
		i_assert(ret != 0);
		dbox_file_append_rollback(&ctx->append_ctx);
		dbox_file_unref(&file);
		ctx->ctx.failed = TRUE;
		return -1;
	}
	ctx->cur_file = file;
	dbox_save_begin(&ctx->ctx, input);

	sdbox_save_add_file(_ctx, file);
	return ctx->ctx.failed ? -1 : 0;
}

static void sdbox_save_set_fs_metadata(struct mail_save_context *_ctx,
			struct dbox_file *file,
			uoff_t output_msg_size ATTR_UNUSED,
			const char *orig_mailbox_name,
			guid_128_t guid_128)
{
	struct dbox_save_context *ctx = DBOX_SAVECTX(_ctx);
	struct sdbox_file *sfile = container_of(file, struct sdbox_file, file);
	struct mail_save_data *mdata = &ctx->ctx.data;
	const char *guid;
	uoff_t vsize;

	fs_set_metadata(file->fs_file, "Received-Time",
					i_strdup_printf("%"PRIxTIME_T, mdata->received_date));
	if (mail_get_virtual_size(_ctx->dest_mail, &vsize) < 0)
		i_unreached();
	fs_set_metadata(file->fs_file, "Virtual-Size",
					i_strdup_printf("%llx", (unsigned long long)vsize));
	if (mdata->pop3_uidl != NULL) {
		i_assert(strchr(mdata->pop3_uidl, '\n') == NULL);
		fs_set_metadata(file->fs_file, "POP3-UIDL", mdata->pop3_uidl);
		ctx->have_pop3_uidls = TRUE;
		ctx->highest_pop3_uidl_seq =
			I_MAX(ctx->highest_pop3_uidl_seq, ctx->seq);
	}
	if (mdata->pop3_order != 0) {
		fs_set_metadata(file->fs_file, "POP3-Order",
						i_strdup_printf("%u", mdata->pop3_order));
		ctx->have_pop3_orders = TRUE;
		ctx->highest_pop3_uidl_seq =
			I_MAX(ctx->highest_pop3_uidl_seq, ctx->seq);
	}

	guid = mdata->guid;
	i_debug("mdata->guid: %s", guid);
	if (guid != NULL) {
		mail_generate_guid_128_hash(guid, guid_128);
		i_debug("guid after mail_generate_guid_128_hash: %s", guid_128_to_string(guid_128));
	} else {
		guid_128_generate(guid_128);
		guid = guid_128_to_string(guid_128);
		i_debug("guid after guid_128_generate: %s", guid_128_to_string(guid_128));
	}
	fs_set_metadata(file->fs_file, FS_METADATA_WRITE_FNAME,
			(const char*) sdbox_file_make_path(sfile, guid));

	if (orig_mailbox_name != NULL &&
	    strchr(orig_mailbox_name, '\r') == NULL &&
	    strchr(orig_mailbox_name, '\n') == NULL) {
		/* save the original mailbox name so if mailbox indexes get
		   corrupted we can place at least some (hopefully most) of
		   the messages to correct mailboxes. */
		fs_set_metadata(file->fs_file, "Orig-Mailbox", orig_mailbox_name);
	}
}

static int sdbox_save_mail_write_metadata(struct mail_save_context *_ctx,
					 struct dbox_file *file)
{
	FUNC_START();
	struct dbox_save_context *ctx = DBOX_SAVECTX(_ctx);
	struct sdbox_save_context *sctx = SDBOX_SAVECTX(_ctx);
	struct sdbox_file *sfile = container_of(file, struct sdbox_file, file);
	const ARRAY_TYPE(mail_attachment_extref) *extrefs_arr;
	const struct mail_attachment_extref *extrefs;
	struct dbox_message_header dbox_msg_hdr;
	uoff_t message_size;
	guid_128_t guid_128;
	unsigned int i, count;

	i_assert(file->msg_header_size == sizeof(dbox_msg_hdr));

	message_size = ctx->dbox_output->offset -
		file->msg_header_size - file->file_header_size;

	// TODO: save metadata to HTTP X-Meta-* headers
	sdbox_save_set_fs_metadata(_ctx, file,
				 message_size, sctx->mbox->box.name, guid_128);
	i_debug("guid after sdbox_save_set_fs_metadata: %s", guid_128_to_string(guid_128));
	// dbox_save_write_metadata(_ctx, ctx->dbox_output, message_size, NULL, guid_128);
	// i_debug("guid after dbox_save_write_metadata: %s", guid_128_to_string(guid_128));
	/* save the 128bit GUID to index so we can quickly find the message */
	mail_index_update_ext(ctx->trans, ctx->seq,
						  sctx->mbox->guid_ext_id, guid_128, NULL);
	FUNC_IN();
	// bool expunged;
	// mail_index_lookup_ext(ctx->trans, ctx->seq,
	// 					  sctx->mbox->guid_ext_id, &guid_128, &expunged);
	i_debug("sdbox_save_mail_write_metadata: verified guid %s", guid_128_to_string(guid_128));

	// TODO: don't write and parse msg headers
	dbox_msg_header_fill(&dbox_msg_hdr, message_size);
	if (o_stream_pwrite(ctx->dbox_output, &dbox_msg_hdr,
			    sizeof(dbox_msg_hdr),
			    file->file_header_size) < 0) {
		dbox_file_set_syscall_error(file, "pwrite()");
		return -1;
	}
	sfile->written_to_disk = TRUE;

	/* remember the attachment paths until commit time */
	extrefs_arr = index_attachment_save_get_extrefs(_ctx);
	if (extrefs_arr != NULL)
		extrefs = array_get(extrefs_arr, &count);
	else {
		extrefs = NULL;
		count = 0;
	}
	if (count > 0) {
		sfile->attachment_pool =
			pool_alloconly_create("sdbox attachment paths", 512);
		p_array_init(&sfile->attachment_paths,
			     sfile->attachment_pool, count);
		for (i = 0; i < count; i++) {
			const char *path = p_strdup(sfile->attachment_pool,
						    extrefs[i].path);
			array_push_back(&sfile->attachment_paths, &path);
		}
	}
	return 0;
}

static int dbox_save_finish_write(struct mail_save_context *_ctx)
{
	FUNC_START();
	struct sdbox_save_context *ctx = SDBOX_SAVECTX(_ctx);
	struct dbox_file **files;

	ctx->ctx.finished = TRUE;
	if (ctx->ctx.dbox_output == NULL)
		return -1;

	if (_ctx->data.save_date != (time_t)-1) {
		/* we can't change ctime, but we can add the date to cache */
		struct index_mail *mail = (struct index_mail *)_ctx->dest_mail;
		uint32_t t = _ctx->data.save_date;

		index_mail_cache_add(mail, MAIL_CACHE_SAVE_DATE, &t, sizeof(t));
	}
	dbox_save_end(&ctx->ctx);

	files = array_back_modifiable(&ctx->files);
	if (!ctx->ctx.failed) T_BEGIN {
		if (sdbox_save_mail_write_metadata(_ctx, *files) < 0)
			ctx->ctx.failed = TRUE;
	} T_END;

	if (ctx->ctx.failed) {
		index_storage_save_abort_last(&ctx->ctx.ctx, ctx->ctx.seq);
		dbox_file_append_rollback(&ctx->append_ctx);
		dbox_file_unlink(*files);
		dbox_file_unref(files);
		array_pop_back(&ctx->files);
	} else {
		dbox_file_append_checkpoint(ctx->append_ctx);
		if (dbox_file_append_commit(&ctx->append_ctx) < 0)
			ctx->ctx.failed = TRUE;
		dbox_file_close(*files);
	}

	i_stream_unref(&ctx->ctx.input);
	ctx->ctx.dbox_output = NULL;

	return ctx->ctx.failed ? -1 : 0;
}

int sdbox_save_finish(struct mail_save_context *ctx)
{
	FUNC_START();
	int ret;

	ret = dbox_save_finish_write(ctx);
	index_save_context_free(ctx);
	return ret;
}

void sdbox_save_cancel(struct mail_save_context *_ctx)
{
	FUNC_START();
	struct dbox_save_context *ctx = DBOX_SAVECTX(_ctx);

	ctx->failed = TRUE;
	(void)sdbox_save_finish(_ctx);
}

/* not used anymore
static int dbox_save_assign_uids(struct sdbox_save_context *ctx,
				 const ARRAY_TYPE(seq_range) *uids)
{
	FUNC_START();
	struct dbox_file *const *files;
	struct seq_range_iter iter;
	unsigned int i, count, n = 0;
	uint32_t uid;
	bool ret;

	seq_range_array_iter_init(&iter, uids);
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		struct sdbox_file *sfile = (struct sdbox_file *)files[i];

		ret = seq_range_array_iter_nth(&iter, n++, &uid);
		i_assert(ret);
		if (sdbox_file_assign_uid(sfile, uid, FALSE) < 0)
			return -1;
		if (ctx->ctx.highest_pop3_uidl_seq == i+1) {
			index_pop3_uidl_set_max_uid(&ctx->mbox->box,
				ctx->ctx.trans, uid);
		}
	}
	i_assert(!seq_range_array_iter_nth(&iter, n, &uid));
	return 0;
}

static int dbox_save_assign_stub_uids(struct sdbox_save_context *ctx)
{
	FUNC_START();
	struct dbox_file *const *files;
	unsigned int i, count;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		struct sdbox_file *sfile = (struct sdbox_file *)files[i];
		uint32_t uid;

		mail_index_lookup_uid(ctx->ctx.trans->view,
				      ctx->first_saved_seq + i, &uid);
		i_assert(uid != 0);

		if (sdbox_file_assign_uid(sfile, uid, TRUE) < 0)
			return -1;
	}

	return 0;
}
*/

static void dbox_save_unref_files(struct sdbox_save_context *ctx)
{
	FUNC_START();
	struct dbox_file **files;
	unsigned int i, count;

	files = array_get_modifiable(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (ctx->ctx.failed) {
			struct sdbox_file *sfile =
				(struct sdbox_file *)files[i];

			(void)sdbox_file_unlink_aborted_save(sfile);
		}
		dbox_file_unref(&files[i]);
	}
	array_free(&ctx->files);
}

int sdbox_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	FUNC_START();
	struct sdbox_save_context *ctx = SDBOX_SAVECTX(_ctx);
	struct mailbox_transaction_context *_t = _ctx->transaction;
	const struct mail_index_header *hdr;

	i_assert(ctx->ctx.finished);

	if (array_count(&ctx->files) == 0) {
		/* the mail must be freed in the commit_pre() */
		return 0;
	}

	if (sdbox_sync_begin(ctx->mbox, SDBOX_SYNC_FLAG_FORCE |
			     SDBOX_SYNC_FLAG_FSYNC, &ctx->sync_ctx) < 0) {
		sdbox_transaction_save_rollback(_ctx);
		return -1;
	}

	/* update dbox header flags */
	dbox_save_update_header_flags(&ctx->ctx, ctx->sync_ctx->sync_view,
		ctx->mbox->hdr_ext_id, offsetof(struct sdbox_index_header, flags));

	hdr = mail_index_get_header(ctx->sync_ctx->sync_view);

	// TODO: move uid assignment to sdbox_save_begin by setting FS_METADATA_WRITE_FNAME
	if ((_ctx->transaction->flags & MAILBOX_TRANSACTION_FLAG_FILL_IN_STUB) == 0) {
		/* assign UIDs for new messages */
		mail_index_append_finish_uids(ctx->ctx.trans, hdr->next_uid,
					      &_t->changes->saved_uids);
		/* TODO: don't assign uids, but save with immutable message guids
		if (dbox_save_assign_uids(ctx, &_t->changes->saved_uids) < 0) {
			sdbox_transaction_save_rollback(_ctx);
			return -1;
		}
		*/
	} else {
		/* assign UIDs that we stashed away 
		if (dbox_save_assign_stub_uids(ctx) < 0) {
			sdbox_transaction_save_rollback(_ctx);
			return -1;
		}
		*/
	}

	_t->changes->uid_validity = hdr->uid_validity;
	return 0;
}

void sdbox_transaction_save_commit_post(struct mail_save_context *_ctx,
					struct mail_index_transaction_commit_result *result)
{
	FUNC_START();
	struct sdbox_save_context *ctx = SDBOX_SAVECTX(_ctx);

	_ctx->transaction = NULL; /* transaction is already freed */

	if (array_count(&ctx->files) == 0) {
		sdbox_transaction_save_rollback(_ctx);
		return;
	}

	mail_index_sync_set_commit_result(ctx->sync_ctx->index_sync_ctx,
					  result);

	if (sdbox_sync_finish(&ctx->sync_ctx, TRUE) < 0)
		ctx->ctx.failed = TRUE;

	i_assert(ctx->ctx.finished);
	dbox_save_unref_files(ctx);
	i_free(ctx);
}

void sdbox_transaction_save_rollback(struct mail_save_context *_ctx)
{
	FUNC_START();
	struct sdbox_save_context *ctx = SDBOX_SAVECTX(_ctx);

	ctx->ctx.failed = TRUE;
	if (!ctx->ctx.finished)
		sdbox_save_cancel(_ctx);
	dbox_save_unref_files(ctx);

	if (ctx->sync_ctx != NULL)
		(void)sdbox_sync_finish(&ctx->sync_ctx, FALSE);
	i_free(ctx);
}
