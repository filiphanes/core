/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "abox-storage.h"
#include "abox-file.h"
#include "abox-sync.h"
#include "mailbox-recent-flags.h"

#define ABOX_REBUILD_COUNT 3

static void abox_sync_file(struct abox_sync_context *ctx,
			    uint32_t seq, uint32_t uid,
			    enum abox_sync_entry_type type)
{
	FUNC_START();

	switch (type) {
	case ABOX_SYNC_ENTRY_TYPE_EXPUNGE:
		if (!mail_index_transaction_is_expunged(ctx->trans, seq)) {
			mail_index_expunge(ctx->trans, seq);
			array_push_back(&ctx->expunged_uids, &uid);
		}
		break;
	case ABOX_SYNC_ENTRY_TYPE_MOVE_FROM_ALT:
	case ABOX_SYNC_ENTRY_TYPE_MOVE_TO_ALT:
		break;
	}
}

static void abox_sync_add(struct abox_sync_context *ctx,
			   const struct mail_index_sync_rec *sync_rec)
{
	FUNC_START();
	uint32_t uid;
	enum abox_sync_entry_type type;
	uint32_t seq, seq1, seq2;

	if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_EXPUNGE) {
		/* we're interested */
		type = ABOX_SYNC_ENTRY_TYPE_EXPUNGE;
	} else if (sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS) {
		/* not interested */
		return;
	} else {
		/* not interested */
		return;
	}

	if (!mail_index_lookup_seq_range(ctx->sync_view,
					 sync_rec->uid1, sync_rec->uid2,
					 &seq1, &seq2)) {
		/* already expunged everything. nothing to do. */
		return;
	}

	for (seq = seq1; seq <= seq2; seq++) {
		mail_index_lookup_uid(ctx->sync_view, seq, &uid);
		abox_sync_file(ctx, seq, uid, type);
	}
}

static int abox_sync_index(struct abox_sync_context *ctx)
{
	FUNC_START();
	struct mailbox *box = &ctx->mbox->box;
	const struct mail_index_header *hdr;
	struct mail_index_sync_rec sync_rec;
	uint32_t seq1, seq2;

	hdr = mail_index_get_header(ctx->sync_view);
	if (hdr->uid_validity == 0) {
		/* newly created index file */
		if (hdr->next_uid == 1) {
			/* could be just a race condition where we opened the
			   mailbox between mkdir and index creation. fix this
			   silently. */
			if (abox_mailbox_create_indexes(box, NULL, ctx->trans) < 0)
				return -1;
			return 1;
		}
		mailbox_set_critical(box,
			"abox: Broken index: missing UIDVALIDITY");
		abox_set_mailbox_corrupted(box);
		return 0;
	}

	/* mark the newly seen messages as recent */
	if (mail_index_lookup_seq_range(ctx->sync_view, hdr->first_recent_uid,
					hdr->next_uid, &seq1, &seq2))
		mailbox_recent_flags_set_seqs(box, ctx->sync_view, seq1, seq2);

	while (mail_index_sync_next(ctx->index_sync_ctx, &sync_rec))
		abox_sync_add(ctx, &sync_rec);
	return 1;
}

static void abox_sync_file_expunge(struct abox_sync_context *ctx,
				   uint32_t uid)
{
	FUNC_START();
	struct mailbox *box = &ctx->mbox->box;
	struct abox_file *file;
	const void *guid;
	uint32_t seq;
	int ret;

	mail_index_lookup_seq(ctx->sync_view, uid, &seq);
	mail_index_lookup_ext(ctx->sync_view, seq,
						  ctx->mbox->guid_ext_id, &guid, NULL);

	file = abox_file_init(ctx->mbox, guid);
	ret = abox_file_unlink(file);

	/* do sync_notify only when the file was unlinked by us */
	if (ret > 0 && box->v.sync_notify != NULL)
		box->v.sync_notify(box, uid, MAILBOX_SYNC_TYPE_EXPUNGE);
	FUNC_IN();
	abox_file_unref(&file);
	FUNC_END();
}

static void abox_sync_expunge_files(struct abox_sync_context *ctx)
{
	FUNC_START();
	const uint32_t *uidp;

	/* NOTE: Index is no longer locked. Multiple processes may be unlinking
	   the files at the same time. */
	ctx->mbox->box.tmp_sync_view = ctx->sync_view;
	array_foreach(&ctx->expunged_uids, uidp) T_BEGIN {
		abox_sync_file_expunge(ctx, *uidp);
	} T_END;
	if (ctx->mbox->box.v.sync_notify != NULL)
		ctx->mbox->box.v.sync_notify(&ctx->mbox->box, 0, 0);
	ctx->mbox->box.tmp_sync_view = NULL;
}

static int
abox_refresh_header(struct abox_mailbox *mbox, bool retry, bool log_error)
{
	FUNC_START();
	struct mail_index_view *view;
	struct abox_index_header hdr;
	bool need_resize;
	int ret;

	view = mail_index_view_open(mbox->box.index);
	ret = abox_read_header(mbox, &hdr, log_error, &need_resize);
	mail_index_view_close(&view);

	if (ret < 0 && retry) {
		mail_index_refresh(mbox->box.index);
		return abox_refresh_header(mbox, FALSE, log_error);
	}
	return ret;
}

int abox_sync_begin(struct abox_mailbox *mbox, enum abox_sync_flags flags,
		     struct abox_sync_context **ctx_r)
{
	FUNC_START();
	const struct mail_index_header *hdr =
		mail_index_get_header(mbox->box.view);
	struct abox_sync_context *ctx;
	enum mail_index_sync_flags sync_flags;
	unsigned int i;
	int ret;
	bool rebuild, force_rebuild;

	force_rebuild = (flags & ABOX_SYNC_FLAG_FORCE_REBUILD) != 0;
	rebuild = force_rebuild ||
		(hdr->flags & MAIL_INDEX_HDR_FLAG_FSCKD) != 0 ||
		mbox->corrupted_rebuild_count != 0 ||
		abox_refresh_header(mbox, TRUE, FALSE) < 0;

	ctx = i_new(struct abox_sync_context, 1);
	ctx->mbox = mbox;
	ctx->flags = flags;
	i_array_init(&ctx->expunged_uids, 32);

	sync_flags = index_storage_get_sync_flags(&mbox->box);
	if (!rebuild && (flags & ABOX_SYNC_FLAG_FORCE) == 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_REQUIRE_CHANGES;
	if ((flags & ABOX_SYNC_FLAG_FSYNC) != 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_FSYNC;
	/* don't write unnecessary dirty flag updates */
	sync_flags |= MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES;

	for (i = 0;; i++) {
		ret = index_storage_expunged_sync_begin(&mbox->box,
				&ctx->index_sync_ctx, &ctx->sync_view,
				&ctx->trans, sync_flags);
		if (mail_index_reset_fscked(mbox->box.index))
			abox_set_mailbox_corrupted(&mbox->box);
		if (ret <= 0) {
			array_free(&ctx->expunged_uids);
			i_free(ctx);
			*ctx_r = NULL;
			return ret;
		}

		if (rebuild)
			ret = 0;
		else {
			if ((ret = abox_sync_index(ctx)) > 0)
				break;
		}

		/* failure. keep the index locked while we're doing a
		   rebuild. */
		if (ret == 0) {
			if (i >= ABOX_REBUILD_COUNT) {
				mailbox_set_critical(&ctx->mbox->box,
					"abox: Index keeps breaking");
				ret = -1;
			} else {
				/* do a full resync and try again. */
				rebuild = FALSE;
				ret = abox_sync_index_rebuild(mbox,
							       force_rebuild);
			}
		}
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		if (ret < 0) {
			index_storage_expunging_deinit(&ctx->mbox->box);
			array_free(&ctx->expunged_uids);
			i_free(ctx);
			return -1;
		}
	}

	*ctx_r = ctx;
	return 0;
}

int abox_sync_finish(struct abox_sync_context **_ctx, bool success)
{
	FUNC_START();
	struct abox_sync_context *ctx = *_ctx;
	int ret = success ? 0 : -1;

	*_ctx = NULL;

	if (success) {
		mail_index_view_ref(ctx->sync_view);

		if (mail_index_sync_commit(&ctx->index_sync_ctx) < 0) {
			mailbox_set_index_error(&ctx->mbox->box);
			ret = -1;
		} else {
			abox_sync_expunge_files(ctx);
			mail_index_view_close(&ctx->sync_view);
		}
	} else {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
	}

	index_storage_expunging_deinit(&ctx->mbox->box);
	array_free(&ctx->expunged_uids);
	i_free(ctx);
	return ret;
}

int abox_sync(struct abox_mailbox *mbox, enum abox_sync_flags flags)
{
	FUNC_START();
	struct abox_sync_context *sync_ctx;

	if (abox_sync_begin(mbox, flags, &sync_ctx) < 0)
		return -1;

	if (sync_ctx == NULL)
		return 0;
	return abox_sync_finish(&sync_ctx, TRUE);
}

struct mailbox_sync_context *
abox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	FUNC_START();
	struct abox_mailbox *mbox = ABOX_MAILBOX(box);
	enum abox_sync_flags abox_sync_flags = 0;
	int ret = 0;

	if (mail_index_reset_fscked(box->index))
		abox_set_mailbox_corrupted(box);
	if (index_mailbox_want_full_sync(&mbox->box, flags) ||
	    mbox->corrupted_rebuild_count != 0) {
		if ((flags & MAILBOX_SYNC_FLAG_FORCE_RESYNC) != 0)
			abox_sync_flags |= ABOX_SYNC_FLAG_FORCE_REBUILD;
		ret = abox_sync(mbox, abox_sync_flags);
	}

	return index_mailbox_sync_init(box, flags, ret < 0);
}
