/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "nfs-workarounds.h"
#include "fs-api.h"
#include "abox-save.h"
#include "abox-storage.h"
#include "abox-file.h"
#include "mail-copy.h"

static int
abox_copy_hardlink(struct mail_save_context *_ctx, struct mail *mail)
{
	struct abox_save_context *ctx = ABOX_SAVECTX(_ctx);
	struct abox_mailbox *dest_mbox = ABOX_MAILBOX(_ctx->transaction->box);
	struct abox_mailbox *src_mbox;
	struct abox_file *src_file, *dest_file;
	const char *src_path, *dest_path;
	const void *guid;
	int ret;

	if (strcmp(mail->box->storage->name, ABOX_STORAGE_NAME) == 0)
		src_mbox = ABOX_MAILBOX(mail->box);
	else {
		/* Source storage isn't abox, can't hard link */
		return 0;
	}

	mail_index_lookup_ext(mail->transaction->view, mail->seq,
				src_mbox->guid_ext_id, &guid, NULL);
	src_file = abox_file_init(src_mbox, guid);

	// TODO: detect if other guid in data.guid is empty, then use old guid
	_ctx->data.guid = i_memdup(guid, GUID_128_SIZE);
	dest_file = abox_file_init(dest_mbox, guid);

	// ctx->ctx.data.flags &= ~ABOX_INDEX_FLAG_ALT;

	// TODO: use fs_copy
	src_path = src_file->primary_path;
	dest_path = dest_file->primary_path;
	ret = nfs_safe_link(src_path, dest_path, FALSE);
	if (ret < 0 && errno == ENOENT && src_file->alt_path != NULL) {
		src_path = src_file->alt_path;
		if (dest_file->alt_path != NULL) {
			dest_path = dest_file->cur_path = dest_file->alt_path;
			// ctx->ctx.data.flags |= ABOX_INDEX_FLAG_ALT;
		}
		ret = nfs_safe_link(src_path, dest_path, FALSE);
	}
	if (ret < 0) {
		if (ECANTLINK(errno))
			ret = 0;
		else if (errno == ENOENT) {
			/* try if the fallback copying code can still
			   read the file (the mail could still have the
			   stream open) */
			ret = 0;
		} else {
			mail_set_critical(mail, "link(%s, %s) failed: %m",
					  src_path, dest_path);
		}
		abox_file_unref(&src_file);
		abox_file_unref(&dest_file);
		return ret;
	}

	((struct abox_file *)dest_file)->written_to_disk = TRUE;

	abox_save_add_to_index(ctx);
	index_copy_cache_fields(_ctx, mail, ctx->seq);

	abox_save_add_file(_ctx, dest_file);
	mail_set_seq_saving(_ctx->dest_mail, ctx->seq);
	abox_file_unref(&src_file);
	return 1;
}

int abox_copy(struct mail_save_context *_ctx, struct mail *mail)
{
	struct abox_save_context *ctx = (struct abox_save_context *)_ctx;
	struct mailbox_transaction_context *_t = _ctx->transaction;
	struct abox_mailbox *mbox = (struct abox_mailbox *)_t->box;
	int ret;

	i_assert((_t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	ctx->finished = TRUE;
	if (mail_storage_copy_can_use_hardlink(mail->box, &mbox->box) &&
	    _ctx->data.guid == NULL) {
		T_BEGIN {
			ret = abox_copy_hardlink(_ctx, mail);
		} T_END;

		if (ret != 0) {
			index_save_context_free(_ctx);
			return ret > 0 ? 0 : -1;
		}

		/* non-fatal hardlinking failure, try the slow way */
	}
	return mail_storage_copy(_ctx, mail);
}
