#ifndef ABOX_SYNC_H
#define ABOX_SYNC_H

struct mailbox;
struct abox_mailbox;

enum abox_sync_flags {
	ABOX_SYNC_FLAG_FORCE		= 0x01,
	ABOX_SYNC_FLAG_FSYNC		= 0x02,
	ABOX_SYNC_FLAG_FORCE_REBUILD	= 0x04
};

enum abox_sync_entry_type {
	ABOX_SYNC_ENTRY_TYPE_EXPUNGE,
	ABOX_SYNC_ENTRY_TYPE_MOVE_FROM_ALT,
	ABOX_SYNC_ENTRY_TYPE_MOVE_TO_ALT
};

struct abox_sync_context {
	struct abox_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;
	enum abox_sync_flags flags;
	ARRAY_TYPE(uint32_t) expunged_uids;
};

int abox_sync_begin(struct abox_mailbox *mbox, enum abox_sync_flags flags,
		     struct abox_sync_context **ctx_r);
int abox_sync_finish(struct abox_sync_context **ctx, bool success);
int abox_sync(struct abox_mailbox *mbox, enum abox_sync_flags flags);

int abox_sync_index_rebuild(struct abox_mailbox *mbox, bool force);

struct mailbox_sync_context *
abox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

#endif
