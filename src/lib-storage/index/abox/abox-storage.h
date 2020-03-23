#ifndef ABOX_STORAGE_H
#define ABOX_STORAGE_H

#include "index-storage.h"
#include "dbox-storage.h"

#define ABOX_STORAGE_NAME "abox"
#define ABOX_MAIL_FILE_PREFIX "u."
#define ABOX_MAIL_FILE_FORMAT ABOX_MAIL_FILE_PREFIX"%u"

#define ABOX_INDEX_HEADER_MIN_SIZE (sizeof(uint32_t))
struct abox_index_header {
	/* increased every time a full mailbox rebuild is done */
	uint32_t rebuild_count;
	guid_128_t mailbox_guid;
	uint8_t flags; /* enum dbox_index_header_flags */
	uint8_t unused[3];
};

struct abox_storage {
	struct dbox_storage storage;
};

struct abox_mailbox {
	struct mailbox box;
	struct abox_storage *storage;

	uint32_t hdr_ext_id, guid_ext_id;
	/* if non-zero, storage should be rebuilt (except if rebuild_count
	   has changed from this value) */
	uint32_t corrupted_rebuild_count;

	guid_128_t mailbox_guid;
};

#define ABOX_STORAGE(s)	container_of(DBOX_STORAGE(s), struct abox_storage, storage)
#define ABOX_MAILBOX(s)	container_of(s, struct abox_mailbox, box)

extern struct mail_vfuncs abox_mail_vfuncs;

int abox_mail_open(struct dbox_mail *mail, uoff_t *offset_r,
		    struct dbox_file **file_r);

int abox_read_header(struct abox_mailbox *mbox,
		      struct abox_index_header *hdr, bool log_error,
		      bool *need_resize_r);
int abox_mailbox_create_indexes(struct mailbox *box,
				 const struct mailbox_update *update,
				 struct mail_index_transaction *trans);
void abox_set_mailbox_corrupted(struct mailbox *box);

struct mail_save_context *
abox_save_alloc(struct mailbox_transaction_context *_t);
int abox_save_begin(struct mail_save_context *ctx, struct istream *input);
int abox_save_finish(struct mail_save_context *ctx);
void abox_save_cancel(struct mail_save_context *ctx);

struct dbox_file *
abox_save_file_get_file(struct mailbox_transaction_context *t, uint32_t seq);
void abox_save_add_file(struct mail_save_context *ctx, struct dbox_file *file);

int abox_transaction_save_commit_pre(struct mail_save_context *ctx);
void abox_transaction_save_commit_post(struct mail_save_context *ctx,
					struct mail_index_transaction_commit_result *result);
void abox_transaction_save_rollback(struct mail_save_context *ctx);

int abox_copy(struct mail_save_context *ctx, struct mail *mail);

#endif
