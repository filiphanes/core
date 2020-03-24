#ifndef ABOX_STORAGE_H
#define ABOX_STORAGE_H

#include "index-storage.h"
#include "abox-mail.h"
#include "abox-file.h"

#define ABOX_STORAGE_NAME "abox"

#define ABOX_SUBSCRIPTION_FILE_NAME "subscriptions"
#define ABOX_UIDVALIDITY_FILE_NAME "dovecot-uidvalidity"
#define ABOX_TEMP_FILE_PREFIX ".temp."

#define ABOX_MAILBOX_DIR_NAME "mailboxes"
#define ABOX_TRASH_DIR_NAME "trash"
#define ABOX_MAILDIR_NAME "abox-Mails"

/* Delete temp files having ctime older than this. */
#define ABOX_TMP_DELETE_SECS (36*60*60)

#define ABOX_INDEX_HEADER_MIN_SIZE (sizeof(uint32_t))
struct abox_index_header {
	/* increased every time a full mailbox rebuild is done */
	uint32_t rebuild_count;
	guid_128_t mailbox_guid;
	uint8_t flags; /* enum abox_index_header_flags */
	uint8_t unused[3];
};

struct abox_storage {
	struct mail_storage storage;

	struct fs *mail_fs;
	const char *mail_dir;
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

#define ABOX_STORAGE(s)	container_of(s, struct abox_storage, storage)
#define ABOX_MAILBOX(s)	container_of(s, struct abox_mailbox, box)

enum abox_index_header_flags {
	/* messages' metadata contain POP3 UIDLs */
	ABOX_INDEX_HEADER_FLAG_HAVE_POP3_UIDLS	= 0x01,
	/* messages' metadata contain POP3 orders */
	ABOX_INDEX_HEADER_FLAG_HAVE_POP3_ORDERS	= 0x02
};

extern struct mail_vfuncs abox_mail_vfuncs;

int abox_read_header(struct abox_mailbox *mbox,
		      struct abox_index_header *hdr, bool log_error,
		      bool *need_resize_r);
int abox_mailbox_create_indexes(struct mailbox *box,
				 const struct mailbox_update *update,
				 struct mail_index_transaction *trans);
void abox_set_mailbox_corrupted(struct mailbox *box);

void abox_storage_get_list_settings(const struct mail_namespace *ns,
				    struct mailbox_list_settings *set);
void abox_storage_destroy(struct mail_storage *storage);
uint32_t abox_get_uidvalidity_next(struct mailbox_list *list);
void abox_notify_changes(struct mailbox *box);
int abox_mailbox_check_existence(struct mailbox *box, time_t *path_ctime_r);
bool abox_header_have_flag(struct mailbox *box, uint32_t ext_id,
			   unsigned int flags_offset, uint8_t flag);

struct mail_save_context *
abox_save_alloc(struct mailbox_transaction_context *_t);
int abox_save_begin(struct mail_save_context *ctx, struct istream *input);
int abox_save_finish(struct mail_save_context *ctx);
void abox_save_cancel(struct mail_save_context *ctx);

struct abox_file *
abox_save_file_get_file(struct mailbox_transaction_context *t, uint32_t seq);
void abox_save_add_file(struct mail_save_context *ctx, struct abox_file *file);

int abox_transaction_save_commit_pre(struct mail_save_context *ctx);
void abox_transaction_save_commit_post(struct mail_save_context *ctx,
					struct mail_index_transaction_commit_result *result);
void abox_transaction_save_rollback(struct mail_save_context *ctx);

int abox_copy(struct mail_save_context *ctx, struct mail *mail);
bool abox_header_have_flag(struct mailbox *box, uint32_t ext_id,
			   unsigned int flags_offset, uint8_t flag);

#endif
