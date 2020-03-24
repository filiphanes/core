#ifndef ABOX_SAVE_H
#define ABOX_SAVE_H

#include "abox-storage.h"

struct abox_save_context {
	struct mail_save_context ctx;
	struct mail_index_transaction *trans;

	/* updated for each appended mail: */
	uint32_t seq;
	struct istream *input;

	struct ostream *abox_output;

	uint32_t highest_pop3_uidl_seq;
	bool failed:1;
	bool finished:1;
	bool have_pop3_uidls:1;
	bool have_pop3_orders:1;

	struct abox_mailbox *mbox;
	struct abox_sync_context *sync_ctx;

	struct abox_file *cur_file;
	struct abox_file_append_context *append_ctx;

	uint32_t first_saved_seq;
	ARRAY(struct abox_file *) files;
};

#define ABOX_SAVECTX(s)	container_of(s, struct abox_save_context, ctx)

int abox_save_begin(struct mail_save_context *_ctx, struct istream *input);
int abox_save_continue(struct mail_save_context *_ctx);
void abox_save_end(struct abox_save_context *ctx);

void abox_save_add_to_index(struct abox_save_context *ctx);

void abox_save_update_header_flags(struct abox_save_context *ctx,
				   struct mail_index_view *sync_view,
				   uint32_t ext_id,
				   unsigned int flags_offset);

#endif
