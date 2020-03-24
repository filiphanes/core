#ifndef ABOX_MAIL_H
#define ABOX_MAIL_H

#include "index-mail.h"

struct abox_mail {
	struct index_mail imail;

	struct abox_file *open_file;
	uoff_t offset;
};

#define ABOX_MAIL(s)	container_of(s, struct abox_mail, imail.mail.mail)

struct mail *
abox_mail_alloc(struct mailbox_transaction_context *t,
		enum mail_fetch_field wanted_fields,
		struct mailbox_header_lookup_ctx *wanted_headers);
int abox_mail_open(struct abox_mail *mail, struct abox_file **file_r);
void abox_mail_close(struct mail *mail);

int abox_mail_get_physical_size(struct mail *mail, uoff_t *size_r);
int abox_mail_get_virtual_size(struct mail *mail, uoff_t *size_r);
int abox_mail_get_received_date(struct mail *mail, time_t *date_r);
int abox_mail_get_save_date(struct mail *_mail, time_t *date_r);
int abox_mail_get_special(struct mail *mail, enum mail_fetch_field field,
			  const char **value_r);
int abox_mail_get_stream(struct mail *_mail, bool get_body ATTR_UNUSED,
			 struct message_size *hdr_size,
			 struct message_size *body_size,
			 struct istream **stream_r);

int abox_mail_metadata_read(struct abox_mail *mail, struct abox_file **file_r);

#endif
