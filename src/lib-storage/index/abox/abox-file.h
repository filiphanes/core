#ifndef ABOX_FILE_H
#define ABOX_FILE_H

#include "dbox-file.h"

struct abox_file {
	struct dbox_file file;
	struct abox_mailbox *mbox;

	/* 0 while file is being created */
	uint32_t uid;
	guid_128_t guid;

	/* list of attachment paths while saving/copying message */
	pool_t attachment_pool;
	ARRAY_TYPE(const_string) attachment_paths;
	bool written_to_disk;
};

/* Globally unique identifier for the message. Preserved when copying. */
#define ABOX_METADATA_GUID	"GUID"
/* POP3 UIDL overriding the default format */
#define ABOX_METADATA_POP3_UIDL "POP3-UIDL"
/* POP3 message ordering (for migrated mails) */
#define ABOX_METADATA_POP3_ORDER "POP3-Order"
/* Received UNIX timestamp in hex */
#define ABOX_METADATA_RECEIVED_TIME "Received-Time"
/* Physical message size in hex. Necessary only if it differs from
	the dbox_message_header.message_size_hex, for example because the
	message is compressed. */
#define ABOX_METADATA_PHYSICAL_SIZE "Physical-Size"
/* Virtual message size in hex (line feeds counted as CRLF) */
#define ABOX_METADATA_VIRTUAL_SIZE	"Virtual-Size"
/* Pointer to external message data. Format is:
	1*(<start offset> <byte count> <options> <ref>) */
#define ABOX_METADATA_EXT_REF	"Ext-Ref"
/* Mailbox name where this message was originally saved to.
	When rebuild finds a message whose mailbox is unknown, it's
	placed to this mailbox. */
#define ABOX_METADATA_ORIG_MAILBOX	"Orig-Mailbox"

char *abox_file_make_path(struct abox_file *file, const char *fname);
struct dbox_file *abox_file_init(struct abox_mailbox *mbox, guid_128_t guid);
void abox_file_free(struct dbox_file *file);

/* Get file's extrefs metadata. */
int abox_file_get_attachments(struct dbox_file *file, const char **extrefs_r);
/* Returns attachment path for this file, given the source path. The result is
   always <hash>-<guid>-<mailbox_guid>-<uid>. The source path is expected to
   contain <hash>-<guid>[-*]. */
const char *
abox_file_attachment_relpath(struct abox_file *file, const char *srcpath);

/* Assign UID for a newly created file (by renaming it) 
int abox_file_assign_uid(struct abox_file *file, uint32_t uid,
			  bool ignore_if_exists);
*/

struct fs_file *abox_file_init_fs_file(struct dbox_file *file, const char *path,
			 bool parents);
/* Move the file to alt path or back. */
int abox_file_move(struct dbox_file *file, bool alt_path);
/* Unlink file and all of its referenced attachments. */
int abox_file_unlink_with_attachments(struct abox_file *sfile);
/* Unlink file and its attachments when rolling back a saved message. */
int abox_file_unlink_aborted_save(struct dbox_file *file);

#endif
