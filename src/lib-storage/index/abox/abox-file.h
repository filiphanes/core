#ifndef ABOX_FILE_H
#define ABOX_FILE_H

struct abox_file {
	struct abox_storage *storage;
	int refcount;

	time_t create_time;
	unsigned int file_version;
	unsigned int file_header_size;
	unsigned int msg_header_size;

	const char *cur_path;
	char *primary_path, *alt_path;
	int fd;
	struct fs_file *fs_file;
	struct fs_lock *fs_lock;
	struct istream *input;

	uoff_t cur_offset;
	uoff_t cur_physical_size;

	/* Metadata for the currently seeked metadata block. */
	pool_t metadata_pool;
	ARRAY(const char *) metadata;
	uoff_t metadata_read_offset;

	bool appending:1;
	bool corrupted:1;

	struct abox_mailbox *mbox;

	/* 0 while file is being created */
	uint32_t uid;
	guid_128_t guid;

	bool written_to_disk;
};

struct abox_file_append_context {
	struct abox_file *file;

	uoff_t first_append_offset, last_checkpoint_offset, last_flush_offset;
	struct ostream *output;
};

#define abox_file_is_open(file) ((file)->fs_file != NULL)

/* Globally unique identifier for the message. Preserved when copying. */
#define ABOX_METADATA_GUID	"guid"
/* POP3 UIDL overriding the default format */
#define ABOX_METADATA_POP3_UIDL "pop3-uidl"
/* POP3 message ordering (for migrated mails) */
#define ABOX_METADATA_POP3_ORDER "pop3-order"
/* Received UNIX timestamp in decimal */
#define ABOX_METADATA_RECEIVED_TIME "received-time"
/* Physical message size in decimal. Necessary only if it differs from
	the Virtual-Size, for example because the
	message is compressed. */
#define ABOX_METADATA_PHYSICAL_SIZE "physical-size"
/* Virtual message size in decimal (line feeds counted as CRLF) */
#define ABOX_METADATA_VIRTUAL_SIZE	"virtual-size"
/* Pointer to external message data. Format is:
	1*(<start offset> <byte count> <options> <ref>) */
#define ABOX_METADATA_EXT_REF	"ext-ref"
/* Mailbox name where this message was originally saved to.
	When rebuild finds a message whose mailbox is unknown, it's
	placed to this mailbox. */
#define ABOX_METADATA_ORIG_MAILBOX	"orig-mailbox"

void abox_file_set_syscall_error(struct abox_file *file, const char *function);
void abox_file_set_corrupted(struct abox_file *file, const char *reason, ...)
	ATTR_FORMAT(2, 3);

/* Open the file. Returns 1 if ok, 0 if file header is corrupted, -1 if error.
   If file is deleted, deleted_r=TRUE and 1 is returned. */
int abox_file_open(struct abox_file *file, bool *deleted_r);
/* Close the file handle from the file, but don't free it. */
void abox_file_close(struct abox_file *file);

/* fs_stat() the file. If file is already deleted, fails with errno=ENOENT. */
int abox_file_stat(struct abox_file *file, struct stat *st_r);

/* Try to lock the abox file. Returns
    1 if ok,
	0 if already locked by someone
   -1 if error. */
int abox_file_try_lock(struct abox_file *file);
void abox_file_unlock(struct abox_file *file);

/* Seek to given offset in file. Returns
    1 if ok/expunged,
	0 if file/offset is corrupted,
   -1 if I/O error. */
int abox_file_seek(struct abox_file *file, uoff_t offset);

char *abox_file_make_path(struct abox_file *file, const char *fname);
struct abox_file *abox_file_init(struct abox_mailbox *mbox, guid_128_t guid);
void abox_file_free(struct abox_file *file);
void abox_file_unref(struct abox_file **_file);

/* Start appending to abox file */
struct abox_file_append_context *abox_file_append_init(struct abox_file *file);
/* Finish writing appended mails. */
int abox_file_append_commit(struct abox_file_append_context **ctx);
/* Truncate appended mails. */
void abox_file_append_rollback(struct abox_file_append_context **ctx);
/* Get output stream for appending a new message. Returns 1 if ok, 0 if file
   can't be appended to (old file version or corruption) or -1 if error. */
int abox_file_get_append_stream(struct abox_file_append_context *ctx,
				struct ostream **output_r);
/* Call after message has been fully saved. If this isn't done, the writes
   since the last checkpoint are truncated. */
void abox_file_append_checkpoint(struct abox_file_append_context *ctx);
/* Flush output buffer. */
int abox_file_append_flush(struct abox_file_append_context *ctx);

const char *abox_file_metadata_get(struct abox_file *file, const char *key);
uoff_t abox_file_get_plaintext_size(struct abox_file *file);

/* Delete the given abox file. Returns
    1 if deleted,
    0 if file wasn't found
   -1 if error. */
int abox_file_unlink(struct abox_file *file);
/* Unlink file and its attachments when rolling back a saved message. */
int abox_file_unlink_aborted_save(struct abox_file *file);

#endif
