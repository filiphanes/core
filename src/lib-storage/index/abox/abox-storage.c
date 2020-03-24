/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "fs-api.h"
#include "master-service.h"
#include "mail-index-modseq.h"
#include "mail-search-build.h"
#include "mailbox-list-private.h"
#include "mailbox-uidvalidity.h"
#include "unlink-old-files.h"
#include "index-pop3-uidl.h"
#include "abox-mail.h"
#include "abox-save.h"
#include "abox-file.h"
#include "abox-sync.h"
#include "abox-storage.h"

extern struct mail_storage abox_storage;
extern struct mailbox abox_mailbox;

static struct event_category event_category_abox = {
	.name = "abox",
	.parent = &event_category_storage,
};

static struct mail_storage *abox_storage_alloc(void)
{
	FUNC_START();
	struct abox_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("abox storage", 512+256);
	storage = p_new(pool, struct abox_storage, 1);
	storage->storage = abox_storage;
	storage->storage.pool = pool;
	return &storage->storage;
}

static int abox_storage_create(struct mail_storage *_storage,
				struct mail_namespace *ns,
				const char **error_r)
{
	FUNC_START();
	struct abox_storage *storage = ABOX_STORAGE(_storage);
	// enum fs_properties props;
	const struct mail_storage_settings *set = _storage->set;
	const char *error;
	const char *name, *args;

	if (*set->mail_fs != '\0') {
		args = strpbrk(set->mail_fs, ": ");
		if (args == NULL) {
			name = set->mail_fs;
			args = "";
		} else {
			name = t_strdup_until(set->mail_fs, args++);
		}

		if (mailbox_list_init_fs(ns->list, name, args,
					 storage->mail_dir,
					 &storage->mail_fs, &error) < 0) {
			*error_r = t_strdup_printf("mail_fs: %s", error);
			return -1;
		}
	}

	return 0;
}

void abox_storage_destroy(struct mail_storage *_storage)
{
	struct abox_storage *storage = ABOX_STORAGE(_storage);

	fs_deinit(&storage->mail_fs);
	index_storage_destroy(_storage);
}

static const char *
abox_storage_find_root_dir(const struct mail_namespace *ns)
{
	FUNC_START();
	bool debug = ns->mail_set->mail_debug;
	const char *home, *path;

	if (ns->owner != NULL &&
	    mail_user_get_home(ns->owner, &home) > 0) {
		path = t_strconcat(home, "/abox", NULL);
		if (access(path, R_OK|W_OK|X_OK) == 0) {
			if (debug)
				i_debug("abox: root exists (%s)", path);
			return path;
		} 
		if (debug)
			i_debug("abox: access(%s, rwx): failed: %m", path);
	}
	return NULL;
}

void abox_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
				    struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_FS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = ABOX_SUBSCRIPTION_FILE_NAME;
	if (*set->maildir_name == '\0')
		set->maildir_name = ABOX_MAILDIR_NAME;
	if (*set->mailbox_dir_name == '\0')
		set->mailbox_dir_name = ABOX_MAILBOX_DIR_NAME;
}

static bool abox_storage_autodetect(const struct mail_namespace *ns,
				     struct mailbox_list_settings *set)
{
	FUNC_START();
	bool debug = ns->mail_set->mail_debug;
	struct stat st;
	const char *path, *root_dir;

	if (set->root_dir != NULL)
		root_dir = set->root_dir;
	else {
		root_dir = abox_storage_find_root_dir(ns);
		if (root_dir == NULL) {
			if (debug)
				i_debug("abox: couldn't find root dir");
			return FALSE;
		}
	}

	/* TODO: maybe use fs-api */
	path = t_strconcat(root_dir, "/"ABOX_MAILBOX_DIR_NAME, NULL);
	if (stat(path, &st) < 0) {
		if (debug)
			i_debug("abox autodetect: stat(%s) failed: %m", path);
		return FALSE;
	}

	if (!S_ISDIR(st.st_mode)) {
		if (debug)
			i_debug("abox autodetect: %s not a directory", path);
		return FALSE;
	}

	set->root_dir = root_dir;
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_FS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = ABOX_SUBSCRIPTION_FILE_NAME;
	if (*set->maildir_name == '\0')
		set->maildir_name = ABOX_MAILDIR_NAME;
	if (*set->mailbox_dir_name == '\0')
		set->mailbox_dir_name = ABOX_MAILBOX_DIR_NAME;

	return TRUE;
}

static struct mailbox *
abox_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *vname, enum mailbox_flags flags)
{
	FUNC_START();
	struct abox_mailbox *mbox;
	struct index_mailbox_context *ibox;
	pool_t pool;

	/* abox can't work without index files */
	flags &= ~MAILBOX_FLAG_NO_INDEX_FILES;

	pool = pool_alloconly_create("abox mailbox", 1024*3);
	mbox = p_new(pool, struct abox_mailbox, 1);
	mbox->box = abox_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &abox_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	ibox = INDEX_STORAGE_CONTEXT(&mbox->box);
	ibox->index_flags |= MAIL_INDEX_OPEN_FLAG_KEEP_BACKUPS |
		MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY;

	mbox->storage = ABOX_STORAGE(storage);
	return &mbox->box;
}

int abox_read_header(struct abox_mailbox *mbox,
		      struct abox_index_header *hdr, bool log_error,
		      bool *need_resize_r)
{
	FUNC_START();
	struct mail_index_view *view;
	const void *data;
	size_t data_size;
	int ret = 0;

	i_assert(mbox->box.opened);

	view = mail_index_view_open(mbox->box.index);
	mail_index_get_header_ext(view, mbox->hdr_ext_id,
				  &data, &data_size);
	if (data_size < ABOX_INDEX_HEADER_MIN_SIZE &&
	    (!mbox->box.creating || data_size != 0)) {
		if (log_error) {
			mailbox_set_critical(&mbox->box,
				"abox: Invalid abox header size");
		}
		ret = -1;
	} else {
		i_zero(hdr);
		memcpy(hdr, data, I_MIN(data_size, sizeof(*hdr)));
		if (guid_128_is_empty(hdr->mailbox_guid))
			ret = -1;
		else {
			/* data is valid. remember it in case mailbox
			   is being reset */
			mail_index_set_ext_init_data(mbox->box.index,
						     mbox->hdr_ext_id,
						     hdr, sizeof(*hdr));
		}
	}
	mail_index_view_close(&view);
	*need_resize_r = data_size < sizeof(*hdr);
	return ret;
}

static void abox_update_header(struct abox_mailbox *mbox,
				struct mail_index_transaction *trans,
				const struct mailbox_update *update)
{
	FUNC_START();
	struct abox_index_header hdr, new_hdr;
	bool need_resize;

	if (abox_read_header(mbox, &hdr, TRUE, &need_resize) < 0) {
		i_zero(&hdr);
		need_resize = TRUE;
	}

	new_hdr = hdr;

	if (update != NULL && !guid_128_is_empty(update->mailbox_guid)) {
		guid_128_copy(new_hdr.mailbox_guid, update->mailbox_guid);
	} else if (guid_128_is_empty(new_hdr.mailbox_guid)) {
		guid_128_generate(new_hdr.mailbox_guid);
	}

	if (need_resize) {
		mail_index_ext_resize_hdr(trans, mbox->hdr_ext_id,
					  sizeof(new_hdr));
	}
	if (memcmp(&hdr, &new_hdr, sizeof(hdr)) != 0) {
		mail_index_update_header_ext(trans, mbox->hdr_ext_id, 0,
					     &new_hdr, sizeof(new_hdr));
	}
	guid_128_copy(mbox->mailbox_guid, new_hdr.mailbox_guid);
}

uint32_t abox_get_uidvalidity_next(struct mailbox_list *list)
{
	FUNC_START();
	const char *path;

	path = mailbox_list_get_root_forced(list, MAILBOX_LIST_PATH_TYPE_CONTROL);
	path = t_strconcat(path, "/"ABOX_UIDVALIDITY_FILE_NAME, NULL);
	return mailbox_uidvalidity_next(list, path);
}

void abox_notify_changes(struct mailbox *box)
{
	const char *dir, *path;

	if (box->notify_callback == NULL)
		mailbox_watch_remove_all(box);
	else {
		if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX,
					&dir) <= 0)
			return;
		path = t_strdup_printf("%s/"MAIL_INDEX_PREFIX".log", dir);
		mailbox_watch_add(box, path);
	}
}

int abox_mailbox_create_indexes(struct mailbox *box,
				 const struct mailbox_update *update,
				 struct mail_index_transaction *trans)
{
	FUNC_START();
	struct abox_mailbox *mbox = ABOX_MAILBOX(box);
	struct mail_index_transaction *new_trans = NULL;
	const struct mail_index_header *hdr;
	uint32_t uid_validity, uid_next;

	if (trans == NULL) {
		new_trans = mail_index_transaction_begin(box->view, 0);
		trans = new_trans;
	}

	hdr = mail_index_get_header(box->view);
	if (update != NULL && update->uid_validity != 0)
		uid_validity = update->uid_validity;
	else if (hdr->uid_validity != 0)
		uid_validity = hdr->uid_validity;
	else {
		/* set uidvalidity */
		uid_validity = abox_get_uidvalidity_next(box->list);
	}

	if (hdr->uid_validity != uid_validity) {
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}
	if (update != NULL && hdr->next_uid < update->min_next_uid) {
		uid_next = update->min_next_uid;
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, next_uid),
			&uid_next, sizeof(uid_next), TRUE);
	}
	if (update != NULL && update->min_first_recent_uid != 0 &&
	    hdr->first_recent_uid < update->min_first_recent_uid) {
		uint32_t first_recent_uid = update->min_first_recent_uid;

		mail_index_update_header(trans,
			offsetof(struct mail_index_header, first_recent_uid),
			&first_recent_uid, sizeof(first_recent_uid), FALSE);
	}
	if (update != NULL && update->min_highest_modseq != 0 &&
	    mail_index_modseq_get_highest(box->view) <
	    					update->min_highest_modseq) {
		mail_index_modseq_enable(box->index);
		mail_index_update_highest_modseq(trans,
						 update->min_highest_modseq);
	}

	if (box->inbox_user && box->creating) {
		/* initialize pop3-uidl header when creating mailbox
		   (not on mailbox_update()) */
		index_pop3_uidl_set_max_uid(box, trans, 0);
	}

	abox_update_header(mbox, trans, update);
	if (new_trans != NULL) {
		if (mail_index_transaction_commit(&new_trans) < 0) {
			mailbox_set_index_error(box);
			return -1;
		}
	}
	return 0;
}

void abox_set_mailbox_corrupted(struct mailbox *box)
{
	FUNC_START();
	struct abox_mailbox *mbox = ABOX_MAILBOX(box);
	struct abox_index_header hdr;
	bool need_resize;

	if (abox_read_header(mbox, &hdr, TRUE, &need_resize) < 0 ||
	    hdr.rebuild_count == 0)
		mbox->corrupted_rebuild_count = 1;
	else
		mbox->corrupted_rebuild_count = hdr.rebuild_count;
}

static int abox_mailbox_alloc_index(struct abox_mailbox *mbox)
{
	FUNC_START();
	struct abox_index_header hdr;

	if (index_storage_mailbox_alloc_index(&mbox->box) < 0)
		return -1;

	mbox->hdr_ext_id =
		mail_index_ext_register(mbox->box.index, "abox-hdr",
					sizeof(struct abox_index_header), 0, 0);
	mbox->guid_ext_id =
		mail_index_ext_register(mbox->box.index, "guid",
					0, GUID_128_SIZE, 1);
	/* set the initialization data in case the mailbox is created */
	i_zero(&hdr);
	guid_128_generate(hdr.mailbox_guid);
	mail_index_set_ext_init_data(mbox->box.index, mbox->hdr_ext_id,
				     &hdr, sizeof(hdr));
	return 0;
}

static bool
abox_cleanup_temp_files(struct mailbox_list *list, const char *path,
			time_t last_scan_time, time_t last_change_time)
{
	unsigned int interval = list->mail_set->mail_temp_scan_interval;

	/* check once in a while if there are temp files to clean up */
	if (interval == 0) {
		/* disabled */
		return FALSE;
	} else if (last_scan_time >= ioloop_time - (time_t)interval) {
		/* not the time to scan it yet */
		return FALSE;
	} else {
		bool stated = FALSE;
		if (last_change_time == (time_t)-1) {
			/* Don't know the ctime yet - look it up. */
			struct stat st;

			if (stat(path, &st) < 0) {
				if (errno == ENOENT)
					i_error("stat(%s) failed: %m", path);
				return FALSE;
			}
			last_change_time = st.st_ctime;
			stated = TRUE;
		}
		if (last_scan_time > last_change_time + ABOX_TMP_DELETE_SECS) {
			/* there haven't been any changes to this directory
			   since we last checked it. If we did an extra stat(),
			   we need to update the last_scan_time to avoid
			   stat()ing the next time. */
			return stated;
		}
		const char *prefix =
			mailbox_list_get_global_temp_prefix(list);
		(void)unlink_old_files(path, prefix,
				       ioloop_time - ABOX_TMP_DELETE_SECS);
		return TRUE;
	}
	return FALSE;
}

int abox_mailbox_check_existence(struct mailbox *box, time_t *path_ctime_r)
{
	const char *index_path, *box_path = mailbox_get_path(box);
	struct stat st;
	int ret = -1;

	*path_ctime_r = (time_t)-1;

	if (box->list->set.iter_from_index_dir) {
		/* Just because the index directory exists, it doesn't mean
		   that the mailbox is selectable. Check that by seeing if
		   dovecot.index.log exists. If it doesn't, fallback to
		   checking for the abox-Mails in the mail root directory.
		   So this also means that if a mailbox is \NoSelect, listing
		   it will always do a stat() for abox-Mails in the mail root
		   directory. That's not ideal, but this makes the behavior
		   safer and \NoSelect mailboxes are somewhat rare. */
		if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX,
					&index_path) < 0)
			return -1;
		i_assert(index_path != NULL);
		index_path = t_strconcat(index_path, "/", box->index_prefix,
					 ".log", NULL);
		ret = stat(index_path, &st);
	}
	if (ret < 0) {
		ret = stat(box_path, &st);
		if (ret == 0)
			*path_ctime_r = st.st_ctime;
	}

	if (ret == 0) {
		return 0;
	} else if (errno == ENOENT || errno == ENAMETOOLONG) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
		return -1;
	} else if (errno == EACCES) {
		mailbox_set_critical(box, "%s",
			mail_error_eacces_msg("stat", box_path));
		return -1;
	} else {
		mailbox_set_critical(box, "stat(%s) failed: %m", box_path);
		return -1;
	}
}

static int abox_mailbox_open(struct mailbox *box)
{
	FUNC_START();
	struct abox_mailbox *mbox = ABOX_MAILBOX(box);
	struct abox_index_header hdr;
	const char *box_path = mailbox_get_path(box);
	bool need_resize;
	time_t path_ctime;

	if (abox_mailbox_check_existence(box, &path_ctime) < 0)
		return -1;

	if (abox_mailbox_alloc_index(mbox) < 0)
		return -1;

	if (index_storage_mailbox_open(box, FALSE) < 0)
		return -1;

	mail_index_set_fsync_mode(box->index,
				  box->storage->set->parsed_fsync_mode,
				  MAIL_INDEX_FSYNC_MASK_APPENDS |
				  MAIL_INDEX_FSYNC_MASK_EXPUNGES);

	const struct mail_index_header *_hdr = mail_index_get_header(box->view);
	if (abox_cleanup_temp_files(box->list, box_path,
				    _hdr->last_temp_file_scan, path_ctime)) {
		/* temp files were scanned. update the last scan timestamp. */
		index_mailbox_update_last_temp_file_scan(box);
	}

	if (box->creating) {
		/* wait for mailbox creation to initialize the index */
		return 0;
	}

	/* get/generate mailbox guid */
	if (abox_read_header(mbox, &hdr, FALSE, &need_resize) < 0) {
		/* looks like the mailbox is corrupted */
		(void)abox_sync(mbox, ABOX_SYNC_FLAG_FORCE);
		if (abox_read_header(mbox, &hdr, TRUE, &need_resize) < 0)
			i_zero(&hdr);
	}

	if (guid_128_is_empty(hdr.mailbox_guid)) {
		/* regenerate it */
		if (abox_mailbox_create_indexes(box, NULL, NULL) < 0 ||
		    abox_read_header(mbox, &hdr, TRUE, &need_resize) < 0)
			return -1;
	}
	guid_128_copy(mbox->mailbox_guid, hdr.mailbox_guid);
	return 0;
}

static void abox_mailbox_close(struct mailbox *box)
{
	FUNC_START();
	struct abox_mailbox *mbox = ABOX_MAILBOX(box);

	if (mbox->corrupted_rebuild_count != 0)
		(void)abox_sync(mbox, 0);
	FUNC_IN();
	index_storage_mailbox_close(box);
	FUNC_END();
}

static int
abox_mailbox_create(struct mailbox *box,
		     const struct mailbox_update *update, bool directory)
{
	FUNC_START();
	struct abox_mailbox *mbox = ABOX_MAILBOX(box);
	struct abox_index_header hdr;
	bool need_resize;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	int ret;

	if ((ret = index_storage_mailbox_create(box, directory)) <= 0)
		return ret;
	if (mailbox_open(box) < 0)
		return -1;

	if (mail_index_get_header(box->view)->uid_validity != 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	}

	/* use syncing as a lock */
	ret = mail_index_sync_begin(box->index, &sync_ctx, &view, &trans, 0);
	if (ret <= 0) {
		i_assert(ret != 0);
		mailbox_set_index_error(box);
		return -1;
	}

	if (mail_index_get_header(view)->uid_validity == 0) {
		if (abox_mailbox_create_indexes(box, update, trans) < 0) {
			mail_index_sync_rollback(&sync_ctx);
			return -1;
		}
	}

	if (mail_index_sync_commit(&sync_ctx) < 0)
		return -1;

	if (directory || !guid_128_is_empty(mbox->mailbox_guid))
		return 0;

	/* another process just created the mailbox. read the mailbox_guid. */
	if (abox_read_header(mbox, &hdr, FALSE, &need_resize) < 0) {
		mailbox_set_critical(box,
			"abox: Failed to read newly created abox header");
		return -1;
	}
	guid_128_copy(mbox->mailbox_guid, hdr.mailbox_guid);
	i_assert(!guid_128_is_empty(mbox->mailbox_guid));
	return 0;
}

static int
abox_mailbox_get_metadata(struct mailbox *box,
			   enum mailbox_metadata_items items,
			   struct mailbox_metadata *metadata_r)
{
	FUNC_START();
	struct abox_mailbox *mbox = ABOX_MAILBOX(box);

	if (index_mailbox_get_metadata(box, items, metadata_r) < 0)
		return -1;
	if ((items & MAILBOX_METADATA_GUID) != 0) {
		guid_128_copy(metadata_r->guid, mbox->mailbox_guid);
	}
	return 0;
}

static int
abox_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	FUNC_START();
	if (!box->opened) {
		if (mailbox_open(box) < 0)
			return -1;
	}
	if (abox_mailbox_create_indexes(box, update, NULL) < 0)
		return -1;
	return index_storage_mailbox_update_common(box, update);
}

bool abox_header_have_flag(struct mailbox *box, uint32_t ext_id,
			   unsigned int flags_offset, uint8_t flag)
{
	const void *data;
	size_t data_size;
	uint8_t flags = 0;

	mail_index_get_header_ext(box->view, ext_id, &data, &data_size);
	if (flags_offset < data_size)
		flags = *((const uint8_t *)data + flags_offset);
	return (flags & flag) != 0;
}

struct mail_storage abox_storage = {
	.name = ABOX_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_FILE_PER_MSG |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_SAVE_GUIDS |
		MAIL_STORAGE_CLASS_FLAG_BINARY_DATA,
	.event_category = &event_category_abox,

	.v = {
                NULL,
		abox_storage_alloc,
		abox_storage_create,
		abox_storage_destroy,
		NULL,
		abox_storage_get_list_settings,
		abox_storage_autodetect,
		abox_mailbox_alloc,
		NULL,
		NULL,
	}
};

struct mailbox abox_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_mailbox_enable,
		index_storage_mailbox_exists,
		abox_mailbox_open,
		abox_mailbox_close,
		index_storage_mailbox_free,
		abox_mailbox_create,
		abox_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		abox_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
		index_storage_list_index_has_changed,
		index_storage_list_index_update_sync,
		abox_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		abox_notify_changes,
		index_transaction_begin,
		index_transaction_commit,
		index_transaction_rollback,
		NULL,
		abox_mail_alloc,
		index_storage_search_init,
		index_storage_search_deinit,
		index_storage_search_next_nonblock,
		index_storage_search_next_update_seq,
		abox_save_alloc,
		abox_save_begin,
		abox_save_continue,
		abox_save_finish,
		abox_save_cancel,
		abox_copy,
		abox_transaction_save_commit_pre,
		abox_transaction_save_commit_post,
		abox_transaction_save_rollback,
		index_storage_is_inconsistent
	}
};
