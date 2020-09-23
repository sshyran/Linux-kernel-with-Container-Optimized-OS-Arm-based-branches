// SPDX-License-Identifier: GPL-2.0
/*
 * Container Security Monitor module
 *
 * Copyright (c) 2018 Google, Inc
 */

#include "monitor.h"

#include <linux/atomic.h>
#include <linux/audit.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/mempool.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/notifier.h>
#include <linux/net.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <overlayfs/overlayfs.h>
#include <uapi/linux/magic.h>
#include <uapi/asm/mman.h>

/* Configuration options for execute collector. */
struct execute_config csm_execute_config;

/* unique atomic value for the machine boot instance */
static atomic_t machine_rand = ATOMIC_INIT(0);

/* sequential container identifier */
static atomic_t contid = ATOMIC_INIT(0);

/* Generation id for each enumeration invocation. */
static atomic_t enumeration_count = ATOMIC_INIT(0);

struct file_provenance {
	/* pid of the process doing the first write. */
	pid_t tgid;
	/* start_time of the process to uniquely identify it. */
	u64 start_time;
};

struct csm_enumerate_processes_work_data {
	struct work_struct work;
	int enumeration_count;
};

static void *kmap_argument_stack(struct linux_binprm *bprm, void **ctx)
{
	char *argv;
	int err;
	unsigned long i, pos, count;
	void *map;
	struct page *page;

	/* vma_pages() returns the number of pages reserved for the stack */
	count = vma_pages(bprm->vma);

	if (likely(count == 1)) {
		err = get_user_pages_remote(current, bprm->mm, bprm->p, 1,
					    FOLL_FORCE, &page, NULL, NULL);
		if (err != 1)
			return NULL;

		argv = kmap(page);
		*ctx = page;
	} else {
		/*
		 * If more than one pages is needed, copy all of them to a set
		 * of pages. Parsing the argument across kmap pages in different
		 * addresses would make it impractical.
		 */
		argv = vmalloc(count * PAGE_SIZE);
		if (!argv)
			return NULL;

		for (i = 0; i < count; i++) {
			pos = ALIGN_DOWN(bprm->p, PAGE_SIZE) + i * PAGE_SIZE;
			err = get_user_pages_remote(current, bprm->mm, pos, 1,
						    FOLL_FORCE, &page, NULL,
						    NULL);
			if (err <= 0) {
				vfree(argv);
				return NULL;
			}

			map = kmap(page);
			memcpy(argv + i * PAGE_SIZE, map, PAGE_SIZE);
			kunmap(page);
			put_page(page);
		}
		*ctx = bprm;
	}

	return argv;
}

static void kunmap_argument_stack(struct linux_binprm *bprm, void *addr,
				  void *ctx)
{
	struct page *page;

	if (!addr)
		return;

	if (likely(vma_pages(bprm->vma) == 1)) {
		page = (struct page *)ctx;
		kunmap(page);
		put_page(ctx);
	} else {
		vfree(addr);
	}
}

static char *find_array_next_entry(char *array, unsigned long *offset,
				   unsigned long end)
{
	char *entry;
	unsigned long off = *offset;

	if (off >= end)
		return NULL;

	/* Check the entry is null terminated and in bound */
	entry = array + off;
	while (array[off]) {
		if (++off >= end)
			return NULL;
	}

	/* Pass the null byte for the next iteration */
	*offset = off + 1;

	return entry;
}

struct string_arr_ctx {
	struct linux_binprm *bprm;
	void *stack;
};

static size_t get_config_limit(size_t *config_ptr)
{
	lockdep_assert_held_read(&csm_rwsem_config);

	/*
	 * If execute is not enabled, do not capture arguments.
	 * The vsock packet won't be sent anyway.
	 */
	if (!csm_execute_enabled)
		return 0;

	return *config_ptr;
}

static bool encode_current_argv(pb_ostream_t *stream, const pb_field_t *field,
				void * const *arg)
{
	struct string_arr_ctx *ctx = (struct string_arr_ctx *)*arg;
	int i;
	struct linux_binprm *bprm = ctx->bprm;
	unsigned long offset = bprm->p % PAGE_SIZE;
	unsigned long end = vma_pages(bprm->vma) * PAGE_SIZE;
	char *argv = ctx->stack;
	char *entry;
	size_t limit, used = 0;
	ssize_t ret;

	limit = get_config_limit(&csm_execute_config.argv_limit);
	if (!limit)
		return true;

	for (i = 0; i < bprm->argc; i++) {
		entry = find_array_next_entry(argv, &offset, end);
		if (!entry)
			return false;

		ret = pb_encode_string_field_limit(stream, field,
						   (void * const *)&entry,
						   limit - used);
		if (ret < 0)
			return false;

		used += ret;

		if (used >= limit)
			break;
	}

	return true;
}

static bool check_envp_allowlist(char *envp)
{
	bool ret = false;
	char *strs, *equal;
	size_t str_size, equal_pos;

	/* If execute is not enabled, skip all. */
	if (!csm_execute_enabled)
		goto out;

	/* No filter, allow all. */
	strs = csm_execute_config.envp_allowlist;
	if (!strs) {
		ret = true;
		goto out;
	}

	/*
	 * Identify the key=value separation.
	 * If none exists use the whole string as a key.
	 */
	equal = strchr(envp, '=');
	equal_pos = equal ? (equal - envp) : strlen(envp);

	/* Default to skip if no match found. */
	ret = false;

	do {
		str_size = strlen(strs);

		/*
		 * If the filter length align with the key value equal sign,
		 * it might be a match, check the key value.
		 */
		if (str_size == equal_pos &&
		    !strncmp(strs, envp, str_size)) {
			ret = true;
			goto out;
		}

		strs += str_size + 1;
	} while (*strs != 0);

out:
	return ret;
}

static bool encode_current_envp(pb_ostream_t *stream, const pb_field_t *field,
				void * const *arg)
{
	struct string_arr_ctx *ctx = (struct string_arr_ctx *)*arg;
	int i;
	struct linux_binprm *bprm = ctx->bprm;
	unsigned long offset = bprm->p % PAGE_SIZE;
	unsigned long end = vma_pages(bprm->vma) * PAGE_SIZE;
	char *argv = ctx->stack;
	char *entry;
	size_t limit, used = 0;
	ssize_t ret;

	limit = get_config_limit(&csm_execute_config.envp_limit);
	if (!limit)
		return true;

	/* Skip arguments */
	for (i = 0; i < bprm->argc; i++) {
		if (!find_array_next_entry(argv, &offset, end))
			return false;
	}

	for (i = 0; i < bprm->envc; i++) {
		entry = find_array_next_entry(argv, &offset, end);
		if (!entry)
			return false;

		if (!check_envp_allowlist(entry))
			continue;

		ret = pb_encode_string_field_limit(stream, field,
						   (void * const *)&entry,
						   limit - used);
		if (ret < 0)
			return false;

		used += ret;

		if (used >= limit)
			break;
	}

	return true;
}

static bool is_overlayfs_mounted(struct file *file)
{
	struct vfsmount *mnt;
	struct super_block *mnt_sb;

	mnt = file->f_path.mnt;
	if (mnt == NULL)
		return false;

	mnt_sb = mnt->mnt_sb;
	if (mnt_sb == NULL || mnt_sb->s_magic != OVERLAYFS_SUPER_MAGIC)
		return false;

	return true;
}

/*
 * Before the process starts, identify a possible container by checking if the
 * task is on a pid namespace and the target file is using an overlayfs mounting
 * point. This check is valid for COS and GKE but not all existing containers.
 */
static bool is_possible_container(struct task_struct *task,
				  struct file *file)
{
	if (task_active_pid_ns(task) == &init_pid_ns)
		return false;

	return is_overlayfs_mounted(file);
}

/*
 * Generates a random identifier for this boot instance.
 * This identifier is generated only when needed to increase the entropy
 * available compared to doing it at early boot.
 */
static u32 get_machine_id(void)
{
	int machineid, old;

	machineid = atomic_read(&machine_rand);

	if (unlikely(machineid == 0)) {
		machineid = (int)get_random_int();
		if (machineid == 0)
			machineid = 1;
		old = atomic_cmpxchg(&machine_rand, 0, machineid);

		/* If someone beat us, use their value. */
		if (old != 0)
			machineid = old;
	}

	return (u32)machineid;
}

/*
 * Generate a 128-bit unique identifier for the process by appending:
 *  - A machine identifier unique per boot.
 *  - The start time of the process in nanoseconds.
 *  - The tgid for the set of threads in a process.
 */
static int get_process_uuid(struct task_struct *task, char *buffer, size_t size)
{
	union process_uuid *id = (union process_uuid *)buffer;

	memset(buffer, 0, size);

	if (WARN_ON(size < PROCESS_UUID_SIZE))
		return -EINVAL;

	id->machineid = get_machine_id();
	id->start_time = ktime_mono_to_real(task->group_leader->start_time);
	id->tgid = task_tgid_nr(task);

	return 0;
}

int get_process_uuid_by_pid(pid_t pid_nr, char *buffer, size_t size)
{
	int err;
	struct task_struct *task = NULL;

	rcu_read_lock();
	task = find_task_by_pid_ns(pid_nr, &init_pid_ns);
	if (!task) {
		err = -ENOENT;
		goto out;
	}
	err = get_process_uuid(task, buffer, size);
out:
	rcu_read_unlock();
	return err;
}

static int get_process_uuid_from_xattr(struct file *file, char *buffer,
				       size_t size)
{
	struct dentry *dentry;
	int err;
	struct file_provenance prov;
	union process_uuid *id = (union process_uuid *)buffer;

	memset(buffer, 0, size);

	if (WARN_ON(size < PROCESS_UUID_SIZE))
		return -EINVAL;

	/* The file is part of overlayfs on the upper layer. */
	if (!is_overlayfs_mounted(file))
		return -ENODATA;

	dentry = ovl_dentry_upper(file->f_path.dentry);
	if (!dentry)
		return -ENODATA;

	err = __vfs_getxattr(dentry, dentry->d_inode,
			     XATTR_SECURITY_CSM, &prov, sizeof(prov));
	/* returns -ENODATA if the xattr does not exist. */
	if (err < 0)
		return err;
	if (err != sizeof(prov)) {
		pr_err("unexpected size for xattr: %zu -> %d\n",
		       size, err);
		return -ENODATA;
	}

	id->machineid = get_machine_id();
	id->start_time = prov.start_time;
	id->tgid = prov.tgid;
	return 0;
}

u64 csm_set_contid(struct task_struct *task)
{
	u64 cid;
	struct pid_namespace *ns;

	ns = task_active_pid_ns(task);
	if (WARN_ON(!task->audit) || WARN_ON(!ns))
		return AUDIT_CID_UNSET;

	cid = atomic_inc_return(&contid);
	task->audit->contid = cid;

	/*
	 * If the namespace container-id is not set, use the one assigned
	 * to the first process created.
	 */
	cmpxchg(&ns->cid, 0, cid);
	return cid;
}

u64 csm_get_ns_contid(struct pid_namespace *ns)
{
	if (!ns || !ns->cid)
		return AUDIT_CID_UNSET;

	return ns->cid;
}

union ip_data {
	struct in_addr ip4;
	struct in6_addr ip6;
};

struct file_data {
	void *allocated;
	union ip_data local;
	union ip_data remote;
	char modified_uuid[PROCESS_UUID_SIZE];
};

static void free_file_data(struct file_data *fdata)
{
	free_page((unsigned long)fdata->allocated);
	fdata->allocated = NULL;
}

static void fill_socket_description(struct sockaddr_storage *saddr,
				   union ip_data *idata,
				   schema_SocketIp *schema_socketip)
{
	struct sockaddr_in *sin4 = (struct sockaddr_in *)saddr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)saddr;

	schema_socketip->family = saddr->ss_family;

	switch (saddr->ss_family) {
	case AF_INET:
		schema_socketip->port = ntohs(sin4->sin_port);
		idata->ip4 = sin4->sin_addr;
		schema_socketip->ip.funcs.encode = pb_encode_ip4;
		schema_socketip->ip.arg = &idata->ip4;
		break;
	case AF_INET6:
		schema_socketip->port = ntohs(sin6->sin6_port);
		idata->ip6 = sin6->sin6_addr;
		schema_socketip->ip.funcs.encode = pb_encode_ip6;
		schema_socketip->ip.arg = &idata->ip6;
		break;
	}
}

static int fill_file_overlayfs(struct file *file, schema_File *schema_file,
			       struct file_data *fdata)
{
	struct dentry *dentry;
	int err;
	schema_Overlay *overlayfs;

	/* If not an overlayfs superblock, done. */
	if (!is_overlayfs_mounted(file))
		return 0;

	dentry = file->f_path.dentry;
	schema_file->which_filesystem = schema_File_overlayfs_tag;
	overlayfs = &schema_file->filesystem.overlayfs;
	overlayfs->lower_layer = ovl_dentry_lower(dentry);
	overlayfs->upper_layer = ovl_dentry_upper(dentry);

	err = get_process_uuid_from_xattr(file, fdata->modified_uuid,
					  sizeof(fdata->modified_uuid));
	/* If there is no xattr, just skip the modified_uuid field. */
	if (err == -ENODATA)
		return 0;
	if (err < 0)
		return err;

	overlayfs->modified_uuid.funcs.encode = pb_encode_uuid_field;
	overlayfs->modified_uuid.arg = fdata->modified_uuid;
	return 0;
}

static int fill_file_description(struct file *file, schema_File *schema_file,
				 struct file_data *fdata)
{
	char *buf;
	int err;
	u32 mode;
	char *path;
	struct socket *socket;
	schema_Socket *socketfs;
	struct sockaddr_storage saddr;

	memset(fdata, 0, sizeof(*fdata));

	if (file == NULL)
		return 0;

	schema_file->ino = file_inode(file)->i_ino;
	mode = file_inode(file)->i_mode;

	/* For pipes, no need to resolve the path. */
	if (S_ISFIFO(mode))
		return 0;

	if (S_ISSOCK(mode)) {
		socket = (struct socket *)file->private_data;
		socketfs = &schema_file->filesystem.socket;

		/* Local socket */
		err = kernel_getsockname(socket, (struct sockaddr *)&saddr);
		if (err >= 0) {
			fill_socket_description(&saddr, &fdata->local,
						&socketfs->local);
		}

		/* Remote socket, might not be connected. */
		err = kernel_getpeername(socket, (struct sockaddr *)&saddr);
		if (err >= 0) {
			fill_socket_description(&saddr, &fdata->remote,
						&socketfs->remote);
		}

		schema_file->which_filesystem = schema_File_socket_tag;
		return 0;
	}

	/*
	 * From this point, we care about all the other types of files as their
	 * path provides interesting insight.
	 */
	buf = (char *)__get_free_page(GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	fdata->allocated = buf;

	path = d_path(&file->f_path, buf, PAGE_SIZE);
	if (IS_ERR(path)) {
		free_file_data(fdata);
		return PTR_ERR(path);
	}

	schema_file->fullpath.funcs.encode = pb_encode_string_field;
	schema_file->fullpath.arg = path; /* buf is freed in free_file_data. */

	err = fill_file_overlayfs(file, schema_file, fdata);
	if (err) {
		free_file_data(fdata);
		return err;
	}

	return 0;
}

static int fill_stream_description(schema_Descriptor *desc, int fd,
				   struct file_data *fdata)
{
	struct fd sfd;
	struct file *file;
	int err = 0;

	sfd = fdget(fd);
	file = sfd.file;

	if (file == NULL) {
		memset(fdata, 0, sizeof(*fdata));
		goto end;
	}

	desc->mode = file_inode(file)->i_mode;
	err = fill_file_description(file, &desc->file, fdata);

end:
	fdput(sfd);
	return err;
}

static int populate_proc_uuid_common(schema_Process *proc, char *uuid,
				     size_t uuid_size, char *parent_uuid,
				     size_t parent_uuid_size,
				     struct task_struct *task)
{
	int err;
	struct task_struct *parent;
	/* Generate unique identifier for the process and its parent */
	err = get_process_uuid(task, uuid, uuid_size);
	if (err)
		return err;

	proc->uuid.funcs.encode = pb_encode_uuid_field;
	proc->uuid.arg = uuid;

	rcu_read_lock();

	if (!pid_alive(task))
		goto out;
	/*
	 * I don't think this needs to be task_rcu_dereference because
	 * real_parent is only supposed to be accessed using RCU.
	 */
	parent = rcu_dereference(task->real_parent);

	if (parent) {
		err = get_process_uuid(parent, parent_uuid, parent_uuid_size);
		if (!err) {
			proc->parent_uuid.funcs.encode = pb_encode_uuid_field;
			proc->parent_uuid.arg = parent_uuid;
		}
	}

out:
	rcu_read_unlock();

	return err;
}

/* Populate the fields that we always want to set in Process messages. */
static int populate_proc_common(schema_Process *proc, char *uuid,
				size_t uuid_size, char *parent_uuid,
				size_t parent_uuid_size,
				struct task_struct *task)
{
	u64 cid;
	struct pid_namespace *ns = task_active_pid_ns(task);

	/* Container identifier for the current namespace. */
	proc->container_id = csm_get_ns_contid(ns);

	/*
	 * If the process container-id is different, the process tree is part of
	 * a different session within the namespace (kubectl/docker exec,
	 * liveness probe or others).
	 */
	cid = audit_get_contid(task);
	if (proc->container_id != cid)
		proc->exec_session_id = cid;

	/* Add information about pid in different namespaces */
	proc->pid = task_pid_nr(task);
	proc->parent_pid = task_ppid_nr(task);
	proc->container_pid = task_pid_nr_ns(task, ns);
	proc->container_parent_pid = task_ppid_nr_ns(task, ns);

	return populate_proc_uuid_common(proc, uuid, uuid_size, parent_uuid,
					 parent_uuid_size, task);
}

int csm_bprm_check_security(struct linux_binprm *bprm)
{
	char uuid[PROCESS_UUID_SIZE];
	char parent_uuid[PROCESS_UUID_SIZE];
	int err;
	schema_Event event = {};
	schema_Process *proc;
	struct string_arr_ctx argv_ctx;
	void *stack = NULL, *ctx = NULL;
	u64 cid;
	struct file_data path_data = {};
	struct file_data stdin_data = {};
	struct file_data stdout_data = {};
	struct file_data stderr_data = {};

	/*
	 * Always create a container-id for containerized processes.
	 * If the LSM is enabled later, we can track existing containers.
	 */
	cid = audit_get_contid(current);

	if (cid == AUDIT_CID_UNSET) {
		if (!is_possible_container(current, bprm->file))
			return 0;

		cid = csm_set_contid(current);

		if (cid == AUDIT_CID_UNSET)
			return 0;
	}

	if (!csm_execute_enabled)
		return 0;

	/* The interpreter will call us again with more context. */
	if (bprm->buf[0] == '#' && bprm->buf[1] == '!')
		return 0;

	proc = &event.event.execute.proc;
	err = populate_proc_common(proc, uuid, sizeof(uuid), parent_uuid,
				   sizeof(parent_uuid), current);
	if (err)
		goto out_free_buf;

	proc->creation_timestamp = ktime_get_real_ns();

	/* Provide information about the launched binary. */
	err = fill_file_description(bprm->file, &proc->binary, &path_data);
	if (err)
		goto out_free_buf;

	/* Information about streams */
	err = fill_stream_description(&proc->streams.stdin, STDIN_FILENO,
				      &stdin_data);
	if (err)
		goto out_free_buf;

	err = fill_stream_description(&proc->streams.stdout, STDOUT_FILENO,
				      &stdout_data);
	if (err)
		goto out_free_buf;

	err = fill_stream_description(&proc->streams.stderr, STDERR_FILENO,
				      &stderr_data);
	if (err)
		goto out_free_buf;

	stack = kmap_argument_stack(bprm, &ctx);
	if (!stack) {
		err = -EFAULT;
		goto out_free_buf;
	}

	/* Capture process argument */
	argv_ctx.bprm = bprm;
	argv_ctx.stack = stack;
	proc->args.argv.funcs.encode = encode_current_argv;
	proc->args.argv.arg = &argv_ctx;

	/* Capture process environment variables */
	proc->args.envp.funcs.encode = encode_current_envp;
	proc->args.envp.arg = &argv_ctx;

	event.which_event = schema_Event_execute_tag;

	/*
	 * Configurations options are checked when computing the serialized
	 * protobufs.
	 */
	down_read(&csm_rwsem_config);
	err = csm_sendeventproto(schema_Event_fields, &event);
	up_read(&csm_rwsem_config);

	if (err)
		pr_err("csm_sendeventproto returned %d on execve\n", err);
	err = 0;

out_free_buf:
	kunmap_argument_stack(bprm, stack, ctx);
	free_file_data(&path_data);
	free_file_data(&stdin_data);
	free_file_data(&stdout_data);
	free_file_data(&stderr_data);

	/*
	 * On failure, enforce it only if the execute config is enabled.
	 * If the collector was disabled, prefer to succeed to not impact the
	 * system.
	 */
	if (unlikely(err < 0 && !csm_execute_enabled))
		err = 0;

	return err;
}

/* Create a clone event when a new task leader is created. */
void csm_task_post_alloc(struct task_struct *task)
{
	int err;
	char uuid[PROCESS_UUID_SIZE];
	char parent_uuid[PROCESS_UUID_SIZE];
	schema_Event event = {};
	schema_Process *proc;

	if (!csm_execute_enabled ||
	    audit_get_contid(task) == AUDIT_CID_UNSET ||
	    !thread_group_leader(task))
		return;

	proc = &event.event.clone.proc;

	err = populate_proc_uuid_common(proc, uuid, sizeof(uuid), parent_uuid,
					sizeof(parent_uuid), task);

	event.which_event = schema_Event_clone_tag;
	err = csm_sendeventproto(schema_Event_fields, &event);
	if (err)
		pr_err("csm_sendeventproto returned %d on exit\n", err);
}

/*
 * This LSM hook callback doesn't exist upstream and is called only when the
 * last thread of a thread group exit.
 */
void csm_task_exit(struct task_struct *task)
{
	int err;
	schema_Event event = {};
	schema_ExitEvent *exit;
	char uuid[PROCESS_UUID_SIZE];

	if (!csm_execute_enabled ||
	    audit_get_contid(task) == AUDIT_CID_UNSET)
		return;

	exit = &event.event.exit;

	/* Fetch the unique identifier for this process */
	err = get_process_uuid(task, uuid, sizeof(uuid));
	if (err) {
		pr_err("failed to get process uuid on exit\n");
		return;
	}

	exit->process_uuid.funcs.encode = pb_encode_uuid_field;
	exit->process_uuid.arg = uuid;

	event.which_event = schema_Event_exit_tag;

	err = csm_sendeventproto(schema_Event_fields, &event);
	if (err)
		pr_err("csm_sendeventproto returned %d on exit\n", err);
}

int csm_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		unsigned long prot)
{
	char uuid[PROCESS_UUID_SIZE];
	char parent_uuid[PROCESS_UUID_SIZE];
	int err;
	schema_Event event = {};
	schema_MemoryExecEvent *memexec;
	u64 cid;
	struct file_data path_data = {};

	cid = audit_get_contid(current);

	if (!csm_memexec_enabled ||
	    !(prot & PROT_EXEC) ||
	    vma->vm_file == NULL ||
	    cid == AUDIT_CID_UNSET)
		return 0;

	memexec = &event.event.memexec;

	err = fill_file_description(vma->vm_file, &memexec->mapped_file,
				    &path_data);
	if (err)
		return err;

	err = populate_proc_common(&memexec->proc, uuid, sizeof(uuid),
				   parent_uuid, sizeof(parent_uuid), current);
	if (err)
		goto out;

	memexec->prot_exec_timestamp = ktime_get_real_ns();
	memexec->new_flags = prot;
	memexec->req_flags = reqprot;
	memexec->old_vm_flags = vma->vm_flags;

	memexec->action = schema_MemoryExecEvent_Action_MPROTECT;
	memexec->start_addr = vma->vm_start;
	memexec->end_addr = vma->vm_end;

	event.which_event = schema_Event_memexec_tag;

	err = csm_sendeventproto(schema_Event_fields, &event);
	if (err)
		pr_err("csm_sendeventproto returned %d on mprotect\n", err);
	err = 0;

	if (unlikely(err < 0 && !csm_memexec_enabled))
		err = 0;

out:
	free_file_data(&path_data);
	return err;
}

int csm_mmap_file(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags)
{
	char uuid[PROCESS_UUID_SIZE];
	char parent_uuid[PROCESS_UUID_SIZE];
	int err;
	schema_Event event = {};
	schema_MemoryExecEvent *memexec;
	struct file *exe_file;
	u64 cid;
	struct file_data path_data = {};

	cid = audit_get_contid(current);

	if (!csm_memexec_enabled ||
	    !(prot & PROT_EXEC) ||
	    file == NULL ||
	    cid == AUDIT_CID_UNSET)
		return 0;

	memexec = &event.event.memexec;
	err = fill_file_description(file, &memexec->mapped_file,
				    &path_data);
	if (err)
		return err;

	err = populate_proc_common(&memexec->proc, uuid, sizeof(uuid),
				   parent_uuid, sizeof(parent_uuid), current);
	if (err)
		goto out;

	/* get_mm_exe_file does its own locking on mm_sem. */
	exe_file = get_mm_exe_file(current->mm);
	if (exe_file) {
		if (path_equal(&file->f_path, &exe_file->f_path))
			memexec->is_initial_mmap = 1;
		fput(exe_file);
	}

	memexec->prot_exec_timestamp = ktime_get_real_ns();
	memexec->new_flags = prot;
	memexec->req_flags = reqprot;
	memexec->mmap_flags = flags;
	memexec->action = schema_MemoryExecEvent_Action_MMAP_FILE;
	event.which_event = schema_Event_memexec_tag;

	err = csm_sendeventproto(schema_Event_fields, &event);
	if (err)
		pr_err("csm_sendeventproto returned %d on mmap_file\n", err);
	err = 0;

	if (unlikely(err < 0 && !csm_memexec_enabled))
		err = 0;

out:
	free_file_data(&path_data);
	return err;
}

void csm_file_pre_free(struct file *file)
{
	struct dentry *dentry;
	int err;
	struct file_provenance prov;

	/* The file was opened to be modified and the LSM is enabled */
	if (!(file->f_mode & FMODE_WRITE) ||
	    !csm_enabled)
		return;

	/* The current process is containerized. */
	if (audit_get_contid(current) == AUDIT_CID_UNSET)
		return;

	/* The file is part of overlayfs on the upper layer. */
	if (!is_overlayfs_mounted(file))
		return;

	dentry = ovl_dentry_upper(file->f_path.dentry);
	if (!dentry)
		return;

	err = __vfs_getxattr(dentry, dentry->d_inode, XATTR_SECURITY_CSM,
			     NULL, 0);
	if (err != -ENODATA) {
		if (err < 0)
			pr_err("failed to get security attribute: %d\n", err);
		return;
	}

	prov.tgid = task_tgid_nr(current);
	prov.start_time = ktime_mono_to_real(current->group_leader->start_time);

	err = __vfs_setxattr(dentry, dentry->d_inode, XATTR_SECURITY_CSM, &prov,
			     sizeof(prov), 0);
	if (err < 0)
		pr_err("failed to set security attribute: %d\n", err);
}

/*
 * Based off of fs/proc/base.c:next_tgid
 *
 * next_thread_group_leader returns the task_struct of the next task with a pid
 * greater than or equal to tgid. The reference count is increased so that
 * rcu_read_unlock may be called, and preemption reenabled.
 */
static struct task_struct *next_thread_group_leader(pid_t *tgid)
{
	struct pid *pid;
	struct task_struct *task;

	cond_resched();
	rcu_read_lock();
retry:
	task = NULL;
	pid = find_ge_pid(*tgid, &init_pid_ns);
	if (pid) {
		*tgid = pid_nr_ns(pid, &init_pid_ns);
		task = pid_task(pid, PIDTYPE_PID);
		if (!task || !has_group_leader_pid(task) ||
		    audit_get_contid(task) == AUDIT_CID_UNSET) {
			(*tgid) += 1;
			goto retry;
		}

		/*
		 * Increment the reference count on the task before leaving
		 * the RCU grace period.
		 */
		get_task_struct(task);
		(*tgid) += 1;
	}

	rcu_read_unlock();
	return task;
}

void delayed_enumerate_processes(struct work_struct *work)
{
	pid_t tgid = 0;
	struct task_struct *task;
	struct csm_enumerate_processes_work_data *wd = container_of(
		work, struct csm_enumerate_processes_work_data, work);
	int wd_enumeration_count = wd->enumeration_count;

	kfree(wd);
	wd = NULL;
	work = NULL;

	/*
	 * Try for only a single enumeration routine at a time, as long as the
	 * execute collector is enabled.
	 */
	while ((wd_enumeration_count == atomic_read(&enumeration_count)) &&
	       READ_ONCE(csm_execute_enabled) &&
	       (task = next_thread_group_leader(&tgid))) {
		int err;
		char uuid[PROCESS_UUID_SIZE];
		char parent_uuid[PROCESS_UUID_SIZE];
		struct file *exe_file = NULL;
		struct file_data path_data = {};
		schema_Event event = {};
		schema_Process *proc = &event.event.enumproc.proc;

		exe_file = get_task_exe_file(task);
		if (!exe_file) {
			pr_err("failed to get enumerated process executable, pid: %u\n",
			       task_pid_nr(task));
			goto next;
		}

		err = fill_file_description(exe_file, &proc->binary,
					    &path_data);
		if (err) {
			pr_err("failed to fill enumerated process %u executable description: %d\n",
			       task_pid_nr(task), err);
			goto next;
		}

		err = populate_proc_common(proc, uuid, sizeof(uuid),
					   parent_uuid, sizeof(parent_uuid),
					   task);
		if (err) {
			pr_err("failed to set pid %u common fields: %d\n",
			       task_pid_nr(task), err);
			goto next;
		}

		if (task->flags & PF_EXITING)
			goto next;

		event.which_event = schema_Event_enumproc_tag;
		err = csm_sendeventproto(schema_Event_fields,
					 &event);
		if (err) {
			pr_err("failed to send pid %u enumerated process: %d\n",
			       task_pid_nr(task), err);
			goto next;
		}
next:
		free_file_data(&path_data);
		if (exe_file)
			fput(exe_file);

		put_task_struct(task);
	}
}

void csm_enumerate_processes(unsigned long const config_version)
{
	struct csm_enumerate_processes_work_data *wd;

	wd = kmalloc(sizeof(*wd), GFP_KERNEL);
	if (!wd)
		return;

	INIT_WORK(&wd->work, delayed_enumerate_processes);
	wd->enumeration_count = atomic_add_return(1, &enumeration_count);
	schedule_work(&wd->work);
}
