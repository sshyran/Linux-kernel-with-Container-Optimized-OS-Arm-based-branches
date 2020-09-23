// SPDX-License-Identifier: GPL-2.0
/*
 * Container Security Monitor module
 *
 * Copyright (c) 2018 Google, Inc
 */

#include "monitor.h"
#include "process.h"

#include <linux/audit.h>
#include <linux/lsm_hooks.h>
#include <linux/module.h>
#include <linux/pipe_fs_i.h>
#include <linux/rwsem.h>
#include <linux/string.h>
#include <linux/sysctl.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/vm_sockets.h>
#include <linux/file.h>

/* protects csm_*_enabled and configurations. */
DECLARE_RWSEM(csm_rwsem_config);

/* protects csm_host_port and csm_vsocket. */
DECLARE_RWSEM(csm_rwsem_vsocket);

/* queue used for poll wait on config changes. */
static DECLARE_WAIT_QUEUE_HEAD(config_wait);

/* increase each time a new configuration is applied. */
static unsigned long config_version;

/* Stats gathered from the LSM. */
struct container_stats csm_stats;

struct container_stats_mapping {
	const char *key;
	size_t *value;
};

/* Key value pair mapping for the sysfs entry. */
struct container_stats_mapping csm_stats_mapping[] = {
	{ "ProtoEncodingFailed", &csm_stats.proto_encoding_failed },
	{ "WorkQueueFailed", &csm_stats.workqueue_failed },
	{ "EventWritingFailed", &csm_stats.event_writing_failed },
	{ "SizePickingFailed", &csm_stats.size_picking_failed },
	{ "PipeAlreadyOpened", &csm_stats.pipe_already_opened },
};

/*
 * Is monitoring enabled? Defaults to disabled.
 * These variables might be used without locking csm_rwsem_config to check if an
 * LSM hook can bail quickly. The semaphore is taken later to ensure CSM is
 * still enabled.
 *
 * csm_enabled is true if any collector is enabled.
 */
bool csm_enabled;
static bool csm_container_enabled;
bool csm_execute_enabled;
bool csm_memexec_enabled;

/* securityfs control files */
static struct dentry *csm_dir;
static struct dentry *csm_enabled_file;
static struct dentry *csm_container_file;
static struct dentry *csm_config_file;
static struct dentry *csm_config_vers_file;
static struct dentry *csm_pipe_file;
static struct dentry *csm_stats_file;

/* Pipes to forward data to user-mode. */
DECLARE_RWSEM(csm_rwsem_pipe);
static struct file *csm_user_read_pipe;
struct file *csm_user_write_pipe;

/* Option to disable the CSM features at boot. */
static bool cmdline_boot_disabled;
bool cmdline_boot_vsock_enabled;

/* Options disabled by default. */
static bool cmdline_boot_pipe_enabled;
static bool cmdline_boot_config_enabled;

/* Option to fully enabled the LSM at boot for automated testing. */
static bool cmdline_default_enabled;

static int csm_boot_disabled_setup(char *str)
{
	return kstrtobool(str, &cmdline_boot_disabled);
}
early_param("csm.disabled", csm_boot_disabled_setup);

static int csm_default_enabled_setup(char *str)
{
	return kstrtobool(str, &cmdline_default_enabled);
}
early_param("csm.default.enabled", csm_default_enabled_setup);

static int csm_boot_vsock_enabled_setup(char *str)
{
	return kstrtobool(str, &cmdline_boot_vsock_enabled);
}
early_param("csm.vsock.enabled", csm_boot_vsock_enabled_setup);

static int csm_boot_pipe_enabled_setup(char *str)
{
	return kstrtobool(str, &cmdline_boot_pipe_enabled);
}
early_param("csm.pipe.enabled", csm_boot_pipe_enabled_setup);

static int csm_boot_config_enabled_setup(char *str)
{
	return kstrtobool(str, &cmdline_boot_config_enabled);
}
early_param("csm.config.enabled", csm_boot_config_enabled_setup);

static bool pipe_in_use(void)
{
	struct pipe_inode_info *pipe;

	lockdep_assert_held_write(&csm_rwsem_config);
	if (csm_user_read_pipe) {
		pipe = get_pipe_info(csm_user_read_pipe);
		if (pipe)
			return READ_ONCE(pipe->readers) > 1;
	}
	return false;
}

/* Close pipe, force has to be true to close pipe if it is still being used. */
int close_pipe_files(bool force)
{
	if (csm_user_read_pipe) {
		/* Pipe is still used. */
		if (pipe_in_use()) {
			if (!force)
				return -EBUSY;
			pr_warn("pipe is closed while it is still being used.\n");
		}

		fput(csm_user_read_pipe);
		fput(csm_user_write_pipe);
		csm_user_read_pipe = NULL;
		csm_user_write_pipe = NULL;
	}
	return 0;
}

static void csm_update_config(schema_ConfigurationRequest *req)
{
	schema_ExecuteCollectorConfig *econf;
	size_t i;
	bool enumerate_processes = false;

	/* Expect the lock to be held for write before this call. */
	lockdep_assert_held_write(&csm_rwsem_config);

	/* This covers the scenario where a client is connected and the config
	 * transitions the execute collector from disabled to enabled. In that
	 * case there may have been execute events not sent. So they are
	 * enumerated.
	 */
	if (!csm_execute_enabled && req->execute_config.enabled &&
	    pipe_in_use())
		enumerate_processes = true;

	csm_container_enabled = req->container_config.enabled;
	csm_execute_enabled = req->execute_config.enabled;
	csm_memexec_enabled = req->memexec_config.enabled;

	/* csm_enabled is true if any collector is enabled. */
	csm_enabled = csm_container_enabled || csm_execute_enabled ||
		csm_memexec_enabled;

	/* Clean-up existing configurations. */
	kfree(csm_execute_config.envp_allowlist);
	memset(&csm_execute_config, 0, sizeof(csm_execute_config));

	if (csm_execute_enabled) {
		econf = &req->execute_config;
		csm_execute_config.argv_limit = econf->argv_limit;
		csm_execute_config.envp_limit = econf->envp_limit;

		/* Swap the allowlist so it is not freed on return. */
		csm_execute_config.envp_allowlist = econf->envp_allowlist.arg;
		econf->envp_allowlist.arg = NULL;
	}

	/* Reset all stats and close pipe if disabled. */
	if (!csm_enabled) {
		for (i = 0; i < ARRAY_SIZE(csm_stats_mapping); i++)
			*csm_stats_mapping[i].value = 0;

		close_pipe_files(true);
	}

	config_version++;
	if (enumerate_processes)
		csm_enumerate_processes();
	wake_up(&config_wait);
}

int csm_update_config_from_buffer(void *data, size_t size)
{
	schema_ConfigurationRequest c = {};
	pb_istream_t istream;

	c.execute_config.envp_allowlist.funcs.decode = pb_decode_string_array;

	istream = pb_istream_from_buffer(data, size);
	if (!pb_decode(&istream, schema_ConfigurationRequest_fields, &c)) {
		kfree(c.execute_config.envp_allowlist.arg);
		return -EINVAL;
	}

	down_write(&csm_rwsem_config);
	csm_update_config(&c);
	up_write(&csm_rwsem_config);

	return 0;
}

static ssize_t csm_config_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t err = 0;
	void *mem;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	/* Duplicate user memory to safely parse protobuf. */
	mem = memdup_user(buf, count);
	if (IS_ERR(mem))
		return PTR_ERR(mem);

	err = csm_update_config_from_buffer(mem, count);
	if (!err)
		err = count;

	kfree(mem);
	return err;
}

static const struct file_operations csm_config_fops = {
	.write = csm_config_write,
};

static void csm_enable(void)
{
	schema_ConfigurationRequest req = {};

	/* Expect the lock to be held for write before this call. */
	lockdep_assert_held_write(&csm_rwsem_config);

	/* Default configuration */
	req.container_config.enabled = true;
	req.execute_config.enabled = true;
	req.execute_config.argv_limit = UINT_MAX;
	req.execute_config.envp_limit = UINT_MAX;
	req.memexec_config.enabled = true;
	csm_update_config(&req);
}

static void csm_disable(void)
{
	schema_ConfigurationRequest req = {};

	/* Expect the lock to be held for write before this call. */
	lockdep_assert_held_write(&csm_rwsem_config);

	/* Zero configuration disable all collectors. */
	csm_update_config(&req);
	pr_info("disabled\n");
}

static ssize_t csm_enabled_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	const char *str = csm_enabled ? "1\n" : "0\n";

	return simple_read_from_buffer(buf, count, ppos, str, 2);
}

static ssize_t csm_enabled_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	bool enabled;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (count <= 0 || count > PAGE_SIZE || *ppos)
		return -EINVAL;

	err = kstrtobool_from_user(buf, count, &enabled);
	if (err)
		return err;

	down_write(&csm_rwsem_config);

	if (enabled)
		csm_enable();
	else
		csm_disable();

	up_write(&csm_rwsem_config);

	return count;
}

static const struct file_operations csm_enabled_fops = {
	.read = csm_enabled_read,
	.write = csm_enabled_write,
};

static int csm_config_version_open(struct inode *inode, struct file *file)
{
	/* private_data is used to keep the latest config version read. */
	file->private_data = (void*)-1;
	return 0;
}

static ssize_t csm_config_version_read(struct file *file, char __user *buf,
				       size_t count, loff_t *ppos)
{
	unsigned long version = config_version;
	file->private_data = (void*)version;
	return simple_read_from_buffer(buf, count, ppos, &version,
				       sizeof(version));
}

static __poll_t csm_config_version_poll(struct file *file,
					struct poll_table_struct *poll_tab)
{
	if ((unsigned long)file->private_data != config_version)
		return EPOLLIN;
	poll_wait(file, &config_wait, poll_tab);
	if ((unsigned long)file->private_data != config_version)
		return EPOLLIN;
	return 0;
}

static const struct file_operations csm_config_version_fops = {
	.open = csm_config_version_open,
	.read = csm_config_version_read,
	.poll = csm_config_version_poll,
};

static int csm_pipe_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!csm_enabled)
		return -EAGAIN;
	return 0;
}

/* Similar to file_clone_open that is available only in 4.19 and up. */
static inline struct file *pipe_clone_open(struct file *file)
{
	return dentry_open(&file->f_path, file->f_flags, file->f_cred);
}

/* Check if the pipe is still used, else recreate and dup it. */
static struct file *csm_dup_pipe(void)
{
	long pipe_size = 1024 * PAGE_SIZE;
	long actual_size;
	struct file *pipes[2] = {NULL, NULL};
	struct file *ret;
	int err;

	down_write(&csm_rwsem_pipe);

	err = close_pipe_files(false);
	if (err) {
		ret = ERR_PTR(err);
		csm_stats.pipe_already_opened++;
		goto out;
	}

	err = create_pipe_files(pipes, O_NONBLOCK);
	if (err) {
		ret = ERR_PTR(err);
		goto out;
	}

	/*
	 * Try to increase the pipe size to 1024 pages, if there is not
	 * enough memory, pipes will stay unchanged.
	 */
	actual_size = pipe_fcntl(pipes[0], F_SETPIPE_SZ, pipe_size);
	if (actual_size != pipe_size)
		pr_err("failed to resize pipe to 1024 pages, error: %ld, fallback to the default value\n",
		       actual_size);

	csm_user_read_pipe = pipes[0];
	csm_user_write_pipe = pipes[1];

	/* Clone the file so we can track if the reader is still used. */
	ret = pipe_clone_open(csm_user_read_pipe);

out:
	up_write(&csm_rwsem_pipe);
	return ret;
}

static ssize_t csm_pipe_read(struct file *file, char __user *buf,
				       size_t count, loff_t *ppos)
{
	int fd;
	ssize_t err;
	struct file *local_pipe;

	/* No partial reads. */
	if (*ppos != 0)
		return -EINVAL;

	fd = get_unused_fd_flags(0);
	if (fd < 0)
		return fd;

	local_pipe = csm_dup_pipe();
	if (IS_ERR(local_pipe)) {
		err = PTR_ERR(local_pipe);
		local_pipe = NULL;
		goto error;
	}

	err = simple_read_from_buffer(buf, count, ppos, &fd, sizeof(fd));
	if (err < 0)
		goto error;

	if (err < sizeof(fd)) {
		err = -EINVAL;
		goto error;
	}

	/* Install the file descriptor when we know everything succeeded. */
	fd_install(fd, local_pipe);

	csm_enumerate_processes();

	return err;

error:
	if (local_pipe)
		fput(local_pipe);
	put_unused_fd(fd);
	return err;
}


static const struct file_operations csm_pipe_fops = {
	.open = csm_pipe_open,
	.read = csm_pipe_read,
};

static void set_container_decode_callbacks(schema_Container *container)
{
	container->pod_namespace.funcs.decode = pb_decode_string_field;
	container->pod_name.funcs.decode = pb_decode_string_field;
	container->container_name.funcs.decode = pb_decode_string_field;
	container->container_image_uri.funcs.decode = pb_decode_string_field;
	container->labels.funcs.decode = pb_decode_string_array;
}

static void set_container_encode_callbacks(schema_Container *container)
{
	container->pod_namespace.funcs.encode = pb_encode_string_field;
	container->pod_name.funcs.encode = pb_encode_string_field;
	container->container_name.funcs.encode = pb_encode_string_field;
	container->container_image_uri.funcs.encode = pb_encode_string_field;
	container->labels.funcs.encode = pb_encode_string_array;
}

static void free_container_callbacks_args(schema_Container *container)
{
	kfree(container->pod_namespace.arg);
	kfree(container->pod_name.arg);
	kfree(container->container_name.arg);
	kfree(container->container_image_uri.arg);
	kfree(container->labels.arg);
}

static ssize_t csm_container_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	ssize_t err = 0;
	void *mem;
	u64 cid;
	pb_istream_t istream;
	struct task_struct *task;
	schema_ContainerReport report = {};
	schema_Event event = {};
	schema_Container *container;
	char *uuid = NULL;

	/* Notify that this collector is not yet enabled. */
	if (!csm_container_enabled)
		return -EAGAIN;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	/* Duplicate user memory to safely parse protobuf. */
	mem = memdup_user(buf, count);
	if (IS_ERR(mem))
		return PTR_ERR(mem);

	/* Callback to decode string in protobuf. */
	set_container_decode_callbacks(&report.container);

	istream = pb_istream_from_buffer(mem, count);
	if (!pb_decode(&istream, schema_ContainerReport_fields, &report)) {
		err = -EINVAL;
		goto out;
	}

	/* Check protobuf is as expected */
	if (report.pid == 0 ||
	    report.container.container_id != 0) {
		err = -EINVAL;
		goto out;
	}

	/* Find if the process id is linked to an existing container-id. */
	rcu_read_lock();
	task = find_task_by_pid_ns(report.pid, &init_pid_ns);
	if (task) {
		cid = audit_get_contid(task);
		if (cid == AUDIT_CID_UNSET)
			err = -ENOENT;
	} else {
		err = -ENOENT;
	}
	rcu_read_unlock();

	if (err)
		goto out;

	uuid = kzalloc(PROCESS_UUID_SIZE, GFP_KERNEL);
	if (!uuid)
		goto out;

	/* Provide the uuid for the top process of the container. */
	err = get_process_uuid_by_pid(report.pid, uuid, PROCESS_UUID_SIZE);
	if (err)
		goto out;

	/* Correct the container-id and feed the event to vsock */
	report.container.container_id = cid;
	report.container.init_uuid.funcs.encode = pb_encode_uuid_field;
	report.container.init_uuid.arg = uuid;
	container = &event.event.container.container;
	*container = report.container;

	/* Use encode callback to generate the final proto. */
	set_container_encode_callbacks(container);

	event.which_event = schema_Event_container_tag;

	err = csm_sendeventproto(schema_Event_fields, &event);
	if (!err)
		err = count;

out:
	/* Free any allocated nanopb callback arguments. */
	free_container_callbacks_args(&report.container);
	kfree(uuid);
	kfree(mem);
	return err;
}

static const struct file_operations csm_container_fops = {
	.write = csm_container_write,
};

static int csm_show_stats(struct seq_file *p, void *v)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(csm_stats_mapping); i++) {
		seq_printf(p, "%s:\t%zu\n",
			   csm_stats_mapping[i].key,
			   *csm_stats_mapping[i].value);
	}

	return 0;
}

static int csm_stats_open(struct inode *inode, struct file *file)
{
	size_t i, size = 1; /* Start at one for the null byte. */

	for (i = 0; i < ARRAY_SIZE(csm_stats_mapping); i++) {
		/*
		 * Calculate the maximum length:
		 * - Length of the key
		 * - 3 additional chars :\t\n
		 * - longest unsigned 64-bit integer.
		 */
		size += strlen(csm_stats_mapping[i].key)
			+ 3 + sizeof("18446744073709551615");
	}

	return single_open_size(file, csm_show_stats, NULL, size);
}

static const struct file_operations csm_stats_fops = {
	.open		= csm_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* Prevent user-mode from using vsock on our port. */
static int csm_socket_connect(struct socket *sock, struct sockaddr *address,
			      int addrlen)
{
	struct sockaddr_vm *vaddr = (struct sockaddr_vm *)address;

	/* Filter only vsock sockets */
	if (!sock->sk || sock->sk->sk_family != AF_VSOCK)
		return 0;

	/* Allow kernel sockets. */
	if (sock->sk->sk_kern_sock)
		return 0;

	if (addrlen < sizeof(*vaddr))
		return -EINVAL;

	/* Forbid access to the CSM VMM backend port. */
	if (vaddr->svm_port == CSM_HOST_PORT)
		return -EPERM;

	return 0;
}

static int csm_setxattr(struct dentry *dentry, const char *name,
			const void *value, size_t size, int flags)
{
	if (csm_enabled && !strcmp(name, XATTR_SECURITY_CSM))
		return -EPERM;
	return 0;
}

static struct security_hook_list csm_hooks[] __lsm_ro_after_init = {
	/* Track process execution. */
	LSM_HOOK_INIT(bprm_check_security, csm_bprm_check_security),
	LSM_HOOK_INIT(task_post_alloc, csm_task_post_alloc),
	LSM_HOOK_INIT(task_exit, csm_task_exit),

	/* Block vsock access when relevant. */
	LSM_HOOK_INIT(socket_connect, csm_socket_connect),

	/* Track memory execution */
	LSM_HOOK_INIT(file_mprotect, csm_mprotect),
	LSM_HOOK_INIT(mmap_file, csm_mmap_file),

	/* Track file modification provenance. */
	LSM_HOOK_INIT(file_pre_free_security, csm_file_pre_free),

	/* Block modyfing csm xattr. */
	LSM_HOOK_INIT(inode_setxattr, csm_setxattr),
};

static int __init csm_init(void)
{
	int err;

	if (cmdline_boot_disabled)
		return 0;

	/*
	 * If cmdline_boot_vsock_enabled is false, only the event pool will be
	 * allocated. The destroy function will clean-up only what was reserved.
	 */
	err = vsock_initialize();
	if (err)
		return err;

	csm_dir = securityfs_create_dir("container_monitor", NULL);
	if (IS_ERR(csm_dir)) {
		err = PTR_ERR(csm_dir);
		goto error;
	}

	csm_enabled_file = securityfs_create_file("enabled", 0644, csm_dir,
						  NULL, &csm_enabled_fops);
	if (IS_ERR(csm_enabled_file)) {
		err = PTR_ERR(csm_enabled_file);
		goto error_rmdir;
	}

	csm_container_file = securityfs_create_file("container", 0200, csm_dir,
						  NULL, &csm_container_fops);
	if (IS_ERR(csm_container_file)) {
		err = PTR_ERR(csm_container_file);
		goto error_rm_enabled;
	}

	csm_config_vers_file = securityfs_create_file("config_version", 0400,
						      csm_dir, NULL,
						      &csm_config_version_fops);
	if (IS_ERR(csm_config_vers_file)) {
		err = PTR_ERR(csm_config_vers_file);
		goto error_rm_container;
	}

	if (cmdline_boot_config_enabled) {
		csm_config_file = securityfs_create_file("config", 0200,
							 csm_dir, NULL,
							 &csm_config_fops);
		if (IS_ERR(csm_config_file)) {
			err = PTR_ERR(csm_config_file);
			goto error_rm_config_vers;
		}
	}

	if (cmdline_boot_pipe_enabled) {
		csm_pipe_file = securityfs_create_file("pipe", 0400, csm_dir,
						       NULL, &csm_pipe_fops);
		if (IS_ERR(csm_pipe_file)) {
			err = PTR_ERR(csm_pipe_file);
			goto error_rm_config;
		}
	}

	csm_stats_file = securityfs_create_file("stats", 0400, csm_dir,
						 NULL, &csm_stats_fops);
	if (IS_ERR(csm_stats_file)) {
		err = PTR_ERR(csm_stats_file);
		goto error_rm_pipe;
	}

	pr_debug("created securityfs control files\n");

	security_add_hooks(csm_hooks, ARRAY_SIZE(csm_hooks), "csm");
	pr_debug("registered hooks\n");

	/* Off-by-default, only used for testing images. */
	if (cmdline_default_enabled) {
		down_write(&csm_rwsem_config);
		csm_enable();
		up_write(&csm_rwsem_config);
	}

	return 0;

error_rm_pipe:
	if (cmdline_boot_pipe_enabled)
		securityfs_remove(csm_pipe_file);
error_rm_config:
	if (cmdline_boot_config_enabled)
		securityfs_remove(csm_config_file);
error_rm_config_vers:
	securityfs_remove(csm_config_vers_file);
error_rm_container:
	securityfs_remove(csm_container_file);
error_rm_enabled:
	securityfs_remove(csm_enabled_file);
error_rmdir:
	securityfs_remove(csm_dir);
error:
	vsock_destroy();
	pr_warn("fs initialization error: %d", err);
	return err;
}

late_initcall(csm_init);
