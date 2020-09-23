// SPDX-License-Identifier: GPL-2.0
/*
 * Container Security Monitor module
 *
 * Copyright (c) 2018 Google, Inc
 */

#include "monitor.h"

#include <net/net_namespace.h>
#include <net/vsock_addr.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/printk.h>
#include <linux/delay.h>
#include <linux/timekeeping.h>

/*
 * virtio vsocket over which to send events to the host.
 * NULL if monitoring is disabled, or if the socket was disconnected and we're
 * trying to reconnect to the host.
 */
static struct socket *csm_vsocket;

/* reconnect delay */
#define CSM_RECONNECT_FREQ_MSEC 5000

/* config pull delay */
#define CSM_CONFIG_FREQ_MSEC 1000

/* vsock receive attempts and delay until giving up */
#define CSM_RECV_ATTEMPTS 2
#define CSM_RECV_DELAY_MSEC 100

/* heartbeat work */
#define CSM_HEARTBEAT_FREQ msecs_to_jiffies(5000)
static void csm_heartbeat(struct work_struct *work);
static DECLARE_DELAYED_WORK(csm_heartbeat_work, csm_heartbeat);

/* csm protobuf work */
static void csm_sendmsg_pipe_handler(struct work_struct *work);

/* csm message work container*/
struct msg_work_data {
	struct work_struct msg_work;
	size_t pos_bytes_written;
	char msg[];
};

/* size used for the config error message. */
#define CSM_ERROR_BUF_SIZE 40

/* Running thread to manage vsock connections. */
static struct task_struct *socket_thread;

/* Mutex to ensure sequential dumping of protos */
static DEFINE_MUTEX(protodump);

static struct socket *csm_create_socket(void)
{
	int err;
	struct sockaddr_vm host_addr;
	struct socket *sock;

	err = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0,
			       &sock);
	if (err) {
		pr_debug("error creating AF_VSOCK socket: %d\n", err);
		return ERR_PTR(err);
	}

	vsock_addr_init(&host_addr, VMADDR_CID_HYPERVISOR, CSM_HOST_PORT);

	err = kernel_connect(sock, (struct sockaddr *)&host_addr,
			     sizeof(host_addr), 0);
	if (err) {
		if (err != -ECONNRESET) {
			pr_debug("error connecting AF_VSOCK socket to host port %u: %d\n",
				CSM_HOST_PORT, err);
		}
		goto error_release;
	}

	return sock;

error_release:
	sock_release(sock);
	return ERR_PTR(err);
}

static void csm_destroy_socket(void)
{
	down_write(&csm_rwsem_vsocket);
	if (csm_vsocket) {
		sock_release(csm_vsocket);
		csm_vsocket = NULL;
	}
	up_write(&csm_rwsem_vsocket);
}

static int csm_vsock_sendmsg(struct kvec *vecs, size_t vecs_size,
			     size_t total_length)
{
	struct msghdr msg = { };
	int res = -EPIPE;

	if (!cmdline_boot_vsock_enabled)
		return 0;

	down_read(&csm_rwsem_vsocket);
	if (csm_vsocket) {
		res = kernel_sendmsg(csm_vsocket, &msg, vecs, vecs_size,
				     total_length);
		if (res > 0)
			res = 0;
	}
	up_read(&csm_rwsem_vsocket);

	return res;
}

static ssize_t csm_user_pipe_write(struct kvec *vecs, size_t vecs_size,
				   size_t total_length)
{
	ssize_t perr = 0;
	struct iov_iter io = { };
	loff_t pos = 0;
	struct pipe_inode_info *pipe;
	unsigned int readers;

	if (!csm_user_write_pipe)
		return 0;

	down_read(&csm_rwsem_pipe);

	if (csm_user_write_pipe == NULL)
		goto end;

	/* The pipe info is the same for reader and write files. */
	pipe = get_pipe_info(csm_user_write_pipe);

	/* If nobody is listening, don't write events. */
	readers = READ_ONCE(pipe->readers);
	if (readers <= 1) {
		WARN_ON(readers == 0);
		goto end;
	}


	iov_iter_kvec(&io, WRITE, vecs, vecs_size,
		      total_length);

	file_start_write(csm_user_write_pipe);
	perr = vfs_iter_write(csm_user_write_pipe, &io, &pos, 0);
	file_end_write(csm_user_write_pipe);

end:
	up_read(&csm_rwsem_pipe);
	return perr;
}

static int csm_sendmsg(int type, const void *buf, size_t len)
{
	struct csm_msg_hdr hdr = {
		.msg_type = cpu_to_le32(type),
		.msg_length = cpu_to_le32(sizeof(hdr) + len),
	};
	struct kvec vecs[] = {
		{
			.iov_base = &hdr,
			.iov_len = sizeof(hdr),
		}, {
			.iov_base = (void *)buf,
			.iov_len = len,
		}
	};
	int res;
	ssize_t perr;

	res = csm_vsock_sendmsg(vecs, ARRAY_SIZE(vecs),
				le32_to_cpu(hdr.msg_length));
	if (res < 0) {
		pr_warn_ratelimited("sendmsg error (msg_type=%d, msg_length=%u): %d\n",
				    type, le32_to_cpu(hdr.msg_length), res);
	}

	perr = csm_user_pipe_write(vecs, ARRAY_SIZE(vecs),
				   le32_to_cpu(hdr.msg_length));
	if (perr < 0) {
		pr_warn_ratelimited("vfs_iter_write error (msg_type=%d, msg_length=%u): %zd\n",
				    type, le32_to_cpu(hdr.msg_length), perr);
	}

	/* If one of them failed, increase the stats once. */
	if (res < 0 || perr < 0)
		csm_stats.event_writing_failed++;

	return res;
}

static bool csm_get_expected_size(size_t *size, const pb_field_t fields[],
				    const void *src_struct)
{
	schema_Event *event;

	if (fields != schema_Event_fields)
		goto other;

	/* Size above 99% of the 100 containers tested running k8s. */
	event = (schema_Event *)src_struct;
	switch (event->which_event) {
	case schema_Event_execute_tag:
		*size = 3344;
		return true;
	case schema_Event_memexec_tag:
		*size = 176;
		return true;
	case schema_Event_clone_tag:
		*size = 50;
		return true;
	case schema_Event_exit_tag:
		*size = 30;
		return true;
	}

other:
	/* If unknown, do the pre-computation. */
	return pb_get_encoded_size(size, fields, src_struct);
}

static struct msg_work_data *csm_encodeproto(size_t size,
					     const pb_field_t fields[],
					     const void *src_struct)
{
	pb_ostream_t pos;
	struct msg_work_data *wd;
	size_t total;

	total = size + sizeof(*wd);
	if (total < size)
		return ERR_PTR(-EINVAL);

	wd = kmalloc(total, GFP_KERNEL);
	if (!wd)
		return ERR_PTR(-ENOMEM);

	pos = pb_ostream_from_buffer(wd->msg, size);
	if (!pb_encode(&pos, fields, src_struct)) {
		kfree(wd);
		return ERR_PTR(-EINVAL);
	}

	INIT_WORK(&wd->msg_work, csm_sendmsg_pipe_handler);
	wd->pos_bytes_written = pos.bytes_written;
	return wd;
}

static int csm_sendproto(int type, const pb_field_t fields[],
			 const void *src_struct)
{
	int err = 0;
	size_t size, previous_size;
	struct msg_work_data *wd;

	/* Use the expected size first. */
	if (!csm_get_expected_size(&size, fields, src_struct))
		return -EINVAL;

	wd = csm_encodeproto(size, fields, src_struct);
	if (unlikely(IS_ERR(wd))) {
		/* If it failed, retry with the exact size. */
		csm_stats.size_picking_failed++;
		previous_size = size;

		if (!pb_get_encoded_size(&size, fields, src_struct))
			return -EINVAL;

		wd = csm_encodeproto(size, fields, src_struct);
		if (IS_ERR(wd)) {
			csm_stats.proto_encoding_failed++;
			return PTR_ERR(wd);
		}

		pr_debug("size picking failed %lu vs %lu\n", previous_size,
			 size);
	}

	/* The work handler takes care of cleanup, if successfully scheduled. */
	if (likely(schedule_work(&wd->msg_work)))
		return 0;

	csm_stats.workqueue_failed++;
	pr_err_ratelimited("Sent msg to workqueue unsuccessfully (assume dropped).\n");

	kfree(wd);
	return err;
}

static void csm_sendmsg_pipe_handler(struct work_struct *work)
{
	int err;
	int type = CSM_MSG_EVENT_PROTO;
	struct msg_work_data *wd = container_of(work, struct msg_work_data,
						msg_work);

	err = csm_sendmsg(type, wd->msg, wd->pos_bytes_written);
	if (err)
		pr_err_ratelimited("csm_sendmsg failed in work handler %s\n",
				   __func__);

	kfree(wd);
}

int csm_sendeventproto(const pb_field_t fields[], schema_Event *event)
{
	/* Last check before generating and sending an event. */
	if (!csm_enabled)
		return -ENOTSUPP;

	event->timestamp = ktime_get_real_ns();

	return csm_sendproto(CSM_MSG_EVENT_PROTO, fields, event);
}

int csm_sendconfigrespproto(const pb_field_t fields[],
			    schema_ConfigurationResponse *resp)
{
	return csm_sendproto(CSM_MSG_CONFIG_RESPONSE_PROTO, fields, resp);
}

static void csm_heartbeat(struct work_struct *work)
{
	csm_sendmsg(CSM_MSG_TYPE_HEARTBEAT, NULL, 0);
	schedule_delayed_work(&csm_heartbeat_work, CSM_HEARTBEAT_FREQ);
}

static int config_send_response(int err)
{
	char buf[CSM_ERROR_BUF_SIZE] = {};
	schema_ConfigurationResponse resp = {};

	resp.error = schema_ConfigurationResponse_ErrorCode_NO_ERROR;
	resp.version = CSM_VERSION;
	resp.kernel_version = LINUX_VERSION_CODE;

	if (err) {
		resp.error = schema_ConfigurationResponse_ErrorCode_UNKNOWN;
		snprintf(buf, sizeof(buf) - 1, "error code: %d", err);
		resp.msg.funcs.encode = pb_encode_string_field;
		resp.msg.arg = buf;
	}

	return csm_sendconfigrespproto(schema_ConfigurationResponse_fields,
				       &resp);
}

static int csm_recvmsg(void *buf, size_t len, bool expected)
{
	int err = 0;
	struct msghdr msg = {};
	struct kvec vecs;
	size_t pos = 0;
	size_t attempts = 0;

	while (pos < len) {
		vecs.iov_base = (char *)buf + pos;
		vecs.iov_len = len - pos;

		down_read(&csm_rwsem_vsocket);
		if (csm_vsocket) {
			err = kernel_recvmsg(csm_vsocket, &msg, &vecs, 1, len,
					     MSG_DONTWAIT);
		} else {
			pr_err("csm_vsocket was unset while the config thread was running\n");
			err = -ENOENT;
		}
		up_read(&csm_rwsem_vsocket);

		if (err == 0) {
			err = -ENOTCONN;
			pr_warn_ratelimited("vsock connection was reset\n");
			break;
		}

		if (err == -EAGAIN) {
			/*
			 * If nothing is received and nothing was expected
			 * just bail.
			 */
			if (!expected && pos == 0) {
				err = -EAGAIN;
				break;
			}

			/*
			 * If we missing data after multiple attempts
			 * reset the connection.
			 */
			if (++attempts >= CSM_RECV_ATTEMPTS) {
				err = -EPIPE;
				break;
			}

			msleep(CSM_RECV_DELAY_MSEC);
			continue;
		}

		if (err < 0) {
			pr_err_ratelimited("kernel_recvmsg failed with %d\n",
					   err);
			break;
		}

		pos += err;
	}

	return err;
}

/*
 * Listen for configuration until connection is closed or desynchronize.
 * If something wrong happens while parsing the packet buffer that may
 * desynchronize the thread with the backend, the connection is reset.
 */

static void listen_configuration(void *buf)
{
	int err;
	struct csm_msg_hdr hdr = {};
	uint32_t msg_type, msg_length;

	pr_debug("listening for configuration messages\n");

	while (true) {
		err = csm_recvmsg(&hdr, sizeof(hdr), false);

		/* Nothing available, wait and try again. */
		if (err == -EAGAIN) {
			msleep(CSM_CONFIG_FREQ_MSEC);
			continue;
		}

		if (err < 0)
			break;

		msg_type = le32_to_cpu(hdr.msg_type);

		if (msg_type != CSM_MSG_CONFIG_REQUEST_PROTO) {
			pr_warn_ratelimited("unexpected message type: %d\n",
					    msg_type);
			break;
		}

		msg_length = le32_to_cpu(hdr.msg_length);

		if (msg_length <= sizeof(hdr) || msg_length > PAGE_SIZE) {
			pr_warn_ratelimited("unexpected message length: %d\n",
					    msg_length);
			break;
		}

		/* The message length include the size of the header. */
		msg_length -= sizeof(hdr);

		err = csm_recvmsg(buf, msg_length, true);
		if (err < 0) {
			pr_warn_ratelimited("failed to gather configuration: %d\n",
					    err);
			break;
		}

		err = csm_update_config_from_buffer(buf, msg_length);
		if (err < 0) {
			/*
			 * Warn of the error but continue listening for
			 * configuration changes.
			 */
			pr_warn_ratelimited("config update failed: %d\n", err);
		} else {
			pr_debug("config received and applied\n");
		}

		err = config_send_response(err);
		if (err < 0) {
			pr_err_ratelimited("config response failed: %d\n", err);
			break;
		}

		pr_debug("config response sent\n");
	}
}

/* Thread managing connection and listening for new configurations. */
static int socket_thread_fn(void *unsued)
{
	void *buf;
	struct socket *sock;

	/* One page should be enough for current configurations. */
	buf = (void *)__get_free_page(GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	while (true) {
		sock = csm_create_socket();
		if (IS_ERR(sock)) {
			pr_debug("unable to connect to host (port %u), will retry in %u ms\n",
				 CSM_HOST_PORT, CSM_RECONNECT_FREQ_MSEC);
			msleep(CSM_RECONNECT_FREQ_MSEC);
			continue;
		}

		down_write(&csm_rwsem_vsocket);
		csm_vsocket = sock;
		up_write(&csm_rwsem_vsocket);

		schedule_delayed_work(&csm_heartbeat_work, 0);

		listen_configuration(buf);

		pr_warn("vsock state incorrect, disconnecting. Messages will be lost.\n");

		cancel_delayed_work_sync(&csm_heartbeat_work);
		csm_destroy_socket();
	}

	return 0;
}

void __init vsock_destroy(void)
{
	if (socket_thread) {
		kthread_stop(socket_thread);
		socket_thread = NULL;
	}
}

int __init vsock_initialize(void)
{
	struct task_struct *task;

	if (cmdline_boot_vsock_enabled) {
		task = kthread_run(socket_thread_fn, NULL, "csm-vsock-thread");
		if (IS_ERR(task)) {
			pr_err("failed to create socket thread: %ld\n", PTR_ERR(task));
			vsock_destroy();
			return PTR_ERR(task);
		}

		socket_thread = task;
	}
	return 0;
}
