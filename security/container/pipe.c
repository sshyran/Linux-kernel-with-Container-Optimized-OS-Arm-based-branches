// SPDX-License-Identifier: GPL-2.0
/*
 * Container Security Monitor module
 *
 * Copyright (c) 2018 Google, Inc
 */

#include "monitor.h"

#include <linux/pipe_fs_i.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/uio.h>
#include <linux/workqueue.h>

/* csm protobuf work */
static void csm_sendmsg_pipe_handler(struct work_struct *work);

/* csm message work container */
struct msg_work_data {
	struct work_struct msg_work;
	size_t pos_bytes_written;
	char msg[];
};

/* Mutex to ensure sequential dumping of protos */
static DEFINE_MUTEX(protodump);

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
	pipe = get_pipe_info(csm_user_write_pipe, false);

	/* If nobody is listening, don't write events. */
	readers = READ_ONCE(pipe->readers);
	if (readers <= 1) {
		WARN_ON(readers == 0);
		goto end;
	}


	iov_iter_kvec(&io, WRITE, vecs, vecs_size, total_length);

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
	ssize_t perr;

	perr = csm_user_pipe_write(vecs, ARRAY_SIZE(vecs),
				   le32_to_cpu(hdr.msg_length));
	if (perr < 0) {
		pr_warn_ratelimited("vfs_iter_write error (msg_type=%d, msg_length=%u): %zd\n",
				    type, le32_to_cpu(hdr.msg_length), perr);
		csm_stats.event_writing_failed++;
	}

	return perr;
}

static bool csm_get_expected_size(size_t *size, const pb_msgdesc_t *fields,
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
					     const pb_msgdesc_t *fields,
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

static int csm_sendproto(int type, const pb_msgdesc_t *fields,
			 const void *src_struct)
{
	int err = 0;
	size_t size, previous_size;
	struct msg_work_data *wd;

	/* Use the expected size first. */
	if (!csm_get_expected_size(&size, fields, src_struct))
		return -EINVAL;

	wd = csm_encodeproto(size, fields, src_struct);
	if (IS_ERR(wd)) {
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
	if (err < 0)
		pr_err_ratelimited("csm_sendmsg failed in work handler %s\n",
				   __func__);

	kfree(wd);
}

int csm_sendeventproto(const pb_msgdesc_t *fields, schema_Event *event)
{
	/* Last check before generating and sending an event. */
	if (!csm_enabled)
		return -ENOTSUPP;

	event->timestamp = ktime_get_real_ns();

	return csm_sendproto(CSM_MSG_EVENT_PROTO, fields, event);
}
