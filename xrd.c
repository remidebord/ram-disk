#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/idr.h>
#include <linux/string.h>
#include <linux/ctype.h>

struct xram_dev_t {
	sector_t capacity;
	u8 *data;
	struct blk_mq_tag_set tag_set;
	struct gendisk *disk;
};

static int major;
static struct xram_dev_t *xram_dev = NULL;

/*
 * Block device operations
 */

static blk_status_t xram_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	blk_status_t err = BLK_STS_OK;
	struct bio_vec bv;
	struct req_iterator iter;
	loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
	struct xram_dev_t *xram = hctx->queue->queuedata;
	loff_t data_len = (xram->capacity << SECTOR_SHIFT);

	blk_mq_start_request(rq);

	rq_for_each_segment(bv, rq, iter) {
		unsigned int len = bv.bv_len;
		void *buf = page_address(bv.bv_page) + bv.bv_offset;

		if (pos + len > data_len) {
			err = BLK_STS_IOERR;
			break;
		}

		switch (req_op(rq)) {
		case REQ_OP_READ:
			memcpy(buf, xram->data + pos, len);
			break;
		case REQ_OP_WRITE:
			memcpy(xram->data + pos, buf, len);
			break;
		default:
			err = BLK_STS_IOERR;
			goto end_request;
		}
		pos += len;
	}

end_request:
	blk_mq_end_request(rq, err);
	return BLK_STS_OK;
}

static const struct blk_mq_ops xram_mq_ops = {
	.queue_rq = xram_queue_rq,
};

static const struct block_device_operations xram_rq_ops = {
	.owner = THIS_MODULE,
};

static int xrd_alloc(struct device* dev, int i, unsigned long maddr, unsigned long msize)
{
	loff_t data_size_bytes = msize << 20;
	struct gendisk *disk;
	int minor, ret;

	if (!major) {
		ret = register_blkdev(0, "xram");
		if (ret < 0)
			return ret;

		major = ret;
	}

	xram_dev = kzalloc(sizeof(struct xram_dev_t), GFP_KERNEL);

	if (xram_dev == NULL) {
		pr_err("failed to allocate memory for xram_dev.\n");
		ret = -ENOMEM;
		goto unregister_blkdev;
	}

	xram_dev->capacity = data_size_bytes >> SECTOR_SHIFT;
	xram_dev->data = kvmalloc(data_size_bytes, GFP_KERNEL);
	if (xram_dev->data == NULL) {
		pr_err("failed to allocate memory for the RAM disk.\n");
		ret = -ENOMEM;
		goto data_err;
	}

	memset(&xram_dev->tag_set, 0, sizeof(xram_dev->tag_set));
	xram_dev->tag_set.ops = &xram_mq_ops;
	xram_dev->tag_set.queue_depth = 128;
	xram_dev->tag_set.numa_node = NUMA_NO_NODE;
	xram_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	xram_dev->tag_set.cmd_size = 0;
	xram_dev->tag_set.driver_data = xram_dev;
	xram_dev->tag_set.nr_hw_queues = 1;

	ret = blk_mq_alloc_tag_set(&xram_dev->tag_set);
	if (ret)
		goto tagset_err;

	//disk = blk_mq_alloc_disk(&xram_dev->tag_set, xram_dev);

	disk = alloc_disk(1);
	if (!disk) {
		ret = -ENOMEM;
		goto tagset_err;
	}

	disk->queue = blk_mq_init_queue_data(&xram_dev->tag_set, xram_dev);
	if (IS_ERR(disk->queue)) {
		ret = PTR_ERR(disk->queue);
		goto queue_err;
	}

	xram_dev->disk = disk;

	blk_queue_logical_block_size(disk->queue, PAGE_SIZE);
	blk_queue_physical_block_size(disk->queue, PAGE_SIZE);
	blk_queue_max_segments(disk->queue, 32);
	blk_queue_max_segment_size(disk->queue, 65536);

	snprintf(disk->disk_name, DISK_NAME_LEN, "xram%d", minor);

	disk->major = major;
	disk->first_minor = 0;
	disk->minors = 1;	
	disk->fops = &xram_rq_ops;
	disk->flags = 0;
	set_capacity(disk, xram_dev->capacity);

	add_disk(disk);

	dev_info(dev, "disk %s created.\n", disk->disk_name);
	return 0;

queue_err:
	put_disk(disk);
tagset_err:
	kfree(xram_dev->data);
data_err:
	kfree(xram_dev);
unregister_blkdev:
	unregister_blkdev(major, "xram");

	return ret;
}

static void xrd_del(void)
{
	if (xram_dev->disk) {
		del_gendisk(xram_dev->disk);
		put_disk(xram_dev->disk);
	}

	unregister_blkdev(major, "xram");
	kfree(xram_dev);
}

/*
 * Char device operations
 */

static ssize_t xrd_write(struct file *file, const char __user *user_buffer, size_t size, loff_t * offset)
{
	struct miscdevice *misc = (struct miscdevice *) file->private_data;
	unsigned long maddr, msize;
	char buffer[32];
	ssize_t len, i;
	int error;
	char *p;

	len = min(sizeof(buffer), size);

	if (len <= 0)
		return 0;

	if (copy_from_user(buffer, user_buffer, len))
		return -EFAULT;

	for (i = 0; i < len; i++) {
		if (isspace(buffer[i]))
			buffer[i] = 0x00;
	}

	error = kstrtoul(buffer, 0, &maddr);
	if (error)
		return error;

	dev_info(misc->this_device, "address: 0x%08lx.\n", maddr);

	if (len <= (strlen(buffer) + 1)) {
		dev_info(misc->this_device, "no size to parse.\n");
		return -EINVAL;
	}

	p = &buffer[0] + (strlen(buffer) + 1);

	error = kstrtoul(p, 0, &msize);
	if (error)
		return error;

	dev_info(misc->this_device, "size: %lu.\n", msize);

    return len;
}

const struct file_operations xrd_fops = {
	.owner = THIS_MODULE,
	.write = xrd_write,
	.llseek = no_llseek,
};

struct miscdevice xrd_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "xrd",
	.fops = &xrd_fops,
};

static int __init xrd_init(void)
{
	int error;

	major = 0;

	error = misc_register(&xrd_device);
	if (error) {
		pr_err("misc register failed.\n");
		return error;
	}

	xrd_alloc(xrd_device.this_device, 0, 0, 10);

	return 0;
}

static void __exit xrd_exit(void)
{
	xrd_del();

	misc_deregister(&xrd_device);
	pr_info("unloaded.\n");
}
 
module_init(xrd_init)
module_exit(xrd_exit)
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Remi Debord>");
MODULE_DESCRIPTION("The Forbidden RAM disk driver");
MODULE_VERSION("1.0");
