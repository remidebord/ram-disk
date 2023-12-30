#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/idr.h>
#include <linux/io.h>

#define DISK_MAX_PARTS 256

struct xrd_device {
	unsigned long address;
	unsigned long size;
	int minor;
	u8 *data;
	sector_t capacity;
	struct blk_mq_tag_set tag_set;
	struct gendisk *disk;
	struct list_head xrd_list;

};

static int major;
static unsigned long address;
static unsigned long size;
static LIST_HEAD(xrd_devices);

static inline bool overlap(void *addr, unsigned long len, void *start, void *end)
{
	unsigned long a1 = (unsigned long)addr;
	unsigned long b1 = a1 + len;
	unsigned long a2 = (unsigned long)start;
	unsigned long b2 = (unsigned long)end;

	return !(b1 <= a2 || a1 >= b2);
}

/*
 * Block device operations
 */

static blk_status_t xrd_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	blk_status_t err = BLK_STS_OK;
	struct bio_vec bv;
	struct req_iterator iter;
	loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
	struct xrd_device *xrd = hctx->queue->queuedata;
	loff_t data_len = (xrd->capacity << SECTOR_SHIFT);

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
			memcpy(buf, xrd->data + pos, len);
			break;
		case REQ_OP_WRITE:
			memcpy(xrd->data + pos, buf, len);
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

static const struct blk_mq_ops xrd_mq_ops = {
	.queue_rq = xrd_queue_rq,
};

static const struct block_device_operations xrd_rq_ops = {
	.owner = THIS_MODULE,
};

static int xrd_alloc(void)
{
	struct xrd_device *xrd, *next;
	struct gendisk *disk;
	int minor, ret;

	minor = 0;

	list_for_each_entry_safe(xrd, next, &xrd_devices, xrd_list) {
		if (overlap((void*)address, size, (void*)xrd->address, (void*)(xrd->address + xrd->size))) {
			pr_err("overlap with %s.\n", xrd->disk->disk_name);
			return -EEXIST;
		}

		minor++;
	}

	xrd = kzalloc(sizeof(struct xrd_device), GFP_KERNEL);

	if (xrd == NULL) {
		pr_err("failed to allocate memory for xrd.\n");
		return -ENOMEM;
	}

	xrd->address = address;
	xrd->size = size;

	xrd->capacity = size >> SECTOR_SHIFT;
	xrd->data = memremap(address, size, MEMREMAP_WB);
	if (xrd->data == NULL) {
		pr_err("failed to memremap.\n");
		ret = -ENOMEM;
		goto data_err;
	}

	memset(&xrd->tag_set, 0, sizeof(xrd->tag_set));
	xrd->tag_set.ops = &xrd_mq_ops;
	xrd->tag_set.queue_depth = 128;
	xrd->tag_set.numa_node = NUMA_NO_NODE;
	xrd->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	xrd->tag_set.cmd_size = 0;
	xrd->tag_set.driver_data = xrd;
	xrd->tag_set.nr_hw_queues = 1;

	ret = blk_mq_alloc_tag_set(&xrd->tag_set);
	if (ret)
		goto tagset_err;

	//disk = blk_mq_alloc_disk(&xrd->tag_set, xrd);

	disk = alloc_disk(1);
	if (!disk) {
		ret = -ENOMEM;
		goto tagset_err;
	}

	disk->queue = blk_mq_init_queue_data(&xrd->tag_set, xrd);
	if (IS_ERR(disk->queue)) {
		ret = PTR_ERR(disk->queue);
		goto queue_err;
	}

	xrd->disk = disk;

	blk_queue_logical_block_size(disk->queue, PAGE_SIZE);
	blk_queue_physical_block_size(disk->queue, PAGE_SIZE);
	blk_queue_max_segments(disk->queue, 32);
	blk_queue_max_segment_size(disk->queue, 65536);

	snprintf(disk->disk_name, DISK_NAME_LEN, "xram%d", minor);

	disk->major = major;
	disk->first_minor = minor * DISK_MAX_PARTS;
	disk->minors = DISK_MAX_PARTS;
	disk->fops = &xrd_rq_ops;
	disk->flags = 0;
	set_capacity(disk, xrd->capacity);

	add_disk(disk);

	list_add_tail(&xrd->xrd_list, &xrd_devices);

	pr_info("RAM disk %s created.\n", disk->disk_name);
	return 0;

queue_err:
	put_disk(disk);
tagset_err:
	kfree(xrd->data);
data_err:
	kfree(xrd);

	return ret;
}

static void xrd_del(struct xrd_device *xrd)
{
	list_del(&xrd->xrd_list);
	del_gendisk(xrd->disk);
	put_disk(xrd->disk);
	memunmap(xrd->data);
	kfree(xrd);
}

/*
 * Parameters
 */

static int xrd_set_parameter(const char *val, const struct kernel_param *kp)
{
	int ret = 0;

	ret = param_set_ulong(val, kp);
	if (ret < 0)
		return ret;

	if ((address != 0) && (size != 0)) {
		pr_info("create RAM disk... (address: 0x%08lx, size: %lu).\n", address, size);

		ret = xrd_alloc();
		if (ret)
			pr_err("failed to create RAM disk... (%d).\n", ret);

		address = 0;
		size = 0;
	}

	return ret;
}

static const struct kernel_param_ops param_ops = {
	.set = xrd_set_parameter,
};

module_param_cb(address, &param_ops, &address, 0644);
module_param_cb(size, &param_ops, &size, 0644);
MODULE_PARM_DESC(address, "RAM address.\n");
MODULE_PARM_DESC(size, "Disk size in bytes.\n");

static int __init xrd_init(void)
{
	int ret;

	ret = register_blkdev(0, "xramdisk");
	if (ret < 0)
		return ret;

	major = ret;

	pr_info("loaded.\n");

	return 0;
}

static void __exit xrd_exit(void)
{
	struct xrd_device *xrd, *next;

	unregister_blkdev(major, "xramdisk");

	list_for_each_entry_safe(xrd, next, &xrd_devices, xrd_list)
		xrd_del(xrd);

	pr_info("unloaded.\n");
}
 
module_init(xrd_init)
module_exit(xrd_exit)
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Remi Debord>");
MODULE_DESCRIPTION("The Forbidden RAM disk driver");
MODULE_VERSION("1.0");
