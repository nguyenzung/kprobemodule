// SPDX-License-Identifier: GPL-2.0-only
/*
 * Here's a sample kernel module showing the use of kprobes count when kmalloc() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/trace/kprobes.rst
 *
 * You will see the trace data in /dev/tracerdriver
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <linux/slab.h>


/* Meta Information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("nguyenvietdungcs52@gmail.com");
MODULE_DESCRIPTION("A Kprobe Module");

#define MAX_COMMAND_LEN 32

#define DRIVER_NAME "tracerdriver"
#define DRIVER_CLASS "TracerClass"
#define RESULT_LINE_LENGTH 30	// PID: 123456, KMalloc: 123456\n	// 29 characters
#define RESULT_TEMPLATE "PID: %6d, KMalloc: %6d\n"
#define HASH_SLOT_BITS 6

static DEFINE_HASHTABLE(pid_map, HASH_SLOT_BITS);
static DEFINE_SPINLOCK(pid_map_lock);

static int num_of_pid;

static dev_t device_nr;
static struct class *device_class;
static struct cdev device;

struct info {
	int pid;
	int kmalloc_count;
	struct hlist_node node;
};

static struct info *find_info_by_pid(int pid)
{
	struct info *pid_info;
	hash_for_each_possible(pid_map, pid_info, node, pid) {
		if (pid_info->pid == pid)
			return pid_info;
	}
	return NULL;
}

static int add_to_trace_file(int pid)
{
	struct info *pid_info;
	spin_lock(&pid_map_lock);
	if (!find_info_by_pid(pid))
	{
		pid_info = kmalloc(sizeof(struct info), GFP_ATOMIC);
		if (!pid_info) {
			spin_unlock(&pid_map_lock);
			return -ENOMEM;
		}
		pid_info->pid = pid;
		pid_info->kmalloc_count = 0;
		INIT_HLIST_NODE(&pid_info->node);
		hash_add_rcu(pid_map, &pid_info->node, pid);
		num_of_pid++;
		spin_unlock(&pid_map_lock);
		return 0;
	}
	spin_unlock(&pid_map_lock);
	return -1;
}

static int delete_from_trace_list(int pid)
{
	struct info *pid_info;
	spin_lock(&pid_map_lock);
	pid_info = find_info_by_pid(pid);
	if (pid_info)
	{
		printk("Del pid from tracer %d \n", pid);
		hash_del_rcu(&pid_info->node);
		num_of_pid--;
		spin_unlock(&pid_map_lock);
		synchronize_rcu();
		kfree(pid_info);
		return 0;
	} else {
		printk("Not found Del pid from tracer %d \n", pid);
	}
	spin_unlock(&pid_map_lock);
	return -1;
}

static int update_trace_list(int pid)
{
	struct info *pid_info;
	rcu_read_lock();
	pid_info = find_info_by_pid(pid);
	if (pid_info)
	{
		pid_info->kmalloc_count++;
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();
	return -1;
}

static char kmalloc_symbol[KSYM_NAME_LEN] = "__kmalloc";
module_param_string(kmalloc_symbol, kmalloc_symbol, KSYM_NAME_LEN, 0644);

static struct kprobe kmalloc_kp = {
	.symbol_name	= kmalloc_symbol,
};

static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	update_trace_list(current->pid);
	return 0;
}

static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
}

static int open_file(struct inode *device_file, struct file *instance) {
	return 0;
}

static int close_file(struct inode *device_file, struct file *instance) {
	return 0;
}

static ssize_t read_file(struct file *File, char *user_buffer, size_t count, loff_t *offset) {
	int remaining;
	size_t size;
	size_t to_copy;
	char *buffer;
	char *ptr;
	struct info *pid_info; 
	int bkt;

	size = (size_t)RESULT_LINE_LENGTH * READ_ONCE(num_of_pid);

	if (*offset >= size)
		return 0;

	to_copy = min(size - (size_t)*offset, count);

	ptr = kmalloc(size, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;

	buffer = ptr;

	rcu_read_lock();
	hash_for_each_rcu(pid_map, bkt, pid_info, node) {
		snprintf(buffer, RESULT_LINE_LENGTH, RESULT_TEMPLATE,
			 pid_info->pid, pid_info->kmalloc_count);
		buffer += RESULT_LINE_LENGTH;
	}
	rcu_read_unlock();

	remaining = copy_to_user(user_buffer, ptr + *offset, to_copy);
	kfree(ptr);

	if (remaining == (int)to_copy)
		return -EFAULT;

	*offset += (to_copy - remaining);
	return to_copy - remaining;
}

static ssize_t write_file(struct file *File, const char *user_buffer, size_t count, loff_t *offs) {
	int not_copied, delta, pid, ret;
	char buffer[MAX_COMMAND_LEN + 1];

	if (count > MAX_COMMAND_LEN || count < 2)
		return -EINVAL;

	not_copied = copy_from_user(buffer, user_buffer, count);
	delta = count - not_copied;

	buffer[count] = 0;
	if (count > 0 && buffer[count - 1] == '\n')
		buffer[count - 1] = 0;

	ret = kstrtoint(buffer + 1, 10, &pid);
	if (ret < 0)
		return -EINVAL;

	switch (buffer[0])
	{
	case 's':
		printk(" Set tracer for process id: %d \n", pid);
		add_to_trace_file(pid);
		break;
	case 'e':
		printk(" Stop tracer for process id: %d \n", pid);
		delete_from_trace_list(pid);
		break;
	default:
		break;
	}
	return delta;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = open_file,
	.release = close_file,
	.read = read_file,
	.write = write_file,
};

static int init_kprobe_module(void)
{
	int ret;
	kmalloc_kp.pre_handler = handler_pre;
	kmalloc_kp.post_handler = handler_post;

	ret = register_kprobe(&kmalloc_kp);
	return ret;
}

static int init_file(void)
{
	if( alloc_chrdev_region(&device_nr, 0, 1, DRIVER_NAME) < 0)
		return -1;

	/* Bug fixed earlier: use MAJOR/MINOR macros instead of logical && */
	printk("[Device] Major: %d, Minor: %d was registered!\n", MAJOR(device_nr), MINOR(device_nr));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	if((device_class = class_create(DRIVER_CLASS)) == NULL)
#else
	if((device_class = class_create(THIS_MODULE, DRIVER_CLASS)) == NULL)
#endif
		goto ClassError;

	if(device_create(device_class, NULL, device_nr, NULL, DRIVER_NAME) == NULL)
		goto FileError;


	cdev_init(&device, &fops);
	if(cdev_add(&device, device_nr, 1) == -1)
		goto AddError;
	
	return 0;
AddError:
	device_destroy(device_class, device_nr);
FileError:
	class_destroy(device_class);
ClassError:
	unregister_chrdev_region(device_nr, 1);	
	return -1;
}

/* Helper to free all entries in pid_map */
static void cleanup_pid_map(void)
{
	struct info *pid_info;
	struct hlist_node *tmp;
	int bkt;

	spin_lock(&pid_map_lock);
	hash_for_each_safe(pid_map, bkt, tmp, pid_info, node) {
		hash_del(&pid_info->node);
		kfree(pid_info);
	}
	num_of_pid = 0;
	spin_unlock(&pid_map_lock);
}

static int __init kprobe_init(void)
{
	int ret;
	int key = 1;
	struct info *pid_info;

	num_of_pid = 0;
	hash_init(pid_map);
	pid_info = kmalloc(sizeof(struct info), GFP_KERNEL);
	if (pid_info)
	{
		INIT_HLIST_NODE(&pid_info->node);
		hash_add(pid_map, &pid_info->node, key);
		pid_info->pid = key;
		pid_info->kmalloc_count = 0;
		num_of_pid++;
	} else {
		printk("Cannot kmalloc memory \n");
	}

	ret = init_kprobe_module();
	if (ret < 0) {
		cleanup_pid_map();
		return ret;
	}
	ret = init_file();
	if (ret < 0) {
		pr_err("Could not init file");
		unregister_kprobe(&kmalloc_kp);
		cleanup_pid_map();
	}
	return ret;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kmalloc_kp);
	cdev_del(&device);
	device_destroy(device_class, device_nr);
	class_destroy(device_class);
	unregister_chrdev_region(device_nr, 1);
	cleanup_pid_map();
}

module_init(kprobe_init)
module_exit(kprobe_exit)
