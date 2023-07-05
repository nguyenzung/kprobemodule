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
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>


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

static struct info* check_pid(int pid)
{
	struct info *pid_info;
	hash_for_each_possible(pid_map, pid_info, node, pid) {
        return pid_info;
    }
	return NULL;
}

static int add_to_trace_file(int pid)
{
	struct info *pid_info;
	spin_lock(&pid_map_lock);
	if (!check_pid(pid))
	{
		pid_info = vmalloc(sizeof(struct info));
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
	pid_info = check_pid(pid);
	if (pid_info)
	{
		printk("Del pid from tracer %d \n", pid);
		hash_del_rcu(&pid_info->node);
		num_of_pid--;
		spin_unlock(&pid_map_lock);
		synchronize_rcu();
		vfree(pid_info);
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
	pid_info = check_pid(pid);
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
	int size;
	char *buffer;
	int num_of_order;
	struct info *pid_info; 
	int bkt;
	void *ptr;

	rcu_read_lock();
	size = RESULT_LINE_LENGTH * num_of_pid;
	num_of_order = count > size ? size : count;
	if (num_of_order == *offset)
	{
		rcu_read_unlock();
		return 0;
	}
	
	buffer = vmalloc(size);
	ptr = buffer;
	if (!buffer)
	{
		rcu_read_unlock();
		return 0;
	}
	hash_for_each(pid_map, bkt, pid_info, node) {
		snprintf(buffer, RESULT_LINE_LENGTH, RESULT_TEMPLATE, pid_info->pid, pid_info->kmalloc_count);
		buffer += RESULT_LINE_LENGTH;
    }
	remaining = copy_to_user(user_buffer, ptr + *offset, num_of_order);
	rcu_read_unlock();
	vfree(ptr);
	
	*offset += (num_of_order - remaining);
	return num_of_order - remaining;
}

static ssize_t write_file(struct file *File, const char *user_buffer, size_t count, loff_t *offs) {
	int not_copied, delta, pid;
	char buffer[MAX_COMMAND_LEN + 1];

	if (count > MAX_COMMAND_LEN || count < 2)
		return -EINVAL;
	
	not_copied = copy_from_user(buffer, user_buffer, count);
	delta = count - not_copied;

	buffer[count - 1] = 0;
	pid = simple_strtol(buffer + 1, NULL, 10);

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

	printk("[Device] Major: %d, Minor: %d was registered!\n", device_nr >> 20, device_nr && 0xfffff);

	if((device_class = class_create(DRIVER_CLASS)) == NULL)
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

static int __init kprobe_init(void)
{
	int ret;
	int key = 1;
	struct info *pid_info;
	num_of_pid = 1;
	hash_init(pid_map);
	pid_info = vmalloc(sizeof(struct info));
	if (pid_info)
	{
		INIT_HLIST_NODE(&pid_info->node);
		hash_add(pid_map, &pid_info->node, key);
		pid_info->pid = key;
		pid_info->kmalloc_count = 0;

	}else{
		printk("Cannot vmalloc memory \n");
	}

	ret = init_kprobe_module();
	if (ret < 0) {
		return ret;
	}
	ret = init_file();
	if (ret < 0)
	{
		pr_err("Could not init file");
		unregister_kprobe(&kmalloc_kp);
	}
	return ret;
}

static void __exit kprobe_exit(void)
{
	struct info *pid_info; 
	int bkt;
	spin_lock(&pid_map_lock);
	hash_for_each(pid_map, bkt, pid_info, node) {
        hash_del(&pid_info->node);
        vfree(pid_info);
    }
	spin_unlock(&pid_map_lock);
	unregister_kprobe(&kmalloc_kp);
	cdev_del(&device);
	device_destroy(device_class, device_nr);
	class_destroy(device_class);
	unregister_chrdev_region(device_nr, 1);
}

module_init(kprobe_init)
module_exit(kprobe_exit)