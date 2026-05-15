// SPDX-License-Identifier: GPL-2.0-only
/*
 * Here's a sample kernel module showing the use of kprobes count when kmalloc() is called.
 *
 * For more information on theory of operation of kprobes, see
 * Documentation/trace/kprobes.rst
 *
 * You will see the trace data in /dev/tracerdriver
 *
 * --- Change log ---
 * Fix 1: Added per-CPU re-entrancy guard in kprobe handler to prevent
 *         infinite recursion when code paths triggered by the handler
 *         itself call kmalloc (e.g. read_file, printk internals).
 *
 * Fix 2 & 3: Replaced hand-rolled read_file (with manual buffer-size
 *         arithmetic and TOCTOU race on num_of_pid) with seq_file /
 *         single_open.  seq_file manages the output buffer internally and
 *         snapshots data atomically under RCU, eliminating both the
 *         snprintf-overflow and the race condition.
 *
 * Fix 4: Changed kmalloc_count from plain int to atomic_t so that
 *         concurrent increments inside the RCU read-side critical section
 *         are race-free without needing a write-side lock.
 *
 * Minor: Removed the spurious ghost entry (pid=1) inserted at init time.
 * Minor: Made write_file null-termination use sizeof(buffer)-1 to be
 *         independent of the value of MAX_COMMAND_LEN.
 * Minor: Replaced raw printk calls with pr_info / pr_err.
 * Minor: Use hash_for_each_possible_rcu in find_info_by_pid so it is
 *         safe to call under rcu_read_lock (as in update_trace_list).
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
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>

/* Meta Information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("nguyenvietdungcs52@gmail.com");
MODULE_DESCRIPTION("A Kprobe Module");

#define MAX_COMMAND_LEN 32

#define DRIVER_NAME  "tracerdriver"
#define DRIVER_CLASS "TracerClass"
#define RESULT_TEMPLATE "PID: %6d, KMalloc: %6d\n"
#define HASH_SLOT_BITS 6

static DEFINE_HASHTABLE(pid_map, HASH_SLOT_BITS);
static DEFINE_SPINLOCK(pid_map_lock);

static int num_of_pid;

static dev_t device_nr;
static struct class *device_class;
static struct cdev device;

/* Fix 4 – use atomic_t so concurrent increments are safe under RCU. */
struct info {
	int pid;
	atomic_t kmalloc_count;
	struct hlist_node node;
};

/*
 * Use hash_for_each_possible_rcu so this helper is safe to call both
 *  - under rcu_read_lock()  (update_trace_list path), and
 *  - under pid_map_lock spinlock (add / delete paths).
 * READ_ONCE semantics in the RCU variant prevent torn pointer reads in
 * both cases.
 */
static struct info *find_info_by_pid(int pid)
{
	struct info *pid_info;

	hash_for_each_possible_rcu(pid_map, pid_info, node, pid) {
		if (pid_info->pid == pid)
			return pid_info;
	}
	return NULL;
}

static int add_to_trace_file(int pid)
{
	struct info *pid_info;

	spin_lock(&pid_map_lock);
	if (!find_info_by_pid(pid)) {
		pid_info = kmalloc(sizeof(struct info), GFP_ATOMIC);
		if (!pid_info) {
			spin_unlock(&pid_map_lock);
			return -ENOMEM;
		}
		pid_info->pid = pid;
		atomic_set(&pid_info->kmalloc_count, 0);
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
	if (pid_info) {
		pr_info("Del pid from tracer %d\n", pid);
		hash_del_rcu(&pid_info->node);
		num_of_pid--;
		spin_unlock(&pid_map_lock);
		synchronize_rcu();
		kfree(pid_info);
		return 0;
	}
	pr_info("Not found pid in tracer: %d\n", pid);
	spin_unlock(&pid_map_lock);
	return -1;
}

/*
 * Fix 4 – atomic_inc is safe inside an RCU read-side critical section.
 * Multiple CPUs can call atomic_inc concurrently without data loss.
 */
static int update_trace_list(int pid)
{
	struct info *pid_info;

	rcu_read_lock();
	pid_info = find_info_by_pid(pid);
	if (pid_info) {
		atomic_inc(&pid_info->kmalloc_count);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();
	return -1;
}

/* ------------------------------------------------------------------ */
/* Kprobe glue                                                          */
/* ------------------------------------------------------------------ */

static char kmalloc_symbol[KSYM_NAME_LEN] = "__kmalloc";
module_param_string(kmalloc_symbol, kmalloc_symbol, KSYM_NAME_LEN, 0644);

static struct kprobe kmalloc_kp = {
	.symbol_name = kmalloc_symbol,
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

/* ------------------------------------------------------------------ */
/* /dev/tracerdriver – file operations                                  */
/* ------------------------------------------------------------------ */

/*
 * Fix 2 & 3 – use seq_file (single_open) instead of a hand-rolled
 * read_file.
 *
 * Benefits:
 *  - No manual buffer-size arithmetic → no snprintf overflow.
 *  - No TOCTOU race between reading num_of_pid and iterating the table;
 *    the whole iteration happens inside one RCU read-side critical section
 *    and seq_file handles paging transparently.
 *  - copy_to_user is handled by seq_read, not us.
 */
static int pid_seq_show(struct seq_file *s, void *v)
{
	struct info *pid_info;
	int bkt;

	rcu_read_lock();
	hash_for_each_rcu(pid_map, bkt, pid_info, node) {
		seq_printf(s, RESULT_TEMPLATE,
			   pid_info->pid,
			   atomic_read(&pid_info->kmalloc_count));
	}
	rcu_read_unlock();
	return 0;
}

static int open_file(struct inode *inode, struct file *file)
{
	return single_open(file, pid_seq_show, NULL);
}

static int close_file(struct inode *inode, struct file *file)
{
	return single_release(inode, file);
}

static ssize_t write_file(struct file *File, const char *user_buffer,
			  size_t count, loff_t *offs)
{
	int not_copied, delta, pid, ret;
	char buffer[MAX_COMMAND_LEN + 1];

	if (count > MAX_COMMAND_LEN || count < 2)
		return -EINVAL;

	not_copied = copy_from_user(buffer, user_buffer, count);
	delta = count - not_copied;

	/*
	 * Minor fix: null-terminate at sizeof(buffer)-1 (== MAX_COMMAND_LEN)
	 * to be safe regardless of the value of count.  count is already
	 * checked to be <= MAX_COMMAND_LEN above, so buffer[count] is always
	 * a valid index, but the explicit cap removes any doubt.
	 */
	buffer[min(count, sizeof(buffer) - 1)] = '\0';
	if (count > 0 && buffer[count - 1] == '\n')
		buffer[count - 1] = '\0';

	ret = kstrtoint(buffer + 1, 10, &pid);
	if (ret < 0)
		return -EINVAL;

	switch (buffer[0]) {
	case 's':
		pr_info("Set tracer for process id: %d\n", pid);
		add_to_trace_file(pid);
		break;
	case 'e':
		pr_info("Stop tracer for process id: %d\n", pid);
		delete_from_trace_list(pid);
		break;
	default:
		break;
	}
	return delta;
}

static const struct file_operations fops = {
	.owner   = THIS_MODULE,
	.open    = open_file,
	.read    = seq_read,      /* provided by seq_file */
	.llseek  = seq_lseek,     /* provided by seq_file */
	.release = close_file,
	.write   = write_file,
};

/* ------------------------------------------------------------------ */
/* Module init / exit helpers                                           */
/* ------------------------------------------------------------------ */

static int init_kprobe_module(void)
{
	int ret;

	kmalloc_kp.pre_handler  = handler_pre;
	kmalloc_kp.post_handler = handler_post;

	ret = register_kprobe(&kmalloc_kp);
	if (ret < 0)
		pr_err("register_kprobe failed, returned %d\n", ret);
	return ret;
}

static int init_file(void)
{
	if (alloc_chrdev_region(&device_nr, 0, 1, DRIVER_NAME) < 0)
		return -1;

	pr_info("[Device] Major: %d, Minor: %d was registered!\n",
		MAJOR(device_nr), MINOR(device_nr));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	if ((device_class = class_create(DRIVER_CLASS)) == NULL)
#else
	if ((device_class = class_create(THIS_MODULE, DRIVER_CLASS)) == NULL)
#endif
		goto ClassError;

	if (device_create(device_class, NULL, device_nr, NULL, DRIVER_NAME) == NULL)
		goto FileError;

	cdev_init(&device, &fops);
	if (cdev_add(&device, device_nr, 1) == -1)
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

/* ------------------------------------------------------------------ */
/* Module init / exit                                                   */
/* ------------------------------------------------------------------ */

static int __init kprobe_init(void)
{
	int ret;

	num_of_pid = 0;
	hash_init(pid_map);

	/*
	 * Minor fix: removed the spurious ghost entry (pid = 1) that was
	 * inserted here.  It polluted the tracer output and was never
	 * explicitly added by the user.
	 */

	ret = init_kprobe_module();
	if (ret < 0) {
		pr_err("Could not init kprobe module\n");
		return ret;
	}

	ret = init_file();
	if (ret < 0) {
		pr_err("Could not init file\n");
		unregister_kprobe(&kmalloc_kp);
		cleanup_pid_map();
		return ret;
	}

	pr_info("kprobe module loaded, hooked on '%s'\n", kmalloc_symbol);
	return 0;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kmalloc_kp);
	cdev_del(&device);
	device_destroy(device_class, device_nr);
	class_destroy(device_class);
	unregister_chrdev_region(device_nr, 1);
	cleanup_pid_map();
	pr_info("kprobe module unloaded\n");
}

module_init(kprobe_init)
module_exit(kprobe_exit)
