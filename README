# Kprobe Module - Usage Guide and Technical Details

This module uses **Kprobes** to **hook** into kernel functions and **monitor** the number of `kmalloc()` calls per Process ID (PID).

---

## 1. Core Logic and How it Works

. **What is kmalloc?**

kmalloc is the memory allocation function in the Linux kernel, similar to malloc() in a user-space C program.

**Example in user-space:**
```c
ptr = malloc(size);
```

**Example in kernel-space:**
```c
ptr = kmalloc(size, GFP_KERNEL);
```

**Key Differences:**

| Feature | User-space | Kernel-space |
| :--- | :--- | :--- |
| **Function** | `malloc()` | `kmalloc()` |
| **Context** | Standard process | Kernel |
| **Memory Region** | User-space memory | Kernel-space memory |
| **Deallocation** | `free()` | `kfree()` |

kmalloc() is typically used for small to medium-sized memory allocations within the kernel. The returned memory is contiguous in the kernel's virtual address space and usually physically contiguous as well, making it ideal for drivers and kernel modules.

. **What does the program monitor?**
The module monitors calls to the `__kmalloc` symbol, which is the core implementation behind various `kmalloc` variants.

. **How it works**
1.  **Kprobes Hooking**: Uses Linux Kprobes to hook into the `__kmalloc` function.
2.  **Handler Execution**: A `handler_pre` function runs whenever `__kmalloc` is called.
3.  **PID Analysis**: Retrieves the current PID using `current->pid`.
4.  **Storage**: Tracks counts in a **Hashtable** (`pid_map`) using **RCU** and **Spinlocks** for thread safety.
5.  **Interface**: Provides a character device at `/dev/tracerdriver` for interaction.

---

## 2. Usage Guide

### Standard Workflow (Using VM)

**Step 1: Start the VM**
```bash
make start
```

**Step 2: Connect via SSH**
```bash
make ssh
```

**Step 3: Build and Install (Inside VM)**
```bash
cd /hostshare
sudo make all
sudo insmod kprobemodule.ko
sudo chmod 777 /dev/tracerdriver
```

### Interaction

- **View stats**: `cat /dev/tracerdriver`
- **Start tracking**: `echo s{PID} > /dev/tracerdriver`
- **Stop tracking**: `echo e{PID} > /dev/tracerdriver`

---

## 3. VM Management

- `make status` - Check VM status.
- `make stop` - Stop the VM.
- `make reset` - Wipe and recreate VM.
- `make clear` - Remove all VM-related files.

---

## 4. Technical Notes
- **Compatibility**: Supports kernel versions pre/post 6.4.
- **Sharing**: Host directory is mounted at `/hostshare` via 9p.
