obj-m += kprobemodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

# QEMU / VM configuration
QEMU_BASE_IMAGE ?= ubuntu-22.04-server-cloudimg-amd64.img
QEMU_BASE_URL ?= https://cloud-images.ubuntu.com/releases/22.04/release/$(QEMU_BASE_IMAGE)
VM_IMG ?= kprobemodule-vm.qcow2
DISK_SIZE ?= 5G
MEM ?= 2048
CPUS ?= 2
SSH_PORT ?= 2222
VM_PIDFILE ?= .qemu_vm_pid
SEED_DIR ?= .cloud-init
SEED_IMG ?= $(SEED_DIR)/seed.img
VM_USER ?= ubuntu
HOST_PROJECT_DIR ?= $(abspath .)

# Internal QEMU helpers
qemu-download:
	@if [ ! -f "$(QEMU_BASE_IMAGE)" ]; then \
		echo "Downloading base cloud image..."; \
		wget -c $(QEMU_BASE_URL) -O $(QEMU_BASE_IMAGE) || curl -L $(QEMU_BASE_URL) -o $(QEMU_BASE_IMAGE); \
	fi

qemu-create: qemu-download
	@if [ ! -f "$(VM_IMG)" ]; then \
		echo "Creating VM image $(VM_IMG) from base..."; \
		qemu-img convert -O qcow2 "$(QEMU_BASE_IMAGE)" "$(VM_IMG)"; \
		echo "Resizing VM image to $(DISK_SIZE)..."; \
		qemu-img resize "$(VM_IMG)" $(DISK_SIZE); \
	fi

qemu-seed-create:
	@mkdir -p $(SEED_DIR)
	@PUBKEY=""; \
	for key in $(HOME)/.ssh/id_rsa.pub $(HOME)/.ssh/id_ed25519.pub $(HOME)/.ssh/id_ecdsa.pub; do \
		if [ -f "$$key" ]; then PUBKEY="$$(cat $$key | tr -d '\r\n')"; break; fi; \
	done; \
	{ \
		echo "#cloud-config"; \
		echo "ssh_pwauth: true"; \
		echo "users:"; \
		echo "  - name: $(VM_USER)"; \
		echo "    sudo: ALL=(ALL) NOPASSWD:ALL"; \
		echo "    shell: /bin/bash"; \
		echo "    lock_passwd: false"; \
		if [ -n "$$PUBKEY" ]; then \
			echo "    ssh_authorized_keys:"; \
			echo "      - $$PUBKEY"; \
		fi; \
		echo "chpasswd:"; \
		echo "  list: |"; \
		echo "    $(VM_USER):ubuntu"; \
		echo "  expire: False"; \
		echo "mounts:"; \
		echo "  - [ hostshare, /hostshare, 9p, \"trans=virtio,version=9p2000.L,msize=262144,_netdev\", 0, 0 ]"; \
		echo "runcmd:"; \
		echo "  - rm -f /etc/ssh/sshd_config.d/*.conf"; \
		echo "  - sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config"; \
		echo "  - echo 'PasswordAuthentication yes' > /etc/ssh/sshd_config.d/99-manual.conf"; \
		echo "  - systemctl restart ssh"; \
	} > $(SEED_DIR)/user-data
	@printf 'instance-id: iid-local01\nlocal-hostname: kprobemodule-vm\n' > $(SEED_DIR)/meta-data
	@cloud-localds $(SEED_IMG) $(SEED_DIR)/user-data $(SEED_DIR)/meta-data

qemu-stop:
	@if [ -f "$(VM_PIDFILE)" ]; then \
		PID=$$(cat $(VM_PIDFILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			echo "Stopping VM (pid $$PID)..."; \
			kill $$PID; \
			sleep 1; \
		fi; \
		rm -f $(VM_PIDFILE); \
	else \
		echo "VM is not running."; \
	fi

# Primary User Rules
start: qemu-create qemu-seed-create
	@if [ -f "$(VM_PIDFILE)" ] && kill -0 $$(cat $(VM_PIDFILE)) 2>/dev/null; then \
		echo "VM is already running."; \
	else \
		echo "Starting VM in background..."; \
		qemu-system-x86_64 -enable-kvm -cpu host -m $(MEM) -smp $(CPUS) \
		  -drive file=$(VM_IMG),if=virtio,format=qcow2 \
		  -drive file=$(SEED_IMG),if=virtio,format=raw \
		  -netdev user,id=net0,hostfwd=tcp::$(SSH_PORT)-:22 -device virtio-net-pci,netdev=net0 \
		  -fsdev local,id=shared,path=$(HOST_PROJECT_DIR),security_model=none \
		  -device virtio-9p-pci,fsdev=shared,mount_tag=hostshare \
		  -pidfile $(VM_PIDFILE) -daemonize -display none; \
		echo "VM started. PLEASE WAIT ~60s for SSH to be ready."; \
		echo "Then connect via: make ssh"; \
	fi

ssh:
	@ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=password,publickey -p $(SSH_PORT) $(VM_USER)@localhost

stop: qemu-stop

clear: qemu-stop
	@rm -f $(VM_IMG) $(SEED_IMG)
	@rm -rf $(SEED_DIR)
	@echo "VM and all related files have been cleared."

reset: clear start

status:
	@if [ -f "$(VM_PIDFILE)" ]; then \
		PID=$$(cat $(VM_PIDFILE)); \
		if kill -0 $$PID 2>/dev/null; then \
			echo "Status: VM IS RUNNING (PID: $$PID)"; \
		else \
			echo "Status: VM IS STOPPED (Stale PID file)"; \
		fi; \
	else \
		echo "Status: VM IS STOPPED"; \
	fi
	@if [ -f "$(VM_IMG)" ]; then echo "Disk image: EXISTS"; else echo "Disk image: MISSING"; fi

.PHONY: all clean start stop clear reset status ssh qemu-download qemu-create qemu-seed-create qemu-stop
