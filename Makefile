obj-m += kprobemodule.o

all: kprobemodule.ko

kprobemodule.ko: kprobemodule.c
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
