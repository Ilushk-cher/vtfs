obj-m += vtfs.o 
vtfs-objs := vtfs_main.o super.o inode.o dir.o store.o file.o ops.o http.o remote.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf .cache

load:
	sudo insmod vtfs.ko

unload:
	sudo rmmod vtfs

mount:
	sudo mount -t vtfs none /mnt/vt/

umount:
	sudo rm -rf /mnt/vt/*
	sudo umount /mnt/vt