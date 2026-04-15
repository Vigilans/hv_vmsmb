obj-m := hv_vmsmb.o
hv_vmsmb-objs := vmsmb_main.o vmsmb_transport.o vmsmb_smb2.o vmsmb_vfs.o

KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
