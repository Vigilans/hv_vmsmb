obj-m := hv_vmsmb.o
hv_vmsmb-objs := vmsmb_main.o vmsmb_transport.o vmsmb_smb2.o vmsmb_vfs.o

ifneq ($(KERNELRELEASE),)
else

VMSMB_SRCS := vmsmb_main.c vmsmb_transport.c vmsmb_smb2.c vmsmb_vfs.c
VMSMB_HDRS := fscc.h smb1pdu.h smb2pdu.h smb2status.h smbfsctl.h vmsmb.h

KDIR := /lib/modules/$(shell uname -r)/build
VERSION := $(shell sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' dkms.conf)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# --- Packaging ---

DEB_BUILD_ROOT := build/debian
DEB_SRC_DIR := $(DEB_BUILD_ROOT)/hv-vmsmb-$(VERSION)
DEB_PACKAGE := $(DEB_BUILD_ROOT)/hv-vmsmb-dkms_$(VERSION)-1_all.deb

deb:
	test -n "$(VERSION)"
	rm -rf $(DEB_BUILD_ROOT)
	mkdir -p $(DEB_SRC_DIR)
	cp Makefile dkms.conf LICENSE README.md $(DEB_SRC_DIR)/
	cp $(VMSMB_SRCS) $(VMSMB_HDRS) $(DEB_SRC_DIR)/
	cp -a packaging/debian $(DEB_SRC_DIR)/debian
	cd $(DEB_SRC_DIR) && dpkg-buildpackage -us -uc -b
	@echo "Built $(DEB_PACKAGE)"

rpm:
	mkdir -p rpmbuild/{SOURCES,BUILD,RPMS,SRPMS}
	tar czf rpmbuild/SOURCES/hv-vmsmb-dkms-$(VERSION).tar.gz \
		--transform='s,^,hv-vmsmb-dkms-$(VERSION)/,' \
		Makefile dkms.conf *.c *.h LICENSE README.md
	rpmbuild --define "_topdir $(PWD)/rpmbuild" -ba packaging/rpm/hv-vmsmb-dkms.spec

endif

.PHONY: all clean deb rpm
