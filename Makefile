obj-m := hv_vmsmb.o
hv_vmsmb-objs := vmsmb_main.o vmsmb_transport.o vmsmb_smb2.o vmsmb_vfs.o

KDIR := /lib/modules/$(shell uname -r)/build
VERSION := $(shell sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' dkms.conf)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# --- Packaging ---

deb:
	ln -sfn pkg/debian debian
	dpkg-buildpackage -us -uc -b
	rm -f debian

rpm:
	mkdir -p rpmbuild/{SOURCES,BUILD,RPMS,SRPMS}
	tar czf rpmbuild/SOURCES/hv-vmsmb-dkms-$(VERSION).tar.gz \
		--transform='s,^,hv-vmsmb-dkms-$(VERSION)/,' \
		Makefile dkms.conf *.c *.h LICENSE README.md
	rpmbuild --define "_topdir $(PWD)/rpmbuild" -ba pkg/rpm/hv-vmsmb-dkms.spec

.PHONY: all clean deb rpm
