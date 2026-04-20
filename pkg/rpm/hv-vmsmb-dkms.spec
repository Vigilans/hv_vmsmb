Name:           hv-vmsmb-dkms
Version:        0.1.0
Release:        1%{?dist}
Summary:        Hyper-V VSMB filesystem client kernel module (DKMS)

License:        GPL-2.0-only
URL:            https://github.com/Vigilans/hv_vmsmb
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       dkms
Requires:       kernel-devel

%description
DKMS package for hv_vmsmb, a Linux kernel module that implements
a VSMB (Virtual SMB) filesystem client over Hyper-V VMBus.

VSMB is Hyper-V's native file sharing mechanism, used internally
by Windows Containers and Windows Sandbox. This module provides
shared folder access between host and Linux guest with significantly
better performance than Plan9 (9p) shares.

The module auto-loads via VMBus modalias when a VSMB channel is present.

%prep
%autosetup -n %{name}-%{version}

%build

%install
install -d %{buildroot}%{_usrsrc}/hv-vmsmb-%{version}
install -m 0644 Makefile dkms.conf %{buildroot}%{_usrsrc}/hv-vmsmb-%{version}/
install -m 0644 *.c *.h %{buildroot}%{_usrsrc}/hv-vmsmb-%{version}/

%post
dkms add -m hv-vmsmb -v %{version} --rpm_safe_upgrade || :
dkms build -m hv-vmsmb -v %{version} || :
dkms install -m hv-vmsmb -v %{version} --force || :

%preun
if [ $1 -eq 0 ]; then
    dkms remove -m hv-vmsmb -v %{version} --all || :
fi

%files
%license LICENSE
%doc README.md
%{_usrsrc}/hv-vmsmb-%{version}

%changelog
* Sun Apr 19 2026 Vigilans <vigilans@foxmail.com> - 0.1.0-1
- Initial DKMS packaging
