# hv_vmsmb

Reference implementation of a VSMB (Virtual SMB) filesystem client as a Linux kernel module for Hyper-V guests. Implements a simplified SMB2 client over VMBus pipe-mode channels, providing shared folder access between host and guest.

VSMB is Hyper-V's native file sharing mechanism, used internally by Windows Containers and Windows Sandbox. It offers significantly better performance than Plan9 shares (`9p`) used by WSL. The Windows guest client is built into `mrxsmb.sys`; this project provides the equivalent for Linux guests.

## Usage

### Prerequisites

- A Hyper-V Linux VM with VirtualSmb shares configured in the HCS schema (supported by [NanaBox](https://github.com/M2Team/NanaBox), Windows Sandbox, and hcsshim-based launchers)
- `build-essential` (or equivalent) and kernel headers for the running kernel (e.g. `linux-headers-$(uname -r)`)

### Build and install

```bash
# Manual
make
sudo insmod hv_vmsmb.ko

# DKMS (persists across kernel updates)
sudo dkms add .
sudo dkms build hv-vmsmb/0.1.0
sudo dkms install hv-vmsmb/0.1.0
```

Arch Linux: an AUR package is available in `packaging/arch/`.

Debian/Ubuntu: `make deb` builds a `.deb` package (requires `dpkg-dev`, `debhelper`, and `dh-dkms`):

```bash
make deb
sudo dpkg -i build/debian/hv-vmsmb-dkms_0.1.0-1_all.deb
```

Fedora/RHEL: `make rpm` builds an RPM (requires `rpm-build`):

```bash
make rpm
sudo rpm -i rpmbuild/RPMS/noarch/hv-vmsmb-dkms-0.1.0-1.*.noarch.rpm
```

### Mount

```bash
mount -t vsmb <ShareName> /mnt/share
mount -t vsmb <ShareName> /mnt/share -o uid=1000,gid=1000,file_mode=0644,dir_mode=0755
mount -t vsmb <ShareName> /mnt/share -o noperm      # skip VFS permission checks
mount -t vsmb <ShareName> /mnt/share -o actimeo=10   # metadata cache TTL (default 1s)
mount -t vsmb <ShareName> /mnt/share -o symlinkroot=/media/Drives  # Windows symlink translation
```

The module auto-loads when the VMBus channel is detected (MODALIAS match on the VSMB class GUID `4d12e519-17a0-4ae4-8eaa-5270fc6abdb7`).

### Supported kernels

Requires a relatively recent kernel with the `netfs` library (`fs/netfs/`), which provides the page cache read/write infrastructure. Developed and tested on kernel 6.19.

## Performance

Benchmarked on NVMe-backed host (128 GB RAM), 16 GB guest.

### fio-cdm (1 GB, host page cache warm)

| Workload | Read | Write |
|----------|------|-------|
| SEQ1M Q8T1 | 7,856 MB/s | 3,853 MB/s |
| SEQ1M Q1T1 | 2,481 MB/s | 1,697 MB/s |
| RND4K Q32T16 | 456 MB/s | 578 MB/s |
| RND4K Q1T1 | 27 MB/s (6,900 IOPS) | 27 MB/s (6,900 IOPS) |

### Real-world sequential read (LLM model weights, `dd`)

| Scenario | Speed |
|----------|-------|
| Host NVMe raw (dd, QD=1) | 1.2-2.2 GB/s |
| VM cold (both caches empty) | 1.5-2.5 GB/s |
| VM hot (host page cache warm) | 2.9-3.8 GB/s |

Tested with 4.7-47 GB model shards (Qwen3, GLM-4.5, Qwen3.5-122B).

See [docs/performance.md](docs/performance.md) for the full optimization journey from initial prototype to current numbers.

### Filesystem correctness

[pjdfstest](https://github.com/pjd/pjdfstest): 8,787 / 8,789 pass. The 2 failures are `utimensat` timestamp precision (Windows FILETIME granularity vs POSIX nanoseconds).

## Hardlinks and symlinks

By default, `link(2)` and `symlink(2)` on a VSMB share fail with `Permission denied`. Both link types are blocked at the host (vmusrv) by default and need explicit unlocking on the host.

### Hardlink

`link(2)` is denied at NTFS-level ACL check if the per-VM token (`NT VIRTUAL MACHINE\<vmid>`) lacks `SeBackupPrivilege`. Set `UseShareRootIdentity` and `TakeBackupPrivilege` in the share's `VirtualSmbShareOptions`:

```jsonc
{
  "Name": "Shared",
  "Path": "C:\\Path\\To\\Shared",
  "Options": {
    "UseShareRootIdentity": true,
    "TakeBackupPrivilege": true
  }
}
```

Note: When adding shares through HCS, shares using `UseShareRootIdentity` must be added with `HcsModifyComputeSystem` after Start instead of being embedded in the Create document. The Create path fails with `0x80070006` when `UseShareRootIdentity` is set.

The links created over the share are owned by `NT AUTHORITY\SYSTEM` on the host.

### Symlink

`symlink(2)` is denied by an orphan `IsAdmin` boolean gate which is not exposed by any HCS API or share option. As a workaround, a script [`scripts/vsmb_enable_symlink.py`](scripts/vsmb_enable_symlink.py) is provided to directly attach to the per-VM `vmwp.exe` and flip the byte:

```powershell
sudo python vsmb_enable_symlink.py <vm-name>
```

The script should be run on the host as Administrator, after the VM has booted and a share is mounted, and lasts until the next cold restart of the VM.

For startup automation, use `--wait [seconds]` to wait for the VM and VSMB session before flipping the byte:

```powershell
sudo python scripts\vsmb_enable_symlink.py <vm-name> --wait 300
```

For example, if the VM is managed by NSSM, a `Start/Post` hook can run the script after the VM process starts (increase NSSM's default 60s hook deadline separately if it is shorter than the wait timeout):

```powershell
sudo nssm set <service-name> AppEvents Start/Post `
  '"C:\Path\To\python.exe" "C:\Path\To\hv_vmsmb\scripts\vsmb_enable_symlink.py" <vm-name> --wait 300'
```

## Maintenance Status

This project is primarily for personal use. I will maintain it for my own needs but do not plan to provide support beyond that scope.

Contributions are welcome. Also feel free to fork and maintain your own version based on this reference implementation.

## Background

I first encountered VirtualSmb through Windows Sandbox's MappedFolders, which use VSMB to share host directories into the sandbox VM. When I consolidated my Windows Sandbox and Hyper-V Linux VMs onto [NanaBox](https://github.com/M2Team/NanaBox) (an HCS-based VM manager), I wanted the same shared folder experience for full Windows guests. In late 2025, hcsshim [open-sourced](https://github.com/microsoft/hcsshim) the GCS sidecar's VSMB initialization code (`internal/gcs-sidecar/vsmb.go`), which made it possible to implement Windows guest support without reverse engineering — the full discussion is in [NanaBox#49](https://github.com/M2Team/NanaBox/issues/49).

With Windows guest VSMB working and Plan9 share performance on Linux being a known pain point, the natural next step was bringing VirtualSmb to Linux guests. Unlike the Windows guest work, the Linux kernel module required reverse engineering the undocumented wire protocol and host-side behavior — which is this project.

## Development

The implementation is based on reverse engineering of Windows host and guest components (`vmusrv.dll`, `vmbuspiper.dll`, `mrxsmb.sys`, `vmwp.exe`, `vid.sys`) using [Ghidra](https://ghidra-sre.org/), developed with LLM coding agent using [ghidra-cli](https://github.com/akiselev/ghidra-cli) [skill](https://github.com/akiselev/ghidra-cli/blob/master/.claude/skills/ghidra-cli/SKILL.md).

The VMBus transport layer draws from the kernel's `hv_sock` (`hyperv_transport.c`) for the receive loop and from `storvsc`/`netvsc` for packet buffer sizing. The SMB2 layer is a simplified subset of the kernel CIFS client (`fs/smb/`), reusing its struct definitions and NTSTATUS mapping. The VFS layer integrates with the kernel's `netfs` infrastructure for page cache management.

See [docs/ATTRIBUTION.md](docs/ATTRIBUTION.md) for per-function upstream source attribution.

## WSL Support

This module should theoretically work under WSL2, since WSL2 runs on HCS. However, WSL does not expose HCS schema customization to the user, so a VirtualSmb device may not be present by default. If WSL's underlying HCS configuration already includes a VirtualSmb device, it may be possible to add shares via `HcsModifyComputeSystem`. This has not been tested.

## References

- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/) — SMB2 protocol specification
- [hcsshim](https://github.com/microsoft/hcsshim) — HCS Go bindings; `internal/gcs-sidecar/vsmb.go` for the container VSMB client
- [libsmb2](https://github.com/sahlberg/libsmb2) — Lightweight C SMB2 client; async request/callback model reference
- [NanaBox](https://github.com/M2Team/NanaBox) — HCS-based VM manager with VirtualSmb share support
- Linux kernel `fs/smb/` — CIFS client (struct definitions, NTSTATUS mapping, VFS patterns)
- Linux kernel `net/vmw_vsock/hyperv_transport.c` — VMBus pipe-mode receive pattern

## License

GPL-2.0. See [LICENSE](LICENSE) for the full text.

Header files copied from the Linux kernel retain their original SPDX licenses: `smb2pdu.h`, `smb2status.h`, and `fscc.h` are LGPL-2.1; `smbfsctl.h` is LGPL-2.1+; `smb1pdu.h` is GPL-2.0.
