# WSL2 packaging for `hv_vmsmb`

This directory builds everything a WSL2 user needs to mount Windows drives over
**VirtualSmb** instead of 9p/virtiofs:

1. a **kernel-modules vhd** containing the `hv_vmsmb` module, injected into an
   existing WSL kernel's module set, and
2. a **patched WSL package** (`wsl.msi`) whose service understands the
   `wsl2.virtualSmb` option and whose guest `init` mounts DrvFs over `mount -t
   vsmb`.

Everything is driven by the [`Makefile`](Makefile). It **never rebuilds a
kernel** — it compiles only `hv_vmsmb` and injects it into a modules vhd.

## Two source modes (auto-selected)

| Mode | Kernel source | Build tree / `Module.symvers` | Inject target |
|------|---------------|-------------------------------|---------------|
| **official** (default) | the Microsoft.WSL.Kernel NuGet package (public, anonymous feed) | fetched WSL2-Linux-Kernel source; `Module.symvers` reconstructed from the stripped `vmlinux` ([`gen-symvers.py`](gen-symvers.py)) | the NuGet `modules.vhd` (fixed vhd → `.vhd` out) |
| **custom** | a kernel declared in `.wslconfig` (e.g. a locally built / [xanmod](https://github.com/Locietta/xanmod-kernel-WSL2) kernel) | the running kernel's mounted `/lib/modules/<rel>/build`, which ships its own `Module.symvers` (nothing fetched/prepared/reconstructed) | its `kernelModules` vhdx (→ `.vhdx` out) |

Custom mode is entered automatically when a `.wslconfig` (located via Windows
interop) declares `kernel=`; otherwise official mode runs. The toolchain follows
the kernel — GCC for official, the matching `clang-NN` for a custom LLVM kernel.

## Building

Run inside WSL:

```bash
make module   # compile hv_vmsmb.ko against the selected kernel
make vhd      # ...and inject it into a modules vhd  (make vhdx is an alias)
make msi      # ...and build the WSL MSI bundling the kernel + modules vhd
make clean
```

When driving the build from Windows, use PowerShell (`wsl make msi`) rather than
Git Bash, which rewrites `/mnt/c` paths and mangles `$`-variables and quoting on
the way into WSL.

Heavy staging is kept on a local fs automatically when the project lives on a
host-backed mount (virtiofs/9p/vsmb), so a custom inject is ~5 s rather than
minutes; only the final vhd lands in `build/wsl/`.

### Overrides

Every source input is a `make` variable — pass a path to override the
auto-selection:

| Variable | Meaning |
|----------|---------|
| `WSL_SRC` | **Local WSL fork checkout to build the MSI from.** If it exists it is used **as-is** — its git/working tree is never touched — otherwise the fork (`WSL_REPO` @ `WSL_REF`) is cloned into it. Point it at a local checkout (incl. unpushed patches) to build the MSI from it: `make msi WSL_SRC=/mnt/c/Users/you/Projects/.../WSL`. |
| `WSL_REPO` / `WSL_REF` | fork + ref to clone when `WSL_SRC` does not exist |
| `KBUILD` | kernel build tree to compile against (default: the mounted tree in custom mode, the fetched source in official) |
| `KIMG` | kernel image, used only to reconstruct `Module.symvers` when the tree ships none |
| `MODULES_VHD` | the modules vhd to inject into |
| `LLVM` | toolchain override (auto-detected from the kernel config, down to the matching `clang-NN`); e.g. `make LLVM=1` or `make LLVM=-21` |
| `KVER` | NuGet kernel version (official mode; default: newest on the feed) |

### Prerequisites

`qemu-img` (qemu-utils), `e2fsprogs` (`debugfs`, `mke2fs`), `kmod` (`depmod`),
`python3`, and a toolchain matching the kernel — GCC for the official kernel, a
`clang-NN` matching the kernel's clang for a custom LLVM-built kernel.

## Installing

1. Install the produced MSI (`msiexec /i wsl.msi`) and `wsl --shutdown`.
2. Drop the kernel and the produced modules vhd somewhere stable, e.g. `C:\wsl\`.
3. On WSL **2.7.1+**, grant the vhd the ACLs WSL requires:
   ```powershell
   icacls C:\wsl\modules.vhdx /grant "BUILTIN\Users:(RX)" "ALL APPLICATION PACKAGES:(RX)" "ALL RESTRICTED APPLICATION PACKAGES:(RX)"
   ```
4. Configure `%UserProfile%\.wslconfig`:
   ```ini
   [wsl2]
   kernel = C:\\wsl\\bzImage
   kernelModules = C:\\wsl\\modules.vhdx
   virtualSmb = true
   ```
5. `wsl --shutdown`, then start WSL. Verify:
   ```bash
   mount | grep vsmb     # /mnt/c, /mnt/d, ... should be on type vsmb
   ```

If the kernel lacks `hv_vmsmb` (or the share can't be added), the guest falls
back to 9p automatically, so the drives still mount.

## CI

TODO: a Linux runner (`make vhd`) and a Windows runner (`make msi`) publishing a
release together — not yet wired up.
