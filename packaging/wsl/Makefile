# WSL packaging for hv_vmsmb. Compiles only the module (never rebuilds a kernel),
# injects it into a WSL modules vhd, and `msi` bundles a WSL installer.
#
# Two source modes, auto-selected (see "source selection" below):
#   official - the Microsoft.WSL.Kernel NuGet package (public, anonymous feed):
#              fetch its matching source, reconstruct Module.symvers, build, and
#              inject into its modules.vhd. The default.
#   custom   - a kernel declared in .wslconfig (e.g. a locally built / xanmod
#              kernel): build against its already-prepared /lib/modules/<rel>/
#              build tree and inject into its kernelModules vhd.
#
# Runs inside WSL: the Linux steps use the native toolchain; the `msi` step calls
# the Windows cmake.exe over WSL interop.
#
# Work dir is keyed by version ($(O)/<KVER>/); after the first build, editing only
# the source recompiles just the module (modules_prepare / symvers are cached).

SHELL := /bin/bash

ARCH ?= x64
# Toolchain follows the kernel: the official WSL kernel is GCC, a custom/xanmod
# kernel LLVM. Auto-detected from the kernel config (CONFIG_CC_IS_CLANG), down to
# the matching clang version (LLVM=-21) when that toolchain is installed; override
# with `make LLVM=1` or `make LLVM=-NN`.
LLVM ?=
FEED := https://pkgs.dev.azure.com/shine-oss/wsl/_packaging/WslDependencies/nuget/v3/flat2/microsoft.wsl.kernel

# --- source selection: .wslconfig custom kernel vs official nuget --------------
# .wslconfig (located via Windows interop; absent on generic hosts / CI) declares
# a custom kernel + its modules vhd. Its presence switches the whole pipeline to
# "custom": build against the running kernel's mounted build tree and inject into
# that vhd. Otherwise everything comes from the official Microsoft.WSL.Kernel nuget.
USERPROFILE := $(shell cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')
WSLCONFIG  := $(shell w=$$(wslpath '$(USERPROFILE)')/.wslconfig; [ -f "$$w" ] && echo "$$w")
WSL_KERNEL := $(and $(WSLCONFIG),$(shell sed -n 's/\r$$//; s#^kernel=##p' '$(WSLCONFIG)' | head -1))
WSL_KMODS  := $(and $(WSLCONFIG),$(shell sed -n 's/\r$$//; s#^kernelModules=##p' '$(WSLCONFIG)' | head -1))

ifneq ($(WSL_KERNEL),)
# custom: name the work dir + output by the running kernel release; vhdx out
KVER    ?= $(shell uname -r)
VHD_FMT := vhdx
else
# official: newest version on the nuget feed (override: make KVER=6.18.33.1-1)
KVER    ?= $(shell curl -fsSL "$(FEED)/index.json" | tr ',][' '\n' | grep -oE '[0-9][0-9.]+[^"]*' | sort -V | tail -1)
VHD_FMT := vpc
endif
# 6.18.33.1-1 -> linux-msft-wsl-6.18.33.1 (only used by the nuget path)
KTAG := linux-msft-wsl-$(firstword $(subst -, ,$(KVER)))

# WSL fork to build the MSI from. By default the fork (WSL_REPO @ WSL_REF) is
# cloned into a managed build dir. To build from a local checkout instead — e.g.
# one with unpushed patches — pass WSL_SRC=/path/to/WSL: an existing checkout is
# used AS-IS (its working tree / git is never touched). Keep it on the Windows fs;
# the Windows cmake.exe build chokes on \\wsl$ paths.
WSL_REPO ?= https://github.com/Vigilans/WSL
WSL_REF  ?= virtual-smb
WSL_SRC  ?= $(O)/WSL

VMSMB := $(abspath $(CURDIR)/../..)
O     := $(VMSMB)/build/wsl
W     := $(O)/$(KVER)

NUPKG := $(W)/kernel.nupkg
NBIN  := $(W)/nuget/build/native/bin/$(ARCH)
KBIN  := $(NBIN)/kernel
KCFG  := $(NBIN)/kernel_config
KVHD  := $(NBIN)/modules.vhd
KSRC  := $(W)/ksrc
PREP  := $(KSRC)/scripts/mod/modpost       # real product of modules_prepare
KO    := $(W)/hv_vmsmb.ko
MODVHD := $(O)/modules-$(KVER).$(if $(filter vhdx,$(VHD_FMT)),vhdx,vhd)
MSI    := $(O)/wsl-$(KVER)-$(WSL_REF).msi

# --- source paths: explicit vars > .wslconfig custom kernel > nuget ------------
# Each input is overridable with a path, e.g. make KBUILD=/path MODULES_VHD=/path.
ifneq ($(WSL_KERNEL),)
# custom: the running kernel's mounted tree carries Module.symvers, so nothing is
# fetched / prepared / reconstructed; inject into its kernelModules vhd.
KIMG        ?= $(shell wslpath '$(WSL_KERNEL)')
KBUILD      ?= /lib/modules/$(shell uname -r)/build
MODULES_VHD ?= $(and $(WSL_KMODS),$(shell wslpath '$(WSL_KMODS)'))
endif

# official nuget defaults (also the path-override entry points)
KIMG        ?= $(KBIN)
KBUILD      ?= $(KSRC)
MODULES_VHD ?= $(KVHD)

# Is the project on a host-backed passthrough fs? Extracting + rebuilding a
# custom build's ~20k-file modules tree (kernel headers) on such a mount round-
# trips every file out of the VM twice (~5s local vs >10min). virtiofs/9p/drvfs =
# WSL Windows drives, vsmb = an hv_vmsmb share. If so, stage on the local fs;
# only the final vhd lands in $(O). Native projects stage in-place ($(W)).
PROJ_FS     := $(shell findmnt -nro FSTYPE -T '$(VMSMB)' 2>/dev/null)
PROJ_ON_WIN := $(filter virtiofs 9p v9fs drvfs vsmb,$(PROJ_FS))
STAGE       := $(if $(PROJ_ON_WIN),/tmp/hv_vmsmb,$(W))

# When KBUILD is our own fetched source we fetch it + run modules_prepare; an
# externally supplied build tree is already prepared and used as-is.
ifeq ($(KBUILD),$(KSRC))
KO_PREP       := $(PREP)
SYMVERS_ORDER := | $(PREP)
endif

# LLVM= is resolved when the recipe runs (the config exists by then): honour an
# explicit override; else, for a clang-built kernel, pick the versioned toolchain
# matching its compiler (LLVM=-21 -> clang-21/ld.lld-21) when present, else LLVM=1.
MAKE_K = $(MAKE) -C $(KBUILD) $$(if [ -n '$(LLVM)' ]; then echo LLVM=$(LLVM); elif grep -q '^CONFIG_CC_IS_CLANG=y' $(KBUILD)/.config 2>/dev/null; then v=$$(sed -n 's/.*clang version \([0-9]*\).*/\1/p' $(KBUILD)/.config | head -1); if [ -n "$$v" ] && command -v clang-$$v >/dev/null 2>&1; then echo LLVM=-$$v; else echo LLVM=1; fi; fi)

.PHONY: all module vhd vhdx msi install_vhd install_vhdx clean
all: msi

# --- official kernel package: anonymous download + unzip (no nuget.exe) --------
$(NUPKG):
	mkdir -p $(@D)
	curl -fsSL "$(FEED)/$(KVER)/microsoft.wsl.kernel.$(KVER).nupkg" -o $@

# One unzip produces kernel + kernel_config + modules.vhd together.
# -DD: extract with current mtime (zip stores stale times older than the .nupkg,
# which would otherwise make these outputs look perpetually out of date).
$(KBIN) $(KCFG) $(KVHD) &: $(NUPKG)
	rm -rf $(W)/nuget && mkdir -p $(W)/nuget
	cd $(W)/nuget && unzip -oqDD $(NUPKG)
	chmod -R u+rwX $(W)/nuget          # .nupkg packs files mode 0000

# --- prepared kernel source tree (skipped once modpost exists) -----------------
$(KSRC)/Makefile:
	rm -rf $(KSRC) && mkdir -p $(KSRC)
	curl -fsSL "https://github.com/microsoft/WSL2-Linux-Kernel/archive/refs/tags/$(KTAG).tar.gz" \
	  | tar xz -C $(KSRC) --strip-components=1

$(PREP): $(KSRC)/Makefile $(KCFG)
	cp $(KCFG) $(KSRC)/.config
	$(MAKE_K) olddefconfig modules_prepare

# --- Module.symvers: keep the build tree's own, else reconstruct from vmlinux --
# A kernel that ships build/Module.symvers (a locally built / xanmod kernel) is
# used directly. The official nuget kernel ships none, so reconstruct the
# exported-symbol CRCs from the stripped vmlinux's __ksymtab/__kcrctab sections.
$(KBUILD)/Module.symvers: $(SYMVERS_ORDER)
	@if [ -s '$@' ]; then \
	  echo "Module.symvers: using the one shipped in the build tree"; \
	else \
	  echo "Module.symvers: reconstructing from vmlinux"; \
	  $(KBUILD)/scripts/extract-vmlinux $(KIMG) > $(W)/vmlinux; \
	  python3 gen-symvers.py $(W)/vmlinux > '$@'; \
	fi

# --- the module: recompiles on .c/.h change (modules_prepare already done) -----
$(KO): $(KO_PREP) $(KBUILD)/Module.symvers $(wildcard $(VMSMB)/*.c $(VMSMB)/*.h)
	$(MAKE_K) M=$(VMSMB) modules
	mkdir -p $(@D)
	cp $(VMSMB)/hv_vmsmb.ko $@
module: $(KO)

# --- modules vhd with hv_vmsmb injected ----------------------------------------
# Read the *source vhd file* (never the live /lib/modules overlay, which may hold
# user-stuffed junk): qemu-img -> raw normalises both a fixed vhd (official) and a
# dynamic vhdx (custom) so debugfs can dump the contents. Restage under
# lib/modules/<rel>, add our .ko, depmod, rebuild the ext4 rootless with
# mke2fs -d, and wrap back to the source's format (vpc / vhdx) with qemu-img.
# Tools: qemu-img (qemu-utils), e2fsprogs (debugfs, mke2fs), kmod (depmod).
$(MODVHD): $(MODULES_VHD) $(KO)
	set -e; S=$(STAGE); \
	rm -rf $$S/modstage $$S/src.raw $$S/modules.img; \
	trap 'rm -rf $$S/modstage $$S/src.raw $$S/modules.img' EXIT; \
	REL=$$(cat $(KBUILD)/include/config/kernel.release); \
	D=$$S/modstage/lib/modules/$$REL; mkdir -p $$D; \
	qemu-img convert -O raw $(MODULES_VHD) $$S/src.raw; \
	debugfs -R "rdump / $$D" $$S/src.raw 2>/dev/null || true; \
	rm -rf "$$D/lost+found"; \
	install -D $(KO) $$D/updates/hv_vmsmb.ko; \
	depmod -b $$S/modstage $$REL; \
	SZ=$$(( $$(du -sk $$D | cut -f1)/1024 + 256 )); \
	mke2fs -q -t ext4 -L wsl-modules -d $$D -F $$S/modules.img $${SZ}M; \
	mkdir -p $(@D); \
	qemu-img convert -O $(VHD_FMT) $$S/modules.img $@
vhd vhdx: $(MODVHD)

# --- WSL MSI: build the patched WSL installer via the Windows VS toolchain ------
# Built under vcvars with /p:UseEnv=true so msbuild uses the dev-shell toolchain
# environment; vswhere (fixed install path) locates vcvars, so any VS C++ install
# builds it. cmd's && and paths go as separate argv words — a single pre-quoted
# arg has its inner quotes mangled by WSL interop, while bare spaced args get
# quoted by interop correctly. After configure restores the kernel package, our
# kernel ($(KIMG)) + modules ($(MODVHD), with hv_vmsmb) overwrite its
# bin/$(ARCH)/{kernel,modules.vhd} so the MSI ships them (custom mode = a
# self-contained xanmod kernel; official = hv_vmsmb in the official modules.vhd).
# The old MSI is deleted first — wix keys off the .wxs, not the File Source bytes,
# and would otherwise repackage a stale cached MSI.
# Build out-of-source into out/ — upstream's .gitignore ignores out/ (but not
# build/), so the fork tree stays clean; -B build leaves out/_deps (boost, GSL,
# yaml-cpp, ...) as ~90k untracked files.
$(MSI): $(MODVHD)
	@if [ -e "$(WSL_SRC)/CMakeLists.txt" ]; then \
	  echo ">>> Using existing WSL checkout as-is (git untouched): $(WSL_SRC)"; \
	else \
	  echo ">>> Cloning WSL fork $(WSL_REF) -> $(WSL_SRC)"; \
	  git clone --depth 1 --branch "$(WSL_REF)" "$(WSL_REPO)" "$(WSL_SRC)"; \
	fi
	set -e; \
	pf86=$$(cmd.exe /c 'echo %ProgramFiles(x86)%' 2>/dev/null | tr -d '\r'); \
	vswhere=$$(wslpath "$$pf86/Microsoft Visual Studio/Installer/vswhere.exe"); \
	vsdir=$$("$$vswhere" -latest -property installationPath | tr -d '\r'); \
	vcvars="$$vsdir\\VC\\Auxiliary\\Build\\vcvars64.bat"; \
	winsrc=$$(wslpath -w "$(WSL_SRC)"); \
	echo ">>> Configuring WSL build (restores the official kernel package)"; \
	cmd.exe /c cd /d "$$winsrc" '&&' cmake -S . -B out -DCMAKE_BUILD_TYPE=Release; \
	kver=$$(sed -n 's/.*Microsoft\.WSL\.Kernel" *version="\([^"]*\)".*/\1/p' "$(WSL_SRC)/packages.config"); \
	ksd="$(WSL_SRC)/out/packages/Microsoft.WSL.Kernel.$$kver/build/native/bin/$(ARCH)"; \
	echo ">>> Bundling our kernel + modules (with hv_vmsmb) into $$ksd"; \
	cp "$(KIMG)" "$$ksd/kernel"; \
	rm -f "$$ksd/modules.vhd"; \
	qemu-img convert -O vpc "$(MODVHD)" "$$ksd/modules.vhd"; \
	echo ">>> Building wsl.msi (vcvars + UseEnv=true)"; \
	rm -f "$(WSL_SRC)/out/bin/$(ARCH)/Release/wsl.msi"; \
	cmd.exe /c cd /d "$$winsrc" '&&' call "$$vcvars" '&&' \
	  cmake --build out --config Release --target msipackage -- /m /p:UseEnv=true
	cp "$(WSL_SRC)/out/bin/$(ARCH)/Release/wsl.msi" $@
msi: $(MSI)

# --- install_vhd: point .wslconfig at the built modules vhd, in place -----------
# WSL boots the vhd straight from build/wsl/ — no copy, no extra location, since
# kernelModules takes any absolute Windows path. Grants the RX ACLs WSL 2.7.1+
# needs (icacls by SID, locale-independent), sets kernelModules= to it, and leaves
# kernel= if present (custom) or adds the stock WSL kernel (WSL refuses
# kernelModules without a kernel). The vhd lives in the build tree, so `make clean`
# undoes this — it is an in-place dev install. Apply with `wsl --shutdown`.
install_vhd install_vhdx: $(MODVHD)
	set -e; \
	win=$$(wslpath -w "$(MODVHD)"); destm=$$(wslpath -m "$(MODVHD)"); \
	icacls.exe "$$win" /grant '*S-1-5-32-545:(RX)' '*S-1-15-2-1:(RX)' '*S-1-15-2-2:(RX)' >/dev/null; \
	cfg=$$(wslpath '$(USERPROFILE)')/.wslconfig; touch "$$cfg"; \
	grep -q '^\[wsl2\]' "$$cfg" || printf '\n[wsl2]\n' >> "$$cfg"; \
	grep -q '^kernel=' "$$cfg" || sed -i '/^\[wsl2\]/a kernel=C:/Program Files/WSL/tools/kernel' "$$cfg"; \
	if grep -q '^kernelModules=' "$$cfg"; then \
	  sed -i "s|^kernelModules=.*|kernelModules=$$destm|" "$$cfg"; \
	else \
	  sed -i "/^\[wsl2\]/a kernelModules=$$destm" "$$cfg"; \
	fi; \
	echo ">>> .wslconfig kernelModules -> $$win; run 'wsl --shutdown' to apply"

clean:
	rm -rf $(O)
