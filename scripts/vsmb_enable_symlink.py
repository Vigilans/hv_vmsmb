#!/usr/bin/env python3
"""
vsmb_enable_symlink.py — flip the per-session IsAdmin byte in the host
vmwp.exe so that symlink creation through VSMB shares works.

Run as Administrator after the guest VM has booted and mounted at least
one VSMB share:

    sudo python vsmb_enable_symlink.py <vm-name>

To wait for VM boot and session establishment (e.g. for autostart):

    sudo python vsmb_enable_symlink.py <vm-name> --wait
    sudo python vsmb_enable_symlink.py <vm-name> --wait 600
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import struct
import subprocess
import sys
from dataclasses import dataclass

# vmusrv.dll offsets (verified Win11 26100 / 10.0.26100.x)
VMUSRV_SRV_SESSION_TABLE_RVA = 0xa5db0
RFS_SESSION_ARRAY_OFFSET     = 0x08
RFS_HIGH_WATER_OFFSET        = 0x7c
RFS_CAPACITY_OFFSET          = 0x80
SESSION_SESSION_ID_OFFSET    = 0x00
SESSION_STATE_OFFSET         = 0x10
SESSION_ISADMIN_OFFSET       = 0x68
SESSION_STATE_INIT           = 0xdb
SESSION_STATE_CLOSED         = 0xdd

PROCESS_VM_READ           = 0x0010
PROCESS_VM_WRITE          = 0x0020
PROCESS_VM_OPERATION      = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
LIST_MODULES_64BIT        = 0x02
SE_PRIVILEGE_ENABLED      = 0x00000002
TOKEN_ADJUST_PRIVILEGES   = 0x0020
TOKEN_QUERY               = 0x0008

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
adv = ctypes.WinDLL('advapi32', use_last_error=True)
psa = ctypes.WinDLL('psapi',    use_last_error=True)

k32.OpenProcess.restype, k32.OpenProcess.argtypes = wt.HANDLE, [wt.DWORD, wt.BOOL, wt.DWORD]
k32.CloseHandle.restype, k32.CloseHandle.argtypes = wt.BOOL, [wt.HANDLE]
k32.GetCurrentProcess.restype = wt.HANDLE
k32.ReadProcessMemory.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wt.BOOL
k32.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]


class _MODULEINFO(ctypes.Structure):
    _fields_ = [('lpBaseOfDll', wt.LPVOID), ('SizeOfImage', wt.DWORD), ('EntryPoint', wt.LPVOID)]


psa.EnumProcessModulesEx.restype, psa.EnumProcessModulesEx.argtypes = wt.BOOL, [
    wt.HANDLE, ctypes.POINTER(wt.HMODULE), wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD]
psa.GetModuleBaseNameW.restype, psa.GetModuleBaseNameW.argtypes = wt.DWORD, [wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD]
psa.GetModuleInformation.restype, psa.GetModuleInformation.argtypes = wt.BOOL, [
    wt.HANDLE, wt.HMODULE, ctypes.POINTER(_MODULEINFO), wt.DWORD]


class _LUID(ctypes.Structure):
    _fields_ = [('Lo', wt.DWORD), ('Hi', wt.LONG)]


class _LAA(ctypes.Structure):
    _fields_ = [('Luid', _LUID), ('Attributes', wt.DWORD)]


class _TP(ctypes.Structure):
    _fields_ = [('Count', wt.DWORD), ('Privs', _LAA * 1)]


adv.OpenProcessToken.restype, adv.OpenProcessToken.argtypes = wt.BOOL, [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
adv.LookupPrivilegeValueW.restype, adv.LookupPrivilegeValueW.argtypes = wt.BOOL, [wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(_LUID)]
adv.AdjustTokenPrivileges.restype, adv.AdjustTokenPrivileges.argtypes = wt.BOOL, [
    wt.HANDLE, wt.BOOL, ctypes.POINTER(_TP), wt.DWORD, ctypes.POINTER(_TP), ctypes.POINTER(wt.DWORD)]


def _winerr(msg: str) -> str:
    err = ctypes.get_last_error()
    return f'{msg} (error {err}: {ctypes.FormatError(err).strip()})'


def _enable_se_debug() -> bool:
    htok = wt.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(),
                                 TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(htok)):
        print(_winerr('OpenProcessToken'), file=sys.stderr)
        return False
    try:
        luid = _LUID()
        if not adv.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid)):
            print(_winerr('LookupPrivilegeValue'), file=sys.stderr)
            return False
        tp = _TP()
        tp.Count = 1
        tp.Privs[0].Luid = luid
        tp.Privs[0].Attributes = SE_PRIVILEGE_ENABLED
        adv.AdjustTokenPrivileges(htok, False, ctypes.byref(tp), 0, None, None)
        if ctypes.get_last_error() == 0x514:
            print('SeDebugPrivilege not held; run as Administrator', file=sys.stderr)
            return False
        return True
    finally:
        k32.CloseHandle(htok)


def _find_vmwp_pid(vm: str | None, quiet: bool = False) -> tuple[int, str] | None:
    try:
        out = subprocess.run(['hcsdiag', 'list'], capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        if not quiet:
            print(f'hcsdiag list failed: {e}', file=sys.stderr)
        return None

    vms: list[tuple[str, str, str]] = []  # (id, state, name)
    lines = [l for l in out.splitlines() if l.strip()]
    i = 0
    while i + 1 < len(lines):
        if lines[i + 1].lstrip().startswith('VM,'):
            parts = [p.strip() for p in lines[i + 1].split(',')]
            if len(parts) >= 4:
                vms.append((parts[2], parts[1], parts[3] or lines[i].strip()))
            i += 2
        else:
            i += 1
    running = [v for v in vms if v[1] == 'Running']

    if vm:
        ql = vm.lower()
        matched = [v for v in running if v[0].lower() == ql or v[2].lower() == ql]
        if not matched:
            if not quiet:
                print(f'no running VM matched "{vm}". running:', file=sys.stderr)
                for v in running:
                    print(f'  {v[0]}  {v[2]}', file=sys.stderr)
            return None
        target = matched[0]
    elif len(running) == 1:
        target = running[0]
    else:
        if not quiet:
            print('multiple running VMs, specify by name or id:', file=sys.stderr)
            for v in running:
                print(f'  {v[0]}  {v[2]}', file=sys.stderr)
        return None

    out2 = subprocess.run(
        ['powershell', '-NoProfile', '-Command',
         "Get-CimInstance Win32_Process -Filter \"Name='vmwp.exe'\" | "
         'ForEach-Object { "$($_.ProcessId)|$($_.CommandLine)" }'],
        capture_output=True, text=True, check=False).stdout
    for line in out2.splitlines():
        if '|' in line:
            pid_str, cmdline = line.split('|', 1)
            if target[0].lower() in cmdline.lower():
                return int(pid_str), target[0]
    if not quiet:
        print(f'no vmwp.exe matched VM {target[0]}', file=sys.stderr)
    return None


@dataclass
class _Session:
    address: int
    session_id: int
    is_admin: int


def _find_vmusrv_base(hp: int) -> int | None:
    needed = wt.DWORD(0)
    psa.EnumProcessModulesEx(hp, None, 0, ctypes.byref(needed), LIST_MODULES_64BIT)
    if not needed.value:
        return None
    arr = (wt.HMODULE * (needed.value // ctypes.sizeof(wt.HMODULE)))()
    if not psa.EnumProcessModulesEx(hp, arr, ctypes.sizeof(arr), ctypes.byref(needed), LIST_MODULES_64BIT):
        return None
    nb = ctypes.create_unicode_buffer(260)
    for i in range(len(arr)):
        if arr[i] and psa.GetModuleBaseNameW(hp, arr[i], nb, 260) and nb.value.lower() == 'vmusrv.dll':
            mi = _MODULEINFO()
            if psa.GetModuleInformation(hp, arr[i], ctypes.byref(mi), ctypes.sizeof(mi)):
                return mi.lpBaseOfDll
    return None


def _rpm(hp: int, addr: int, size: int) -> bytes | None:
    buf = (ctypes.c_ubyte * size)()
    rd = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(hp, addr, buf, size, ctypes.byref(rd)):
        return None
    return bytes(buf[:rd.value])


def _walk_sessions(hp: int, base: int) -> list[_Session] | None:
    raw = _rpm(hp, base + VMUSRV_SRV_SESSION_TABLE_RVA, 8)
    if not raw:
        return None
    table = struct.unpack('<Q', raw)[0]
    if not table:
        return []

    raw = _rpm(hp, table + RFS_SESSION_ARRAY_OFFSET, 0x80)
    if not raw:
        return None
    array = struct.unpack_from('<Q', raw, 0)[0]
    high  = struct.unpack_from('<I', raw, RFS_HIGH_WATER_OFFSET - RFS_SESSION_ARRAY_OFFSET)[0]
    cap   = struct.unpack_from('<I', raw, RFS_CAPACITY_OFFSET   - RFS_SESSION_ARRAY_OFFSET)[0]
    bound = min(high, cap) if cap else high
    if not 0 < bound <= 0x10000:
        return None

    raw = _rpm(hp, array, bound * 8)
    if not raw:
        return None

    sessions: list[_Session] = []
    for i in range(bound):
        sa = struct.unpack_from('<Q', raw, i * 8)[0]
        if not (0x10000 <= sa <= 0x7fffffffffff):
            continue
        if 0x00007ff000000000 <= sa <= 0x00007fffffffffff:
            continue  # module image range — never a heap session pointer
        sd = _rpm(hp, sa, 0x70)
        if not sd or len(sd) < 0x70:
            continue
        state = struct.unpack_from('<I', sd, SESSION_STATE_OFFSET)[0]
        if state not in (SESSION_STATE_INIT, SESSION_STATE_CLOSED):
            continue
        is_admin = sd[SESSION_ISADMIN_OFFSET]
        if is_admin not in (0, 1):
            continue
        sessions.append(_Session(sa, struct.unpack_from('<Q', sd, SESSION_SESSION_ID_OFFSET)[0], is_admin))
    return sessions


def _flip(hp: int, sess: _Session) -> bool:
    written = ctypes.c_size_t(0)
    one = (ctypes.c_ubyte * 1)(1)
    if not k32.WriteProcessMemory(hp, sess.address + SESSION_ISADMIN_OFFSET, one, 1, ctypes.byref(written)):
        return False
    return _rpm(hp, sess.address + SESSION_ISADMIN_OFFSET, 1) == b'\x01'


def _wait_for_session(vm: str | None, timeout: int) -> tuple[int, str] | None:
    import time as _time
    deadline = _time.monotonic() + timeout
    print(f'waiting up to {timeout}s for VM + VSMB session...', flush=True)
    pid = None
    vm_id = None
    while _time.monotonic() < deadline:
        r = _find_vmwp_pid(vm, quiet=True)
        if r is not None:
            pid, vm_id = r
            hp = k32.OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                False, pid)
            if hp:
                base = _find_vmusrv_base(hp)
                if base:
                    sessions = _walk_sessions(hp, base)
                    if sessions:
                        k32.CloseHandle(hp)
                        return pid, vm_id
                k32.CloseHandle(hp)
        _time.sleep(3)
    what = 'VSMB session' if pid else 'VM'
    print(f'timeout: no {what} after {timeout}s', file=sys.stderr)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('vm', nargs='?', help='VM name or UUID (auto-discovers vmwp.exe)')
    ap.add_argument('--pid', type=int, help='Explicit vmwp.exe PID')
    ap.add_argument('--list', action='store_true', help='List sessions and exit, do not write')
    ap.add_argument('--wait', nargs='?', type=int, const=300, default=None,
                    metavar='SECONDS',
                    help='Wait for VM and VSMB session to appear (default: 300s)')
    args = ap.parse_args()

    if not _enable_se_debug():
        return 1

    if args.pid:
        pid, vm = args.pid, '(explicit pid)'
    elif args.wait is not None:
        r = _wait_for_session(args.vm, args.wait)
        if r is None:
            return 1
        pid, vm = r
    else:
        r = _find_vmwp_pid(args.vm)
        if r is None:
            return 1
        pid, vm = r
    print(f'target: vmwp.exe pid={pid} (VM={vm})')

    hp = k32.OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        False, pid)
    if not hp:
        print(_winerr(f'OpenProcess pid={pid}'), file=sys.stderr)
        return 1
    try:
        base = _find_vmusrv_base(hp)
        if not base:
            print('vmusrv.dll not loaded in target', file=sys.stderr)
            return 1

        sessions = _walk_sessions(hp, base)
        if sessions is None:
            print('walk_sessions failed', file=sys.stderr)
            return 1
        if not sessions:
            print('no SMB2 sessions in vmusrv (mount a VSMB share first)')
            return 0

        for s in sessions:
            print(f'  session 0x{s.address:016x}  SessionId=0x{s.session_id:x}  '
                  f'IsAdmin={s.is_admin}')
        if args.list:
            return 0

        flipped = sum(1 for s in sessions if not s.is_admin and _flip(hp, s))
        print(f'flipped {flipped}/{sum(1 for s in sessions if not s.is_admin)} '
              f'session(s) to IsAdmin=1')
        return 0
    finally:
        k32.CloseHandle(hp)


if __name__ == '__main__':
    sys.exit(main())
