"""User-mode client for the CnCProcExp process-explorer driver.

The driver (proc_explorer/cncprocexp.sys) is the privileged core: it enumerates
processes, threads and handles from the kernel and can force-terminate a
process. Everything the driver does not provide -- full image paths, the owning
user, loaded modules, suspend/resume -- is filled in from user mode, and if the
driver is not loaded the process/thread queries fall back to Toolhelp so the UI
still works (with less detail). This mirrors how Sysinternals Process Explorer
splits work between its helper driver and user mode.
"""

import ctypes
import datetime
import struct
import sys
from ctypes import wintypes
from dataclasses import dataclass, field

PROCEXP_DEVICE_TYPE = 0x8005
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MORE_DATA = 234

PROCEXP_VERSION = 1
PROCEXP_MAX_NAME = 260
PROCEXP_MAX_TYPE_NAME = 64

DEVICE_PATH = r"\\.\CnCProcExp"


def ctl_code(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method


IOCTL_PROCEXP_QUERY_PROCESSES = ctl_code(PROCEXP_DEVICE_TYPE, 0xA01, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_PROCEXP_QUERY_THREADS = ctl_code(PROCEXP_DEVICE_TYPE, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_PROCEXP_QUERY_HANDLES = ctl_code(PROCEXP_DEVICE_TYPE, 0xA03, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_PROCEXP_KILL_PROCESS = ctl_code(PROCEXP_DEVICE_TYPE, 0xA04, METHOD_BUFFERED, FILE_ANY_ACCESS)

# Layouts mirror procexpuser.h exactly (widest field first, no padding).
PID_REQUEST_STRUCT = struct.Struct("<II")
LIST_HEADER_STRUCT = struct.Struct("<II")
PROCESS_STRUCT = struct.Struct(f"<5Q5Ii{PROCEXP_MAX_NAME}H")
THREAD_STRUCT = struct.Struct("<4QIIiiIIII")
HANDLE_STRUCT = struct.Struct(f"<Q4I{PROCEXP_MAX_TYPE_NAME}H{PROCEXP_MAX_NAME}H")


def _decode_wchar(values):
    chars = []
    for value in values:
        if value == 0:
            break
        chars.append(chr(value))
    return "".join(chars)


def filetime_to_text(timestamp):
    """Render a FILETIME (100ns ticks since 1601) as local wall-clock time."""
    if not timestamp:
        return "-"
    try:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        when = epoch + datetime.timedelta(microseconds=timestamp / 10)
        return when.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return str(timestamp)


THREAD_STATE_NAMES = {
    0: "Initialized",
    1: "Ready",
    2: "Running",
    3: "Standby",
    4: "Terminated",
    5: "Waiting",
    6: "Transition",
    7: "DeferredReady",
    8: "GateWait",
}


@dataclass
class ProcessInfo:
    process_id: int = 0
    parent_process_id: int = 0
    session_id: int = 0
    thread_count: int = 0
    handle_count: int = 0
    base_priority: int = 0
    create_time: int = 0
    kernel_time: int = 0
    user_time: int = 0
    working_set: int = 0
    virtual_size: int = 0
    image_name: str = ""
    image_path: str = ""
    user_name: str = ""

    @property
    def working_set_mb(self):
        return self.working_set / (1024 * 1024)


@dataclass
class ThreadInfo:
    thread_id: int = 0
    process_id: int = 0
    priority: int = 0
    base_priority: int = 0
    state: int = 0
    wait_reason: int = 0
    start_address: int = 0
    kernel_time: int = 0
    user_time: int = 0
    create_time: int = 0
    context_switches: int = 0

    @property
    def state_text(self):
        return THREAD_STATE_NAMES.get(self.state, f"state-{self.state}")


@dataclass
class HandleInfo:
    handle_value: int = 0
    granted_access: int = 0
    object_type_index: int = 0
    object_address: int = 0
    type_name: str = ""
    name: str = ""


@dataclass
class ModuleInfo:
    base_address: int = 0
    size: int = 0
    name: str = ""
    path: str = ""


# --- Win32 / NT plumbing -------------------------------------------------

_is_windows = sys.platform == "win32"

if _is_windows:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.DeviceIoControl.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    kernel32.DeviceIoControl.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wintypes.BOOL

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p

    ntdll.NtSuspendProcess.argtypes = [ctypes.c_void_p]
    ntdll.NtSuspendProcess.restype = ctypes.c_long
    ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
    ntdll.NtResumeProcess.restype = ctypes.c_long

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

PROCESS_TERMINATE = 0x0001
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
TOKEN_QUERY = 0x0008


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


if _is_windows:
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.Thread32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.Module32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = wintypes.BOOL


def _open_process(access, pid):
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        return None
    return handle


_path_cache = {}


def get_image_path(pid):
    """Full image path for a pid, or "" if it cannot be read (cached per pid)."""
    if not _is_windows or pid <= 4:
        return ""
    if pid in _path_cache:
        return _path_cache[pid]

    result = ""
    handle = _open_process(PROCESS_QUERY_LIMITED_INFORMATION, pid)
    if handle is not None:
        try:
            size = wintypes.DWORD(PROCEXP_MAX_NAME * 4)
            buffer = ctypes.create_unicode_buffer(size.value)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                result = buffer.value
        finally:
            kernel32.CloseHandle(handle)

    _path_cache[pid] = result
    return result


_user_cache = {}


def get_user_name(pid):
    """Best-effort DOMAIN\\user that owns the process (cached per pid)."""
    if not _is_windows or pid <= 4:
        return ""
    if pid in _user_cache:
        return _user_cache[pid]

    result = ""
    handle = _open_process(PROCESS_QUERY_LIMITED_INFORMATION, pid)
    if handle is None:
        handle = _open_process(PROCESS_QUERY_INFORMATION, pid)
    if handle is not None:
        try:
            token = ctypes.c_void_p()
            if advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token)):
                try:
                    result = _token_user_name(token)
                finally:
                    kernel32.CloseHandle(token)
        finally:
            kernel32.CloseHandle(handle)

    _user_cache[pid] = result
    return result


def _token_user_name(token):
    length = wintypes.DWORD(0)
    advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))  # TokenUser = 1
    if length.value == 0:
        return ""
    buffer = ctypes.create_string_buffer(length.value)
    if not advapi32.GetTokenInformation(token, 1, buffer, length, ctypes.byref(length)):
        return ""

    # TOKEN_USER { SID_AND_ATTRIBUTES User { PSID Sid; DWORD Attributes; } }
    sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
    name = ctypes.create_unicode_buffer(256)
    domain = ctypes.create_unicode_buffer(256)
    name_len = wintypes.DWORD(256)
    domain_len = wintypes.DWORD(256)
    use = wintypes.DWORD(0)
    if advapi32.LookupAccountSidW(
        None, sid, name, ctypes.byref(name_len), domain, ctypes.byref(domain_len), ctypes.byref(use)
    ):
        if domain.value:
            return f"{domain.value}\\{name.value}"
        return name.value
    return ""


if _is_windows:
    advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.LookupAccountSidW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.LookupAccountSidW.restype = wintypes.BOOL


class ProcExpClient:
    def __init__(self, device_path=DEVICE_PATH):
        self.device_path = device_path
        self.available = _is_windows

    # --- driver transport ------------------------------------------------

    def _open(self):
        handle = kernel32.CreateFileW(
            self.device_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def driver_loaded(self):
        """True when the control device can be opened."""
        if not _is_windows:
            return False
        try:
            handle = self._open()
        except OSError:
            return False
        kernel32.CloseHandle(handle)
        return True

    def _ioctl(self, control_code, in_buffer=b"", out_size=0):
        handle = self._open()
        try:
            bytes_returned = wintypes.DWORD(0)
            input_buffer = ctypes.create_string_buffer(in_buffer) if in_buffer else None
            output_buffer = ctypes.create_string_buffer(out_size) if out_size else None
            ok = kernel32.DeviceIoControl(
                handle, control_code,
                input_buffer, len(in_buffer) if in_buffer else 0,
                output_buffer, out_size,
                ctypes.byref(bytes_returned), None,
            )
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
            if not output_buffer:
                return b""
            return bytes(output_buffer.raw[: bytes_returned.value])
        finally:
            kernel32.CloseHandle(handle)

    def _ioctl_grow(self, control_code, in_buffer=b"", initial=0x40000):
        """Call an IOCTL that reports a required size on ERROR_INSUFFICIENT_BUFFER."""
        handle = self._open()
        try:
            size = initial
            for _ in range(8):
                bytes_returned = wintypes.DWORD(0)
                input_buffer = ctypes.create_string_buffer(in_buffer) if in_buffer else None
                output_buffer = ctypes.create_string_buffer(size)
                ok = kernel32.DeviceIoControl(
                    handle, control_code,
                    input_buffer, len(in_buffer) if in_buffer else 0,
                    output_buffer, size,
                    ctypes.byref(bytes_returned), None,
                )
                if ok:
                    return bytes(output_buffer.raw[: bytes_returned.value])
                err = ctypes.get_last_error()
                if err in (ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA):
                    needed = bytes_returned.value
                    size = max(needed + 0x10000, size * 2)
                    continue
                raise ctypes.WinError(err)
            raise OSError("driver output did not fit after repeated growth")
        finally:
            kernel32.CloseHandle(handle)

    # --- high-level queries ---------------------------------------------

    def query_processes(self):
        if _is_windows and self.driver_loaded():
            try:
                return self._decorate(self._query_processes_driver())
            except OSError:
                pass
        return self._decorate(_query_processes_toolhelp())

    def _query_processes_driver(self):
        output = self._ioctl_grow(IOCTL_PROCEXP_QUERY_PROCESSES)
        version, count = LIST_HEADER_STRUCT.unpack_from(output, 0)
        if version != PROCEXP_VERSION:
            raise OSError(f"unsupported process version: {version}")
        items = []
        offset = LIST_HEADER_STRUCT.size
        for _ in range(count):
            chunk = output[offset: offset + PROCESS_STRUCT.size]
            if len(chunk) < PROCESS_STRUCT.size:
                break
            fields = PROCESS_STRUCT.unpack(chunk)
            items.append(ProcessInfo(
                create_time=fields[0], kernel_time=fields[1], user_time=fields[2],
                working_set=fields[3], virtual_size=fields[4],
                process_id=fields[5], parent_process_id=fields[6], session_id=fields[7],
                thread_count=fields[8], handle_count=fields[9], base_priority=fields[10],
                image_name=_decode_wchar(fields[11:11 + PROCEXP_MAX_NAME]),
            ))
            offset += PROCESS_STRUCT.size
        return items

    def _decorate(self, processes):
        for info in processes:
            if not info.image_path:
                info.image_path = get_image_path(info.process_id)
            if not info.user_name:
                info.user_name = get_user_name(info.process_id)
        return processes

    def query_threads(self, pid):
        if _is_windows and self.driver_loaded():
            try:
                return self._query_threads_driver(pid)
            except OSError:
                pass
        return _query_threads_toolhelp(pid)

    def _query_threads_driver(self, pid):
        request = PID_REQUEST_STRUCT.pack(PROCEXP_VERSION, int(pid))
        output = self._ioctl_grow(IOCTL_PROCEXP_QUERY_THREADS, request, initial=0x20000)
        version, count = LIST_HEADER_STRUCT.unpack_from(output, 0)
        if version != PROCEXP_VERSION:
            raise OSError(f"unsupported thread version: {version}")
        items = []
        offset = LIST_HEADER_STRUCT.size
        for _ in range(count):
            chunk = output[offset: offset + THREAD_STRUCT.size]
            if len(chunk) < THREAD_STRUCT.size:
                break
            f = THREAD_STRUCT.unpack(chunk)
            items.append(ThreadInfo(
                start_address=f[0], kernel_time=f[1], user_time=f[2], create_time=f[3],
                thread_id=f[4], process_id=f[5], priority=f[6], base_priority=f[7],
                state=f[8], wait_reason=f[9], context_switches=f[10],
            ))
            offset += THREAD_STRUCT.size
        return items

    def query_handles(self, pid):
        """Handle enumeration is driver-only (empty list without the driver)."""
        if not (_is_windows and self.driver_loaded()):
            return []
        try:
            request = PID_REQUEST_STRUCT.pack(PROCEXP_VERSION, int(pid))
            output = self._ioctl_grow(IOCTL_PROCEXP_QUERY_HANDLES, request, initial=0x40000)
        except OSError:
            return []
        version, count = LIST_HEADER_STRUCT.unpack_from(output, 0)
        if version != PROCEXP_VERSION:
            raise OSError(f"unsupported handle version: {version}")
        items = []
        offset = LIST_HEADER_STRUCT.size
        for _ in range(count):
            chunk = output[offset: offset + HANDLE_STRUCT.size]
            if len(chunk) < HANDLE_STRUCT.size:
                break
            f = HANDLE_STRUCT.unpack(chunk)
            type_start = 5
            name_start = type_start + PROCEXP_MAX_TYPE_NAME
            items.append(HandleInfo(
                object_address=f[0], handle_value=f[1], granted_access=f[2],
                object_type_index=f[3],
                type_name=_decode_wchar(f[type_start:type_start + PROCEXP_MAX_TYPE_NAME]),
                name=_decode_wchar(f[name_start:name_start + PROCEXP_MAX_NAME]),
            ))
            offset += HANDLE_STRUCT.size
        return items

    def query_modules(self, pid):
        """Loaded modules always come from user mode (Toolhelp)."""
        return _query_modules_toolhelp(pid)

    # --- management ------------------------------------------------------

    def kill_process(self, pid):
        if _is_windows and self.driver_loaded():
            try:
                self._ioctl(IOCTL_PROCEXP_KILL_PROCESS, PID_REQUEST_STRUCT.pack(PROCEXP_VERSION, int(pid)))
                return
            except OSError:
                pass
        _kill_process_usermode(pid)

    def suspend_process(self, pid):
        _suspend_resume(pid, ntdll.NtSuspendProcess if _is_windows else None)

    def resume_process(self, pid):
        _suspend_resume(pid, ntdll.NtResumeProcess if _is_windows else None)


# --- user-mode fallbacks -------------------------------------------------


def _snapshot(flags, pid=0):
    handle = kernel32.CreateToolhelp32Snapshot(flags, pid)
    if handle == INVALID_HANDLE_VALUE or handle is None:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def _query_processes_toolhelp():
    if not _is_windows:
        return []
    handle = _snapshot(TH32CS_SNAPPROCESS)
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        items = []
        ok = kernel32.Process32FirstW(handle, ctypes.byref(entry))
        while ok:
            items.append(ProcessInfo(
                process_id=entry.th32ProcessID,
                parent_process_id=entry.th32ParentProcessID,
                thread_count=entry.cntThreads,
                base_priority=entry.pcPriClassBase,
                image_name=entry.szExeFile,
            ))
            ok = kernel32.Process32NextW(handle, ctypes.byref(entry))
        return items
    finally:
        kernel32.CloseHandle(handle)


def _query_threads_toolhelp(pid):
    if not _is_windows:
        return []
    handle = _snapshot(TH32CS_SNAPTHREAD)
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        items = []
        ok = kernel32.Thread32First(handle, ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID == pid:
                items.append(ThreadInfo(
                    thread_id=entry.th32ThreadID,
                    process_id=entry.th32OwnerProcessID,
                    base_priority=entry.tpBasePri,
                    priority=entry.tpBasePri + entry.tpDeltaPri,
                ))
            ok = kernel32.Thread32Next(handle, ctypes.byref(entry))
        return items
    finally:
        kernel32.CloseHandle(handle)


def _query_modules_toolhelp(pid):
    if not _is_windows or pid <= 4:
        return []
    try:
        handle = _snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    except OSError:
        return []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        items = []
        ok = kernel32.Module32FirstW(handle, ctypes.byref(entry))
        while ok:
            items.append(ModuleInfo(
                base_address=entry.modBaseAddr or 0,
                size=entry.modBaseSize,
                name=entry.szModule,
                path=entry.szExePath,
            ))
            ok = kernel32.Module32NextW(handle, ctypes.byref(entry))
        return items
    finally:
        kernel32.CloseHandle(handle)


def _kill_process_usermode(pid):
    if not _is_windows:
        raise OSError("process management is only available on Windows")
    handle = _open_process(PROCESS_TERMINATE, pid)
    if handle is None:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not kernel32.TerminateProcess(handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(handle)


def _suspend_resume(pid, routine):
    if not _is_windows or routine is None:
        raise OSError("process suspend/resume is only available on Windows")
    handle = _open_process(PROCESS_SUSPEND_RESUME, pid)
    if handle is None:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        status = routine(handle)
        if status < 0:
            raise OSError(f"NT status 0x{status & 0xFFFFFFFF:08X}")
    finally:
        kernel32.CloseHandle(handle)
