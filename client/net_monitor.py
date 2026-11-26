"""User-mode client for the CnCrypt network monitor (a TCPView-style tool).

Two independent capabilities live here, mirroring how the module is split
between user mode and the kernel driver:

* Connection *viewing* -- the ``NetworkTable`` helpers snapshot the live TCP and
  UDP tables (IPv4 and IPv6) together with the owning PID through the IP Helper
  API (``GetExtendedTcpTable`` / ``GetExtendedUdpTable``), and can force-close an
  IPv4 TCP connection with ``SetTcpEntry``. None of this needs the driver -- this
  is exactly how the real Sysinternals TCPView works.

* Connection *blocking* -- ``NetMonClient`` talks to the cncnetmon WFP driver
  over its control device to install / remove block rules (by remote address,
  port, protocol and direction). This is the privileged "网络管控" backend.

The rule layouts mirror net_monitor/netmonuser.h byte-for-byte.
"""

import ctypes
import socket
import struct
import sys
from ctypes import wintypes
from dataclasses import dataclass

# --- constants -----------------------------------------------------------

_is_windows = sys.platform == "win32"

AF_INET = 2
AF_INET6 = 23

TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1

MIB_TCP_STATE_DELETE_TCB = 12

ERROR_INSUFFICIENT_BUFFER = 122
NO_ERROR = 0

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

TH32CS_SNAPPROCESS = 0x00000002

# Driver protocol (netmonuser.h) --------------------------------------------

NETMON_DEVICE_TYPE = 0x8007
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

NETMON_VERSION = 1

NETMON_PROTO_ANY = 0
NETMON_PROTO_TCP = 6
NETMON_PROTO_UDP = 17

NETMON_DIR_OUTBOUND = 0
NETMON_DIR_INBOUND = 1
NETMON_DIR_ANY = 2

NETMON_AF_INET = 4
NETMON_AF_INET6 = 6

NETMON_MAX_RULES = 256

DEVICE_PATH = r"\\.\CnCNetMon"


def ctl_code(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method


IOCTL_NETMON_ADD_RULE = ctl_code(NETMON_DEVICE_TYPE, 0xA01, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_NETMON_DELETE_RULE = ctl_code(NETMON_DEVICE_TYPE, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_NETMON_CLEAR_RULES = ctl_code(NETMON_DEVICE_TYPE, 0xA03, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_NETMON_LIST_RULES = ctl_code(NETMON_DEVICE_TYPE, 0xA04, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_NETMON_GET_STATS = ctl_code(NETMON_DEVICE_TYPE, 0xA05, METHOD_BUFFERED, FILE_ANY_ACCESS)

# RuleId, Enabled, RemotePort, Reserved, Protocol, Direction, AddressFamily, PrefixLength, RemoteAddress[16]
RULE_STRUCT = struct.Struct("<IIHHBBBB16s")
RULE_ID_STRUCT = struct.Struct("<II")
LIST_HEADER_STRUCT = struct.Struct("<II")
STATS_STRUCT = struct.Struct("<IIII")

# TCP connection states (MIB_TCP_STATE).
TCP_STATE_NAMES = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN-SENT",
    4: "SYN-RCVD",
    5: "ESTABLISHED",
    6: "FIN-WAIT1",
    7: "FIN-WAIT2",
    8: "CLOSE-WAIT",
    9: "CLOSING",
    10: "LAST-ACK",
    11: "TIME-WAIT",
    12: "DELETE-TCB",
}


# --- data models ---------------------------------------------------------


@dataclass
class Connection:
    protocol: str = ""          # TCP / TCP6 / UDP / UDP6
    family: int = 4             # 4 or 6
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    state: str = ""             # "" for UDP
    pid: int = 0
    process: str = ""

    @property
    def is_tcp(self):
        return self.protocol.startswith("TCP")

    @property
    def local_endpoint(self):
        return _format_endpoint(self.local_addr, self.local_port, self.family)

    @property
    def remote_endpoint(self):
        if not self.remote_addr or (self.remote_port == 0 and not self.is_tcp):
            return "-"
        return _format_endpoint(self.remote_addr, self.remote_port, self.family)


@dataclass
class BlockRule:
    rule_id: int = 0
    enabled: int = 1
    remote_port: int = 0        # 0 = any
    protocol: int = NETMON_PROTO_ANY
    direction: int = NETMON_DIR_OUTBOUND
    address_family: int = NETMON_AF_INET
    prefix_length: int = 0      # 0 = any address
    remote_address: str = ""    # textual IP; "" = any

    def pack(self):
        af = NETMON_AF_INET6 if self.address_family == NETMON_AF_INET6 else NETMON_AF_INET
        raw = _pack_address(self.remote_address, af)
        return RULE_STRUCT.pack(
            self.rule_id, self.enabled, self.remote_port & 0xFFFF, 0,
            self.protocol & 0xFF, self.direction & 0xFF, af & 0xFF, self.prefix_length & 0xFF,
            raw,
        )

    @classmethod
    def unpack(cls, chunk):
        (rule_id, enabled, remote_port, _reserved, protocol, direction,
         address_family, prefix_length, raw) = RULE_STRUCT.unpack(chunk)
        return cls(
            rule_id=rule_id, enabled=enabled, remote_port=remote_port,
            protocol=protocol, direction=direction, address_family=address_family,
            prefix_length=prefix_length,
            remote_address=_unpack_address(raw, address_family, prefix_length),
        )

    @property
    def protocol_text(self):
        return {NETMON_PROTO_TCP: "TCP", NETMON_PROTO_UDP: "UDP"}.get(self.protocol, "ANY")

    @property
    def direction_text(self):
        return {NETMON_DIR_OUTBOUND: "outbound", NETMON_DIR_INBOUND: "inbound"}.get(
            self.direction, "any"
        )

    @property
    def target_text(self):
        is_v6 = self.address_family == NETMON_AF_INET6
        if self.prefix_length == 0 or not self.remote_address:
            addr = "any"
        else:
            bits = 128 if is_v6 else 32
            addr = self.remote_address if self.prefix_length >= bits else f"{self.remote_address}/{self.prefix_length}"
            if is_v6:
                addr = f"[{addr}]"
        port = "any" if self.remote_port == 0 else str(self.remote_port)
        return f"{addr}:{port}"


# --- address helpers -----------------------------------------------------


def _format_endpoint(addr, port, family):
    if family == 6 and addr:
        return f"[{addr}]:{port}"
    return f"{addr}:{port}"


def _pack_address(text, family):
    if not text:
        return b"\x00" * 16
    try:
        if family == NETMON_AF_INET6:
            return socket.inet_pton(socket.AF_INET6, text)
        return socket.inet_aton(text) + b"\x00" * 12
    except OSError:
        return b"\x00" * 16


def _unpack_address(raw, family, prefix_length):
    if prefix_length == 0:
        return ""
    try:
        if family == NETMON_AF_INET6:
            return socket.inet_ntop(socket.AF_INET6, raw[:16])
        return socket.inet_ntoa(raw[:4])
    except OSError:
        return ""


def _v4_addr(dword):
    return socket.inet_ntoa(struct.pack("<L", dword & 0xFFFFFFFF))


def _v6_addr(raw16):
    try:
        return socket.inet_ntop(socket.AF_INET6, bytes(raw16))
    except (OSError, ValueError):
        return ":".join(f"{b:02x}" for b in bytes(raw16))


def _port(dword):
    return socket.ntohs(dword & 0xFFFF)


# --- Win32 plumbing ------------------------------------------------------

if _is_windows:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

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

    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p

    iphlpapi.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
    ]
    iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD
    iphlpapi.GetExtendedUdpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
    ]
    iphlpapi.GetExtendedUdpTable.restype = wintypes.DWORD


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


if _is_windows:
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL

    # MIB_TCPROW for SetTcpEntry (IPv4 close).
    class MIB_TCPROW(ctypes.Structure):
        _fields_ = [
            ("dwState", wintypes.DWORD),
            ("dwLocalAddr", wintypes.DWORD),
            ("dwLocalPort", wintypes.DWORD),
            ("dwRemoteAddr", wintypes.DWORD),
            ("dwRemotePort", wintypes.DWORD),
        ]

    iphlpapi.SetTcpEntry.argtypes = [ctypes.POINTER(MIB_TCPROW)]
    iphlpapi.SetTcpEntry.restype = wintypes.DWORD


def _process_names():
    """Map pid -> image file name via Toolhelp (best effort, empty off-Windows)."""
    if not _is_windows:
        return {}
    handle = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if handle == INVALID_HANDLE_VALUE or handle is None:
        return {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        names = {}
        ok = kernel32.Process32FirstW(handle, ctypes.byref(entry))
        while ok:
            names[entry.th32ProcessID] = entry.szExeFile
            ok = kernel32.Process32NextW(handle, ctypes.byref(entry))
        return names
    finally:
        kernel32.CloseHandle(handle)


# --- connection enumeration ----------------------------------------------


def _get_extended_table(func, family, table_class):
    """Call a GetExtended*Table function with buffer growth; return raw bytes."""
    size = wintypes.DWORD(0)
    func(None, ctypes.byref(size), False, family, table_class, 0)
    for _ in range(6):
        if size.value == 0:
            return b""
        buffer = ctypes.create_string_buffer(size.value)
        rc = func(buffer, ctypes.byref(size), False, family, table_class, 0)
        if rc == NO_ERROR:
            return buffer.raw[: size.value]
        if rc == ERROR_INSUFFICIENT_BUFFER:
            continue
        raise ctypes.WinError(rc)
    raise OSError("network table did not fit after repeated growth")


def _parse_tcp4(raw):
    if len(raw) < 4:
        return []
    (count,) = struct.unpack_from("<I", raw, 0)
    rows = []
    offset = 4
    row_pid = struct.Struct("<6I")  # state, localAddr, localPort, remoteAddr, remotePort, owningPid
    for _ in range(count):
        if offset + row_pid.size > len(raw):
            break
        state, laddr, lport, raddr, rport, pid = row_pid.unpack_from(raw, offset)
        rows.append(Connection(
            protocol="TCP", family=4,
            local_addr=_v4_addr(laddr), local_port=_port(lport),
            remote_addr=_v4_addr(raddr), remote_port=_port(rport),
            state=TCP_STATE_NAMES.get(state, f"state-{state}"), pid=pid,
        ))
        offset += row_pid.size
    return rows


def _parse_tcp6(raw):
    if len(raw) < 4:
        return []
    (count,) = struct.unpack_from("<I", raw, 0)
    rows = []
    offset = 4
    # ucLocalAddr[16], dwLocalScopeId, dwLocalPort, ucRemoteAddr[16], dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid
    row = struct.Struct("<16sII16sIIII")
    for _ in range(count):
        if offset + row.size > len(raw):
            break
        laddr, _lscope, lport, raddr, _rscope, rport, state, pid = row.unpack_from(raw, offset)
        rows.append(Connection(
            protocol="TCP6", family=6,
            local_addr=_v6_addr(laddr), local_port=_port(lport),
            remote_addr=_v6_addr(raddr), remote_port=_port(rport),
            state=TCP_STATE_NAMES.get(state, f"state-{state}"), pid=pid,
        ))
        offset += row.size
    return rows


def _parse_udp4(raw):
    if len(raw) < 4:
        return []
    (count,) = struct.unpack_from("<I", raw, 0)
    rows = []
    offset = 4
    row = struct.Struct("<3I")  # localAddr, localPort, owningPid
    for _ in range(count):
        if offset + row.size > len(raw):
            break
        laddr, lport, pid = row.unpack_from(raw, offset)
        rows.append(Connection(
            protocol="UDP", family=4,
            local_addr=_v4_addr(laddr), local_port=_port(lport),
            remote_addr="", remote_port=0, state="", pid=pid,
        ))
        offset += row.size
    return rows


def _parse_udp6(raw):
    if len(raw) < 4:
        return []
    (count,) = struct.unpack_from("<I", raw, 0)
    rows = []
    offset = 4
    row = struct.Struct("<16sIII")  # ucLocalAddr[16], dwLocalScopeId, dwLocalPort, dwOwningPid
    for _ in range(count):
        if offset + row.size > len(raw):
            break
        laddr, _lscope, lport, pid = row.unpack_from(raw, offset)
        rows.append(Connection(
            protocol="UDP6", family=6,
            local_addr=_v6_addr(laddr), local_port=_port(lport),
            remote_addr="", remote_port=0, state="", pid=pid,
        ))
        offset += row.size
    return rows


def list_connections(include_tcp=True, include_udp=True):
    """Snapshot all TCP/UDP endpoints (v4 + v6) with owning process name."""
    if not _is_windows:
        return []

    connections = []
    if include_tcp:
        connections += _parse_tcp4(_get_extended_table(iphlpapi.GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL))
        connections += _parse_tcp6(_get_extended_table(iphlpapi.GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL))
    if include_udp:
        connections += _parse_udp4(_get_extended_table(iphlpapi.GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID))
        connections += _parse_udp6(_get_extended_table(iphlpapi.GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID))

    names = _process_names()
    for connection in connections:
        connection.process = names.get(connection.pid, "" if connection.pid else "System Idle")
    return connections


def close_connection(connection):
    """Force-close an established IPv4 TCP connection (SetTcpEntry, admin only)."""
    if not _is_windows:
        raise OSError("closing connections is only available on Windows")
    if connection.protocol != "TCP":
        raise OSError("only IPv4 TCP connections can be closed")

    row = MIB_TCPROW()
    row.dwState = MIB_TCP_STATE_DELETE_TCB
    row.dwLocalAddr = struct.unpack("<L", socket.inet_aton(connection.local_addr))[0]
    row.dwLocalPort = socket.htons(connection.local_port) & 0xFFFF
    row.dwRemoteAddr = struct.unpack("<L", socket.inet_aton(connection.remote_addr))[0]
    row.dwRemotePort = socket.htons(connection.remote_port) & 0xFFFF

    rc = iphlpapi.SetTcpEntry(ctypes.byref(row))
    if rc != NO_ERROR:
        raise ctypes.WinError(rc)


_dns_cache = {}


def resolve_host(addr):
    """Best-effort reverse DNS for an address, cached. Returns "" on failure."""
    if not addr or addr in ("0.0.0.0", "::"):
        return ""
    if addr in _dns_cache:
        return _dns_cache[addr]
    result = ""
    try:
        result = socket.gethostbyaddr(addr)[0]
    except (OSError, socket.herror, socket.gaierror):
        result = ""
    _dns_cache[addr] = result
    return result


# --- driver rule client --------------------------------------------------


class NetMonClient:
    """Manage cncnetmon block rules over the driver's control device."""

    def __init__(self, device_path=DEVICE_PATH):
        self.device_path = device_path
        self.available = _is_windows

    def _open(self):
        handle = kernel32.CreateFileW(
            self.device_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None,
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def driver_loaded(self):
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

    def add_rule(self, rule: BlockRule):
        output = self._ioctl(IOCTL_NETMON_ADD_RULE, rule.pack(), out_size=RULE_ID_STRUCT.size)
        if len(output) >= RULE_ID_STRUCT.size:
            _version, rule_id = RULE_ID_STRUCT.unpack_from(output, 0)
            return rule_id
        return 0

    def delete_rule(self, rule_id):
        self._ioctl(IOCTL_NETMON_DELETE_RULE, RULE_ID_STRUCT.pack(NETMON_VERSION, int(rule_id)))

    def clear_rules(self):
        self._ioctl(IOCTL_NETMON_CLEAR_RULES)

    def list_rules(self):
        output = self._ioctl(IOCTL_NETMON_LIST_RULES, out_size=LIST_HEADER_STRUCT.size + NETMON_MAX_RULES * RULE_STRUCT.size)
        if len(output) < LIST_HEADER_STRUCT.size:
            return []
        version, count = LIST_HEADER_STRUCT.unpack_from(output, 0)
        if version != NETMON_VERSION:
            raise OSError(f"unsupported rule list version: {version}")
        rules = []
        offset = LIST_HEADER_STRUCT.size
        for _ in range(count):
            chunk = output[offset: offset + RULE_STRUCT.size]
            if len(chunk) < RULE_STRUCT.size:
                break
            rules.append(BlockRule.unpack(chunk))
            offset += RULE_STRUCT.size
        return rules

    def get_stats(self):
        output = self._ioctl(IOCTL_NETMON_GET_STATS, out_size=STATS_STRUCT.size)
        if len(output) < STATS_STRUCT.size:
            return {}
        version, rule_count, engine_ready, _reserved = STATS_STRUCT.unpack_from(output, 0)
        return {"version": version, "rule_count": rule_count, "engine_ready": bool(engine_ready)}
