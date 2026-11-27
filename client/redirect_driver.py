r"""NDISLWF 重定向驱动用户态通信模块（纯 Python，无 GUI 依赖）。

严格对齐 driver/filteruser.h 与 driver/device.c 的 IOCTL 及二进制契约：
  - 设备路径: \\.\NDISLWF
  - IOCTL_FILTER_ADD_REDIRECT_RULE    (function 14): 添加规则 (RuleId=0) 或按 RuleId 原地更新
  - IOCTL_FILTER_DEL_REDIRECT_RULE    (function 15): 按 RuleId 删除规则
  - IOCTL_FILTER_CLEAR_REDIRECT_RULES (function 16): 清空所有规则及 NAT 会话
  - IOCTL_FILTER_LIST_REDIRECT_RULES  (function 17): 查询全部规则（扁平数组，无包头）
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import struct
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

if sys.platform == "win32":
    from ctypes import wintypes

# ---------------------------------------------------------------------------
# Win32 & IOCTL 常量（对应 driver/filteruser.h）
# ---------------------------------------------------------------------------

FILE_DEVICE_PHYSICAL_NETCARD = 0x17
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

DEVICE_PATH = r"\\.\NDISLWF"


def ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    return (device_type << 16) | (access << 14) | (function << 2) | method


IOCTL_FILTER_ADD_REDIRECT_RULE = ctl_code(
    FILE_DEVICE_PHYSICAL_NETCARD, 14, METHOD_BUFFERED, FILE_ANY_ACCESS
)
IOCTL_FILTER_DEL_REDIRECT_RULE = ctl_code(
    FILE_DEVICE_PHYSICAL_NETCARD, 15, METHOD_BUFFERED, FILE_ANY_ACCESS
)
IOCTL_FILTER_CLEAR_REDIRECT_RULES = ctl_code(
    FILE_DEVICE_PHYSICAL_NETCARD, 16, METHOD_BUFFERED, FILE_ANY_ACCESS
)
IOCTL_FILTER_LIST_REDIRECT_RULES = ctl_code(
    FILE_DEVICE_PHYSICAL_NETCARD, 17, METHOD_BUFFERED, FILE_ANY_ACCESS
)

# 驱动枚举与标志位
REDIRECT_AF_IPV4 = 4
REDIRECT_AF_IPV6 = 6

REDIRECT_PROTO_ANY = 0
REDIRECT_PROTO_TCP = 6
REDIRECT_PROTO_UDP = 17

REDIRECT_FLAG_REWRITE_MAC = 0x0001
REDIRECT_FLAG_LOCAL_LOOPBACK = 0x0002

MAX_REDIRECT_RULES = 64

# struct _REDIRECT_RULE (52 bytes, 无隐式填充):
#   offset  0 (4B): ULONG  RuleId         (little-endian)
#   offset  4 (1B): UCHAR  AddressFamily  (4 or 6)
#   offset  5 (1B): UCHAR  Protocol       (0=ANY, 6=TCP, 17=UDP)
#   offset  6 (2B): USHORT Flags          (little-endian)
#   offset  8 (16B): UCHAR OrigIp[16]     (network byte order; IPv4 占前 4B)
#   offset 24 (2B): USHORT OrigPort       (network byte order, 0=任意)
#   offset 26 (2B): USHORT NewPort        (network byte order, 0=保持原端口)
#   offset 28 (16B): UCHAR NewIp[16]      (network byte order; IPv4 占前 4B)
#   offset 44 (6B): UCHAR  NewDstMac[6]
#   offset 50 (2B): UCHAR  Reserved[2]
REDIRECT_RULE_STRUCT = struct.Struct("<LBBH16s2s2s16s6s2s")
REDIRECT_DEL_RULE_STRUCT = struct.Struct("<L")
assert REDIRECT_RULE_STRUCT.size == 52
assert REDIRECT_DEL_RULE_STRUCT.size == 4

ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_NOT_ENOUGH_MEMORY = 8
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NOT_FOUND = 1168
ERROR_NO_SYSTEM_RESOURCES = 1450

_WINERROR_HINTS = {
    ERROR_FILE_NOT_FOUND: "未找到驱动设备 \\\\.\\NDISLWF，请确认驱动已安装并启动",
    ERROR_ACCESS_DENIED: "访问驱动设备被拒绝，请以管理员权限运行程序",
    ERROR_INVALID_PARAMETER: "驱动拒绝了规则参数，请检查 IP、端口、协议或规则 ID",
    ERROR_NOT_FOUND: "驱动中未找到指定的规则 ID",
    ERROR_NOT_ENOUGH_MEMORY: f"驱动规则数已达上限（最多 {MAX_REDIRECT_RULES} 条）或内存不足",
    ERROR_NO_SYSTEM_RESOURCES: f"驱动规则数已达上限（最多 {MAX_REDIRECT_RULES} 条）",
}

_APP_DIR = (
    os.path.dirname(os.path.abspath(sys.executable))
    if getattr(sys, "frozen", False)
    else os.path.dirname(os.path.abspath(__file__))
)
DEFAULT_NAME_STORE_PATH = os.path.join(_APP_DIR, "redirect_rule_names.json")


# ---------------------------------------------------------------------------
# Win32 API 绑定
# ---------------------------------------------------------------------------

_is_windows = sys.platform == "win32"
_kernel32 = None
if _is_windows:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    _kernel32.CreateFileW.restype = ctypes.c_void_p
    _kernel32.DeviceIoControl.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.DeviceIoControl.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = wintypes.BOOL


# ---------------------------------------------------------------------------
# 异常与数据模型
# ---------------------------------------------------------------------------


class DriverError(OSError):
    """驱动通信异常，保留底层 Win32 错误码并附带中文可读说明。"""

    def __init__(self, message: str, winerror: Optional[int] = None):
        super().__init__(message)
        self.winerror = winerror


def _raise_win_error(err_code: int) -> None:
    hint = _WINERROR_HINTS.get(err_code)
    raw = ctypes.WinError(err_code)
    if hint:
        raise DriverError(f"{hint}（WinError {err_code}）", winerror=err_code) from raw
    raise DriverError(f"{raw.strerror or '系统调用失败'}（WinError {err_code}）", winerror=err_code) from raw


@dataclass
class RedirectRule:
    rule_id: int = 0
    name: str = ""
    orig_ip: str = ""
    orig_port: int = 0
    new_ip: str = ""
    new_port: int = 0
    protocol: int = REDIRECT_PROTO_TCP
    address_family: int = 0  # 0 表示由 IP 自动推导；4=IPv4, 6=IPv6
    new_dst_mac: str = ""
    local_loopback: bool = False

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        if self.rule_id > 0:
            return f"规则 #{self.rule_id}"
        return "新规则"

    @property
    def protocol_text(self) -> str:
        if self.protocol == REDIRECT_PROTO_TCP:
            return "TCP"
        if self.protocol == REDIRECT_PROTO_UDP:
            return "UDP"
        if self.protocol == REDIRECT_PROTO_ANY:
            return "TCP,UDP"
        return str(self.protocol)

    @property
    def address_family_text(self) -> str:
        if self.address_family == REDIRECT_AF_IPV6:
            return "IPv6"
        if self.address_family == REDIRECT_AF_IPV4:
            return "IPv4"
        return "Auto"

    @property
    def orig_port_text(self) -> str:
        return "任意 (0)" if self.orig_port == 0 else str(self.orig_port)

    @property
    def new_port_text(self) -> str:
        return "保持原端口 (0)" if self.new_port == 0 else str(self.new_port)

    @property
    def options_text(self) -> str:
        parts = []
        if self.new_dst_mac:
            parts.append(f"MAC={self.new_dst_mac}")
        if self.local_loopback:
            parts.append("本机环回")
        return ", ".join(parts) if parts else "-"


# ---------------------------------------------------------------------------
# 参数校验与二进制编解码
# ---------------------------------------------------------------------------


def parse_mac_address(text: str) -> bytes:
    """解析 MAC 地址（支持 ':' 或 '-' 分隔），返回 6 字节原始数据。"""
    cleaned = (text or "").strip()
    if not cleaned:
        return b""
    sep = ":" if ":" in cleaned else ("-" if "-" in cleaned else "")
    if not sep:
        raise ValueError("MAC 地址格式无效，请使用 xx:xx:xx:xx:xx:xx 或 xx-xx-xx-xx-xx-xx。")
    parts = cleaned.split(sep)
    if len(parts) != 6:
        raise ValueError("MAC 地址必须包含 6 组十六进制字节。")
    raw = bytearray()
    for part in parts:
        if not (1 <= len(part) <= 2):
            raise ValueError(f"无效的 MAC 字节段: {part}")
        try:
            val = int(part, 16)
        except ValueError as err:
            raise ValueError(f"无效的 MAC 十六进制字符: {part}") from err
        if not (0 <= val <= 0xFF):
            raise ValueError(f"MAC 字节值超出范围: {part}")
        raw.append(val)
    return bytes(raw)


def format_mac_address(raw: bytes) -> str:
    if len(raw) != 6:
        return ""
    return ":".join(f"{b:02X}" for b in raw)


def normalize_ip_pair(orig_ip_text: str, new_ip_text: str):
    """校验并规范化源/目标 IP 对，确保同属 IPv4 或同属 IPv6。"""
    try:
        orig_obj = ipaddress.ip_address((orig_ip_text or "").strip())
    except ValueError as err:
        raise ValueError(f"原始目的 IP 无效: {orig_ip_text}") from err

    try:
        new_obj = ipaddress.ip_address((new_ip_text or "").strip())
    except ValueError as err:
        raise ValueError(f"重定向目标 IP 无效: {new_ip_text}") from err

    if orig_obj.version != new_obj.version:
        raise ValueError("原始目的 IP 和重定向目标 IP 必须同为 IPv4 或同为 IPv6。")

    family = REDIRECT_AF_IPV6 if orig_obj.version == 6 else REDIRECT_AF_IPV4
    return orig_obj, new_obj, family


def protocol_from_text(text: str) -> int:
    value = (text or "").strip().lower()
    if value == "tcp":
        return REDIRECT_PROTO_TCP
    if value == "udp":
        return REDIRECT_PROTO_UDP
    if value in ("any", "both", "tcp,udp", "udp,tcp"):
        return REDIRECT_PROTO_ANY
    raise ValueError(f"不支持的协议类型: {text}（仅支持 tcp / udp / any）")


def _pack_ip16(ip_obj) -> bytes:
    packed = ip_obj.packed
    if len(packed) == 4:
        return packed + b"\x00" * 12
    return packed


def _unpack_ip16(raw: bytes, family: int) -> str:
    if family == REDIRECT_AF_IPV6:
        return str(ipaddress.IPv6Address(raw[:16]))
    return str(ipaddress.IPv4Address(raw[:4]))


def pack_redirect_rule(rule: RedirectRule) -> bytes:
    """将 RedirectRule 编码为 52 字节 REDIRECT_RULE 结构。"""
    if rule.rule_id < 0 or rule.rule_id > 0xFFFFFFFF:
        raise ValueError(f"规则 ID 超出范围: {rule.rule_id}")

    orig_obj, new_obj, family = normalize_ip_pair(rule.orig_ip, rule.new_ip)
    if rule.address_family not in (0, family):
        raise ValueError("规则地址族与 IP 地址实际版本不一致。")

    if rule.protocol not in (REDIRECT_PROTO_ANY, REDIRECT_PROTO_TCP, REDIRECT_PROTO_UDP):
        raise ValueError(f"不支持的协议值: {rule.protocol}")

    if not (0 <= int(rule.orig_port) <= 65535):
        raise ValueError("原始端口范围必须在 0 到 65535 之间（0 表示任意端口）。")
    if not (0 <= int(rule.new_port) <= 65535):
        raise ValueError("目标端口范围必须在 0 到 65535 之间（0 表示保持原端口）。")

    flags = 0
    mac_bytes = b"\x00" * 6
    if (rule.new_dst_mac or "").strip():
        mac_bytes = parse_mac_address(rule.new_dst_mac)
        flags |= REDIRECT_FLAG_REWRITE_MAC
    if rule.local_loopback:
        flags |= REDIRECT_FLAG_LOCAL_LOOPBACK

    return REDIRECT_RULE_STRUCT.pack(
        int(rule.rule_id),
        family,
        int(rule.protocol),
        flags,
        _pack_ip16(orig_obj),
        struct.pack("!H", int(rule.orig_port)),
        struct.pack("!H", int(rule.new_port)),
        _pack_ip16(new_obj),
        mac_bytes,
        b"\x00\x00",
    )


def unpack_redirect_rule(data: bytes) -> RedirectRule:
    """从 52 字节二进制缓冲区解码出 RedirectRule。"""
    if len(data) < REDIRECT_RULE_STRUCT.size:
        raise DriverError(
            f"驱动返回的规则数据长度不足（收到 {len(data)} 字节，需要 {REDIRECT_RULE_STRUCT.size} 字节）。"
        )

    (
        rule_id,
        family,
        protocol,
        flags,
        orig_ip_raw,
        orig_port_raw,
        new_port_raw,
        new_ip_raw,
        mac_raw,
        _reserved,
    ) = REDIRECT_RULE_STRUCT.unpack_from(data, 0)

    if family not in (REDIRECT_AF_IPV4, REDIRECT_AF_IPV6):
        raise DriverError(f"驱动返回了未知的地址族: {family}")

    mac_text = format_mac_address(mac_raw) if (flags & REDIRECT_FLAG_REWRITE_MAC) else ""
    return RedirectRule(
        rule_id=rule_id,
        orig_ip=_unpack_ip16(orig_ip_raw, family),
        orig_port=struct.unpack("!H", orig_port_raw)[0],
        new_ip=_unpack_ip16(new_ip_raw, family),
        new_port=struct.unpack("!H", new_port_raw)[0],
        protocol=protocol,
        address_family=family,
        new_dst_mac=mac_text,
        local_loopback=bool(flags & REDIRECT_FLAG_LOCAL_LOOPBACK),
    )


# ---------------------------------------------------------------------------
# 本地规则名称映射存储（rule_id -> 规则名称）
# ---------------------------------------------------------------------------


class RuleNameStore:
    """在客户端本地 JSON 文件中持久化 rule_id -> 规则名称 的映射。"""

    def __init__(self, path: str = DEFAULT_NAME_STORE_PATH):
        self.path = path
        self._names: Dict[int, str] = {}
        self.reload()

    def reload(self) -> None:
        self._names = {}
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fp:
                raw = json.load(fp)
            if isinstance(raw, dict):
                for key, value in raw.items():
                    if isinstance(value, str) and value.strip():
                        try:
                            rule_id = int(key)
                        except (TypeError, ValueError):
                            continue
                        if rule_id > 0:
                            self._names[rule_id] = value.strip()
        except (OSError, ValueError):
            self._names = {}

    def _save(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        payload = {str(k): v for k, v in sorted(self._names.items())}
        tmp_path = f"{self.path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, ensure_ascii=False, indent=2)
        os.replace(tmp_path, self.path)

    def get(self, rule_id: int) -> str:
        return self._names.get(int(rule_id), "")

    def set(self, rule_id: int, name: str) -> None:
        rid = int(rule_id)
        if rid <= 0:
            return
        cleaned = (name or "").strip()
        if cleaned:
            self._names[rid] = cleaned
        else:
            self._names.pop(rid, None)
        self._save()

    def delete(self, rule_id: int) -> None:
        if self._names.pop(int(rule_id), None) is not None:
            self._save()

    def clear(self) -> None:
        if self._names:
            self._names.clear()
            self._save()
        elif os.path.exists(self.path):
            self._save()

    def prune(self, active_rule_ids: Iterable[int]) -> None:
        active = {int(rid) for rid in active_rule_ids}
        stale = [rid for rid in self._names if rid not in active]
        if stale:
            for rid in stale:
                self._names.pop(rid, None)
            self._save()

    def apply_names(self, rules: List[RedirectRule]) -> List[RedirectRule]:
        for rule in rules:
            rule.name = self.get(rule.rule_id)
        return rules


# ---------------------------------------------------------------------------
# NDISLWF 驱动客户端
# ---------------------------------------------------------------------------


class RedirectDriverClient:
    r"""通过 DeviceIoControl 与 \\.\NDISLWF 驱动通信的客户端。"""

    def __init__(self, device_path: str = DEVICE_PATH):
        self.device_path = device_path
        self.available = _is_windows

    def _open(self):
        if not self.available or _kernel32 is None:
            raise DriverError("当前环境不是 Windows，无法连接 NDISLWF 驱动设备。")

        handle = _kernel32.CreateFileW(
            self.device_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            _raise_win_error(ctypes.get_last_error())
        return handle

    def probe(self):
        """探测驱动设备是否可打开，返回 (connected: bool, message: str)。"""
        if not self.available:
            return False, "非 Windows 环境"
        try:
            handle = self._open()
        except DriverError as err:
            return False, str(err)
        _kernel32.CloseHandle(handle)
        return True, f"已连接 ({self.device_path})"

    def _device_io_control(self, control_code: int, in_buffer: bytes = b"", out_size: int = 0) -> bytes:
        handle = self._open()
        try:
            bytes_returned = wintypes.DWORD(0)
            input_buf = ctypes.create_string_buffer(in_buffer, len(in_buffer)) if in_buffer else None
            output_buf = ctypes.create_string_buffer(out_size) if out_size > 0 else None

            ok = _kernel32.DeviceIoControl(
                handle,
                control_code,
                input_buf,
                len(in_buffer) if in_buffer else 0,
                output_buf,
                out_size,
                ctypes.byref(bytes_returned),
                None,
            )
            if not ok:
                _raise_win_error(ctypes.get_last_error())
            if output_buf is None:
                return b""
            return bytes(output_buf.raw[: bytes_returned.value])
        finally:
            _kernel32.CloseHandle(handle)

    def list_rules(self) -> List[RedirectRule]:
        out_size = MAX_REDIRECT_RULES * REDIRECT_RULE_STRUCT.size
        for _ in range(3):
            try:
                output = self._device_io_control(IOCTL_FILTER_LIST_REDIRECT_RULES, out_size=out_size)
                break
            except DriverError as err:
                if err.winerror == ERROR_INSUFFICIENT_BUFFER:
                    out_size *= 2
                    continue
                raise
        else:
            raise DriverError("驱动返回的规则数据超出预期缓冲区大小。", winerror=ERROR_INSUFFICIENT_BUFFER)

        count = len(output) // REDIRECT_RULE_STRUCT.size
        rules: List[RedirectRule] = []
        for index in range(count):
            offset = index * REDIRECT_RULE_STRUCT.size
            rules.append(unpack_redirect_rule(output[offset : offset + REDIRECT_RULE_STRUCT.size]))
        return rules

    def add_rule(self, rule: RedirectRule) -> RedirectRule:
        payload = pack_redirect_rule(rule)
        output = self._device_io_control(
            IOCTL_FILTER_ADD_REDIRECT_RULE,
            in_buffer=payload,
            out_size=REDIRECT_RULE_STRUCT.size,
        )
        if len(output) >= REDIRECT_RULE_STRUCT.size:
            created = unpack_redirect_rule(output)
            created.name = rule.name
            return created
        return rule

    def update_rule(self, rule: RedirectRule) -> RedirectRule:
        if int(rule.rule_id) <= 0:
            raise ValueError("更新规则必须指定有效的 RuleId（> 0）。")
        return self.add_rule(rule)

    def delete_rule(self, rule_id: int) -> None:
        rid = int(rule_id)
        if rid <= 0:
            raise ValueError(f"无效的规则 ID: {rule_id}")
        self._device_io_control(
            IOCTL_FILTER_DEL_REDIRECT_RULE,
            in_buffer=REDIRECT_DEL_RULE_STRUCT.pack(rid),
            out_size=0,
        )

    def clear_rules(self) -> None:
        self._device_io_control(IOCTL_FILTER_CLEAR_REDIRECT_RULES, in_buffer=b"", out_size=0)
