r"""NDISLWF 域名欺骗（DNS Spoofing）用户态通信模块（纯 Python，无 GUI 依赖）。

严格对齐 driver/filteruser.h 与 driver/device.c 的 IOCTL 及 288 字节二进制契约：
  - 设备路径: \\.\NDISLWF
  - IOCTL_FILTER_ADD_DNS_SPOOF_RULE    (function 18): 添加规则 (RuleId=0) 或按 RuleId 原地更新
  - IOCTL_FILTER_DEL_DNS_SPOOF_RULE    (function 19): 按 RuleId 删除规则
  - IOCTL_FILTER_CLEAR_DNS_SPOOF_RULES (function 20): 清空全部域名欺骗规则
  - IOCTL_FILTER_LIST_DNS_SPOOF_RULES  (function 21): 查询全部域名欺骗规则（扁平数组，无包头）
"""

from __future__ import annotations

import ctypes
import ipaddress
import struct
import sys
from dataclasses import dataclass
from typing import List, Tuple

from redirect_driver import (
    DEVICE_PATH,
    DriverError,
    ERROR_INSUFFICIENT_BUFFER,
    FILE_ANY_ACCESS,
    FILE_DEVICE_PHYSICAL_NETCARD,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    GENERIC_READ,
    GENERIC_WRITE,
    INVALID_HANDLE_VALUE,
    METHOD_BUFFERED,
    OPEN_EXISTING,
    _is_windows,
    _kernel32,
    _raise_win_error,
    ctl_code,
)

if _is_windows:
    from ctypes import wintypes

# ---------------------------------------------------------------------------
# IOCTL 与结构体常量（严格对应 driver/filteruser.h）
# ---------------------------------------------------------------------------

IOCTL_FILTER_ADD_DNS_SPOOF_RULE = ctl_code(
    FILE_DEVICE_PHYSICAL_NETCARD, 18, METHOD_BUFFERED, FILE_ANY_ACCESS
)
IOCTL_FILTER_DEL_DNS_SPOOF_RULE = ctl_code(
    FILE_DEVICE_PHYSICAL_NETCARD, 19, METHOD_BUFFERED, FILE_ANY_ACCESS
)
IOCTL_FILTER_CLEAR_DNS_SPOOF_RULES = ctl_code(
    FILE_DEVICE_PHYSICAL_NETCARD, 20, METHOD_BUFFERED, FILE_ANY_ACCESS
)
IOCTL_FILTER_LIST_DNS_SPOOF_RULES = ctl_code(
    FILE_DEVICE_PHYSICAL_NETCARD, 21, METHOD_BUFFERED, FILE_ANY_ACCESS
)

DNS_SPOOF_FLAG_HAS_IPV4 = 0x0001
DNS_SPOOF_FLAG_HAS_IPV6 = 0x0002
DNS_SPOOF_FLAG_WILDCARD = 0x0004

DNS_SPOOF_MAX_DOMAIN_LEN = 256
MAX_DNS_SPOOF_RULES = 64
DNS_SPOOF_DEFAULT_TTL = 30

# struct _DNS_SPOOF_RULE (288 bytes, 无隐式填充):
#   offset   0 (4B): ULONG  RuleId       (little-endian)
#   offset   4 (2B): USHORT Flags        (little-endian)
#   offset   6 (2B): USHORT Reserved
#   offset   8 (4B): ULONG  Ttl          (little-endian)
#   offset  12 (4B): UCHAR  FakeIpv4[4]  (network byte order)
#   offset  16 (16B): UCHAR FakeIpv6[16] (network byte order)
#   offset  32 (256B): CHAR Domain[256]  (NUL-terminated ASCII)
DNS_SPOOF_RULE_STRUCT = struct.Struct("<LHHL4s16s256s")
DNS_SPOOF_DEL_RULE_STRUCT = struct.Struct("<L")
assert DNS_SPOOF_RULE_STRUCT.size == 288
assert DNS_SPOOF_DEL_RULE_STRUCT.size == 4

_dnsapi = None
if _is_windows:
    try:
        _dnsapi = ctypes.WinDLL("dnsapi", use_last_error=True)
        _dnsapi.DnsFlushResolverCache.argtypes = []
        _dnsapi.DnsFlushResolverCache.restype = wintypes.BOOL
    except OSError:
        _dnsapi = None


# ---------------------------------------------------------------------------
# 数据模型与参数校验
# ---------------------------------------------------------------------------


@dataclass
class DnsSpoofRule:
    rule_id: int = 0
    domain: str = ""
    fake_ipv4: str = ""
    fake_ipv6: str = ""
    ttl: int = DNS_SPOOF_DEFAULT_TTL
    wildcard: bool = False

    @property
    def match_mode_text(self) -> str:
        return "通配符 (*.子域)" if (self.wildcard or self.domain.startswith("*.")) else "精确匹配"

    @property
    def ipv4_text(self) -> str:
        return self.fake_ipv4 if self.fake_ipv4 else "-"

    @property
    def ipv6_text(self) -> str:
        return self.fake_ipv6 if self.fake_ipv6 else "-"


def normalize_domain(domain: str, wildcard: bool = False) -> Tuple[str, bool]:
    """规范化并校验域名（支持 IDN 国际化域名、自动识别 *. 通配符、去尾点、转小写）。"""
    text = (domain or "").strip().rstrip(".")
    if not text:
        raise ValueError("域名不能为空。")

    is_wildcard = bool(wildcard)
    if text.startswith("*."):
        is_wildcard = True
        text = text[2:]
    elif "*" in text:
        raise ValueError("通配符仅支持前缀形式，例如 *.baidu.com。")

    if not text:
        raise ValueError("通配符后缀域名不能为空，例如 *.baidu.com。")

    try:
        ascii_host = text.encode("idna").decode("ascii").lower()
    except UnicodeError as err:
        raise ValueError(f"域名格式无效: {domain}") from err

    labels = ascii_host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError(f"域名标签长度无效: {domain}")
        for ch in label:
            if not (("a" <= ch <= "z") or ("0" <= ch <= "9") or ch in ("-", "_")):
                raise ValueError(f"域名包含非法字符 '{ch}': {domain}")

    canonical = f"*.{ascii_host}" if is_wildcard else ascii_host
    if len(canonical) > 253:
        raise ValueError("域名总长度不能超过 253 个字符。")
    return canonical, is_wildcard


def pack_dns_spoof_rule(rule: DnsSpoofRule) -> bytes:
    """将 DnsSpoofRule 编码为 288 字节二进制结构。"""
    if rule.rule_id < 0 or rule.rule_id > 0xFFFFFFFF:
        raise ValueError(f"规则 ID 超出范围: {rule.rule_id}")

    ttl = int(rule.ttl)
    if ttl < 0 or ttl > 0xFFFFFFFF:
        raise ValueError(f"TTL 超出范围: {rule.ttl}")

    canonical_domain, is_wildcard = normalize_domain(rule.domain, rule.wildcard)

    flags = DNS_SPOOF_FLAG_WILDCARD if is_wildcard else 0
    v4_bytes = b"\x00" * 4
    v6_bytes = b"\x00" * 16

    v4_text = (rule.fake_ipv4 or "").strip()
    if v4_text:
        try:
            v4_obj = ipaddress.IPv4Address(v4_text)
        except ValueError as err:
            raise ValueError(f"伪造 IPv4 地址无效: {v4_text}") from err
        v4_bytes = v4_obj.packed
        flags |= DNS_SPOOF_FLAG_HAS_IPV4

    v6_text = (rule.fake_ipv6 or "").strip()
    if v6_text:
        try:
            v6_obj = ipaddress.IPv6Address(v6_text)
        except ValueError as err:
            raise ValueError(f"伪造 IPv6 地址无效: {v6_text}") from err
        v6_bytes = v6_obj.packed
        flags |= DNS_SPOOF_FLAG_HAS_IPV6

    if (flags & (DNS_SPOOF_FLAG_HAS_IPV4 | DNS_SPOOF_FLAG_HAS_IPV6)) == 0:
        raise ValueError("必须至少填写一个伪造 IPv4 (A) 或 IPv6 (AAAA) 地址。")

    domain_raw = canonical_domain.encode("ascii")
    domain_padded = domain_raw + b"\x00" * (DNS_SPOOF_MAX_DOMAIN_LEN - len(domain_raw))

    return DNS_SPOOF_RULE_STRUCT.pack(
        int(rule.rule_id),
        flags,
        0,
        ttl,
        v4_bytes,
        v6_bytes,
        domain_padded,
    )


def unpack_dns_spoof_rule(data: bytes) -> DnsSpoofRule:
    """从 288 字节二进制缓冲解码出 DnsSpoofRule。"""
    if len(data) < DNS_SPOOF_RULE_STRUCT.size:
        raise DriverError(
            f"驱动返回的域名规则长度不足（收到 {len(data)} 字节，需要 {DNS_SPOOF_RULE_STRUCT.size} 字节）。"
        )

    rule_id, flags, _reserved, ttl, v4_raw, v6_raw, domain_raw = DNS_SPOOF_RULE_STRUCT.unpack_from(
        data, 0
    )
    domain = domain_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    fake_ipv4 = str(ipaddress.IPv4Address(v4_raw)) if (flags & DNS_SPOOF_FLAG_HAS_IPV4) else ""
    fake_ipv6 = str(ipaddress.IPv6Address(v6_raw)) if (flags & DNS_SPOOF_FLAG_HAS_IPV6) else ""
    wildcard = bool(flags & DNS_SPOOF_FLAG_WILDCARD) or domain.startswith("*.")

    return DnsSpoofRule(
        rule_id=rule_id,
        domain=domain,
        fake_ipv4=fake_ipv4,
        fake_ipv6=fake_ipv6,
        ttl=ttl,
        wildcard=wildcard,
    )


def flush_dns_cache() -> bool:
    """刷新 Windows 本机 DNS 解析器缓存（DnsFlushResolverCache）。"""
    if not _is_windows or _dnsapi is None:
        return False
    try:
        return bool(_dnsapi.DnsFlushResolverCache())
    except OSError:
        return False


# ---------------------------------------------------------------------------
# NDISLWF 域名欺骗驱动客户端
# ---------------------------------------------------------------------------


class DnsSpoofDriverClient:
    r"""通过 DeviceIoControl 与 \\.\NDISLWF 驱动的域名欺骗模块通信。"""

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

    def list_rules(self) -> List[DnsSpoofRule]:
        out_size = MAX_DNS_SPOOF_RULES * DNS_SPOOF_RULE_STRUCT.size
        for _ in range(3):
            try:
                output = self._device_io_control(IOCTL_FILTER_LIST_DNS_SPOOF_RULES, out_size=out_size)
                break
            except DriverError as err:
                if err.winerror == ERROR_INSUFFICIENT_BUFFER:
                    out_size *= 2
                    continue
                raise
        else:
            raise DriverError("驱动返回的域名规则超出预期缓冲区大小。", winerror=ERROR_INSUFFICIENT_BUFFER)

        count = len(output) // DNS_SPOOF_RULE_STRUCT.size
        return [
            unpack_dns_spoof_rule(output[i * DNS_SPOOF_RULE_STRUCT.size : (i + 1) * DNS_SPOOF_RULE_STRUCT.size])
            for i in range(count)
        ]

    def add_rule(self, rule: DnsSpoofRule, flush_cache: bool = True) -> DnsSpoofRule:
        payload = pack_dns_spoof_rule(rule)
        output = self._device_io_control(
            IOCTL_FILTER_ADD_DNS_SPOOF_RULE,
            in_buffer=payload,
            out_size=DNS_SPOOF_RULE_STRUCT.size,
        )
        if flush_cache:
            flush_dns_cache()
        if len(output) >= DNS_SPOOF_RULE_STRUCT.size:
            return unpack_dns_spoof_rule(output)
        return rule

    def update_rule(self, rule: DnsSpoofRule, flush_cache: bool = True) -> DnsSpoofRule:
        if int(rule.rule_id) <= 0:
            raise ValueError("更新域名规则必须指定有效的 RuleId（> 0）。")
        return self.add_rule(rule, flush_cache=flush_cache)

    def delete_rule(self, rule_id: int, flush_cache: bool = True) -> None:
        rid = int(rule_id)
        if rid <= 0:
            raise ValueError(f"无效的规则 ID: {rule_id}")
        self._device_io_control(
            IOCTL_FILTER_DEL_DNS_SPOOF_RULE,
            in_buffer=DNS_SPOOF_DEL_RULE_STRUCT.pack(rid),
            out_size=0,
        )
        if flush_cache:
            flush_dns_cache()

    def clear_rules(self, flush_cache: bool = True) -> None:
        self._device_io_control(IOCTL_FILTER_CLEAR_DNS_SPOOF_RULES, in_buffer=b"", out_size=0)
        if flush_cache:
            flush_dns_cache()
