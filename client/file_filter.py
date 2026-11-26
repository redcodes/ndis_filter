import ctypes
import struct
import sys
from dataclasses import dataclass


FILE_FILTER_DEVICE_TYPE = 0x8000
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

FILE_FILTER_RULE_VERSION = 1
FILE_FILTER_RULE_FLAG_ENABLED = 0x00000001
FILE_FILTER_RULE_FLAG_DENY_WRITE = 0x00000002
FILE_FILTER_RULE_FLAG_DENY_DELETE = 0x00000004
FILE_FILTER_RULE_FLAG_DENY_RENAME = 0x00000008
FILE_FILTER_RULE_FLAG_DENY_READ = 0x00000010

FILE_FILTER_MAX_RULE_NAME_LENGTH = 64
FILE_FILTER_MAX_PATH_LENGTH = 260

DEVICE_PATH = r"\\.\CnCFileFilter"


def ctl_code(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method


IOCTL_FILE_FILTER_ADD_RULE = ctl_code(FILE_FILTER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILE_FILTER_UPDATE_RULE = ctl_code(FILE_FILTER_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILE_FILTER_DELETE_RULE = ctl_code(FILE_FILTER_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILE_FILTER_QUERY_RULES = ctl_code(FILE_FILTER_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILE_FILTER_QUERY_STATS = ctl_code(FILE_FILTER_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILE_FILTER_CLEAR_STATS = ctl_code(FILE_FILTER_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

FILE_RULE_STRUCT = struct.Struct(
    f"<LLL{FILE_FILTER_MAX_RULE_NAME_LENGTH}H{FILE_FILTER_MAX_PATH_LENGTH}H"
)
FILE_RULE_KEY_STRUCT = struct.Struct("<LL")
FILE_RULES_HEADER_STRUCT = struct.Struct("<LL")
FILE_STATS_STRUCT = struct.Struct("<LLQQQQ")

kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None
if kernel32 is not None:
    # Declare prototypes so 64-bit HANDLE values are marshalled correctly and
    # INVALID_HANDLE_VALUE comparisons work. Without these the default restype
    # is a signed 32-bit int and open-failure detection silently breaks.
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.DeviceIoControl.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_void_p,
    ]
    kernel32.DeviceIoControl.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int


@dataclass
class FileFilterRule:
    rule_id: int = 0
    name: str = "New file rule"
    path_pattern: str = r"\Device\HarddiskVolume*\Protected\*"
    enabled: bool = True
    deny_read: bool = False
    deny_write: bool = True
    deny_delete: bool = True
    deny_rename: bool = True

    @property
    def flags(self):
        flags = 0
        if self.enabled:
            flags |= FILE_FILTER_RULE_FLAG_ENABLED
        if self.deny_read:
            flags |= FILE_FILTER_RULE_FLAG_DENY_READ
        if self.deny_write:
            flags |= FILE_FILTER_RULE_FLAG_DENY_WRITE
        if self.deny_delete:
            flags |= FILE_FILTER_RULE_FLAG_DENY_DELETE
        if self.deny_rename:
            flags |= FILE_FILTER_RULE_FLAG_DENY_RENAME
        return flags

    @property
    def action_text(self):
        actions = []
        if self.deny_read:
            actions.append("Read")
        if self.deny_write:
            actions.append("Write")
        if self.deny_delete:
            actions.append("Delete")
        if self.deny_rename:
            actions.append("Rename")
        return ", ".join(actions) if actions else "None"

    @property
    def status(self):
        return "Enabled" if self.enabled else "Disabled"


@dataclass
class FileFilterStats:
    examined_creates: int = 0
    blocked_creates: int = 0
    examined_set_information: int = 0
    blocked_set_information: int = 0


def _encode_wchar_buffer(text, max_chars):
    trimmed = (text or "")[: max_chars - 1]
    values = [ord(ch) for ch in trimmed]
    values.extend([0] * (max_chars - len(values)))
    return values


def _decode_wchar_buffer(values):
    chars = []
    for value in values:
        if value == 0:
            break
        chars.append(chr(value))
    return "".join(chars)


def pack_rule(rule: FileFilterRule):
    return FILE_RULE_STRUCT.pack(
        FILE_FILTER_RULE_VERSION,
        int(rule.rule_id),
        int(rule.flags),
        *_encode_wchar_buffer(rule.name, FILE_FILTER_MAX_RULE_NAME_LENGTH),
        *_encode_wchar_buffer(rule.path_pattern, FILE_FILTER_MAX_PATH_LENGTH),
    )


def unpack_rule(data):
    unpacked = FILE_RULE_STRUCT.unpack(data[: FILE_RULE_STRUCT.size])
    version, rule_id, flags = unpacked[:3]
    cursor = 3
    name = _decode_wchar_buffer(unpacked[cursor : cursor + FILE_FILTER_MAX_RULE_NAME_LENGTH])
    cursor += FILE_FILTER_MAX_RULE_NAME_LENGTH
    path_pattern = _decode_wchar_buffer(unpacked[cursor : cursor + FILE_FILTER_MAX_PATH_LENGTH])

    if version != FILE_FILTER_RULE_VERSION:
        raise OSError(f"unsupported file rule version: {version}")

    return FileFilterRule(
        rule_id=rule_id,
        name=name or "New file rule",
        path_pattern=path_pattern,
        enabled=bool(flags & FILE_FILTER_RULE_FLAG_ENABLED),
        deny_read=bool(flags & FILE_FILTER_RULE_FLAG_DENY_READ),
        deny_write=bool(flags & FILE_FILTER_RULE_FLAG_DENY_WRITE),
        deny_delete=bool(flags & FILE_FILTER_RULE_FLAG_DENY_DELETE),
        deny_rename=bool(flags & FILE_FILTER_RULE_FLAG_DENY_RENAME),
    )


def unpack_stats(data):
    unpacked = FILE_STATS_STRUCT.unpack(data[: FILE_STATS_STRUCT.size])
    version = unpacked[0]
    if version != FILE_FILTER_RULE_VERSION:
        raise OSError(f"unsupported file stats version: {version}")

    return FileFilterStats(
        examined_creates=unpacked[2],
        blocked_creates=unpacked[3],
        examined_set_information=unpacked[4],
        blocked_set_information=unpacked[5],
    )


class FileFilterDriverClient:
    def __init__(self, device_path=DEVICE_PATH):
        self.device_path = device_path
        self.available = sys.platform == "win32"

    def _open(self):
        if not self.available:
            raise OSError("file filter device is only available on Windows")

        handle = kernel32.CreateFileW(
            self.device_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            raise ctypes.WinError()
        return handle

    def _device_io_control(self, control_code, in_buffer=b"", out_size=0):
        handle = self._open()
        try:
            bytes_returned = ctypes.c_ulong(0)
            input_buffer = ctypes.create_string_buffer(in_buffer) if in_buffer else None
            output_buffer = ctypes.create_string_buffer(out_size) if out_size else None

            ok = kernel32.DeviceIoControl(
                handle,
                control_code,
                input_buffer,
                len(in_buffer) if in_buffer else 0,
                output_buffer,
                out_size,
                ctypes.byref(bytes_returned),
                None,
            )
            if not ok:
                raise ctypes.WinError()
            return bytes(output_buffer.raw[: bytes_returned.value]) if output_buffer else b""
        finally:
            kernel32.CloseHandle(handle)

    def query_rules(self):
        if not self.available:
            return [FileFilterRule()]

        output = self._device_io_control(IOCTL_FILE_FILTER_QUERY_RULES, out_size=65536)
        if len(output) < FILE_RULES_HEADER_STRUCT.size:
            return []

        version, count = FILE_RULES_HEADER_STRUCT.unpack_from(output, 0)
        if version != FILE_FILTER_RULE_VERSION:
            raise OSError(f"unsupported file rules version: {version}")

        offset = FILE_RULES_HEADER_STRUCT.size
        rules = []
        for _ in range(count):
            chunk = output[offset : offset + FILE_RULE_STRUCT.size]
            if len(chunk) < FILE_RULE_STRUCT.size:
                break
            rules.append(unpack_rule(chunk))
            offset += FILE_RULE_STRUCT.size
        return rules

    def add_rule(self, rule: FileFilterRule):
        if not self.available:
            rule.rule_id = 1
            return rule
        output = self._device_io_control(IOCTL_FILE_FILTER_ADD_RULE, pack_rule(rule), FILE_RULE_STRUCT.size)
        return unpack_rule(output)

    def update_rule(self, rule: FileFilterRule):
        if not self.available:
            return rule
        output = self._device_io_control(IOCTL_FILE_FILTER_UPDATE_RULE, pack_rule(rule), FILE_RULE_STRUCT.size)
        return unpack_rule(output)

    def delete_rule(self, rule_id: int):
        if not self.available:
            return
        self._device_io_control(
            IOCTL_FILE_FILTER_DELETE_RULE,
            FILE_RULE_KEY_STRUCT.pack(FILE_FILTER_RULE_VERSION, int(rule_id)),
        )

    def query_stats(self):
        if not self.available:
            return FileFilterStats()
        output = self._device_io_control(IOCTL_FILE_FILTER_QUERY_STATS, out_size=FILE_STATS_STRUCT.size)
        if len(output) < FILE_STATS_STRUCT.size:
            raise OSError("file filter stats response is too short")
        return unpack_stats(output)

    def clear_stats(self):
        if not self.available:
            return
        self._device_io_control(IOCTL_FILE_FILTER_CLEAR_STATS)
