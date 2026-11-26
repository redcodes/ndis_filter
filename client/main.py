import ctypes
import ipaddress
import struct
import sys
from dataclasses import dataclass

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QLinearGradient, QPainter
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QStyle,
    QStyledItemDelegate,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from file_filter_page import FileFilterPage
from proc_explorer_page import ProcessExplorerPage


APP_STYLE = """
QMainWindow, QDialog {
    background: #f3f3f3;
}
QMenuBar {
    background: #ffffff;
    border-bottom: 1px solid #d5d5d5;
}
QMenuBar::item {
    spacing: 12px;
    padding: 5px 10px;
}
QMenuBar::item:selected {
    background: #e8f2fb;
}
QTabWidget::pane {
    border: 1px solid #cfcfcf;
    background: #f7f7f7;
    top: -1px;
}
QTabBar::tab {
    background: #efefef;
    border: 1px solid #cfcfcf;
    padding: 8px 14px;
    margin-right: -1px;
}
QTabBar::tab:selected {
    background: #ffffff;
    border-bottom-color: #ffffff;
}
QPushButton {
    background: #efefef;
    border: 1px solid #b6b6b6;
    padding: 7px 18px;
    min-height: 16px;
}
QPushButton:hover {
    background: #f7f7f7;
}
QPushButton:pressed {
    background: #e2e2e2;
}
QPushButton:disabled {
    color: #8b8b8b;
    background: #e9e9e9;
}
QLineEdit, QListWidget {
    background: #ffffff;
    border: 1px solid #a9a9a9;
    padding: 4px 6px;
}
QLineEdit:focus, QListWidget:focus {
    border: 1px solid #0078d7;
}
QHeaderView::section {
    background: #ffffff;
    border: 0px;
    border-right: 1px solid #dadada;
    border-bottom: 1px solid #dadada;
    padding: 6px 8px;
}
QTableWidget {
    background: #ffffff;
    border: 1px solid #a9a9a9;
    gridline-color: #e3e3e3;
    selection-background-color: #e8f2fb;
    selection-color: #111111;
}
QTableWidget::item {
    padding: 6px;
}
QFrame[panel='true'] {
    background: #f3f3f3;
    border: 1px solid #d7d7d7;
}
"""


FILE_DEVICE_PHYSICAL_NETCARD = 0x17
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PORT_REDIRECT_RULE_VERSION = 2
PORT_REDIRECT_RULE_FLAG_ENABLED = 0x00000001
PORT_REDIRECT_PROTOCOL_TCP = 0x00000001
PORT_REDIRECT_PROTOCOL_UDP = 0x00000002
PORT_REDIRECT_ADDRESS_FAMILY_UNSPEC = 0
PORT_REDIRECT_ADDRESS_FAMILY_IPV4 = 4
PORT_REDIRECT_ADDRESS_FAMILY_IPV6 = 6
PORT_REDIRECT_PROCESS_MODE_EXCLUDE = 0
PORT_REDIRECT_PROCESS_MODE_INCLUDE = 1

FILTER_MAX_PORT_RULE_NAME_LENGTH = 64
FILTER_MAX_PORT_HOST_LENGTH = 64

DEVICE_PATH = r"\\.\NDISLWF"


def ctl_code(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method


IOCTL_FILTER_ADD_PORT_REDIRECT_RULE = ctl_code(FILE_DEVICE_PHYSICAL_NETCARD, 20, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILTER_UPDATE_PORT_REDIRECT_RULE = ctl_code(FILE_DEVICE_PHYSICAL_NETCARD, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILTER_DELETE_PORT_REDIRECT_RULE = ctl_code(FILE_DEVICE_PHYSICAL_NETCARD, 22, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILTER_QUERY_PORT_REDIRECT_RULES = ctl_code(FILE_DEVICE_PHYSICAL_NETCARD, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILTER_QUERY_PORT_REDIRECT_STATS = ctl_code(FILE_DEVICE_PHYSICAL_NETCARD, 24, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_FILTER_CLEAR_PORT_REDIRECT_STATS = ctl_code(FILE_DEVICE_PHYSICAL_NETCARD, 25, METHOD_BUFFERED, FILE_ANY_ACCESS)

PORT_RULE_STRUCT = struct.Struct(
    f"<LLLL{FILTER_MAX_PORT_RULE_NAME_LENGTH}H{FILTER_MAX_PORT_HOST_LENGTH}HL"
    f"{FILTER_MAX_PORT_HOST_LENGTH}HLLL"
)
PORT_RULE_KEY_STRUCT = struct.Struct("<LL")
PORT_RULES_HEADER_STRUCT = struct.Struct("<LL")
PORT_STATS_STRUCT = struct.Struct("<LLQQQQQQQQQQQ")


kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None
if kernel32 is not None:
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
class PortRedirectRule:
    rule_id: int = 0
    name: str = "新规则"
    target_host: str = "127.0.0.1"
    target_port: int = 81
    redirect_host: str = "127.0.0.1"
    redirect_port: int = 80
    protocol_mask: int = PORT_REDIRECT_PROTOCOL_TCP | PORT_REDIRECT_PROTOCOL_UDP
    enabled: bool = True
    process_mode: int = PORT_REDIRECT_PROCESS_MODE_EXCLUDE
    address_family: int = PORT_REDIRECT_ADDRESS_FAMILY_UNSPEC

    @property
    def status(self):
        return "启用" if self.enabled else "禁用"

    @property
    def protocols_text(self):
        protocols = []
        if self.protocol_mask & PORT_REDIRECT_PROTOCOL_TCP:
            protocols.append("TCP")
        if self.protocol_mask & PORT_REDIRECT_PROTOCOL_UDP:
            protocols.append("UDP")
        return ",".join(protocols) if protocols else "TCP"

    @property
    def address_family_text(self):
        if self.address_family == PORT_REDIRECT_ADDRESS_FAMILY_IPV6:
            return "IPv6"
        if self.address_family == PORT_REDIRECT_ADDRESS_FAMILY_IPV4:
            return "IPv4"
        return "Auto"


@dataclass
class PortRedirectStats:
    examined_nbls: int = 0
    redirected_nbls: int = 0
    passed_nbls: int = 0
    clone_failures: int = 0
    rewrite_failures: int = 0
    skipped_multi_net_buffer: int = 0
    skipped_lso: int = 0
    skipped_ipsec: int = 0
    skipped_unsupported_protocol: int = 0
    skipped_fragmented_ipv4: int = 0
    skipped_fragmented_ipv6: int = 0


def _normalize_ip_pair(target_host, redirect_host):
    target_ip = ipaddress.ip_address((target_host or "").strip())
    redirect_ip = ipaddress.ip_address((redirect_host or "").strip())
    if target_ip.version != redirect_ip.version:
        raise ValueError("目标地址和重定向地址必须同为 IPv4 或同为 IPv6")
    family = PORT_REDIRECT_ADDRESS_FAMILY_IPV6 if target_ip.version == 6 else PORT_REDIRECT_ADDRESS_FAMILY_IPV4
    return str(target_ip), str(redirect_ip), family


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


def pack_rule(rule: PortRedirectRule):
    flags = PORT_REDIRECT_RULE_FLAG_ENABLED if rule.enabled else 0
    target_host, redirect_host, address_family = _normalize_ip_pair(rule.target_host, rule.redirect_host)
    if rule.address_family not in (PORT_REDIRECT_ADDRESS_FAMILY_UNSPEC, address_family):
        raise ValueError("规则地址族与目标/重定向地址不一致")
    return PORT_RULE_STRUCT.pack(
        PORT_REDIRECT_RULE_VERSION,
        rule.rule_id,
        flags,
        rule.process_mode,
        *_encode_wchar_buffer(rule.name, FILTER_MAX_PORT_RULE_NAME_LENGTH),
        *_encode_wchar_buffer(target_host, FILTER_MAX_PORT_HOST_LENGTH),
        int(rule.target_port),
        *_encode_wchar_buffer(redirect_host, FILTER_MAX_PORT_HOST_LENGTH),
        int(rule.redirect_port),
        int(rule.protocol_mask),
        address_family,
    )


def unpack_rule(data):
    unpacked = PORT_RULE_STRUCT.unpack(data[: PORT_RULE_STRUCT.size])
    version, rule_id, flags, process_mode = unpacked[:4]
    cursor = 4
    name = _decode_wchar_buffer(unpacked[cursor : cursor + FILTER_MAX_PORT_RULE_NAME_LENGTH])
    cursor += FILTER_MAX_PORT_RULE_NAME_LENGTH
    target_host = _decode_wchar_buffer(unpacked[cursor : cursor + FILTER_MAX_PORT_HOST_LENGTH])
    cursor += FILTER_MAX_PORT_HOST_LENGTH
    target_port = unpacked[cursor]
    cursor += 1
    redirect_host = _decode_wchar_buffer(unpacked[cursor : cursor + FILTER_MAX_PORT_HOST_LENGTH])
    cursor += FILTER_MAX_PORT_HOST_LENGTH
    redirect_port = unpacked[cursor]
    protocol_mask = unpacked[cursor + 1]
    address_family = unpacked[cursor + 2]

    if version != PORT_REDIRECT_RULE_VERSION:
        raise OSError(f"不支持的规则版本: {version}")

    return PortRedirectRule(
        rule_id=rule_id,
        name=name or "新规则",
        target_host=target_host or "127.0.0.1",
        target_port=target_port or 81,
        redirect_host=redirect_host or "127.0.0.1",
        redirect_port=redirect_port or 80,
        protocol_mask=protocol_mask or PORT_REDIRECT_PROTOCOL_TCP,
        enabled=bool(flags & PORT_REDIRECT_RULE_FLAG_ENABLED),
        process_mode=process_mode,
        address_family=address_family,
    )


def unpack_stats(data):
    unpacked = PORT_STATS_STRUCT.unpack(data[: PORT_STATS_STRUCT.size])
    version = unpacked[0]
    if version != PORT_REDIRECT_RULE_VERSION:
        raise OSError(f"驱动返回了不支持的统计版本: {version}")

    return PortRedirectStats(
        examined_nbls=unpacked[2],
        redirected_nbls=unpacked[3],
        passed_nbls=unpacked[4],
        clone_failures=unpacked[5],
        rewrite_failures=unpacked[6],
        skipped_multi_net_buffer=unpacked[7],
        skipped_lso=unpacked[8],
        skipped_ipsec=unpacked[9],
        skipped_unsupported_protocol=unpacked[10],
        skipped_fragmented_ipv4=unpacked[11],
        skipped_fragmented_ipv6=unpacked[12],
    )


class FilterDriverClient:
    def __init__(self, device_path=DEVICE_PATH):
        self.device_path = device_path
        self.available = sys.platform == "win32"

    def _open(self):
        if not self.available:
            raise OSError("当前环境不是 Windows，无法连接驱动设备。")

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
            return [PortRedirectRule()]

        header_size = PORT_RULES_HEADER_STRUCT.size
        output = self._device_io_control(IOCTL_FILTER_QUERY_PORT_REDIRECT_RULES, out_size=65536)
        if len(output) < header_size:
            return []

        version, count = PORT_RULES_HEADER_STRUCT.unpack_from(output, 0)
        if version != PORT_REDIRECT_RULE_VERSION:
            raise OSError(f"驱动返回了不支持的规则版本: {version}")

        offset = header_size
        rules = []
        for _ in range(count):
            chunk = output[offset : offset + PORT_RULE_STRUCT.size]
            if len(chunk) < PORT_RULE_STRUCT.size:
                break
            rules.append(unpack_rule(chunk))
            offset += PORT_RULE_STRUCT.size
        return rules

    def add_rule(self, rule: PortRedirectRule):
        if not self.available:
            rule.rule_id = 1
            return rule
        output = self._device_io_control(IOCTL_FILTER_ADD_PORT_REDIRECT_RULE, pack_rule(rule), PORT_RULE_STRUCT.size)
        return unpack_rule(output)

    def update_rule(self, rule: PortRedirectRule):
        if not self.available:
            return rule
        output = self._device_io_control(IOCTL_FILTER_UPDATE_PORT_REDIRECT_RULE, pack_rule(rule), PORT_RULE_STRUCT.size)
        return unpack_rule(output)

    def delete_rule(self, rule_id: int):
        if not self.available:
            return
        self._device_io_control(
            IOCTL_FILTER_DELETE_PORT_REDIRECT_RULE,
            PORT_RULE_KEY_STRUCT.pack(PORT_REDIRECT_RULE_VERSION, int(rule_id)),
            0,
        )

    def query_stats(self):
        if not self.available:
            return PortRedirectStats()
        output = self._device_io_control(IOCTL_FILTER_QUERY_PORT_REDIRECT_STATS, out_size=PORT_STATS_STRUCT.size)
        if len(output) < PORT_STATS_STRUCT.size:
            raise OSError("驱动返回的统计数据长度不足。")
        return unpack_stats(output)

    def clear_stats(self):
        if not self.available:
            return
        self._device_io_control(IOCTL_FILTER_CLEAR_PORT_REDIRECT_STATS)


class HeroBanner(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(86)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 14, 24, 14)
        layout.setSpacing(16)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(6)

        title = QLabel("CnCrypt 主机防护工具", self)
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setStyleSheet("color: #000000; background: transparent;")

        subtitle = QLabel("CnCrypt 主机防护工具，可根据需要配置主机防护规则。", self)
        subtitle.setStyleSheet("color: #111111; font-size: 12px; background: transparent;")

        text_layout.addWidget(title)
        text_layout.addWidget(subtitle)
        text_layout.addStretch()

        badge = QLabel("锁", self)
        badge.setAlignment(Qt.AlignCenter)
        badge.setFixedSize(46, 46)
        badge.setStyleSheet(
            """
            QLabel {
                color: white;
                font-size: 18px;
                font-weight: 700;
                border: 3px solid rgba(255, 255, 255, 0.9);
                border-radius: 23px;
                background: transparent;
            }
            """
        )

        layout.addLayout(text_layout, 1)
        layout.addWidget(badge, 0, Qt.AlignRight | Qt.AlignVCenter)

    def paintEvent(self, event):
        painter = QPainter(self)
        gradient = QLinearGradient(0, 0, self.width(), 0)
        gradient.setColorAt(0.0, QColor("#d8e7f4"))
        gradient.setColorAt(1.0, QColor("#0f7ac8"))
        painter.fillRect(self.rect(), gradient)
        super().paintEvent(event)


class LeftAlignDelegate(QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        option.displayAlignment = Qt.AlignVCenter | Qt.AlignLeft if index.column() == 0 else Qt.AlignCenter


class PlaceholderPage(QWidget):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        label = QLabel(f"{title} 页面保留。", self)
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("color: #666666; font-size: 15px;")

        layout.addStretch()
        layout.addWidget(label)
        layout.addStretch()


def show_not_implemented(parent, title, message):
    QMessageBox.information(parent, title, message)


class PortRuleDialog(QDialog):
    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.setWindowTitle("CnCrypt Protect - 端口重定向规则")
        self.setFixedSize(760, 700)
        self.setStyleSheet(APP_STYLE)
        self.rule = rule or PortRedirectRule()

        panel = QFrame(self)
        panel.setProperty("panel", True)

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 36, 0, 0)
        root_layout.addWidget(panel)

        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(24, 16, 24, 14)
        panel_layout.setSpacing(16)

        panel_layout.addWidget(QLabel("规则名称(N)", panel))
        self.name_edit = QLineEdit(panel)
        panel_layout.addWidget(self.name_edit)

        address_layout = QGridLayout()
        address_layout.setHorizontalSpacing(24)
        address_layout.setVerticalSpacing(10)

        self.target_host_edit = QLineEdit(panel)
        self.target_port_edit = QLineEdit(panel)
        self.redirect_host_edit = QLineEdit(panel)
        self.redirect_port_edit = QLineEdit(panel)

        address_layout.addWidget(QLabel("目标地址(D)", panel), 0, 0)
        address_layout.addWidget(QLabel("目标端口(P)", panel), 0, 1)
        address_layout.addWidget(self.target_host_edit, 1, 0)
        address_layout.addWidget(self.target_port_edit, 1, 1)
        address_layout.addWidget(QLabel("重定向地址(S)", panel), 2, 0)
        address_layout.addWidget(QLabel("重定向端口(W)", panel), 2, 1)
        address_layout.addWidget(self.redirect_host_edit, 3, 0)
        address_layout.addWidget(self.redirect_port_edit, 3, 1)
        panel_layout.addLayout(address_layout)

        panel_layout.addWidget(QLabel("协议类型(C)", panel))

        protocol_frame = QFrame(panel)
        protocol_frame.setProperty("panel", True)
        protocol_layout = QHBoxLayout(protocol_frame)
        protocol_layout.setContentsMargins(10, 4, 10, 4)

        self.tcp_checkbox = QCheckBox("TCP", protocol_frame)
        self.udp_checkbox = QCheckBox("UDP", protocol_frame)

        protocol_layout.addWidget(self.tcp_checkbox)
        protocol_layout.addStretch(1)
        protocol_layout.addWidget(self.udp_checkbox)
        protocol_layout.addStretch(4)
        panel_layout.addWidget(protocol_frame)

        radio_layout = QHBoxLayout()
        self.exclude_radio = QRadioButton("规则对以下列表中的进程不生效(E)", panel)
        self.include_radio = QRadioButton("规则仅对以下列表中的进程生效(T)", panel)
        radio_layout.addWidget(self.exclude_radio)
        radio_layout.addSpacing(28)
        radio_layout.addWidget(self.include_radio)
        radio_layout.addStretch(1)
        panel_layout.addLayout(radio_layout)

        self.process_list = QListWidget(panel)
        self.process_list.setMinimumHeight(170)
        placeholder_item = QListWidgetItem("点击左下方的“添加进程”按钮")
        placeholder_item.setFlags(Qt.NoItemFlags)
        self.process_list.addItem(placeholder_item)
        self.process_list.setStyleSheet("QListWidget { font-size: 28px; color: #6d6d6d; padding-top: 48px; }")
        panel_layout.addWidget(self.process_list)

        process_buttons = QHBoxLayout()
        add_process_button = QPushButton("添加进程(Q)", panel)
        add_group_button = QPushButton("添加分组(G)...", panel)
        remove_button = QPushButton("移除(R)", panel)
        clear_button = QPushButton("全部移除(A)", panel)
        remove_button.setEnabled(False)
        clear_button.setEnabled(False)
        add_process_button.clicked.connect(
            lambda: show_not_implemented(self, "提示", "当前版本暂未接入进程列表过滤，仅保存端口重定向规则。")
        )
        add_group_button.clicked.connect(
            lambda: show_not_implemented(self, "提示", "当前版本暂未接入进程分组过滤。")
        )

        process_buttons.addWidget(add_process_button)
        process_buttons.addWidget(add_group_button)
        process_buttons.addStretch(1)
        process_buttons.addWidget(remove_button)
        process_buttons.addWidget(clear_button)
        panel_layout.addLayout(process_buttons)

        action_layout = QHBoxLayout()
        action_layout.addStretch(1)
        ok_button = QPushButton("确定", panel)
        cancel_button = QPushButton("取消", panel)
        ok_button.setMinimumWidth(120)
        cancel_button.setMinimumWidth(120)
        ok_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        action_layout.addWidget(ok_button)
        action_layout.addWidget(cancel_button)
        panel_layout.addLayout(action_layout)

        self.load_rule(self.rule)

    def load_rule(self, rule: PortRedirectRule):
        self.name_edit.setText(rule.name)
        self.name_edit.selectAll()
        self.target_host_edit.setText(rule.target_host)
        self.target_port_edit.setText(str(rule.target_port))
        self.redirect_host_edit.setText(rule.redirect_host)
        self.redirect_port_edit.setText(str(rule.redirect_port))
        self.tcp_checkbox.setChecked(bool(rule.protocol_mask & PORT_REDIRECT_PROTOCOL_TCP))
        self.udp_checkbox.setChecked(bool(rule.protocol_mask & PORT_REDIRECT_PROTOCOL_UDP))
        self.exclude_radio.setChecked(rule.process_mode == PORT_REDIRECT_PROCESS_MODE_EXCLUDE)
        self.include_radio.setChecked(rule.process_mode == PORT_REDIRECT_PROCESS_MODE_INCLUDE)

    def get_rule(self):
        protocol_mask = 0
        if self.tcp_checkbox.isChecked():
            protocol_mask |= PORT_REDIRECT_PROTOCOL_TCP
        if self.udp_checkbox.isChecked():
            protocol_mask |= PORT_REDIRECT_PROTOCOL_UDP
        if protocol_mask == 0:
            protocol_mask = PORT_REDIRECT_PROTOCOL_TCP

        try:
            target_port = int(self.target_port_edit.text().strip() or "81")
            redirect_port = int(self.redirect_port_edit.text().strip() or "80")
        except ValueError as error:
            raise ValueError("端口必须是数字。") from error

        if target_port < 1 or target_port > 65535 or redirect_port < 1 or redirect_port > 65535:
            raise ValueError("端口范围必须在 1 到 65535 之间。")

        target_host = self.target_host_edit.text().strip() or "127.0.0.1"
        redirect_host = self.redirect_host_edit.text().strip() or "127.0.0.1"
        target_host, redirect_host, address_family = _normalize_ip_pair(target_host, redirect_host)

        return PortRedirectRule(
            rule_id=self.rule.rule_id,
            name=self.name_edit.text().strip() or "新规则",
            target_host=target_host,
            target_port=target_port,
            redirect_host=redirect_host,
            redirect_port=redirect_port,
            protocol_mask=protocol_mask,
            enabled=True,
            process_mode=(
                PORT_REDIRECT_PROCESS_MODE_INCLUDE
                if self.include_radio.isChecked()
                else PORT_REDIRECT_PROCESS_MODE_EXCLUDE
            ),
            address_family=address_family,
        )


class PortRedirectPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.driver = FilterDriverClient()
        self.rules = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        add_button = QPushButton("添加规则(C)...", self)
        add_button.setMinimumWidth(132)
        add_button.clicked.connect(self.add_rule)
        import_button = QPushButton("导入规则(I)...", self)
        export_button = QPushButton("导出规则(E)...", self)
        refresh_button = QPushButton("查询规则(Q)", self)
        refresh_button.clicked.connect(self.load_rules)
        import_button.clicked.connect(
            lambda: show_not_implemented(self, "提示", "当前版本暂未实现规则导入。")
        )
        export_button.clicked.connect(
            lambda: show_not_implemented(self, "提示", "当前版本暂未实现规则导出。")
        )

        top_row.addWidget(add_button, 0, Qt.AlignLeft)
        top_row.addStretch(1)
        top_row.addWidget(refresh_button)
        top_row.addWidget(import_button)
        top_row.addWidget(export_button)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self.stats_label = QLabel("", self)
        self.stats_label.setStyleSheet("color: #1a1a1a; font-size: 13px;")
        refresh_stats_button = QPushButton("刷新统计", self)
        clear_stats_button = QPushButton("清零统计", self)
        refresh_stats_button.clicked.connect(self.load_stats)
        clear_stats_button.clicked.connect(self.clear_stats)
        stats_row.addWidget(self.stats_label, 1)
        stats_row.addWidget(refresh_stats_button)
        stats_row.addWidget(clear_stats_button)

        self.rule_table = QTableWidget(0, 8, self)
        self.rule_table.setHorizontalHeaderLabels(
            ["规则名称", "访问地址", "访问端口", "转发地址", "转发端口", "协议类型", "IP", "状态"]
        )
        self.rule_table.verticalHeader().setVisible(False)
        self.rule_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rule_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.rule_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rule_table.setFocusPolicy(Qt.NoFocus)
        self.rule_table.setAlternatingRowColors(False)
        self.rule_table.setShowGrid(True)
        self.rule_table.setMinimumHeight(420)
        self.rule_table.setItemDelegate(LeftAlignDelegate(self.rule_table))
        self.rule_table.itemSelectionChanged.connect(self.update_action_state)

        header = self.rule_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for index in range(1, 8):
            header.setSectionResizeMode(index, QHeaderView.ResizeToContents)
        self.rule_table.setColumnWidth(0, 520)

        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(8)

        self.up_button = QPushButton("上移(U)", self)
        self.down_button = QPushButton("下移(D)", self)
        self.up_button.setEnabled(False)
        self.down_button.setEnabled(False)
        self.up_button.clicked.connect(
            lambda: show_not_implemented(self, "提示", "当前驱动按规则创建顺序匹配，暂未实现页面内排序调整。")
        )
        self.down_button.clicked.connect(
            lambda: show_not_implemented(self, "提示", "当前驱动按规则创建顺序匹配，暂未实现页面内排序调整。")
        )

        self.rule_count = QLabel("", self)
        self.rule_count.setStyleSheet("color: #1a1a1a; font-size: 15px;")

        self.edit_button = QPushButton("编辑规则(M)...", self)
        self.remove_button = QPushButton("移除(R)", self)
        self.clear_button = QPushButton("全部移除(A)", self)

        self.edit_button.clicked.connect(self.edit_rule)
        self.remove_button.clicked.connect(self.remove_selected_rule)
        self.clear_button.clicked.connect(self.clear_rules)

        bottom_row.addWidget(self.up_button)
        bottom_row.addWidget(self.down_button)
        bottom_row.addSpacing(12)
        bottom_row.addWidget(self.rule_count)
        bottom_row.addStretch(1)
        bottom_row.addWidget(self.edit_button)
        bottom_row.addWidget(self.remove_button)
        bottom_row.addWidget(self.clear_button)

        layout.addLayout(top_row)
        layout.addLayout(stats_row)
        layout.addWidget(self.rule_table, 1)
        layout.addLayout(bottom_row)

        self.load_rules()
        self.load_stats()

    def show_driver_error(self, action, error):
        QMessageBox.warning(self, "驱动调用失败", f"{action}失败：{error}")

    def load_stats(self):
        try:
            stats = self.driver.query_stats()
        except OSError as error:
            self.show_driver_error("查询统计", error)
            stats = PortRedirectStats()

        self.stats_label.setText(
            "统计："
            f"检查 {stats.examined_nbls}，"
            f"重定向 {stats.redirected_nbls}，"
            f"放行 {stats.passed_nbls}，"
            f"克隆失败 {stats.clone_failures}，"
            f"重写失败 {stats.rewrite_failures}"
        )

    def clear_stats(self):
        try:
            self.driver.clear_stats()
        except OSError as error:
            self.show_driver_error("清零统计", error)
            return
        self.load_stats()

    def load_rules(self):
        try:
            self.rules = self.driver.query_rules()
        except OSError as error:
            self.show_driver_error("查询规则", error)
            self.rules = []
        self.refresh_table()

    def refresh_table(self):
        self.rule_table.setRowCount(len(self.rules))
        icon = QApplication.style().standardIcon(QStyle.SP_DialogApplyButton)

        for row_index, rule in enumerate(self.rules):
            values = [
                QTableWidgetItem(icon, rule.name),
                QTableWidgetItem(rule.target_host),
                QTableWidgetItem(str(rule.target_port)),
                QTableWidgetItem(rule.redirect_host),
                QTableWidgetItem(str(rule.redirect_port)),
                QTableWidgetItem(rule.protocols_text),
                QTableWidgetItem(rule.address_family_text),
                QTableWidgetItem(rule.status),
            ]
            for column, item in enumerate(values):
                self.rule_table.setItem(row_index, column, item)
            self.rule_table.setRowHeight(row_index, 30)

        if self.rules:
            self.rule_table.selectRow(0)
        self.rule_count.setText(f"规则数目：{len(self.rules)} 条")
        self.update_action_state()

    def current_rule_index(self):
        selected_rows = self.rule_table.selectionModel().selectedRows()
        return selected_rows[0].row() if selected_rows else -1

    def update_action_state(self):
        has_rule = bool(self.rules)
        has_selection = self.current_rule_index() >= 0
        self.edit_button.setEnabled(has_selection)
        self.remove_button.setEnabled(has_selection)
        self.clear_button.setEnabled(has_rule)

    def add_rule(self):
        dialog = PortRuleDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return
        try:
            self.driver.add_rule(dialog.get_rule())
            self.load_rules()
        except (OSError, ValueError) as error:
            self.show_driver_error("添加规则", error)

    def edit_rule(self):
        index = self.current_rule_index()
        if index < 0:
            return
        dialog = PortRuleDialog(self, self.rules[index])
        if dialog.exec_() != QDialog.Accepted:
            return
        try:
            self.driver.update_rule(dialog.get_rule())
            self.load_rules()
            if index < len(self.rules):
                self.rule_table.selectRow(index)
        except (OSError, ValueError) as error:
            self.show_driver_error("修改规则", error)

    def remove_selected_rule(self):
        index = self.current_rule_index()
        if index < 0:
            return
        try:
            self.driver.delete_rule(self.rules[index].rule_id)
            self.load_rules()
        except OSError as error:
            self.show_driver_error("删除规则", error)

    def clear_rules(self):
        for rule in list(self.rules):
            try:
                self.driver.delete_rule(rule.rule_id)
            except OSError as error:
                self.show_driver_error("批量删除规则", error)
                break
        self.load_rules()


class NetworkControlPage(PortRedirectPage):
    pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CnCrypt Protect - 主机防护工具")
        self.resize(1100, 760)
        self.setStyleSheet(APP_STYLE)

        self._setup_menu_bar()
        self._setup_ui()

    def _setup_menu_bar(self):
        bar = QMenuBar(self)
        bar.addAction("Powered by CnCrypt")
        bar.addAction("主机防护(R)")
        bar.addAction("防护日志(L)")
        bar.addAction("防护设置(S)")
        bar.addSeparator()
        bar.addAction("关于(A)")
        self.setMenuBar(bar)

    def _setup_ui(self):
        central = QWidget(self)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(HeroBanner(central))

        content_host = QWidget(central)
        content_layout = QVBoxLayout(content_host)
        content_layout.setContentsMargins(18, 22, 18, 18)
        content_layout.setSpacing(0)

        tab_widget = QTabWidget(content_host)
        stop_button = QPushButton("停止保护(S)", tab_widget)
        stop_button.setMinimumWidth(132)
        stop_button.clicked.connect(
            lambda: show_not_implemented(tab_widget, "提示", "当前版本未实现保护开关控制。")
        )
        tab_widget.setCornerWidget(stop_button, Qt.TopRightCorner)

        tabs = [
            "文件锁定",
            "注册表锁定",
            "网络管控",
            "驱动拦截",
            "动态库拦截",
            "进程拦截",
            "文件重定向",
            "端口重定向(1)",
            "进程行为",
            "进程浏览器",
        ]

        for index, title in enumerate(tabs):
            if index == 0:
                tab_widget.addTab(FileFilterPage(tab_widget), title)
            elif title == "网络管控":
                tab_widget.addTab(NetworkControlPage(tab_widget), title)
            elif title.startswith("端口重定向"):
                tab_widget.addTab(PortRedirectPage(tab_widget), title)
            elif title == "进程浏览器":
                tab_widget.addTab(ProcessExplorerPage(tab_widget), title)
            else:
                tab_widget.addTab(PlaceholderPage(title, tab_widget), title)

        tab_widget.setCurrentIndex(2)
        content_layout.addWidget(tab_widget)
        root_layout.addWidget(content_host)
        self.setCentralWidget(central)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
