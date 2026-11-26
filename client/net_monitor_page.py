"""Network monitor GUI page -- a TCPView-style view for the 网络管控 tab.

Top pane: the live TCP/UDP connection table (IPv4 + IPv6) with the owning
process, refreshed on demand or on a timer. A connection can be force-closed
(IPv4 TCP, via SetTcpEntry) or turned into a driver block rule.

Bottom pane: the block rules currently installed in the cncnetmon WFP driver.
The connection table works with no driver; the rules pane needs the driver
loaded (otherwise its actions report that clearly).
"""

import socket

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import net_monitor as nm

CONNECTION_COLUMNS = ["进程", "PID", "协议", "本地地址", "远程地址", "状态"]
RULE_COLUMNS = ["ID", "协议", "方向", "目标 (地址:端口)"]

# Row background by TCP state, so the table reads at a glance like TCPView.
STATE_COLORS = {
    "ESTABLISHED": QColor(226, 245, 229),
    "LISTEN": QColor(240, 240, 240),
    "TIME-WAIT": QColor(248, 244, 228),
    "CLOSE-WAIT": QColor(248, 244, 228),
    "SYN-SENT": QColor(250, 238, 224),
    "SYN-RCVD": QColor(250, 238, 224),
}

PROTOCOL_CHOICES = [("任意", nm.NETMON_PROTO_ANY), ("TCP", nm.NETMON_PROTO_TCP), ("UDP", nm.NETMON_PROTO_UDP)]
DIRECTION_CHOICES = [
    ("出站 (连接)", nm.NETMON_DIR_OUTBOUND),
    ("入站 (接受)", nm.NETMON_DIR_INBOUND),
    ("双向", nm.NETMON_DIR_ANY),
]


def _table(columns):
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(columns)
    table.verticalHeader().setVisible(False)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setAlternatingRowColors(True)
    return table


class BlockRuleDialog(QDialog):
    """Compose a block rule; optionally pre-filled from a selected connection."""

    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.setWindowTitle("CnCrypt Protect - 网络拦截规则")
        self.setMinimumWidth(420)
        rule = rule or nm.BlockRule()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)

        layout.addWidget(QLabel("远程地址 (留空表示任意)", self))
        self.address_edit = QLineEdit(self)
        self.address_edit.setText(rule.remote_address)
        layout.addWidget(self.address_edit)

        prefix_row = QHBoxLayout()
        prefix_row.addWidget(QLabel("前缀长度", self))
        self.prefix_edit = QLineEdit(self)
        self.prefix_edit.setText(str(rule.prefix_length))
        self.prefix_edit.setMaximumWidth(80)
        prefix_row.addWidget(self.prefix_edit)
        prefix_row.addSpacing(16)
        prefix_row.addWidget(QLabel("远程端口 (0=任意)", self))
        self.port_edit = QLineEdit(self)
        self.port_edit.setText(str(rule.remote_port))
        self.port_edit.setMaximumWidth(90)
        prefix_row.addWidget(self.port_edit)
        prefix_row.addStretch(1)
        layout.addLayout(prefix_row)

        combo_row = QHBoxLayout()
        combo_row.addWidget(QLabel("协议", self))
        self.protocol_combo = QComboBox(self)
        for label, value in PROTOCOL_CHOICES:
            self.protocol_combo.addItem(label, value)
        self._select_value(self.protocol_combo, rule.protocol)
        combo_row.addWidget(self.protocol_combo)
        combo_row.addSpacing(16)
        combo_row.addWidget(QLabel("方向", self))
        self.direction_combo = QComboBox(self)
        for label, value in DIRECTION_CHOICES:
            self.direction_combo.addItem(label, value)
        self._select_value(self.direction_combo, rule.direction)
        combo_row.addWidget(self.direction_combo)
        combo_row.addStretch(1)
        layout.addLayout(combo_row)

        action_row = QHBoxLayout()
        action_row.addStretch(1)
        ok_button = QPushButton("确定", self)
        cancel_button = QPushButton("取消", self)
        ok_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        action_row.addWidget(ok_button)
        action_row.addWidget(cancel_button)
        layout.addLayout(action_row)

    @staticmethod
    def _select_value(combo, value):
        index = combo.findData(value)
        if index >= 0:
            combo.setCurrentIndex(index)

    def get_rule(self):
        address = self.address_edit.text().strip()
        family = nm.NETMON_AF_INET
        if address:
            try:
                socket.inet_pton(socket.AF_INET6, address)
                family = nm.NETMON_AF_INET6
            except OSError:
                try:
                    socket.inet_aton(address)
                except OSError as error:
                    raise ValueError("远程地址不是有效的 IP。") from error

        try:
            prefix = int(self.prefix_edit.text().strip() or "0")
            port = int(self.port_edit.text().strip() or "0")
        except ValueError as error:
            raise ValueError("前缀长度和端口必须是数字。") from error

        if not address:
            prefix = 0
        elif prefix <= 0:
            prefix = 128 if family == nm.NETMON_AF_INET6 else 32
        if port < 0 or port > 65535:
            raise ValueError("端口范围必须在 0 到 65535 之间。")

        return nm.BlockRule(
            remote_address=address,
            prefix_length=prefix,
            remote_port=port,
            protocol=self.protocol_combo.currentData(),
            direction=self.direction_combo.currentData(),
            address_family=family,
        )


class NetworkMonitorPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.client = nm.NetMonClient()
        self.connections = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        layout.addLayout(self._build_toolbar())

        self.table = _table(CONNECTION_COLUMNS)
        self.table.setMinimumHeight(320)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        layout.addWidget(self.table, 3)

        layout.addWidget(self._build_rules_group(), 2)

        self.status_label = QLabel("", self)
        layout.addWidget(self.status_label)

        self.timer = QTimer(self)
        self.timer.setInterval(3000)
        self.timer.timeout.connect(self.refresh)

        self.refresh()
        self.refresh_rules()

    # --- toolbar ---------------------------------------------------------

    def _build_toolbar(self):
        row = QHBoxLayout()

        refresh_button = QPushButton("刷新(R)", self)
        refresh_button.clicked.connect(self.refresh)

        self.auto_checkbox = QCheckBox("自动刷新 (3s)", self)
        self.auto_checkbox.toggled.connect(self._toggle_auto_refresh)

        self.tcp_checkbox = QCheckBox("TCP", self)
        self.udp_checkbox = QCheckBox("UDP", self)
        self.tcp_checkbox.setChecked(True)
        self.udp_checkbox.setChecked(True)
        self.tcp_checkbox.toggled.connect(self.refresh)
        self.udp_checkbox.toggled.connect(self.refresh)

        self.filter_edit = QLineEdit(self)
        self.filter_edit.setPlaceholderText("按进程 / 地址 / 端口过滤...")
        self.filter_edit.setMaximumWidth(220)
        self.filter_edit.textChanged.connect(self._rebuild_table)

        self.close_button = QPushButton("关闭连接(K)", self)
        self.block_button = QPushButton("拦截远端(B)", self)
        self.close_button.clicked.connect(self._close_selected)
        self.block_button.clicked.connect(self._block_selected)

        row.addWidget(refresh_button)
        row.addWidget(self.auto_checkbox)
        row.addSpacing(12)
        row.addWidget(self.tcp_checkbox)
        row.addWidget(self.udp_checkbox)
        row.addWidget(self.filter_edit)
        row.addStretch(1)
        row.addWidget(self.block_button)
        row.addWidget(self.close_button)
        return row

    def _build_rules_group(self):
        group = QGroupBox("网络拦截规则 (WFP 驱动)", self)
        group_layout = QVBoxLayout(group)
        group_layout.setSpacing(8)

        button_row = QHBoxLayout()
        add_button = QPushButton("添加规则(C)...", group)
        delete_button = QPushButton("删除规则(D)", group)
        clear_button = QPushButton("全部清除(A)", group)
        refresh_rules_button = QPushButton("查询规则(Q)", group)
        add_button.clicked.connect(self._add_rule)
        delete_button.clicked.connect(self._delete_rule)
        clear_button.clicked.connect(self._clear_rules)
        refresh_rules_button.clicked.connect(self.refresh_rules)
        button_row.addWidget(add_button)
        button_row.addWidget(delete_button)
        button_row.addWidget(clear_button)
        button_row.addStretch(1)
        button_row.addWidget(refresh_rules_button)
        group_layout.addLayout(button_row)

        self.rule_table = _table(RULE_COLUMNS)
        self.rule_table.setMinimumHeight(120)
        rule_header = self.rule_table.horizontalHeader()
        rule_header.setSectionResizeMode(3, QHeaderView.Stretch)
        group_layout.addWidget(self.rule_table)

        return group

    # --- connection table ------------------------------------------------

    def refresh(self):
        try:
            self.connections = nm.list_connections(
                include_tcp=self.tcp_checkbox.isChecked(),
                include_udp=self.udp_checkbox.isChecked(),
            )
        except OSError as error:
            self.connections = []
            QMessageBox.warning(self, "网络监视", f"读取连接失败: {error}")
        self._rebuild_table()

    def _rebuild_table(self):
        selected = self._selected_key()
        needle = self.filter_edit.text().strip().lower()

        rows = [c for c in self.connections if self._matches(c, needle)]
        rows.sort(key=lambda c: (c.protocol, c.pid))

        self.table.setRowCount(len(rows))
        self._row_connections = rows
        for row, c in enumerate(rows):
            cells = [
                c.process or ("System Idle" if c.pid == 0 else f"pid {c.pid}"),
                str(c.pid),
                c.protocol,
                c.local_endpoint,
                c.remote_endpoint,
                c.state,
            ]
            color = STATE_COLORS.get(c.state)
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column in (1,):
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                if color is not None:
                    item.setBackground(color)
                self.table.setItem(row, column, item)

        self._restore_selection(selected)
        self._update_status()
        self._update_action_state()

    @staticmethod
    def _matches(connection, needle):
        if not needle:
            return True
        haystack = " ".join([
            connection.process, str(connection.pid), connection.protocol,
            connection.local_endpoint, connection.remote_endpoint, connection.state,
        ]).lower()
        return needle in haystack

    def _selected_key(self):
        connection = self.selected_connection()
        if connection is None:
            return None
        return (connection.protocol, connection.local_endpoint, connection.remote_endpoint, connection.pid)

    def _restore_selection(self, key):
        if key is None:
            return
        for row, c in enumerate(getattr(self, "_row_connections", [])):
            if (c.protocol, c.local_endpoint, c.remote_endpoint, c.pid) == key:
                self.table.selectRow(row)
                return

    def selected_connection(self):
        row = self.table.currentRow()
        rows = getattr(self, "_row_connections", [])
        if 0 <= row < len(rows):
            return rows[row]
        return None

    def _update_status(self):
        established = sum(1 for c in self.connections if c.state == "ESTABLISHED")
        listening = sum(1 for c in self.connections if c.state == "LISTEN")
        backend = "内核驱动已加载 (CnCNetMon)" if self.client.driver_loaded() else "驱动未加载 (拦截规则不可用)"
        self.status_label.setText(
            f"连接总数: {len(self.connections)}   已建立: {established}   监听: {listening}   |   拦截后端: {backend}"
        )

    def _update_action_state(self):
        connection = self.selected_connection()
        can_close = connection is not None and connection.protocol == "TCP" and connection.state == "ESTABLISHED"
        can_block = connection is not None and bool(connection.remote_addr) and connection.remote_addr not in ("0.0.0.0", "::")
        self.close_button.setEnabled(can_close)
        self.block_button.setEnabled(can_block)

    # --- connection actions ----------------------------------------------

    def _close_selected(self):
        connection = self.selected_connection()
        if connection is None:
            return
        confirm = QMessageBox.question(
            self, "关闭连接",
            f"强制关闭连接?\n\n{connection.local_endpoint} -> {connection.remote_endpoint}\n进程: {connection.process} (PID {connection.pid})",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            nm.close_connection(connection)
        except OSError as error:
            QMessageBox.warning(self, "关闭连接", f"关闭失败: {error}\n(需要管理员权限，且仅支持 IPv4 TCP)")
            return
        self.refresh()

    def _block_selected(self):
        connection = self.selected_connection()
        if connection is None:
            return
        family = nm.NETMON_AF_INET6 if connection.family == 6 else nm.NETMON_AF_INET
        prefix = 128 if family == nm.NETMON_AF_INET6 else 32
        protocol = nm.NETMON_PROTO_TCP if connection.is_tcp else nm.NETMON_PROTO_UDP
        prefill = nm.BlockRule(
            remote_address=connection.remote_addr,
            prefix_length=prefix,
            remote_port=connection.remote_port,
            protocol=protocol,
            direction=nm.NETMON_DIR_OUTBOUND,
            address_family=family,
        )
        self._add_rule(prefill)

    # --- rules -----------------------------------------------------------

    def refresh_rules(self):
        if not self.client.driver_loaded():
            self.rule_table.setRowCount(0)
            return
        try:
            rules = self.client.list_rules()
        except OSError as error:
            self.rule_table.setRowCount(0)
            QMessageBox.warning(self, "拦截规则", f"查询规则失败: {error}")
            return
        self.rule_table.setRowCount(len(rules))
        self._rules = rules
        for row, rule in enumerate(rules):
            cells = [str(rule.rule_id), rule.protocol_text, rule.direction_text, rule.target_text]
            for column, text in enumerate(cells):
                self.rule_table.setItem(row, column, QTableWidgetItem(text))

    def _require_driver(self):
        if not self.client.driver_loaded():
            QMessageBox.information(
                self, "拦截规则",
                "未检测到 CnCNetMon 驱动。请先安装并启动驱动 (net_monitor/cncnetmon.sys)。",
            )
            return False
        return True

    def _add_rule(self, prefill=None):
        if not self._require_driver():
            return
        dialog = BlockRuleDialog(self, prefill if isinstance(prefill, nm.BlockRule) else None)
        if dialog.exec_() != QDialog.Accepted:
            return
        try:
            rule = dialog.get_rule()
        except ValueError as error:
            QMessageBox.warning(self, "拦截规则", str(error))
            return
        try:
            self.client.add_rule(rule)
        except OSError as error:
            QMessageBox.warning(self, "拦截规则", f"添加规则失败: {error}")
            return
        self.refresh_rules()
        self._update_status()

    def _delete_rule(self):
        if not self._require_driver():
            return
        row = self.rule_table.currentRow()
        rules = getattr(self, "_rules", [])
        if not (0 <= row < len(rules)):
            return
        try:
            self.client.delete_rule(rules[row].rule_id)
        except OSError as error:
            QMessageBox.warning(self, "拦截规则", f"删除规则失败: {error}")
            return
        self.refresh_rules()

    def _clear_rules(self):
        if not self._require_driver():
            return
        confirm = QMessageBox.question(
            self, "全部清除", "清除所有网络拦截规则?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            self.client.clear_rules()
        except OSError as error:
            QMessageBox.warning(self, "拦截规则", f"清除规则失败: {error}")
            return
        self.refresh_rules()

    def _toggle_auto_refresh(self, enabled):
        if enabled:
            self.timer.start()
        else:
            self.timer.stop()
