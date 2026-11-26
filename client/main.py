import os
import sys

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QLinearGradient, QPainter
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QStyle,
    QStyledItemDelegate,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from driver_manager import DriverManagerError, DriverState, NdisLwfDriverManager
from file_filter_page import FileFilterPage
from net_monitor_page import NetworkMonitorPage
from proc_explorer_page import ProcessExplorerPage
from redirect_driver import (
    DriverError,
    MAX_REDIRECT_RULES,
    REDIRECT_PROTO_ANY,
    REDIRECT_PROTO_TCP,
    REDIRECT_PROTO_UDP,
    RedirectDriverClient,
    RedirectRule,
    RuleNameStore,
    format_mac_address,
    normalize_ip_pair,
    parse_mac_address,
)


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


class RuleTableDelegate(QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if index.column() == 1:
            option.displayAlignment = Qt.AlignVCenter | Qt.AlignLeft
        else:
            option.displayAlignment = Qt.AlignCenter


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
    """端口重定向规则编辑弹窗（仅负责表单录入与本地校验）。"""

    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        is_edit = rule is not None and rule.rule_id > 0
        self.setWindowTitle("CnCrypt Protect - 编辑端口重定向规则" if is_edit else "CnCrypt Protect - 添加端口重定向规则")
        self.setFixedWidth(640)
        self.setStyleSheet(APP_STYLE)
        self.rule = rule or RedirectRule()
        self._validated_rule = None

        panel = QFrame(self)
        panel.setProperty("panel", True)

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(12, 16, 12, 12)
        root_layout.addWidget(panel)

        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(24, 18, 24, 16)
        panel_layout.setSpacing(14)

        panel_layout.addWidget(QLabel("规则名称(N)（仅保存在客户端本地）", panel))
        self.name_edit = QLineEdit(panel)
        self.name_edit.setPlaceholderText("可选，留空时自动显示为 规则 #<ID>")
        panel_layout.addWidget(self.name_edit)

        address_layout = QGridLayout()
        address_layout.setHorizontalSpacing(20)
        address_layout.setVerticalSpacing(8)

        self.orig_ip_edit = QLineEdit(panel)
        self.orig_ip_edit.setPlaceholderText("如 10.0.0.10 或 2001:db8::1")
        self.orig_port_edit = QLineEdit(panel)
        self.orig_port_edit.setPlaceholderText("0 表示匹配任意端口")

        self.new_ip_edit = QLineEdit(panel)
        self.new_ip_edit.setPlaceholderText("如 10.0.0.20 或 2001:db8::2")
        self.new_port_edit = QLineEdit(panel)
        self.new_port_edit.setPlaceholderText("0 表示保持原端口不变")

        address_layout.addWidget(QLabel("原始目的地址(D)", panel), 0, 0)
        address_layout.addWidget(QLabel("原始目的端口(P)", panel), 0, 1)
        address_layout.addWidget(self.orig_ip_edit, 1, 0)
        address_layout.addWidget(self.orig_port_edit, 1, 1)
        address_layout.addWidget(QLabel("重定向目标地址(S)", panel), 2, 0)
        address_layout.addWidget(QLabel("重定向目标端口(W)", panel), 2, 1)
        address_layout.addWidget(self.new_ip_edit, 3, 0)
        address_layout.addWidget(self.new_port_edit, 3, 1)
        address_layout.setColumnStretch(0, 3)
        address_layout.setColumnStretch(1, 2)
        panel_layout.addLayout(address_layout)

        panel_layout.addWidget(QLabel("协议类型(C)", panel))
        protocol_frame = QFrame(panel)
        protocol_frame.setProperty("panel", True)
        protocol_layout = QHBoxLayout(protocol_frame)
        protocol_layout.setContentsMargins(12, 6, 12, 6)

        self.tcp_checkbox = QCheckBox("TCP", protocol_frame)
        self.udp_checkbox = QCheckBox("UDP", protocol_frame)
        protocol_layout.addWidget(self.tcp_checkbox)
        protocol_layout.addSpacing(32)
        protocol_layout.addWidget(self.udp_checkbox)
        protocol_layout.addStretch(1)
        panel_layout.addWidget(protocol_frame)

        panel_layout.addWidget(QLabel("目标下一跳 MAC 地址（可选，同网段跨主机重定向时填写）", panel))
        self.mac_edit = QLineEdit(panel)
        self.mac_edit.setPlaceholderText("留空不改写；支持 : 或 - 分隔，例如 aa:bb:cc:dd:ee:ff")
        panel_layout.addWidget(self.mac_edit)

        self.local_checkbox = QCheckBox(
            "强制启用本机环回重定向（--local；目标 IP 为本机网卡 IP 时驱动也会自动识别）",
            panel,
        )
        panel_layout.addWidget(self.local_checkbox)

        tip = QLabel("提示：原始端口填 0 匹配任意端口；目标端口填 0 保持原端口不变。源/目标 IP 必须同为 IPv4 或同为 IPv6。", panel)
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555555; font-size: 12px;")
        panel_layout.addWidget(tip)

        action_layout = QHBoxLayout()
        action_layout.addStretch(1)
        ok_button = QPushButton("确定", panel)
        cancel_button = QPushButton("取消", panel)
        ok_button.setMinimumWidth(110)
        cancel_button.setMinimumWidth(110)
        ok_button.clicked.connect(self._on_accept)
        cancel_button.clicked.connect(self.reject)
        action_layout.addWidget(ok_button)
        action_layout.addWidget(cancel_button)
        panel_layout.addLayout(action_layout)

        self._load_rule(self.rule)

    def _load_rule(self, rule: RedirectRule):
        self.name_edit.setText(rule.name)
        self.name_edit.selectAll()
        self.orig_ip_edit.setText(rule.orig_ip)
        self.orig_port_edit.setText(str(rule.orig_port))
        self.new_ip_edit.setText(rule.new_ip)
        self.new_port_edit.setText(str(rule.new_port))

        is_any = rule.protocol == REDIRECT_PROTO_ANY
        self.tcp_checkbox.setChecked(is_any or rule.protocol == REDIRECT_PROTO_TCP)
        self.udp_checkbox.setChecked(is_any or rule.protocol == REDIRECT_PROTO_UDP)
        self.mac_edit.setText(rule.new_dst_mac)
        self.local_checkbox.setChecked(rule.local_loopback)

    def _build_rule(self) -> RedirectRule:
        tcp = self.tcp_checkbox.isChecked()
        udp = self.udp_checkbox.isChecked()
        if not tcp and not udp:
            raise ValueError("请至少勾选一种协议类型（TCP 或 UDP）。")
        if tcp and udp:
            protocol = REDIRECT_PROTO_ANY
        elif tcp:
            protocol = REDIRECT_PROTO_TCP
        else:
            protocol = REDIRECT_PROTO_UDP

        orig_ip_text = self.orig_ip_edit.text().strip()
        new_ip_text = self.new_ip_edit.text().strip()
        if not orig_ip_text or not new_ip_text:
            raise ValueError("原始目的地址和重定向目标地址不能为空。")
        orig_obj, new_obj, family = normalize_ip_pair(orig_ip_text, new_ip_text)

        try:
            orig_port = int(self.orig_port_edit.text().strip() or "0")
            new_port = int(self.new_port_edit.text().strip() or "0")
        except ValueError as err:
            raise ValueError("端口必须是 0 到 65535 之间的整数。") from err

        if not (0 <= orig_port <= 65535) or not (0 <= new_port <= 65535):
            raise ValueError("端口范围必须在 0 到 65535 之间（0 表示任意/保持原端口）。")

        mac_text = self.mac_edit.text().strip()
        normalized_mac = format_mac_address(parse_mac_address(mac_text)) if mac_text else ""

        return RedirectRule(
            rule_id=self.rule.rule_id,
            name=self.name_edit.text().strip(),
            orig_ip=str(orig_obj),
            orig_port=orig_port,
            new_ip=str(new_obj),
            new_port=new_port,
            protocol=protocol,
            address_family=family,
            new_dst_mac=normalized_mac,
            local_loopback=self.local_checkbox.isChecked(),
        )

    def _on_accept(self):
        try:
            self._validated_rule = self._build_rule()
        except ValueError as err:
            QMessageBox.warning(self, "参数错误", str(err))
            return
        self.accept()

    def get_rule(self) -> RedirectRule:
        if self._validated_rule is not None:
            return self._validated_rule
        return self._build_rule()


class PortRedirectPage(QWidget):
    r"""端口重定向页签：对接 NDISLWF 驱动（\\.\NDISLWF）并维护本地规则名称映射。"""

    ruleCountChanged = pyqtSignal(int)

    def __init__(self, parent=None, driver=None, name_store=None, driver_manager=None):
        super().__init__(parent)
        self.driver = driver or RedirectDriverClient()
        self.name_store = name_store or RuleNameStore()
        self.driver_manager = driver_manager or NdisLwfDriverManager()
        self.driver_status = None
        self.rules = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        add_button = QPushButton("添加规则(C)...", self)
        add_button.setMinimumWidth(132)
        add_button.clicked.connect(self.add_rule)

        refresh_button = QPushButton("查询规则(Q)", self)
        refresh_button.clicked.connect(lambda: self.load_rules(silent=False))

        top_row.addWidget(add_button, 0, Qt.AlignLeft)
        top_row.addStretch(1)
        top_row.addWidget(refresh_button)

        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self.driver_status_label = QLabel("", self)
        self.driver_status_label.setStyleSheet("color: #1a1a1a; font-size: 13px;")

        self.install_driver_button = QPushButton("安装驱动", self)
        self.start_driver_button = QPushButton("启动驱动", self)
        self.uninstall_driver_button = QPushButton("卸载驱动", self)
        self.install_driver_button.clicked.connect(lambda: self.install_driver(prompt_package=True))
        self.start_driver_button.clicked.connect(self.start_driver)
        self.uninstall_driver_button.clicked.connect(self.uninstall_driver)

        status_row.addWidget(self.driver_status_label, 1)
        status_row.addWidget(self.install_driver_button)
        status_row.addWidget(self.start_driver_button)
        status_row.addWidget(self.uninstall_driver_button)

        self.rule_table = QTableWidget(0, 9, self)
        self.rule_table.setHorizontalHeaderLabels(
            ["ID", "规则名称", "原始目的 IP", "原始端口", "重定向目标 IP", "目标端口", "协议", "地址族", "附加选项"]
        )
        self.rule_table.verticalHeader().setVisible(False)
        self.rule_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rule_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.rule_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rule_table.setFocusPolicy(Qt.NoFocus)
        self.rule_table.setAlternatingRowColors(False)
        self.rule_table.setShowGrid(True)
        self.rule_table.setMinimumHeight(420)
        self.rule_table.setItemDelegate(RuleTableDelegate(self.rule_table))
        self.rule_table.itemSelectionChanged.connect(self.update_action_state)
        self.rule_table.itemDoubleClicked.connect(lambda _item: self.edit_rule())

        header = self.rule_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        for col in range(2, 9):
            header.setSectionResizeMode(col, QHeaderView.ResizeToContents)

        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(8)

        self.rule_count = QLabel("", self)
        self.rule_count.setStyleSheet("color: #1a1a1a; font-size: 14px;")

        self.edit_button = QPushButton("编辑规则(M)...", self)
        self.remove_button = QPushButton("移除(R)", self)
        self.clear_button = QPushButton("全部移除(A)", self)

        self.edit_button.clicked.connect(self.edit_rule)
        self.remove_button.clicked.connect(self.remove_selected_rule)
        self.clear_button.clicked.connect(self.clear_rules)

        bottom_row.addWidget(self.rule_count)
        bottom_row.addStretch(1)
        bottom_row.addWidget(self.edit_button)
        bottom_row.addWidget(self.remove_button)
        bottom_row.addWidget(self.clear_button)

        layout.addLayout(top_row)
        layout.addLayout(status_row)
        layout.addWidget(self.rule_table, 1)
        layout.addLayout(bottom_row)

        self.refresh_driver_status()
        self.load_rules(silent=True)

    def _set_driver_status(self, color: str, message: str):
        self.driver_status_label.setStyleSheet(f"color: {color}; font-size: 13px;")
        self.driver_status_label.setText(f"驱动状态：{message}")

    def refresh_driver_status(self):
        status = self.driver_manager.query_status()
        self.driver_status = status

        if status.state == DriverState.RUNNING and status.device_ready:
            self._set_driver_status("#1b6e2d", status.summary)
        elif status.state in (DriverState.RUNNING, DriverState.STOPPED, DriverState.PENDING):
            self._set_driver_status("#b26a00", status.summary)
        else:
            self._set_driver_status("#b00020", status.summary)

        self.install_driver_button.setEnabled(not status.installed)
        self.start_driver_button.setEnabled(status.installed and not status.running)
        self.uninstall_driver_button.setEnabled(status.installed)
        return status

    def ensure_driver_ready_on_startup(self):
        """客户端启动时的驱动状态检查：未安装则提示安装，已安装未启动则自动启动。"""
        status = self.refresh_driver_status()
        if status.state == DriverState.NOT_INSTALLED:
            choice = QMessageBox.question(
                self,
                "驱动未安装",
                "未检测到 NDISLWF 过滤驱动（服务 NdisLwf 未安装）。\n是否立即安装驱动？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if choice == QMessageBox.Yes:
                self.install_driver(prompt_package=False)
        elif status.state == DriverState.STOPPED:
            try:
                QApplication.setOverrideCursor(Qt.WaitCursor)
                try:
                    self.driver_manager.start()
                finally:
                    QApplication.restoreOverrideCursor()
            except (DriverManagerError, OSError) as err:
                self.refresh_driver_status()
                QMessageBox.warning(
                    self,
                    "自动启动驱动失败",
                    f"检测到 NDISLWF 驱动已安装但未启动，尝试自动启动失败：\n{err}",
                )
                return
            self.refresh_driver_status()
            self.load_rules(silent=True)

    def _pick_driver_package(self, prompt_package: bool):
        inf_path, sys_path = self.driver_manager.find_default_package()
        if prompt_package and inf_path and sys_path:
            box = QMessageBox(self)
            box.setWindowTitle("安装 NDISLWF 驱动")
            box.setIcon(QMessageBox.Question)
            box.setText(
                "检测到以下驱动安装文件：\n"
                f"INF: {inf_path}\n"
                f"SYS: {sys_path}\n\n"
                "是否直接使用以上文件安装驱动？"
            )
            use_default_btn = box.addButton("直接安装", QMessageBox.AcceptRole)
            choose_manual_btn = box.addButton("手动选择文件...", QMessageBox.ActionRole)
            box.addButton("取消", QMessageBox.RejectRole)
            box.exec_()
            clicked = box.clickedButton()
            if clicked == use_default_btn:
                return inf_path, sys_path
            if clicked != choose_manual_btn:
                return None, None
            inf_path, sys_path = None, None

        if not inf_path:
            inf_path, _ = QFileDialog.getOpenFileName(
                self, "选择驱动安装文件 (netlwf.inf)", self.driver_manager.project_root, "INF 文件 (*.inf)"
            )
            if not inf_path:
                return None, None

        if not sys_path:
            sibling_sys = os.path.join(os.path.dirname(inf_path), "ndislwf.sys")
            if os.path.isfile(sibling_sys):
                sys_path = sibling_sys
            else:
                sys_path, _ = QFileDialog.getOpenFileName(
                    self, "选择驱动二进制文件 (ndislwf.sys)", self.driver_manager.project_root, "驱动文件 (*.sys)"
                )
                if not sys_path:
                    return None, None
        return inf_path, sys_path

    def install_driver(self, prompt_package: bool = True):
        inf_path, sys_path = self._pick_driver_package(prompt_package=prompt_package)
        if not inf_path or not sys_path:
            return
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                status = self.driver_manager.install(inf_path=inf_path, sys_path=sys_path, start_after_install=True)
            finally:
                QApplication.restoreOverrideCursor()
        except (DriverManagerError, OSError) as err:
            self.refresh_driver_status()
            QMessageBox.warning(self, "安装驱动失败", f"安装 NDISLWF 驱动失败：\n{err}")
            return

        self.refresh_driver_status()
        self.load_rules(silent=True)
        extra = "\n系统提示需要重启计算机以完成网络驱动绑定生效。" if status.reboot_required else ""
        QMessageBox.information(self, "安装驱动完成", f"NDISLWF 驱动安装完成，当前状态：{status.summary}{extra}")

    def start_driver(self):
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                status = self.driver_manager.start()
            finally:
                QApplication.restoreOverrideCursor()
        except (DriverManagerError, OSError) as err:
            self.refresh_driver_status()
            QMessageBox.warning(self, "启动驱动失败", f"启动 NDISLWF 驱动失败：\n{err}")
            return
        self.refresh_driver_status()
        self.load_rules(silent=True)
        QMessageBox.information(self, "启动驱动完成", f"NDISLWF 驱动当前状态：{status.summary}")

    def uninstall_driver(self):
        confirm = QMessageBox.question(
            self,
            "卸载驱动",
            "确定要停止并卸载 NDISLWF 过滤驱动吗？\n卸载过程中网络连接可能会短暂中断。",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                status = self.driver_manager.uninstall()
            finally:
                QApplication.restoreOverrideCursor()
        except (DriverManagerError, OSError) as err:
            self.refresh_driver_status()
            QMessageBox.warning(self, "卸载驱动失败", f"卸载 NDISLWF 驱动失败：\n{err}")
            return

        self.rules = []
        self.refresh_driver_status()
        self.refresh_table()
        extra = "\n系统提示需要重启计算机以完成驱动清理。" if status.reboot_required else ""
        QMessageBox.information(self, "卸载驱动完成", f"NDISLWF 驱动已卸载，当前状态：{status.summary}{extra}")

    def show_driver_error(self, action: str, error: Exception):
        QMessageBox.warning(self, "驱动调用失败", f"{action}失败：{error}")

    def load_rules(self, silent: bool = False):
        status = self.refresh_driver_status()
        try:
            rules = self.driver.list_rules()
        except (DriverError, OSError) as err:
            self.rules = []
            if status.state == DriverState.RUNNING:
                self._set_driver_status("#b00020", str(err))
            self.refresh_table()
            if not silent:
                self.show_driver_error("查询规则", err)
            return

        self.name_store.reload()
        self.name_store.prune([r.rule_id for r in rules])
        self.name_store.apply_names(rules)
        self.rules = rules
        self._set_driver_status("#1b6e2d", f"已安装并运行中 ({self.driver.device_path})  |  支持 IPv4/IPv6、TCP/UDP、MAC 改写及本机环回")
        self.refresh_table()

    def refresh_table(self):
        self.rule_table.setRowCount(len(self.rules))
        icon = QApplication.style().standardIcon(QStyle.SP_DialogApplyButton)

        for row_index, rule in enumerate(self.rules):
            values = [
                QTableWidgetItem(str(rule.rule_id)),
                QTableWidgetItem(icon, rule.display_name),
                QTableWidgetItem(rule.orig_ip),
                QTableWidgetItem(rule.orig_port_text),
                QTableWidgetItem(rule.new_ip),
                QTableWidgetItem(rule.new_port_text),
                QTableWidgetItem(rule.protocol_text),
                QTableWidgetItem(rule.address_family_text),
                QTableWidgetItem(rule.options_text),
            ]
            for column, item in enumerate(values):
                self.rule_table.setItem(row_index, column, item)
            self.rule_table.setRowHeight(row_index, 30)

        if self.rules:
            self.rule_table.selectRow(0)
        self.rule_count.setText(f"规则数目：{len(self.rules)} / {MAX_REDIRECT_RULES} 条")
        self.ruleCountChanged.emit(len(self.rules))
        self.update_action_state()

    def current_rule_index(self) -> int:
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
        rule = dialog.get_rule()
        try:
            created = self.driver.add_rule(rule)
        except (DriverError, OSError, ValueError) as err:
            self.show_driver_error("添加规则", err)
            return
        self.name_store.set(created.rule_id, rule.name)
        self.load_rules(silent=False)

    def edit_rule(self):
        index = self.current_rule_index()
        if index < 0:
            return
        dialog = PortRuleDialog(self, self.rules[index])
        if dialog.exec_() != QDialog.Accepted:
            return
        rule = dialog.get_rule()
        try:
            updated = self.driver.update_rule(rule)
        except (DriverError, OSError, ValueError) as err:
            self.show_driver_error("修改规则", err)
            return
        self.name_store.set(updated.rule_id, rule.name)
        self.load_rules(silent=False)
        for row_idx, item in enumerate(self.rules):
            if item.rule_id == updated.rule_id:
                self.rule_table.selectRow(row_idx)
                break

    def remove_selected_rule(self):
        index = self.current_rule_index()
        if index < 0:
            return
        target = self.rules[index]
        try:
            self.driver.delete_rule(target.rule_id)
        except (DriverError, OSError, ValueError) as err:
            self.show_driver_error("删除规则", err)
            return
        self.name_store.delete(target.rule_id)
        self.load_rules(silent=False)

    def clear_rules(self):
        confirm = QMessageBox.question(
            self,
            "全部移除",
            f"确定要清空驱动中的全部 {len(self.rules)} 条重定向规则吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            self.driver.clear_rules()
        except (DriverError, OSError) as err:
            self.show_driver_error("清空规则", err)
            return
        self.name_store.clear()
        self.load_rules(silent=False)


class MainWindow(QMainWindow):
    def __init__(self, auto_check_driver: bool = True, driver_manager=None):
        super().__init__()
        self.setWindowTitle("CnCrypt Protect - 主机防护工具")
        self.resize(1120, 760)
        self.setStyleSheet(APP_STYLE)
        self._driver_manager = driver_manager
        self.port_redirect_page = None

        self._setup_menu_bar()
        self._setup_ui()

        if auto_check_driver and self.port_redirect_page is not None:
            QTimer.singleShot(0, self.port_redirect_page.ensure_driver_ready_on_startup)

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

        self.tab_widget = QTabWidget(content_host)
        stop_button = QPushButton("停止保护(S)", self.tab_widget)
        stop_button.setMinimumWidth(132)
        stop_button.clicked.connect(
            lambda: show_not_implemented(self.tab_widget, "提示", "当前版本未实现保护开关控制。")
        )
        self.tab_widget.setCornerWidget(stop_button, Qt.TopRightCorner)

        tabs = [
            "文件锁定",
            "注册表锁定",
            "网络管控",
            "驱动拦截",
            "动态库拦截",
            "进程拦截",
            "文件重定向",
            "端口重定向",
            "进程行为",
            "进程浏览器",
        ]

        port_redirect_index = 0
        for index, title in enumerate(tabs):
            if index == 0:
                self.tab_widget.addTab(FileFilterPage(self.tab_widget), title)
            elif title == "网络管控":
                self.tab_widget.addTab(NetworkMonitorPage(self.tab_widget), title)
            elif title == "端口重定向":
                port_redirect_index = index
                page = PortRedirectPage(self.tab_widget, driver_manager=self._driver_manager)
                self.port_redirect_page = page
                self.tab_widget.addTab(page, f"端口重定向({len(page.rules)})")
                page.ruleCountChanged.connect(
                    lambda count, tab_idx=index: self.tab_widget.setTabText(tab_idx, f"端口重定向({count})")
                )
            elif title == "进程浏览器":
                self.tab_widget.addTab(ProcessExplorerPage(self.tab_widget), title)
            else:
                self.tab_widget.addTab(PlaceholderPage(title, self.tab_widget), title)

        self.tab_widget.setCurrentIndex(port_redirect_index)
        content_layout.addWidget(self.tab_widget)
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
