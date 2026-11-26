r"""域名欺骗（DNS Spoofing）GUI 页面与规则编辑对话框。"""

from PyQt5.QtCore import Qt, pyqtSignal
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
    QMessageBox,
    QPushButton,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dns_spoof_driver import (
    DNS_SPOOF_DEFAULT_TTL,
    DnsSpoofDriverClient,
    DnsSpoofRule,
    MAX_DNS_SPOOF_RULES,
    flush_dns_cache,
    pack_dns_spoof_rule,
    unpack_dns_spoof_rule,
)
from redirect_driver import DriverError


class DnsSpoofRuleDialog(QDialog):
    """域名欺骗规则编辑弹窗。"""

    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        is_edit = rule is not None and rule.rule_id > 0
        self.setWindowTitle("CnCrypt Protect - 编辑域名欺骗规则" if is_edit else "CnCrypt Protect - 添加域名欺骗规则")
        self.setFixedWidth(560)
        self.rule = rule or DnsSpoofRule()
        self._validated_rule = None

        panel = QFrame(self)
        panel.setProperty("panel", True)

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(12, 16, 12, 12)
        root_layout.addWidget(panel)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(24, 18, 24, 16)
        layout.setSpacing(12)

        layout.addWidget(QLabel("目标域名（支持精确域名或 *. 通配符）", panel))
        self.domain_edit = QLineEdit(panel)
        self.domain_edit.setPlaceholderText("例如 baidu.com 或 *.baidu.com")
        layout.addWidget(self.domain_edit)

        self.wildcard_checkbox = QCheckBox("按通配符匹配所有子域名（自动规范为 *.域名）", panel)
        layout.addWidget(self.wildcard_checkbox)

        ip_grid = QGridLayout()
        ip_grid.setHorizontalSpacing(18)
        ip_grid.setVerticalSpacing(8)

        self.ipv4_edit = QLineEdit(panel)
        self.ipv4_edit.setPlaceholderText("可选，例如 1.1.1.1")
        self.ipv6_edit = QLineEdit(panel)
        self.ipv6_edit.setPlaceholderText("可选，例如 2001:db8::1")
        self.ttl_edit = QLineEdit(panel)
        self.ttl_edit.setPlaceholderText(f"默认 {DNS_SPOOF_DEFAULT_TTL} 秒")
        self.ttl_edit.setMaximumWidth(140)

        ip_grid.addWidget(QLabel("伪造 IPv4 地址 (A 记录)", panel), 0, 0)
        ip_grid.addWidget(QLabel("伪造 IPv6 地址 (AAAA 记录)", panel), 0, 1)
        ip_grid.addWidget(self.ipv4_edit, 1, 0)
        ip_grid.addWidget(self.ipv6_edit, 1, 1)
        ip_grid.addWidget(QLabel("应答 TTL (秒)", panel), 2, 0)
        ip_grid.addWidget(self.ttl_edit, 3, 0)
        layout.addLayout(ip_grid)

        tip = QLabel(
            "说明：至少填写 IPv4 或 IPv6 之一。若仅配置 IPv4，驱动对同域名的 AAAA 查询会自动返回 "
            "NODATA，避免系统优先解析真实 IPv6 导致欺骗失效。精确匹配优先于通配符匹配。",
            panel,
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #555555; font-size: 12px;")
        layout.addWidget(tip)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        ok_btn = QPushButton("确定", panel)
        cancel_btn = QPushButton("取消", panel)
        ok_btn.setMinimumWidth(100)
        cancel_btn.setMinimumWidth(100)
        ok_btn.clicked.connect(self._on_accept)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

        self._load_rule(self.rule)

    def _load_rule(self, rule: DnsSpoofRule):
        self.domain_edit.setText(rule.domain)
        self.wildcard_checkbox.setChecked(rule.wildcard or rule.domain.startswith("*."))
        self.ipv4_edit.setText(rule.fake_ipv4)
        self.ipv6_edit.setText(rule.fake_ipv6)
        self.ttl_edit.setText(str(rule.ttl if rule.ttl > 0 else DNS_SPOOF_DEFAULT_TTL))

    def _build_rule(self) -> DnsSpoofRule:
        try:
            ttl = int(self.ttl_edit.text().strip() or str(DNS_SPOOF_DEFAULT_TTL))
        except ValueError as err:
            raise ValueError("TTL 必须是非负整数。") from err

        candidate = DnsSpoofRule(
            rule_id=self.rule.rule_id,
            domain=self.domain_edit.text().strip(),
            fake_ipv4=self.ipv4_edit.text().strip(),
            fake_ipv6=self.ipv6_edit.text().strip(),
            ttl=ttl,
            wildcard=self.wildcard_checkbox.isChecked(),
        )
        # 复用打包校验确保与内核规则完全一致
        return unpack_dns_spoof_rule(pack_dns_spoof_rule(candidate))

    def _on_accept(self):
        try:
            self._validated_rule = self._build_rule()
        except ValueError as err:
            QMessageBox.warning(self, "参数错误", str(err))
            return
        self.accept()

    def get_rule(self) -> DnsSpoofRule:
        if self._validated_rule is not None:
            return self._validated_rule
        return self._build_rule()


class DnsSpoofPage(QWidget):
    """域名欺骗管理页签：控制 NDISLWF 驱动的 DNS 欺骗规则并自动刷新本机 DNS 缓存。"""

    ruleCountChanged = pyqtSignal(int)

    def __init__(self, parent=None, driver=None):
        super().__init__(parent)
        self.driver = driver or DnsSpoofDriverClient()
        self.rules = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        add_btn = QPushButton("添加规则(C)...", self)
        add_btn.setMinimumWidth(132)
        add_btn.clicked.connect(self.add_rule)

        flush_btn = QPushButton("刷新本机 DNS 缓存", self)
        flush_btn.clicked.connect(self.flush_cache)

        refresh_btn = QPushButton("查询规则(Q)", self)
        refresh_btn.clicked.connect(lambda: self.load_rules(silent=False))

        top_row.addWidget(add_btn, 0, Qt.AlignLeft)
        top_row.addStretch(1)
        top_row.addWidget(flush_btn)
        top_row.addWidget(refresh_btn)

        self.status_label = QLabel("", self)
        self.status_label.setStyleSheet("color: #1a1a1a; font-size: 13px;")

        self.rule_table = QTableWidget(0, 6, self)
        self.rule_table.setHorizontalHeaderLabels(
            ["ID", "域名", "匹配模式", "伪造 IPv4 (A)", "伪造 IPv6 (AAAA)", "TTL (秒)"]
        )
        self.rule_table.verticalHeader().setVisible(False)
        self.rule_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rule_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.rule_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rule_table.setFocusPolicy(Qt.NoFocus)
        self.rule_table.setShowGrid(True)
        self.rule_table.setMinimumHeight(420)
        self.rule_table.itemSelectionChanged.connect(self.update_action_state)
        self.rule_table.itemDoubleClicked.connect(lambda _item: self.edit_rule())

        header = self.rule_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        for col in range(2, 6):
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
        layout.addWidget(self.status_label)
        layout.addWidget(self.rule_table, 1)
        layout.addLayout(bottom_row)

        self.load_rules(silent=True)

    def _set_status(self, ok: bool, text: str):
        color = "#1b6e2d" if ok else "#b00020"
        self.status_label.setStyleSheet(f"color: {color}; font-size: 13px;")
        self.status_label.setText(f"域名欺骗状态：{text}")

    def load_rules(self, silent: bool = False):
        try:
            rules = self.driver.list_rules()
        except (DriverError, OSError) as err:
            self.rules = []
            self._set_status(False, str(err))
            self.refresh_table()
            if not silent:
                QMessageBox.warning(self, "驱动调用失败", f"查询域名欺骗规则失败：{err}")
            return

        self.rules = rules
        self._set_status(
            True,
            f"已连接 ({self.driver.device_path})  |  拦截 UDP/53 (A/AAAA)，支持通配符与变更后自动刷新 DNS 缓存",
        )
        self.refresh_table()

    def refresh_table(self):
        self.rule_table.setRowCount(len(self.rules))
        icon = QApplication.style().standardIcon(QStyle.SP_DialogApplyButton)

        for row_idx, rule in enumerate(self.rules):
            items = [
                QTableWidgetItem(str(rule.rule_id)),
                QTableWidgetItem(icon, rule.domain),
                QTableWidgetItem(rule.match_mode_text),
                QTableWidgetItem(rule.ipv4_text),
                QTableWidgetItem(rule.ipv6_text),
                QTableWidgetItem(str(rule.ttl)),
            ]
            for col, item in enumerate(items):
                if col != 1:
                    item.setTextAlignment(Qt.AlignCenter)
                self.rule_table.setItem(row_idx, col, item)
            self.rule_table.setRowHeight(row_idx, 30)

        if self.rules:
            self.rule_table.selectRow(0)
        self.rule_count.setText(f"规则数目：{len(self.rules)} / {MAX_DNS_SPOOF_RULES} 条")
        self.ruleCountChanged.emit(len(self.rules))
        self.update_action_state()

    def current_rule_index(self) -> int:
        rows = self.rule_table.selectionModel().selectedRows()
        return rows[0].row() if rows else -1

    def update_action_state(self):
        has_rules = bool(self.rules)
        has_sel = self.current_rule_index() >= 0
        self.edit_button.setEnabled(has_sel)
        self.remove_button.setEnabled(has_sel)
        self.clear_button.setEnabled(has_rules)

    def add_rule(self):
        dlg = DnsSpoofRuleDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        try:
            self.driver.add_rule(dlg.get_rule(), flush_cache=True)
        except (DriverError, OSError, ValueError) as err:
            QMessageBox.warning(self, "添加失败", f"添加域名欺骗规则失败：{err}")
            return
        self.load_rules(silent=False)

    def edit_rule(self):
        idx = self.current_rule_index()
        if idx < 0:
            return
        dlg = DnsSpoofRuleDialog(self, self.rules[idx])
        if dlg.exec_() != QDialog.Accepted:
            return
        try:
            updated = self.driver.update_rule(dlg.get_rule(), flush_cache=True)
        except (DriverError, OSError, ValueError) as err:
            QMessageBox.warning(self, "修改失败", f"修改域名欺骗规则失败：{err}")
            return
        self.load_rules(silent=False)
        for row_idx, item in enumerate(self.rules):
            if item.rule_id == updated.rule_id:
                self.rule_table.selectRow(row_idx)
                break

    def remove_selected_rule(self):
        idx = self.current_rule_index()
        if idx < 0:
            return
        try:
            self.driver.delete_rule(self.rules[idx].rule_id, flush_cache=True)
        except (DriverError, OSError, ValueError) as err:
            QMessageBox.warning(self, "删除失败", f"删除域名欺骗规则失败：{err}")
            return
        self.load_rules(silent=False)

    def clear_rules(self):
        confirm = QMessageBox.question(
            self,
            "全部移除",
            f"确定要清空驱动中的全部 {len(self.rules)} 条域名欺骗规则吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            self.driver.clear_rules(flush_cache=True)
        except (DriverError, OSError) as err:
            QMessageBox.warning(self, "清空失败", f"清空域名欺骗规则失败：{err}")
            return
        self.load_rules(silent=False)

    def flush_cache(self):
        if flush_dns_cache():
            QMessageBox.information(self, "刷新 DNS 缓存", "已成功刷新本机 DNS 解析器缓存。")
        else:
            QMessageBox.warning(self, "刷新 DNS 缓存", "刷新本机 DNS 缓存失败，请确认在 Windows 环境下运行。")
