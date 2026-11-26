from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QFormLayout,
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

from file_filter import FileFilterDriverClient, FileFilterRule


class FileRuleDialog(QDialog):
    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.rule = rule or FileFilterRule()
        self.setWindowTitle("File filter rule")
        self.setMinimumWidth(620)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.name_edit = QLineEdit(self)
        self.path_edit = QLineEdit(self)
        self.enabled_checkbox = QCheckBox("Enabled", self)
        self.deny_read_checkbox = QCheckBox("Block read", self)
        self.deny_write_checkbox = QCheckBox("Block write", self)
        self.deny_delete_checkbox = QCheckBox("Block delete", self)
        self.deny_rename_checkbox = QCheckBox("Block rename", self)

        form.addRow("Rule name", self.name_edit)
        form.addRow("NT path pattern", self.path_edit)
        form.addRow("", self.enabled_checkbox)
        form.addRow("", self.deny_read_checkbox)
        form.addRow("", self.deny_write_checkbox)
        form.addRow("", self.deny_delete_checkbox)
        form.addRow("", self.deny_rename_checkbox)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        ok_button = QPushButton("OK", self)
        cancel_button = QPushButton("Cancel", self)
        ok_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        buttons.addWidget(ok_button)
        buttons.addWidget(cancel_button)
        layout.addLayout(buttons)

        self.load_rule(self.rule)

    def load_rule(self, rule):
        self.name_edit.setText(rule.name)
        self.path_edit.setText(rule.path_pattern)
        self.enabled_checkbox.setChecked(rule.enabled)
        self.deny_read_checkbox.setChecked(rule.deny_read)
        self.deny_write_checkbox.setChecked(rule.deny_write)
        self.deny_delete_checkbox.setChecked(rule.deny_delete)
        self.deny_rename_checkbox.setChecked(rule.deny_rename)

    def get_rule(self):
        path_pattern = self.path_edit.text().strip()
        if not path_pattern:
            raise ValueError("NT path pattern is required")

        return FileFilterRule(
            rule_id=self.rule.rule_id,
            name=self.name_edit.text().strip() or "New file rule",
            path_pattern=path_pattern,
            enabled=self.enabled_checkbox.isChecked(),
            deny_read=self.deny_read_checkbox.isChecked(),
            deny_write=self.deny_write_checkbox.isChecked(),
            deny_delete=self.deny_delete_checkbox.isChecked(),
            deny_rename=self.deny_rename_checkbox.isChecked(),
        )


class FileFilterPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.driver = FileFilterDriverClient()
        self.rules = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        top_row = QHBoxLayout()
        add_button = QPushButton("Add rule...", self)
        refresh_button = QPushButton("Refresh", self)
        stats_button = QPushButton("Stats", self)
        add_button.clicked.connect(self.add_rule)
        refresh_button.clicked.connect(self.load_rules)
        stats_button.clicked.connect(self.show_stats)
        top_row.addWidget(add_button)
        top_row.addStretch(1)
        top_row.addWidget(refresh_button)
        top_row.addWidget(stats_button)

        self.rule_table = QTableWidget(0, 4, self)
        self.rule_table.setHorizontalHeaderLabels(["Rule name", "Path pattern", "Actions", "Status"])
        self.rule_table.verticalHeader().setVisible(False)
        self.rule_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rule_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.rule_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rule_table.setMinimumHeight(420)
        self.rule_table.itemSelectionChanged.connect(self.update_action_state)

        header = self.rule_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        bottom_row = QHBoxLayout()
        self.rule_count = QLabel("", self)
        self.edit_button = QPushButton("Edit...", self)
        self.remove_button = QPushButton("Remove", self)
        self.clear_button = QPushButton("Remove all", self)
        self.edit_button.clicked.connect(self.edit_rule)
        self.remove_button.clicked.connect(self.remove_selected_rule)
        self.clear_button.clicked.connect(self.clear_rules)
        bottom_row.addWidget(self.rule_count)
        bottom_row.addStretch(1)
        bottom_row.addWidget(self.edit_button)
        bottom_row.addWidget(self.remove_button)
        bottom_row.addWidget(self.clear_button)

        layout.addLayout(top_row)
        layout.addWidget(self.rule_table, 1)
        layout.addLayout(bottom_row)

        self.load_rules()

    def show_driver_error(self, action, error):
        QMessageBox.warning(self, "File filter driver call failed", f"{action} failed: {error}")

    def load_rules(self):
        try:
            self.rules = self.driver.query_rules()
        except OSError as error:
            self.show_driver_error("Query rules", error)
            self.rules = []
        self.refresh_table()

    def refresh_table(self):
        self.rule_table.setRowCount(len(self.rules))
        for row_index, rule in enumerate(self.rules):
            values = [
                QTableWidgetItem(rule.name),
                QTableWidgetItem(rule.path_pattern),
                QTableWidgetItem(rule.action_text),
                QTableWidgetItem(rule.status),
            ]
            for column, item in enumerate(values):
                self.rule_table.setItem(row_index, column, item)
            self.rule_table.setRowHeight(row_index, 30)

        if self.rules:
            self.rule_table.selectRow(0)
        self.rule_count.setText(f"Rules: {len(self.rules)}")
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
        dialog = FileRuleDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return
        try:
            self.driver.add_rule(dialog.get_rule())
            self.load_rules()
        except (OSError, ValueError) as error:
            self.show_driver_error("Add rule", error)

    def edit_rule(self):
        index = self.current_rule_index()
        if index < 0:
            return
        dialog = FileRuleDialog(self, self.rules[index])
        if dialog.exec_() != QDialog.Accepted:
            return
        try:
            self.driver.update_rule(dialog.get_rule())
            self.load_rules()
            if index < len(self.rules):
                self.rule_table.selectRow(index)
        except (OSError, ValueError) as error:
            self.show_driver_error("Update rule", error)

    def remove_selected_rule(self):
        index = self.current_rule_index()
        if index < 0:
            return
        try:
            self.driver.delete_rule(self.rules[index].rule_id)
            self.load_rules()
        except OSError as error:
            self.show_driver_error("Remove rule", error)

    def clear_rules(self):
        for rule in list(self.rules):
            try:
                self.driver.delete_rule(rule.rule_id)
            except OSError as error:
                self.show_driver_error("Remove all rules", error)
                break
        self.load_rules()

    def show_stats(self):
        try:
            stats = self.driver.query_stats()
        except OSError as error:
            self.show_driver_error("Query stats", error)
            return

        QMessageBox.information(
            self,
            "File filter stats",
            "\n".join(
                [
                    f"Examined creates: {stats.examined_creates}",
                    f"Blocked creates: {stats.blocked_creates}",
                    f"Examined set information: {stats.examined_set_information}",
                    f"Blocked set information: {stats.blocked_set_information}",
                ]
            ),
        )
