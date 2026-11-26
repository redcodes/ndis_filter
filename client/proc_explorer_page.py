"""Process Explorer GUI page (a procexp-style process manager).

Top pane: a live process tree (parent/child by PPID). Bottom pane: the selected
process's threads, loaded modules and open handles. Toolbar actions kill,
suspend and resume the selection. Data comes from the CnCProcExp driver when it
is loaded, and from Toolhelp/NT user-mode APIs otherwise.
"""

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from proc_explorer import ProcExpClient

PID_ROLE = Qt.UserRole + 1

PROCESS_COLUMNS = ["Process", "PID", "Threads", "Handles", "Working Set", "User", "Image Path"]


def _table(columns):
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(columns)
    table.verticalHeader().setVisible(False)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setAlternatingRowColors(True)
    return table


class ProcessExplorerPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.client = ProcExpClient()
        self.processes = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        layout.addLayout(self._build_toolbar())

        self.tree = QTreeWidget(self)
        self.tree.setColumnCount(len(PROCESS_COLUMNS))
        self.tree.setHeaderLabels(PROCESS_COLUMNS)
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setMinimumHeight(320)
        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for column in range(1, len(PROCESS_COLUMNS)):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self.tree, 3)

        self.detail_tabs = QTabWidget(self)
        self.thread_table = _table(["TID", "Priority", "Base", "Ctx switches", "State", "Start address"])
        self.module_table = _table(["Module", "Base", "Size (KB)", "Path"])
        self.handle_table = _table(["Handle", "Type", "Access", "Name"])
        self.detail_tabs.addTab(self.thread_table, "Threads")
        self.detail_tabs.addTab(self.module_table, "Modules (DLLs)")
        self.detail_tabs.addTab(self.handle_table, "Handles")
        self.detail_tabs.setMinimumHeight(220)
        layout.addWidget(self.detail_tabs, 2)

        self.status_label = QLabel("", self)
        layout.addWidget(self.status_label)

        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self.refresh)

        self.refresh()

    def _build_toolbar(self):
        row = QHBoxLayout()
        refresh_button = QPushButton("Refresh", self)
        refresh_button.clicked.connect(self.refresh)

        self.auto_checkbox = QCheckBox("Auto refresh (2s)", self)
        self.auto_checkbox.toggled.connect(self._toggle_auto_refresh)

        self.filter_edit = QLineEdit(self)
        self.filter_edit.setPlaceholderText("Filter by name or PID...")
        self.filter_edit.setMaximumWidth(220)
        self.filter_edit.textChanged.connect(self._rebuild_tree)

        self.kill_button = QPushButton("Kill process", self)
        self.suspend_button = QPushButton("Suspend", self)
        self.resume_button = QPushButton("Resume", self)
        self.kill_button.clicked.connect(self._kill_selected)
        self.suspend_button.clicked.connect(self._suspend_selected)
        self.resume_button.clicked.connect(self._resume_selected)

        row.addWidget(refresh_button)
        row.addWidget(self.auto_checkbox)
        row.addWidget(self.filter_edit)
        row.addStretch(1)
        row.addWidget(self.suspend_button)
        row.addWidget(self.resume_button)
        row.addWidget(self.kill_button)
        return row

    # --- data ------------------------------------------------------------

    def refresh(self):
        try:
            self.processes = self.client.query_processes()
        except OSError as error:
            self.processes = []
            QMessageBox.warning(self, "Process explorer", f"Query processes failed: {error}")
        backend = "kernel driver (CnCProcExp)" if self.client.driver_loaded() else "user-mode fallback (driver not loaded)"
        self.status_label.setText(f"Processes: {len(self.processes)}   |   Source: {backend}")
        self._rebuild_tree()

    def _rebuild_tree(self):
        expanded = self._expanded_pids()
        selected = self.selected_pid()

        self.tree.clear()
        needle = self.filter_edit.text().strip().lower()

        by_pid = {p.process_id: p for p in self.processes}
        items = {}

        def make_item(proc):
            values = [
                proc.image_name or "(unknown)",
                str(proc.process_id),
                str(proc.thread_count),
                str(proc.handle_count),
                f"{proc.working_set_mb:,.1f} MB" if proc.working_set else "-",
                proc.user_name or "-",
                proc.image_path or "-",
            ]
            item = QTreeWidgetItem(values)
            item.setData(0, PID_ROLE, proc.process_id)
            item.setTextAlignment(1, Qt.AlignRight)
            item.setTextAlignment(2, Qt.AlignRight)
            item.setTextAlignment(3, Qt.AlignRight)
            item.setTextAlignment(4, Qt.AlignRight)
            return item

        # When filtering, show a flat list of matches; otherwise build the tree.
        if needle:
            for proc in self.processes:
                if needle in proc.image_name.lower() or needle in str(proc.process_id):
                    self.tree.addTopLevelItem(make_item(proc))
            self._restore_selection(selected)
            self._update_action_state()
            return

        for pid, proc in by_pid.items():
            items[pid] = make_item(proc)

        for pid, proc in by_pid.items():
            parent = by_pid.get(proc.parent_process_id)
            # Guard against PID reuse: a real parent must predate its child.
            valid_parent = (
                parent is not None
                and proc.parent_process_id != pid
                and (parent.create_time == 0 or proc.create_time == 0 or parent.create_time <= proc.create_time)
            )
            if valid_parent:
                items[proc.parent_process_id].addChild(items[pid])
            else:
                self.tree.addTopLevelItem(items[pid])

        for pid in expanded:
            if pid in items:
                items[pid].setExpanded(True)
        if not expanded:
            self.tree.expandToDepth(1)

        self._restore_selection(selected)
        self._update_action_state()

    def _expanded_pids(self):
        pids = set()

        def walk(item):
            if item.isExpanded():
                pids.add(item.data(0, PID_ROLE))
            for i in range(item.childCount()):
                walk(item.child(i))

        for i in range(self.tree.topLevelItemCount()):
            walk(self.tree.topLevelItem(i))
        return pids

    def _restore_selection(self, pid):
        if pid is None:
            return

        def walk(item):
            if item.data(0, PID_ROLE) == pid:
                self.tree.setCurrentItem(item)
                return True
            for i in range(item.childCount()):
                if walk(item.child(i)):
                    return True
            return False

        for i in range(self.tree.topLevelItemCount()):
            if walk(self.tree.topLevelItem(i)):
                return

    # --- selection / details --------------------------------------------

    def selected_pid(self):
        item = self.tree.currentItem()
        if item is None:
            return None
        return item.data(0, PID_ROLE)

    def _on_selection_changed(self):
        self._update_action_state()
        pid = self.selected_pid()
        if pid is None:
            return
        self._populate_threads(pid)
        self._populate_modules(pid)
        self._populate_handles(pid)

    def _update_action_state(self):
        has_selection = self.selected_pid() is not None
        self.kill_button.setEnabled(has_selection)
        self.suspend_button.setEnabled(has_selection)
        self.resume_button.setEnabled(has_selection)

    def _populate_threads(self, pid):
        try:
            threads = self.client.query_threads(pid)
        except OSError:
            threads = []
        self.thread_table.setRowCount(len(threads))
        for row, t in enumerate(threads):
            cells = [
                str(t.thread_id), str(t.priority), str(t.base_priority),
                str(t.context_switches), t.state_text, f"0x{t.start_address:016X}",
            ]
            for column, text in enumerate(cells):
                self.thread_table.setItem(row, column, QTableWidgetItem(text))

    def _populate_modules(self, pid):
        try:
            modules = self.client.query_modules(pid)
        except OSError:
            modules = []
        self.module_table.setRowCount(len(modules))
        for row, m in enumerate(modules):
            cells = [
                m.name, f"0x{m.base_address:016X}", f"{m.size / 1024:,.0f}", m.path,
            ]
            for column, text in enumerate(cells):
                self.module_table.setItem(row, column, QTableWidgetItem(text))

    def _populate_handles(self, pid):
        try:
            handles = self.client.query_handles(pid)
        except OSError:
            handles = []
        self.handle_table.setRowCount(len(handles))
        for row, h in enumerate(handles):
            cells = [
                f"0x{h.handle_value:X}", h.type_name or "-",
                f"0x{h.granted_access:08X}", h.name or "",
            ]
            for column, text in enumerate(cells):
                self.handle_table.setItem(row, column, QTableWidgetItem(text))

    # --- actions ---------------------------------------------------------

    def _selected_name(self):
        item = self.tree.currentItem()
        return item.text(0) if item else ""

    def _kill_selected(self):
        pid = self.selected_pid()
        if pid is None:
            return
        confirm = QMessageBox.question(
            self, "Kill process",
            f"Terminate {self._selected_name()} (PID {pid})?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            self.client.kill_process(pid)
        except OSError as error:
            QMessageBox.warning(self, "Kill process", f"Failed to terminate PID {pid}: {error}")
            return
        self.refresh()

    def _suspend_selected(self):
        pid = self.selected_pid()
        if pid is None:
            return
        try:
            self.client.suspend_process(pid)
        except OSError as error:
            QMessageBox.warning(self, "Suspend process", f"Failed to suspend PID {pid}: {error}")

    def _resume_selected(self):
        pid = self.selected_pid()
        if pid is None:
            return
        try:
            self.client.resume_process(pid)
        except OSError as error:
            QMessageBox.warning(self, "Resume process", f"Failed to resume PID {pid}: {error}")

    def _toggle_auto_refresh(self, enabled):
        if enabled:
            self.timer.start()
        else:
            self.timer.stop()
