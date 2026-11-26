"""Procmon-style live activity monitor for the CnC kernel filter suite.

Polls the process / file / registry filter drivers' event rings and shows a
single merged, filterable feed -- modeled after Sysinternals Process Monitor.

GUI:      python client\\procmon.py
Console:  python client\\procmon.py --console
"""

import argparse
import ctypes
import datetime
import socket
import struct
import sys
import time
from dataclasses import dataclass


# --------------------------------------------------------------------------
# Win32 device IO plumbing (shared by every source)
# --------------------------------------------------------------------------

METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None
if kernel32 is not None:
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
        ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.DeviceIoControl.argtypes = [
        ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
        ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p,
    ]
    kernel32.DeviceIoControl.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int


def ctl_code(device_type, function, method=METHOD_BUFFERED, access=FILE_ANY_ACCESS):
    return (device_type << 16) | (access << 14) | (function << 2) | method


def _device_io_control(device_path, control_code, in_buffer=b"", out_size=0):
    if kernel32 is None:
        raise OSError("filter devices are only available on Windows")

    handle = kernel32.CreateFileW(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
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


def _decode_wchars(values):
    chars = []
    for value in values:
        if value == 0:
            break
        chars.append(chr(value))
    return "".join(chars)


def filetime_to_local(ticks):
    if ticks == 0:
        return "-"
    try:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        when = epoch + datetime.timedelta(microseconds=ticks / 10)
        return when.astimezone().strftime("%H:%M:%S.%f")[:-3]
    except (OverflowError, OSError, ValueError):
        return str(ticks)


def result_text(status, blocked):
    if blocked:
        return "ACCESS DENIED"
    if status == 0:
        return "SUCCESS"
    return f"0x{status & 0xFFFFFFFF:08X}"


@dataclass
class Row:
    ticks: int
    source: str
    pid: int
    tid: int
    operation: str
    path: str
    detail: str
    result: str
    blocked: bool


# --------------------------------------------------------------------------
# Source definitions -- one per kernel driver
# --------------------------------------------------------------------------

EVENTS_HEADER = struct.Struct("<LL")
MONITOR_INPUT = struct.Struct("<L")
MAX_EVENTS = 256


class Source:
    name = "?"
    device_path = ""
    device_type = 0
    version = 1
    has_monitor = True
    event_struct = None
    fn_query_events = 0
    fn_clear_events = 0
    fn_set_monitor = 0

    def __init__(self):
        self.ioctl_query = ctl_code(self.device_type, self.fn_query_events)
        self.ioctl_clear = ctl_code(self.device_type, self.fn_clear_events)
        self.ioctl_monitor = ctl_code(self.device_type, self.fn_set_monitor) if self.has_monitor else 0

    def available(self):
        try:
            _device_io_control(self.device_path, self.ioctl_query,
                               out_size=EVENTS_HEADER.size + self.event_struct.size)
            return True
        except OSError:
            return False

    def set_monitor(self, enable):
        if not self.has_monitor:
            return
        _device_io_control(self.device_path, self.ioctl_monitor,
                           in_buffer=MONITOR_INPUT.pack(1 if enable else 0))

    def clear(self):
        _device_io_control(self.device_path, self.ioctl_clear)

    def poll(self, and_clear=True):
        out_size = EVENTS_HEADER.size + MAX_EVENTS * self.event_struct.size
        data = _device_io_control(self.device_path, self.ioctl_query, out_size=out_size)
        rows = []
        if len(data) >= EVENTS_HEADER.size:
            version, count = EVENTS_HEADER.unpack_from(data, 0)
            offset = EVENTS_HEADER.size
            for _ in range(count):
                chunk = data[offset: offset + self.event_struct.size]
                if len(chunk) < self.event_struct.size:
                    break
                rows.append(self.decode(self.event_struct.unpack(chunk)))
                offset += self.event_struct.size
        if and_clear:
            try:
                self.clear()
            except OSError:
                pass
        return [r for r in rows if r is not None]

    def decode(self, unpacked):
        raise NotImplementedError


class ProcessSource(Source):
    name = "进程"
    device_path = r"\\.\CnCProcFilter"
    device_type = 0x8004
    has_monitor = False  # proc_filter records events unconditionally
    fn_query_events = 0x907
    fn_clear_events = 0x908
    # Version, EventType, TimeStamp, Pid, CreatorPid, Flags, MatchedRuleId, ImagePath[260]
    event_struct = struct.Struct("<LLQLLLL260H")

    OPS = {1: "ProcessCreate", 2: "ProcessBlock", 3: "ProcessExit",
           4: "RemoteThread", 5: "ImageLoad", 6: "HandleStrip"}

    def decode(self, u):
        event_type, ticks, pid, creator, flags, rule_id = u[1], u[2], u[3], u[4], u[5], u[6]
        path = _decode_wchars(u[7: 7 + 260])
        blocked = bool(flags & 0x1)
        detail = ""
        if creator:
            detail = f"creator PID {creator}"
        if rule_id:
            detail = (detail + " " if detail else "") + f"rule {rule_id}"
        return Row(ticks, self.name, pid, 0, self.OPS.get(event_type, f"op{event_type}"),
                   path, detail, result_text(0, blocked), blocked)


class FileSource(Source):
    name = "文件"
    device_path = r"\\.\CnCFileFilter"
    device_type = 0x8000
    fn_query_events = 0x808
    fn_clear_events = 0x809
    fn_set_monitor = 0x807
    # Version, Operation, TimeStamp, Pid, Tid, Status(signed), Flags, DesiredAccess, Reserved, Path[260]
    event_struct = struct.Struct("<LLQLLlLLL260H")

    OPS = {1: "CreateFile", 2: "ReadFile", 3: "WriteFile",
           4: "DeleteFile", 5: "RenameFile", 6: "SetInformation"}

    def decode(self, u):
        operation, ticks, pid, tid, status, flags, desired = u[1], u[2], u[3], u[4], u[5], u[6], u[7]
        path = _decode_wchars(u[9: 9 + 260])
        blocked = bool(flags & 0x1)
        detail = f"access 0x{desired & 0xFFFFFFFF:08X}" if desired else ""
        return Row(ticks, self.name, pid, tid, self.OPS.get(operation, f"op{operation}"),
                   path, detail, result_text(status, blocked), blocked)


class RegistrySource(Source):
    name = "注册表"
    device_path = r"\\.\CnCRegFilter"
    device_type = 0x8001
    fn_query_events = 0x908
    fn_clear_events = 0x909
    fn_set_monitor = 0x907
    # Version, Operation, TimeStamp, Pid, Tid, Status(signed), Flags, KeyPath[512], ValueName[128]
    event_struct = struct.Struct("<LLQLLlL512H128H")

    OPS = {1: "RegSetValue", 2: "RegDeleteValue", 3: "RegDeleteKey",
           4: "RegRenameKey", 5: "RegCreateKey"}

    def decode(self, u):
        operation, ticks, pid, tid, status, flags = u[1], u[2], u[3], u[4], u[5], u[6]
        key_path = _decode_wchars(u[7: 7 + 512])
        value_name = _decode_wchars(u[7 + 512: 7 + 512 + 128])
        blocked = bool(flags & 0x1)
        detail = f"value: {value_name}" if value_name else ""
        return Row(ticks, self.name, pid, tid, self.OPS.get(operation, f"op{operation}"),
                   key_path, detail, result_text(status, blocked), blocked)


class NetSource:
    """Live TCP/UDP connection feed for Procmon, sourced in user mode.

    Unlike the process / file / registry sources, this one does *not* read a
    kernel event ring. The net_monitor driver is a WFP block-rule enforcement
    backend (net_monitor/cli.py) and -- by its own design -- leaves connection
    enumeration to user mode, because the kernel connection tables (NSI/TDI) are
    undocumented while the IP Helper API is not. So this source snapshots the
    IP Helper connection tables (with owning PID) each poll and emits a row for
    every connection that appeared or disappeared since the previous snapshot,
    merging into the same feed as the kernel sources.
    """

    name = "网络"

    AF_INET = 2
    AF_INET6 = 23
    TCP_TABLE_OWNER_PID_ALL = 5
    UDP_TABLE_OWNER_PID = 1

    # FILETIME epoch (1601-01-01) is 11644473600 seconds before the Unix epoch.
    _FILETIME_EPOCH_DELTA = 11644473600

    TCP_STATES = {
        1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
        6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
        10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
    }

    # Row layouts of the MIB_*ROW_OWNER_PID structures (all fields little-endian;
    # ports are stored in network byte order in the low 16 bits of a DWORD).
    _TCP4 = struct.Struct("<LLLLLL")          # state, laddr, lport, raddr, rport, pid
    _TCP6 = struct.Struct("<16sLL16sLLLL")    # laddr, lscope, lport, raddr, rscope, rport, state, pid
    _UDP4 = struct.Struct("<LLL")             # laddr, lport, pid
    _UDP6 = struct.Struct("<16sLLL")          # laddr, lscope, lport, pid

    def __init__(self):
        self._prev = {}
        self._name_cache = {}
        self._iphlpapi = None

        if kernel32 is None:
            return
        try:
            self._iphlpapi = ctypes.windll.iphlpapi
            table_argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_int,
                ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong,
            ]
            self._iphlpapi.GetExtendedTcpTable.argtypes = table_argtypes
            self._iphlpapi.GetExtendedTcpTable.restype = ctypes.c_ulong
            self._iphlpapi.GetExtendedUdpTable.argtypes = table_argtypes
            self._iphlpapi.GetExtendedUdpTable.restype = ctypes.c_ulong
            kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.QueryFullProcessImageNameW.argtypes = [
                ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong),
            ]
            kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
        except (OSError, AttributeError):
            self._iphlpapi = None

    # -- interface expected by the poller (duck-typed like Source) -----------

    def available(self):
        return self._iphlpapi is not None

    def set_monitor(self, enable):
        # Snapshot on start so only connections that change *after* capture
        # begins are reported, rather than dumping every existing socket.
        if enable:
            self._prev = self._snapshot()

    def clear(self):
        self._prev = self._snapshot()

    def poll(self, and_clear=True):
        if self._iphlpapi is None:
            return []
        current = self._snapshot()
        ticks = int((time.time() + self._FILETIME_EPOCH_DELTA) * 10_000_000)
        rows = []
        for key, info in current.items():
            if key not in self._prev:
                rows.append(self._row(info, ticks, opened=True))
        for key, info in self._prev.items():
            if key not in current:
                rows.append(self._row(info, ticks, opened=False))
        self._prev = current
        return rows

    # -- table enumeration ---------------------------------------------------

    def _get_table(self, fn, af, table_class):
        size = ctypes.c_ulong(0)
        fn(None, ctypes.byref(size), 0, af, table_class, 0)
        if size.value == 0:
            return b""
        buf = ctypes.create_string_buffer(size.value)
        if fn(buf, ctypes.byref(size), 0, af, table_class, 0) != 0:
            return b""
        return buf.raw[: size.value]

    def _snapshot(self):
        conns = {}
        if self._iphlpapi is None:
            return conns
        try:
            self._parse_tcp(conns, self.AF_INET)
            self._parse_tcp(conns, self.AF_INET6)
            self._parse_udp(conns, self.AF_INET)
            self._parse_udp(conns, self.AF_INET6)
        except (OSError, struct.error, ValueError):
            pass
        return conns

    def _parse_tcp(self, conns, af):
        data = self._get_table(self._iphlpapi.GetExtendedTcpTable, af, self.TCP_TABLE_OWNER_PID_ALL)
        if len(data) < 4:
            return
        count = struct.unpack_from("<L", data, 0)[0]
        row = self._TCP4 if af == self.AF_INET else self._TCP6
        offset = 4
        for _ in range(count):
            if offset + row.size > len(data):
                break
            fields = row.unpack_from(data, offset)
            offset += row.size
            if af == self.AF_INET:
                state, laddr, lport, raddr, rport, pid = fields
                la = socket.inet_ntoa(struct.pack("<L", laddr))
                ra = socket.inet_ntoa(struct.pack("<L", raddr))
            else:
                laddr, _ls, lport, raddr, _rs, rport, state, pid = fields
                la = socket.inet_ntop(socket.AF_INET6, laddr)
                ra = socket.inet_ntop(socket.AF_INET6, raddr)
            lp = socket.ntohs(lport & 0xFFFF)
            rp = socket.ntohs(rport & 0xFFFF)
            key = ("tcp", af, la, lp, ra, rp, pid)
            conns[key] = {"proto": "tcp", "la": la, "lp": lp, "ra": ra,
                          "rp": rp, "pid": pid, "state": state}

    def _parse_udp(self, conns, af):
        data = self._get_table(self._iphlpapi.GetExtendedUdpTable, af, self.UDP_TABLE_OWNER_PID)
        if len(data) < 4:
            return
        count = struct.unpack_from("<L", data, 0)[0]
        row = self._UDP4 if af == self.AF_INET else self._UDP6
        offset = 4
        for _ in range(count):
            if offset + row.size > len(data):
                break
            fields = row.unpack_from(data, offset)
            offset += row.size
            if af == self.AF_INET:
                laddr, lport, pid = fields
                la = socket.inet_ntoa(struct.pack("<L", laddr))
            else:
                laddr, _ls, lport, pid = fields
                la = socket.inet_ntop(socket.AF_INET6, laddr)
            lp = socket.ntohs(lport & 0xFFFF)
            key = ("udp", af, la, lp, "", 0, pid)
            conns[key] = {"proto": "udp", "la": la, "lp": lp, "pid": pid}

    # -- row rendering -------------------------------------------------------

    def _row(self, info, ticks, opened):
        pid = info["pid"]
        pname = self._proc_name(pid)
        if info["proto"] == "tcp":
            if info["rp"]:
                op = "TCP连接" if opened else "TCP关闭"
                path = f"{info['la']}:{info['lp']} -> {info['ra']}:{info['rp']}"
            else:
                op = "TCP监听" if opened else "TCP停止"
                path = f"{info['la']}:{info['lp']}"
            detail = self.TCP_STATES.get(info["state"], f"state{info['state']}")
        else:
            op = "UDP绑定" if opened else "UDP释放"
            path = f"{info['la']}:{info['lp']}"
            detail = ""
        if pname:
            detail = (detail + " " if detail else "") + pname
        return Row(ticks, self.name, pid, 0, op, path, detail, "SUCCESS", False)

    def _proc_name(self, pid):
        if pid in self._name_cache:
            return self._name_cache[pid]
        name = ""
        if pid == 0:
            name = "Idle"
        elif pid == 4:
            name = "System"
        elif kernel32 is not None:
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                try:
                    size = ctypes.c_ulong(260)
                    buf = ctypes.create_unicode_buffer(size.value)
                    if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                        name = buf.value.rsplit("\\", 1)[-1]
                finally:
                    kernel32.CloseHandle(handle)
        self._name_cache[pid] = name
        return name


def build_sources():
    return [ProcessSource(), FileSource(), RegistrySource(), NetSource()]


# --------------------------------------------------------------------------
# Console mode (no Qt required)
# --------------------------------------------------------------------------

def run_console(interval=0.4):
    sources = build_sources()
    active = []
    for source in sources:
        if source.available():
            try:
                source.set_monitor(True)
                source.clear()
            except OSError as error:
                print(f"[{source.name}] enable failed: {error}", file=sys.stderr)
                continue
            active.append(source)
            print(f"[+] monitoring {source.name} ({source.device_path})")
        else:
            print(f"[-] {source.name} unavailable ({source.device_path})")

    if not active:
        print("no filter devices available; install/start the drivers first", file=sys.stderr)
        return 1

    print("capturing... press Ctrl+C to stop\n")
    print(f"{'TIME':<13} {'SOURCE':<8} {'PID':>6} {'OPERATION':<16} RESULT / PATH")
    try:
        while True:
            batch = []
            for source in active:
                try:
                    batch.extend(source.poll())
                except OSError:
                    pass
            batch.sort(key=lambda r: r.ticks)
            for r in batch:
                mark = "!" if r.blocked else " "
                print(f"{filetime_to_local(r.ticks):<13} {r.source:<8} {r.pid:>6} "
                      f"{r.operation:<16}{mark}{r.result}  {r.path}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        for source in active:
            try:
                source.set_monitor(False)
            except OSError:
                pass
    return 0


# --------------------------------------------------------------------------
# GUI mode
# --------------------------------------------------------------------------

def run_gui():
    from PyQt5.QtCore import Qt, QTimer
    from PyQt5.QtGui import QColor
    from PyQt5.QtWidgets import (
        QAbstractItemView, QApplication, QCheckBox, QHBoxLayout, QHeaderView,
        QLabel, QLineEdit, QMainWindow, QPushButton, QTableWidget,
        QTableWidgetItem, QVBoxLayout, QWidget,
    )

    COLUMNS = ["时间", "来源", "PID", "TID", "操作", "路径", "详情", "结果"]
    MAX_ROWS = 20000

    class ProcmonWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("CnC 内核活动监视器 (Procmon 风格)")
            self.resize(1200, 700)

            self.sources = build_sources()
            self.source_boxes = {}
            self.capturing = False

            self.timer = QTimer(self)
            self.timer.setInterval(400)
            self.timer.timeout.connect(self._poll)

            central = QWidget()
            layout = QVBoxLayout(central)
            layout.setContentsMargins(8, 8, 8, 8)

            toolbar = QHBoxLayout()
            self.capture_btn = QPushButton("开始捕获")
            self.capture_btn.setCheckable(True)
            self.capture_btn.clicked.connect(self._toggle_capture)
            toolbar.addWidget(self.capture_btn)

            self.clear_btn = QPushButton("清空")
            self.clear_btn.clicked.connect(self._clear_table)
            toolbar.addWidget(self.clear_btn)

            self.autoscroll = QCheckBox("自动滚动")
            self.autoscroll.setChecked(True)
            toolbar.addWidget(self.autoscroll)

            toolbar.addSpacing(16)
            for source in self.sources:
                box = QCheckBox(source.name)
                box.setChecked(source.available())
                box.setEnabled(source.available())
                if not source.available():
                    box.setText(f"{source.name}(未安装)")
                self.source_boxes[source.name] = box
                toolbar.addWidget(box)

            toolbar.addSpacing(16)
            toolbar.addWidget(QLabel("过滤:"))
            self.filter_edit = QLineEdit()
            self.filter_edit.setPlaceholderText("按路径/操作/详情过滤...")
            self.filter_edit.textChanged.connect(self._apply_filter)
            toolbar.addWidget(self.filter_edit, 1)

            self.count_label = QLabel("0 事件")
            toolbar.addWidget(self.count_label)
            layout.addLayout(toolbar)

            self.table = QTableWidget(0, len(COLUMNS))
            self.table.setHorizontalHeaderLabels(COLUMNS)
            self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.table.verticalHeader().setVisible(False)
            self.table.setShowGrid(False)
            header = self.table.horizontalHeader()
            header.setSectionResizeMode(5, QHeaderView.Stretch)
            for col in (0, 1, 2, 3, 4, 6, 7):
                header.setSectionResizeMode(col, QHeaderView.ResizeToContents)
            layout.addWidget(self.table)

            self.setCentralWidget(central)
            self._refresh_count()

        def _toggle_capture(self):
            if self.capture_btn.isChecked():
                self._start_capture()
            else:
                self._stop_capture()

        def _start_capture(self):
            started = False
            for source in self.sources:
                if not self.source_boxes[source.name].isChecked():
                    continue
                try:
                    source.set_monitor(True)
                    source.clear()
                    started = True
                except OSError:
                    self.source_boxes[source.name].setChecked(False)
            if not started:
                self.capture_btn.setChecked(False)
                self.count_label.setText("无可用驱动")
                return
            self.capturing = True
            self.capture_btn.setText("停止捕获")
            self.timer.start()

        def _stop_capture(self):
            self.timer.stop()
            self.capturing = False
            self.capture_btn.setText("开始捕获")
            for source in self.sources:
                try:
                    source.set_monitor(False)
                except OSError:
                    pass

        def _poll(self):
            batch = []
            for source in self.sources:
                if not self.source_boxes[source.name].isChecked():
                    continue
                try:
                    batch.extend(source.poll())
                except OSError:
                    pass
            batch.sort(key=lambda r: r.ticks)
            for row in batch:
                self._append_row(row)
            if batch and self.autoscroll.isChecked():
                self.table.scrollToBottom()
            self._refresh_count()

        def _append_row(self, row):
            if self.table.rowCount() >= MAX_ROWS:
                self.table.removeRow(0)

            r = self.table.rowCount()
            self.table.insertRow(r)
            values = [
                filetime_to_local(row.ticks), row.source, str(row.pid),
                str(row.tid) if row.tid else "", row.operation, row.path,
                row.detail, row.result,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if row.blocked:
                    item.setBackground(QColor(0x4a, 0x1f, 0x1f))
                    item.setForeground(QColor(0xff, 0xd0, 0xd0))
                self.table.setItem(r, col, item)

            self._filter_row(r)

        def _row_matches(self, r):
            needle = self.filter_edit.text().strip().lower()
            if not needle:
                return True
            for col in (1, 4, 5, 6, 7):
                item = self.table.item(r, col)
                if item and needle in item.text().lower():
                    return True
            return False

        def _filter_row(self, r):
            self.table.setRowHidden(r, not self._row_matches(r))

        def _apply_filter(self):
            for r in range(self.table.rowCount()):
                self._filter_row(r)
            self._refresh_count()

        def _clear_table(self):
            self.table.setRowCount(0)
            for source in self.sources:
                try:
                    source.clear()
                except OSError:
                    pass
            self._refresh_count()

        def _refresh_count(self):
            visible = sum(1 for r in range(self.table.rowCount()) if not self.table.isRowHidden(r))
            self.count_label.setText(f"{visible}/{self.table.rowCount()} 事件")

        def closeEvent(self, event):
            if self.capturing:
                self._stop_capture()
            super().closeEvent(event)

    app = QApplication(sys.argv)
    window = ProcmonWindow()
    window.show()
    return app.exec_()


def main():
    parser = argparse.ArgumentParser(description="CnC Procmon-style activity monitor")
    parser.add_argument("--console", action="store_true", help="run a headless console tail instead of the GUI")
    parser.add_argument("--interval", type=float, default=0.4, help="console poll interval seconds")
    args = parser.parse_args()

    if args.console:
        return run_console(args.interval)
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
