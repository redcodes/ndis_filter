r"""NDISLWF 驱动安装、卸载、启停与状态查询模块（纯 Python，无 GUI 依赖）。

设计要点：
  - 状态查询与服务启停：直接调用 Win32 SCM API (advapi32.dll)，查询仅需只读权限。
  - 安装与卸载：NDIS 6.0 LWF (Class=NetService, ComponentId=MS_NdisLwf) 必须经由 NetCfg
    注册并绑定网卡，不能仅用 sc create。模块优先使用系统自带 netcfg.exe（Win10/11），
    当系统缺少 netcfg.exe（如 Win7）时自动回退到原生 SetupCopyOEMInfW + INetCfg COM 接口。
  - 安装包暂存：当 netlwf.inf 与 ndislwf.sys 分处不同目录（如开发仓库结构）时，自动打包至
    临时目录执行安装并清理。
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from redirect_driver import DEVICE_PATH, RedirectDriverClient

if sys.platform == "win32":
    from ctypes import wintypes

# ---------------------------------------------------------------------------
# 驱动标识常量（严格对应 driver/netlwf.inf）
# ---------------------------------------------------------------------------

SERVICE_NAME = "NdisLwf"
COMPONENT_ID = "MS_NdisLwf"
INF_FILENAME = "netlwf.inf"
SYS_FILENAME = "ndislwf.sys"
DISPLAY_NAME = "NDIS Sample LightWeight Filter"

# SCM 常量
SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_CONTROL_STOP = 0x00000001
SC_STATUS_PROCESS_INFO = 0

SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_CONTINUE_PENDING = 5
SERVICE_PAUSE_PENDING = 6
SERVICE_PAUSED = 7

SERVICE_STATE_NAMES = {
    SERVICE_STOPPED: "已停止",
    SERVICE_START_PENDING: "正在启动",
    SERVICE_STOP_PENDING: "正在停止",
    SERVICE_RUNNING: "运行中",
    SERVICE_CONTINUE_PENDING: "正在恢复",
    SERVICE_PAUSE_PENDING: "正在暂停",
    SERVICE_PAUSED: "已暂停",
}

ERROR_ACCESS_DENIED = 5
ERROR_SERVICE_ALREADY_RUNNING = 1056
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_NOT_ACTIVE = 1062

# NetCfg COM 常量
CLSID_CNETCFG_STR = "{5B035261-40F9-11D1-AAEC-00805FC1270E}"
IID_INETCFG_STR = "{C0E8AE93-306E-11D1-AACF-00805FC1270E}"
IID_INETCFGLOCK_STR = "{C0E8AE9F-306E-11D1-AACF-00805FC1270E}"
IID_INETCFGCLASSSETUP_STR = "{C0E8AE9D-306E-11D1-AACF-00805FC1270E}"
GUID_DEVCLASS_NETSERVICE_STR = "{4D36E974-E325-11CE-BFC1-08002BE10318}"

COINIT_APARTMENTTHREADED = 0x2
CLSCTX_INPROC_SERVER = 0x1
SPOST_PATH = 1
OBO_USER = 1
NETCFG_S_REBOOT = 0x0004A020
S_OK = 0
S_FALSE = 1

_is_windows = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Win32 结构体与 DLL 绑定
# ---------------------------------------------------------------------------


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_str(cls, text: str) -> "_GUID":
        parsed = uuid.UUID(text)
        data4 = (ctypes.c_ubyte * 8).from_buffer_copy(parsed.bytes[8:])
        return cls(parsed.time_low, parsed.time_mid, parsed.time_hi_version, data4)


class _OBO_TOKEN(ctypes.Structure):
    _fields_ = [
        ("Type", ctypes.c_int),
        ("pncc", ctypes.c_void_p),
        ("pszwManufacturer", ctypes.c_wchar_p),
        ("pszwProduct", ctypes.c_wchar_p),
        ("pszwDisplayName", ctypes.c_wchar_p),
        ("fRegistered", ctypes.c_int),
    ]


if _is_windows:

    class _SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    class _SERVICE_STATUS_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
            ("dwProcessId", wintypes.DWORD),
            ("dwServiceFlags", wintypes.DWORD),
        ]

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _advapi32.OpenSCManagerW.restype = ctypes.c_void_p

    _advapi32.OpenServiceW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD]
    _advapi32.OpenServiceW.restype = ctypes.c_void_p

    _advapi32.QueryServiceStatusEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.QueryServiceStatusEx.restype = wintypes.BOOL

    _advapi32.StartServiceW.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    _advapi32.StartServiceW.restype = wintypes.BOOL

    _advapi32.ControlService.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_SERVICE_STATUS),
    ]
    _advapi32.ControlService.restype = wintypes.BOOL

    _advapi32.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    _advapi32.CloseServiceHandle.restype = wintypes.BOOL

    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    _shell32.IsUserAnAdmin.argtypes = []
    _shell32.IsUserAnAdmin.restype = wintypes.BOOL

    _setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
    _setupapi.SetupCopyOEMInfW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    _setupapi.SetupCopyOEMInfW.restype = wintypes.BOOL

    _ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    _ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    _ole32.CoInitializeEx.restype = ctypes.c_long
    _ole32.CoUninitialize.argtypes = []
    _ole32.CoUninitialize.restype = None
    _ole32.CoCreateInstance.argtypes = [
        ctypes.POINTER(_GUID),
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_GUID),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _ole32.CoCreateInstance.restype = ctypes.c_long
    _ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    _ole32.CoTaskMemFree.restype = None
else:
    _advapi32 = None
    _shell32 = None
    _setupapi = None
    _ole32 = None


# ---------------------------------------------------------------------------
# 状态枚举、数据结构与异常
# ---------------------------------------------------------------------------


class DriverState(Enum):
    NOT_INSTALLED = "not_installed"
    STOPPED = "stopped"
    RUNNING = "running"
    PENDING = "pending"
    UNKNOWN = "unknown"


@dataclass
class DriverStatus:
    state: DriverState
    installed: bool
    running: bool
    service_state_code: int = 0
    service_state_text: str = ""
    device_ready: bool = False
    is_admin: bool = False
    reboot_required: bool = False
    detail: str = ""

    @property
    def summary(self) -> str:
        if self.state == DriverState.NOT_INSTALLED:
            return "未安装"
        if self.state == DriverState.RUNNING:
            if self.device_ready:
                return f"已安装并运行中 ({DEVICE_PATH})"
            return "服务运行中（控制设备暂不可访问，可能需要管理员权限）"
        if self.state == DriverState.STOPPED:
            return "已安装但未启动"
        if self.state == DriverState.PENDING:
            return f"状态切换中 ({self.service_state_text})"
        return self.detail or "状态未知"


class DriverManagerError(OSError):
    """驱动安装、卸载或启停操作失败异常。"""

    def __init__(self, message: str, code: Optional[int] = None, reboot_required: bool = False):
        super().__init__(message)
        self.code = code
        self.reboot_required = reboot_required


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def is_user_admin() -> bool:
    if not _is_windows or _shell32 is None:
        return False
    try:
        return bool(_shell32.IsUserAnAdmin())
    except OSError:
        return False


def _detect_os_arch() -> str:
    """返回目标操作系统架构：'amd64' 或 'x86'。"""
    env_arch = (
        os.environ.get("PROCESSOR_ARCHITEW6432")
        or os.environ.get("PROCESSOR_ARCHITECTURE")
        or platform.machine()
        or ""
    ).lower()
    if "64" in env_arch or "amd64" in env_arch or "x86_64" in env_arch:
        return "amd64"
    return "x86"


def find_netcfg_executable() -> Optional[str]:
    """定位系统 netcfg.exe（兼容 32 位 Python 在 64 位 Windows 下的 Sysnative 路径）。"""
    if not _is_windows:
        return None
    windir = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    candidates = [
        os.path.join(windir, "Sysnative", "netcfg.exe"),
        os.path.join(windir, "System32", "netcfg.exe"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return shutil.which("netcfg.exe")


def _com_vtable_fn(com_ptr: ctypes.c_void_p, slot: int, restype, *argtypes):
    vtable_ptr = ctypes.cast(com_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    func_addr = vtable_ptr[slot]
    proto = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)
    return proto(func_addr)


def _com_release(com_ptr: Optional[ctypes.c_void_p]) -> None:
    if com_ptr and com_ptr.value:
        release = _com_vtable_fn(com_ptr, 2, ctypes.c_ulong)
        release(com_ptr)


# ---------------------------------------------------------------------------
# 驱动管理器
# ---------------------------------------------------------------------------


class NdisLwfDriverManager:
    """管理 NDISLWF 驱动的安装、卸载、启停与状态查询。"""

    def __init__(
        self,
        service_name: str = SERVICE_NAME,
        component_id: str = COMPONENT_ID,
        device_path: str = DEVICE_PATH,
        project_root: Optional[str] = None,
    ):
        self.service_name = service_name
        self.component_id = component_id
        self.device_path = device_path
        if project_root is None:
            if getattr(sys, "frozen", False):
                self.project_root = os.path.dirname(os.path.abspath(sys.executable))
            else:
                self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        else:
            self.project_root = os.path.abspath(project_root)

    # --- 权限与驱动包定位 -------------------------------------------------

    def is_admin(self) -> bool:
        return is_user_admin()

    def _require_windows_and_admin(self, action_name: str) -> None:
        if not _is_windows:
            raise DriverManagerError(f"当前系统不是 Windows，无法执行{action_name}。")
        if not self.is_admin():
            raise DriverManagerError(
                f"{action_name}需要管理员权限，请以管理员身份重新运行程序。",
                code=ERROR_ACCESS_DENIED,
            )

    def find_default_package(self, arch: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """自动在仓库目录中探测 netlwf.inf 和对应架构的 ndislwf.sys。"""
        target_arch = (arch or _detect_os_arch()).lower()
        driver_dir = os.path.join(self.project_root, "driver")
        dist_dir = os.path.join(self.project_root, "dist")

        if target_arch == "amd64":
            sys_candidates = [
                os.path.join(dist_dir, "ndislwf_win7_x64", SYS_FILENAME),
                os.path.join(driver_dir, "objfre_win7_amd64", "amd64", SYS_FILENAME),
                os.path.join(driver_dir, "objchk_win7_amd64", "amd64", SYS_FILENAME),
                os.path.join(driver_dir, SYS_FILENAME),
                os.path.join(self.project_root, SYS_FILENAME),
            ]
            inf_candidates = [
                os.path.join(dist_dir, "ndislwf_win7_x64", INF_FILENAME),
                os.path.join(driver_dir, INF_FILENAME),
                os.path.join(self.project_root, INF_FILENAME),
            ]
        else:
            sys_candidates = [
                os.path.join(dist_dir, "ndislwf_win7_x86", SYS_FILENAME),
                os.path.join(driver_dir, "objfre_win7_x86", "i386", SYS_FILENAME),
                os.path.join(driver_dir, "objchk_win7_x86", "i386", SYS_FILENAME),
                os.path.join(driver_dir, SYS_FILENAME),
                os.path.join(self.project_root, SYS_FILENAME),
            ]
            inf_candidates = [
                os.path.join(dist_dir, "ndislwf_win7_x86", INF_FILENAME),
                os.path.join(driver_dir, INF_FILENAME),
                os.path.join(self.project_root, INF_FILENAME),
            ]

        inf_path = next((p for p in inf_candidates if os.path.isfile(p)), None)
        sys_path = next((p for p in sys_candidates if os.path.isfile(p)), None)
        return inf_path, sys_path

    def _resolve_package_files(
        self, inf_path: Optional[str], sys_path: Optional[str]
    ) -> Tuple[str, str]:
        default_inf, default_sys = self.find_default_package()
        resolved_inf = os.path.abspath(inf_path) if inf_path else default_inf
        if not resolved_inf or not os.path.isfile(resolved_inf):
            raise DriverManagerError(f"未找到驱动安装文件 {INF_FILENAME}，请检查 driver 目录或手动选择。")

        resolved_sys = os.path.abspath(sys_path) if sys_path else None
        if not resolved_sys:
            sibling_sys = os.path.join(os.path.dirname(resolved_inf), SYS_FILENAME)
            if os.path.isfile(sibling_sys):
                resolved_sys = sibling_sys
            else:
                resolved_sys = default_sys

        if not resolved_sys or not os.path.isfile(resolved_sys):
            raise DriverManagerError(
                f"未找到驱动二进制文件 {SYS_FILENAME}，请先编译驱动或手动选择该文件。"
            )
        return resolved_inf, resolved_sys

    @staticmethod
    def _stage_package(inf_path: str, sys_path: str) -> Tuple[str, str]:
        """将 netlwf.inf、ndislwf.sys 及可选 .cat 暂存至同一临时目录，避免目录分离或路径问题。"""
        staging_dir = tempfile.mkdtemp(prefix="ndislwf_install_")
        staged_inf = os.path.join(staging_dir, os.path.basename(inf_path))
        staged_sys = os.path.join(staging_dir, SYS_FILENAME)
        shutil.copy2(inf_path, staged_inf)
        shutil.copy2(sys_path, staged_sys)

        for src_dir in {os.path.dirname(inf_path), os.path.dirname(sys_path)}:
            try:
                for entry in os.listdir(src_dir):
                    if entry.lower().endswith(".cat"):
                        dst_cat = os.path.join(staging_dir, entry)
                        if not os.path.exists(dst_cat):
                            shutil.copy2(os.path.join(src_dir, entry), dst_cat)
            except OSError:
                pass
        return staging_dir, staged_inf

    # --- 状态查询（SCM + 设备探测） ---------------------------------------

    def _query_scm_service_state(self) -> Tuple[bool, int]:
        """查询 SCM 服务状态，返回 (installed, dwCurrentState)。"""
        if not _is_windows or _advapi32 is None:
            return False, 0

        scm = _advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not scm:
            err = ctypes.get_last_error()
            raise DriverManagerError(f"无法打开服务控制管理器（WinError {err}）。", code=err)

        svc = None
        try:
            svc = _advapi32.OpenServiceW(scm, self.service_name, SERVICE_QUERY_STATUS)
            if not svc:
                err = ctypes.get_last_error()
                if err == ERROR_SERVICE_DOES_NOT_EXIST:
                    return False, 0
                raise DriverManagerError(
                    f"查询服务 {self.service_name} 失败（WinError {err}）。", code=err
                )

            ssp = _SERVICE_STATUS_PROCESS()
            needed = wintypes.DWORD(0)
            ok = _advapi32.QueryServiceStatusEx(
                svc,
                SC_STATUS_PROCESS_INFO,
                ctypes.byref(ssp),
                ctypes.sizeof(ssp),
                ctypes.byref(needed),
            )
            if not ok:
                err = ctypes.get_last_error()
                raise DriverManagerError(
                    f"读取服务 {self.service_name} 状态失败（WinError {err}）。", code=err
                )
            return True, int(ssp.dwCurrentState)
        finally:
            if svc:
                _advapi32.CloseServiceHandle(svc)
            _advapi32.CloseServiceHandle(scm)

    def _probe_device(self) -> Tuple[bool, str]:
        return RedirectDriverClient(self.device_path).probe()

    def query_status(self) -> DriverStatus:
        """查询 NDISLWF 驱动当前安装及运行状态。"""
        admin = self.is_admin()
        if not _is_windows:
            return DriverStatus(
                state=DriverState.UNKNOWN,
                installed=False,
                running=False,
                is_admin=False,
                detail="非 Windows 环境",
            )

        try:
            installed, code = self._query_scm_service_state()
        except DriverManagerError as err:
            return DriverStatus(
                state=DriverState.UNKNOWN,
                installed=False,
                running=False,
                is_admin=admin,
                detail=str(err),
            )

        if not installed:
            return DriverStatus(
                state=DriverState.NOT_INSTALLED,
                installed=False,
                running=False,
                service_state_code=0,
                service_state_text="未安装",
                device_ready=False,
                is_admin=admin,
                detail=f"未检测到服务 {self.service_name}",
            )

        state_text = SERVICE_STATE_NAMES.get(code, f"状态码 {code}")
        device_ready, probe_msg = self._probe_device()

        if code == SERVICE_RUNNING:
            return DriverStatus(
                state=DriverState.RUNNING,
                installed=True,
                running=True,
                service_state_code=code,
                service_state_text=state_text,
                device_ready=device_ready,
                is_admin=admin,
                detail=probe_msg if device_ready else f"服务运行中，但设备探测失败：{probe_msg}",
            )
        if code == SERVICE_STOPPED:
            return DriverStatus(
                state=DriverState.STOPPED,
                installed=True,
                running=False,
                service_state_code=code,
                service_state_text=state_text,
                device_ready=False,
                is_admin=admin,
                detail=f"服务 {self.service_name} 已安装但当前未运行",
            )
        return DriverStatus(
            state=DriverState.PENDING,
            installed=True,
            running=False,
            service_state_code=code,
            service_state_text=state_text,
            device_ready=device_ready,
            is_admin=admin,
            detail=f"服务 {self.service_name} 当前处于{state_text}状态",
        )

    # --- 服务启动与停止（SCM） --------------------------------------------

    def start(self, timeout: float = 10.0) -> DriverStatus:
        """启动已安装的 NdisLwf 驱动服务并等待其进入运行状态。"""
        self._require_windows_and_admin("启动驱动")

        scm = _advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not scm:
            err = ctypes.get_last_error()
            raise DriverManagerError(f"无法打开服务控制管理器（WinError {err}）。", code=err)

        svc = None
        try:
            svc = _advapi32.OpenServiceW(
                scm, self.service_name, SERVICE_START | SERVICE_QUERY_STATUS
            )
            if not svc:
                err = ctypes.get_last_error()
                if err == ERROR_SERVICE_DOES_NOT_EXIST:
                    raise DriverManagerError(
                        f"驱动服务 {self.service_name} 尚未安装，无法启动。", code=err
                    )
                raise DriverManagerError(
                    f"打开服务 {self.service_name} 失败（WinError {err}）。", code=err
                )

            ok = _advapi32.StartServiceW(svc, 0, None)
            if not ok:
                err = ctypes.get_last_error()
                if err != ERROR_SERVICE_ALREADY_RUNNING:
                    hint = ""
                    if err == 577:
                        hint = "（驱动签名校验失败，请确认已开启测试签名模式并对 sys 签名）"
                    elif err == 2:
                        hint = f"（未找到驱动文件 System32\\drivers\\{SYS_FILENAME}）"
                    raise DriverManagerError(
                        f"启动驱动服务 {self.service_name} 失败（WinError {err}）{hint}。",
                        code=err,
                    )

            deadline = time.monotonic() + max(timeout, 1.0)
            while time.monotonic() < deadline:
                ssp = _SERVICE_STATUS_PROCESS()
                needed = wintypes.DWORD(0)
                if _advapi32.QueryServiceStatusEx(
                    svc,
                    SC_STATUS_PROCESS_INFO,
                    ctypes.byref(ssp),
                    ctypes.sizeof(ssp),
                    ctypes.byref(needed),
                ):
                    if ssp.dwCurrentState == SERVICE_RUNNING:
                        break
                    if ssp.dwCurrentState == SERVICE_STOPPED:
                        raise DriverManagerError(
                            f"驱动服务 {self.service_name} 启动后立即停止（退出码 {ssp.dwWin32ExitCode}）。",
                            code=int(ssp.dwWin32ExitCode),
                        )
                time.sleep(0.2)
            else:
                raise DriverManagerError(f"等待驱动服务 {self.service_name} 启动超时。")
        finally:
            if svc:
                _advapi32.CloseServiceHandle(svc)
            _advapi32.CloseServiceHandle(scm)

        return self.query_status()

    def stop(self, timeout: float = 10.0) -> DriverStatus:
        """停止 NdisLwf 驱动服务。"""
        self._require_windows_and_admin("停止驱动")

        scm = _advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not scm:
            err = ctypes.get_last_error()
            raise DriverManagerError(f"无法打开服务控制管理器（WinError {err}）。", code=err)

        svc = None
        try:
            svc = _advapi32.OpenServiceW(
                scm, self.service_name, SERVICE_STOP | SERVICE_QUERY_STATUS
            )
            if not svc:
                err = ctypes.get_last_error()
                if err == ERROR_SERVICE_DOES_NOT_EXIST:
                    return self.query_status()
                raise DriverManagerError(
                    f"打开服务 {self.service_name} 失败（WinError {err}）。", code=err
                )

            svc_status = _SERVICE_STATUS()
            ok = _advapi32.ControlService(svc, SERVICE_CONTROL_STOP, ctypes.byref(svc_status))
            if not ok:
                err = ctypes.get_last_error()
                if err == ERROR_SERVICE_NOT_ACTIVE:
                    return self.query_status()
                raise DriverManagerError(
                    f"停止驱动服务 {self.service_name} 失败（WinError {err}）。", code=err
                )

            deadline = time.monotonic() + max(timeout, 1.0)
            while time.monotonic() < deadline:
                ssp = _SERVICE_STATUS_PROCESS()
                needed = wintypes.DWORD(0)
                if _advapi32.QueryServiceStatusEx(
                    svc,
                    SC_STATUS_PROCESS_INFO,
                    ctypes.byref(ssp),
                    ctypes.sizeof(ssp),
                    ctypes.byref(needed),
                ):
                    if ssp.dwCurrentState == SERVICE_STOPPED:
                        break
                time.sleep(0.2)
        finally:
            if svc:
                _advapi32.CloseServiceHandle(svc)
            _advapi32.CloseServiceHandle(scm)

        return self.query_status()

    # --- 安装与卸载（优先 netcfg.exe，自动回退 INetCfg COM） --------------

    def _run_netcfg(self, netcfg_exe: str, args: List[str]) -> Tuple[bool, str]:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(
            [netcfg_exe, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="mbcs",
            errors="replace",
            creationflags=creationflags,
            timeout=120,
        )
        output = (proc.stdout or "").strip()
        reboot_needed = ("reboot" in output.lower()) or ("重新启动" in output) or (proc.returncode == 3010)
        if proc.returncode not in (0, 3010):
            raise DriverManagerError(
                f"netcfg 执行失败（退出码 {proc.returncode}）：{output or '无详细输出'}",
                code=proc.returncode,
            )
        return reboot_needed, output

    def _netcfg_com_install(self, staged_inf: str) -> bool:
        """无 netcfg.exe 环境（如 Win7）下的原生 INetCfg COM 安装实现。"""
        inf_dir = os.path.dirname(staged_inf)
        ok = _setupapi.SetupCopyOEMInfW(
            staged_inf, inf_dir, SPOST_PATH, 0, None, 0, None, None
        )
        if not ok:
            err = ctypes.get_last_error()
            raise DriverManagerError(
                f"SetupCopyOEMInfW 复制驱动 INF 失败（WinError {err}）。", code=err
            )

        hr_co = _ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
        co_inited = hr_co in (S_OK, S_FALSE)
        pnc = ctypes.c_void_p()
        pnc_lock = ctypes.c_void_p()
        pnc_setup = ctypes.c_void_p()
        pncc = ctypes.c_void_p()
        lock_acquired = False
        netcfg_inited = False

        try:
            clsid = _GUID.from_str(CLSID_CNETCFG_STR)
            iid_netcfg = _GUID.from_str(IID_INETCFG_STR)
            iid_lock = _GUID.from_str(IID_INETCFGLOCK_STR)
            iid_setup = _GUID.from_str(IID_INETCFGCLASSSETUP_STR)
            guid_service = _GUID.from_str(GUID_DEVCLASS_NETSERVICE_STR)

            hr = _ole32.CoCreateInstance(
                ctypes.byref(clsid),
                None,
                CLSCTX_INPROC_SERVER,
                ctypes.byref(iid_netcfg),
                ctypes.byref(pnc),
            )
            if hr < 0:
                raise DriverManagerError(f"创建 INetCfg 实例失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr)

            qi = _com_vtable_fn(pnc, 0, ctypes.c_long, ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p))
            hr = qi(pnc, ctypes.byref(iid_lock), ctypes.byref(pnc_lock))
            if hr < 0:
                raise DriverManagerError(f"获取 INetCfgLock 失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr)

            acquire = _com_vtable_fn(
                pnc_lock, 3, ctypes.c_long, wintypes.DWORD, wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPWSTR)
            )
            locked_by = wintypes.LPWSTR()
            hr = acquire(pnc_lock, 15000, "NDISLWF Client Installer", ctypes.byref(locked_by))
            if locked_by.value:
                holder = locked_by.value
                _ole32.CoTaskMemFree(locked_by)
            else:
                holder = ""
            if hr < 0:
                extra = f"（当前被 {holder} 占用）" if holder else ""
                raise DriverManagerError(
                    f"获取网络配置写锁失败{extra}（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr
                )
            lock_acquired = True

            initialize = _com_vtable_fn(pnc, 3, ctypes.c_long, ctypes.c_void_p)
            hr = initialize(pnc, None)
            if hr < 0:
                raise DriverManagerError(f"INetCfg::Initialize 失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr)
            netcfg_inited = True

            query_class = _com_vtable_fn(
                pnc, 9, ctypes.c_long, ctypes.POINTER(_GUID), ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)
            )
            hr = query_class(pnc, ctypes.byref(guid_service), ctypes.byref(iid_setup), ctypes.byref(pnc_setup))
            if hr < 0:
                raise DriverManagerError(
                    f"INetCfg::QueryNetCfgClass 失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr
                )

            obo = _OBO_TOKEN(Type=OBO_USER)
            install_fn = _com_vtable_fn(
                pnc_setup,
                4,
                ctypes.c_long,
                wintypes.LPCWSTR,
                ctypes.POINTER(_OBO_TOKEN),
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                ctypes.POINTER(ctypes.c_void_p),
            )
            hr = install_fn(
                pnc_setup, self.component_id, ctypes.byref(obo), 0, 0, None, None, ctypes.byref(pncc)
            )
            if hr < 0:
                raise DriverManagerError(
                    f"INetCfgClassSetup::Install({self.component_id}) 失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。",
                    code=hr,
                )

            apply_fn = _com_vtable_fn(pnc, 5, ctypes.c_long)
            hr_apply = apply_fn(pnc)
            if hr_apply < 0:
                raise DriverManagerError(
                    f"INetCfg::Apply 失败（HRESULT 0x{hr_apply & 0xFFFFFFFF:08X}）。", code=hr_apply
                )
            return hr == NETCFG_S_REBOOT or hr_apply == NETCFG_S_REBOOT
        finally:
            _com_release(pncc)
            _com_release(pnc_setup)
            if netcfg_inited and pnc.value:
                uninit = _com_vtable_fn(pnc, 4, ctypes.c_long)
                uninit(pnc)
            if lock_acquired and pnc_lock.value:
                release_lock = _com_vtable_fn(pnc_lock, 4, ctypes.c_long)
                release_lock(pnc_lock)
            _com_release(pnc_lock)
            _com_release(pnc)
            if co_inited:
                _ole32.CoUninitialize()

    def _netcfg_com_uninstall(self) -> bool:
        """无 netcfg.exe 环境（如 Win7）下的原生 INetCfg COM 卸载实现。"""
        hr_co = _ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
        co_inited = hr_co in (S_OK, S_FALSE)
        pnc = ctypes.c_void_p()
        pnc_lock = ctypes.c_void_p()
        pnc_setup = ctypes.c_void_p()
        pncc = ctypes.c_void_p()
        lock_acquired = False
        netcfg_inited = False

        try:
            clsid = _GUID.from_str(CLSID_CNETCFG_STR)
            iid_netcfg = _GUID.from_str(IID_INETCFG_STR)
            iid_lock = _GUID.from_str(IID_INETCFGLOCK_STR)
            iid_setup = _GUID.from_str(IID_INETCFGCLASSSETUP_STR)
            guid_service = _GUID.from_str(GUID_DEVCLASS_NETSERVICE_STR)

            hr = _ole32.CoCreateInstance(
                ctypes.byref(clsid), None, CLSCTX_INPROC_SERVER, ctypes.byref(iid_netcfg), ctypes.byref(pnc)
            )
            if hr < 0:
                raise DriverManagerError(f"创建 INetCfg 实例失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr)

            qi = _com_vtable_fn(pnc, 0, ctypes.c_long, ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p))
            hr = qi(pnc, ctypes.byref(iid_lock), ctypes.byref(pnc_lock))
            if hr < 0:
                raise DriverManagerError(f"获取 INetCfgLock 失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr)

            acquire = _com_vtable_fn(
                pnc_lock, 3, ctypes.c_long, wintypes.DWORD, wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPWSTR)
            )
            locked_by = wintypes.LPWSTR()
            hr = acquire(pnc_lock, 15000, "NDISLWF Client Uninstaller", ctypes.byref(locked_by))
            if locked_by.value:
                _ole32.CoTaskMemFree(locked_by)
            if hr < 0:
                raise DriverManagerError(f"获取网络配置写锁失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr)
            lock_acquired = True

            initialize = _com_vtable_fn(pnc, 3, ctypes.c_long, ctypes.c_void_p)
            hr = initialize(pnc, None)
            if hr < 0:
                raise DriverManagerError(f"INetCfg::Initialize 失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr)
            netcfg_inited = True

            find_comp = _com_vtable_fn(pnc, 8, ctypes.c_long, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p))
            hr = find_comp(pnc, self.component_id, ctypes.byref(pncc))
            if hr == S_FALSE or not pncc.value:
                return False
            if hr < 0:
                raise DriverManagerError(
                    f"查找组件 {self.component_id} 失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr
                )

            query_class = _com_vtable_fn(
                pnc, 9, ctypes.c_long, ctypes.POINTER(_GUID), ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)
            )
            hr = query_class(pnc, ctypes.byref(guid_service), ctypes.byref(iid_setup), ctypes.byref(pnc_setup))
            if hr < 0:
                raise DriverManagerError(
                    f"INetCfg::QueryNetCfgClass 失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。", code=hr
                )

            obo = _OBO_TOKEN(Type=OBO_USER)
            deinstall = _com_vtable_fn(
                pnc_setup,
                5,
                ctypes.c_long,
                ctypes.c_void_p,
                ctypes.POINTER(_OBO_TOKEN),
                ctypes.POINTER(wintypes.LPWSTR),
            )
            refs = wintypes.LPWSTR()
            hr = deinstall(pnc_setup, pncc, ctypes.byref(obo), ctypes.byref(refs))
            if refs.value:
                _ole32.CoTaskMemFree(refs)
            if hr < 0:
                raise DriverManagerError(
                    f"INetCfgClassSetup::DeInstall({self.component_id}) 失败（HRESULT 0x{hr & 0xFFFFFFFF:08X}）。",
                    code=hr,
                )

            apply_fn = _com_vtable_fn(pnc, 5, ctypes.c_long)
            hr_apply = apply_fn(pnc)
            if hr_apply < 0:
                raise DriverManagerError(
                    f"INetCfg::Apply 失败（HRESULT 0x{hr_apply & 0xFFFFFFFF:08X}）。", code=hr_apply
                )
            return hr == NETCFG_S_REBOOT or hr_apply == NETCFG_S_REBOOT
        finally:
            _com_release(pncc)
            _com_release(pnc_setup)
            if netcfg_inited and pnc.value:
                uninit = _com_vtable_fn(pnc, 4, ctypes.c_long)
                uninit(pnc)
            if lock_acquired and pnc_lock.value:
                release_lock = _com_vtable_fn(pnc_lock, 4, ctypes.c_long)
                release_lock(pnc_lock)
            _com_release(pnc_lock)
            _com_release(pnc)
            if co_inited:
                _ole32.CoUninitialize()

    def install(
        self,
        inf_path: Optional[str] = None,
        sys_path: Optional[str] = None,
        start_after_install: bool = True,
    ) -> DriverStatus:
        """安装 NDISLWF 过滤驱动；可选在安装后自动启动服务。"""
        self._require_windows_and_admin("安装驱动")
        resolved_inf, resolved_sys = self._resolve_package_files(inf_path, sys_path)

        staging_dir, staged_inf = self._stage_package(resolved_inf, resolved_sys)
        reboot_required = False
        try:
            netcfg_exe = find_netcfg_executable()
            if netcfg_exe:
                reboot_required, _out = self._run_netcfg(
                    netcfg_exe, ["-v", "-l", staged_inf, "-c", "s", "-i", self.component_id]
                )
            else:
                reboot_required = self._netcfg_com_install(staged_inf)
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

        status = self.query_status()
        if start_after_install and status.installed and not status.running:
            status = self.start()
        status.reboot_required = reboot_required
        return status

    def uninstall(self) -> DriverStatus:
        """停止并卸载 NDISLWF 过滤驱动。"""
        self._require_windows_and_admin("卸载驱动")

        # 尽量先停止服务（即使未运行或正在停止也不阻塞卸载）
        try:
            self.stop(timeout=5.0)
        except DriverManagerError:
            pass

        netcfg_exe = find_netcfg_executable()
        if netcfg_exe:
            reboot_required, _out = self._run_netcfg(netcfg_exe, ["-v", "-u", self.component_id])
        else:
            reboot_required = self._netcfg_com_uninstall()

        status = self.query_status()
        status.reboot_required = reboot_required
        return status
