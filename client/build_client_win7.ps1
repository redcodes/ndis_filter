<#
.SYNOPSIS
    使用 Python 3.8 + PyInstaller 将客户端打包为单文件可执行程序（兼容 Windows 7 SP1+）。
.DESCRIPTION
    - 强制使用 Python 3.8（最后一个官方支持 Windows 7 的 CPython 分支）
    - 单文件模式（--onefile），将 Python 运行时、PyQt5/Qt5、VC++ 运行库以及 Win7 所需的
      Universal CRT（api-ms-win-crt-*.dll / ucrtbase.dll）全部打入单个 .exe
    - 默认请求管理员权限（--uac-admin），以支持驱动安装与 IOCTL 通信
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build_client_win7.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build_client_win7.ps1 -Clean -Name CnCryptClient
#>

[CmdletBinding()]
param(
    [string]$PythonExe = "",
    [string]$Name = "CnCryptClient",
    [string]$OutDir = "",
    [string]$UcrtDir = "",
    [switch]$NoUacAdmin,
    [switch]$Console,
    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ClientDir = Join-Path $RepoRoot "client"
$EntryScript = Join-Path $ClientDir "main.py"

if (-not (Test-Path -LiteralPath $EntryScript)) {
    throw "未找到客户端入口文件: $EntryScript"
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot "dist"
} elseif (-not [System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = Join-Path $RepoRoot $OutDir
}

function Resolve-Python38 {
    param([string]$Requested)

    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        if (-not (Test-Path -LiteralPath $Requested)) {
            throw "指定的 Python 路径不存在: $Requested"
        }
        return (Resolve-Path -LiteralPath $Requested).Path
    }

    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $detected = & py -3.8 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($detected)) {
            $exe = ($detected | Select-Object -Last 1).Trim()
            if (Test-Path -LiteralPath $exe) {
                return $exe
            }
        }
    }

    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python38\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python38-32\python.exe"),
        "C:\Python38\python.exe",
        "C:\Python38-32\python.exe",
        "C:\Program Files\Python38\python.exe",
        "C:\Program Files (x86)\Python38-32\python.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "未找到 Python 3.8。请先安装 Python 3.8.10，或通过 -PythonExe 指定 python.exe 路径。"
}

function Resolve-UcrtRedistDir {
    param(
        [string]$Requested,
        [string]$Arch
    )

    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        if (-not (Test-Path -LiteralPath $Requested)) {
            throw "指定的 UCRT 目录不存在: $Requested"
        }
        return (Resolve-Path -LiteralPath $Requested).Path
    }

    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\Redist"
    if (-not (Test-Path -LiteralPath $kitsRoot)) {
        return $null
    }

    $versioned = Get-ChildItem -LiteralPath $kitsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName "ucrt\DLLs\$Arch" }

    $candidates = @($versioned) + @(Join-Path $kitsRoot "ucrt\DLLs\$Arch")
    foreach ($dir in $candidates) {
        if ((Test-Path -LiteralPath $dir) -and (Test-Path -LiteralPath (Join-Path $dir "ucrtbase.dll"))) {
            return $dir
        }
    }

    return $null
}

$Python = Resolve-Python38 -Requested $PythonExe
Write-Host "[1/4] 检查 Python 3.8 与构建依赖..." -ForegroundColor Cyan

$envInfoRaw = & $Python -c "
import json, os, struct, sys
info = {
    'major': sys.version_info.major,
    'minor': sys.version_info.minor,
    'version': sys.version.split()[0],
    'bits': struct.calcsize('P') * 8,
    'py_dir': os.path.dirname(sys.executable),
    'has_pyqt5': False,
    'qt_bin': '',
    'has_pyinstaller': False,
    'pyinstaller_ver': '',
}
try:
    import PyQt5
    info['has_pyqt5'] = True
    qt_bin = os.path.join(os.path.dirname(PyQt5.__file__), 'Qt5', 'bin')
    if os.path.isdir(qt_bin):
        info['qt_bin'] = qt_bin
except ImportError:
    pass
try:
    import PyInstaller
    info['has_pyinstaller'] = True
    info['pyinstaller_ver'] = PyInstaller.__version__
except ImportError:
    pass
print(json.dumps(info))
"
if ($LASTEXITCODE -ne 0) {
    throw "执行 Python 环境探测失败: $Python"
}

$envInfo = $envInfoRaw | ConvertFrom-Json
if ($envInfo.major -ne 3 -or $envInfo.minor -ne 8) {
    throw "需要 Python 3.8.x 以兼容 Windows 7，当前版本为 $($envInfo.version) ($Python)"
}
if (-not $envInfo.has_pyqt5) {
    throw "Python 3.8 缺少 PyQt5。请运行: `"$Python`" -m pip install -r `"$ClientDir\requirements.txt`""
}
if (-not $envInfo.has_pyinstaller) {
    throw "Python 3.8 缺少 PyInstaller。请运行: `"$Python`" -m pip install pyinstaller"
}

$Arch = if ($envInfo.bits -eq 64) { "x64" } else { "x86" }
Write-Host "  Python      : $($envInfo.version) ($Arch) - $Python"
Write-Host "  PyInstaller : $($envInfo.pyinstaller_ver)"

$BuildDir = Join-Path $RepoRoot "build\client_win7_$Arch"
if ($Clean -and (Test-Path -LiteralPath $BuildDir)) {
    Remove-Item -LiteralPath $BuildDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null

Write-Host "[2/4] 收集 Windows 7 运行库依赖 (VC++ Runtime & UCRT)..." -ForegroundColor Cyan

$BinaryArgs = New-Object System.Collections.Generic.List[string]
$AddedDllNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

function Add-BundledDll {
    param([string]$DllPath)
    if (-not (Test-Path -LiteralPath $DllPath)) {
        return
    }
    $fileName = [System.IO.Path]::GetFileName($DllPath)
    if ($AddedDllNames.Add($fileName)) {
        $BinaryArgs.Add("--add-binary")
        $BinaryArgs.Add("${DllPath};.")
    }
}

# 显式打包 VC++ 14 运行库，避免未安装 VC++ Redistributable 的 Win7 机器缺少 DLL
$VcDllNames = @(
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "concrt140.dll"
)
$VcSearchDirs = @($envInfo.qt_bin, $envInfo.py_dir) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
foreach ($dllName in $VcDllNames) {
    foreach ($searchDir in $VcSearchDirs) {
        $candidate = Join-Path $searchDir $dllName
        if (Test-Path -LiteralPath $candidate) {
            Add-BundledDll -DllPath $candidate
            break
        }
    }
}

# 打包 Universal CRT (KB2999226)，保证未打齐补丁的 Win7 SP1 也能直接运行
$ResolvedUcrtDir = Resolve-UcrtRedistDir -Requested $UcrtDir -Arch $Arch
if ($ResolvedUcrtDir) {
    $ucrtDlls = Get-ChildItem -LiteralPath $ResolvedUcrtDir -Filter "*.dll" -File
    foreach ($dll in $ucrtDlls) {
        Add-BundledDll -DllPath $dll.FullName
    }
    Write-Host "  UCRT Redist : $ResolvedUcrtDir ($($ucrtDlls.Count) 个 DLL)"
} else {
    Write-Warning "未找到 Windows 10 SDK UCRT Redist 目录 (ucrt\DLLs\$Arch)。若目标 Win7 未安装 KB2999226，可能提示缺少 api-ms-win-crt-*.dll。"
}

Write-Host "[3/4] 执行 PyInstaller 单文件编译..." -ForegroundColor Cyan

$ExcludedModules = @(
    "tkinter",
    "unittest",
    "pydoc",
    "doctest",
    "test",
    "numpy",
    "pandas",
    "matplotlib",
    "PIL",
    "scipy",
    "PyQt5.QtBluetooth",
    "PyQt5.QtDBus",
    "PyQt5.QtDesigner",
    "PyQt5.QtHelp",
    "PyQt5.QtLocation",
    "PyQt5.QtMultimedia",
    "PyQt5.QtMultimediaWidgets",
    "PyQt5.QtNetwork",
    "PyQt5.QtNfc",
    "PyQt5.QtOpenGL",
    "PyQt5.QtPositioning",
    "PyQt5.QtPrintSupport",
    "PyQt5.QtQml",
    "PyQt5.QtQuick",
    "PyQt5.QtQuick3D",
    "PyQt5.QtQuickWidgets",
    "PyQt5.QtRemoteObjects",
    "PyQt5.QtSensors",
    "PyQt5.QtSerialPort",
    "PyQt5.QtSql",
    "PyQt5.QtSvg",
    "PyQt5.QtTest",
    "PyQt5.QtTextToSpeech",
    "PyQt5.QtWebChannel",
    "PyQt5.QtWebEngine",
    "PyQt5.QtWebEngineCore",
    "PyQt5.QtWebEngineWidgets",
    "PyQt5.QtWebSockets",
    "PyQt5.QtXml",
    "PyQt5.QtXmlPatterns"
)

$PyInstallerArgs = New-Object System.Collections.Generic.List[string]
$PyInstallerArgs.Add("-m")
$PyInstallerArgs.Add("PyInstaller")
$PyInstallerArgs.Add("--noconfirm")
$PyInstallerArgs.Add("--onefile")
$PyInstallerArgs.Add("--noupx")
$PyInstallerArgs.Add("--name")
$PyInstallerArgs.Add($Name)
$PyInstallerArgs.Add("--paths")
$PyInstallerArgs.Add($ClientDir)
$PyInstallerArgs.Add("--distpath")
$PyInstallerArgs.Add($OutDir)
$PyInstallerArgs.Add("--workpath")
$PyInstallerArgs.Add((Join-Path $BuildDir "work"))
$PyInstallerArgs.Add("--specpath")
$PyInstallerArgs.Add($BuildDir)

if ($Clean) {
    $PyInstallerArgs.Add("--clean")
}
if ($Console) {
    $PyInstallerArgs.Add("--console")
} else {
    $PyInstallerArgs.Add("--windowed")
}
if (-not $NoUacAdmin) {
    $PyInstallerArgs.Add("--uac-admin")
}

foreach ($mod in $ExcludedModules) {
    $PyInstallerArgs.Add("--exclude-module")
    $PyInstallerArgs.Add($mod)
}
foreach ($arg in $BinaryArgs) {
    $PyInstallerArgs.Add($arg)
}

$PyInstallerArgs.Add($EntryScript)

& $Python @PyInstallerArgs
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller 打包失败（退出码 $LASTEXITCODE）"
}

Write-Host "[4/4] 校验输出文件..." -ForegroundColor Cyan
$OutputExe = Join-Path $OutDir "$Name.exe"
if (-not (Test-Path -LiteralPath $OutputExe)) {
    throw "未生成预期输出文件: $OutputExe"
}

$FileInfo = Get-Item -LiteralPath $OutputExe
$Hash = (Get-FileHash -LiteralPath $OutputExe -Algorithm SHA256).Hash
$SizeMB = [Math]::Round($FileInfo.Length / 1MB, 2)

Write-Host ""
Write-Host "编译完成!" -ForegroundColor Green
Write-Host "  输出文件 : $OutputExe"
Write-Host "  架构     : $Arch (Python $($envInfo.version), 兼容 Windows 7 SP1+)"
Write-Host "  大小     : $SizeMB MB ($($FileInfo.Length) 字节)"
Write-Host "  SHA256   : $Hash"
