# PyQt 客户端说明

## 运行

```powershell
pip install -r client\requirements.txt
python client\main.py
```

也可以先用命令行直接验证驱动接口：

```powershell
python client\cli.py list
python client\cli.py add --target-host 127.0.0.1 --target-port 81 --redirect-host 127.0.0.1 --redirect-port 80 --protocol tcp
python client\cli.py add --target-host ::1 --target-port 8081 --redirect-host ::1 --redirect-port 8080 --protocol both
python client\cli.py list
python client\cli.py delete 1
```

安装并启动驱动后，可以运行 smoke test 临时添加 IPv4/IPv6 TCP 规则并查询统计：

```powershell
python client\port_redirect_smoke.py
```

如果要做端到端流量验证，请使用真实网卡可达的地址；纯 `127.0.0.1` / `::1` 回环流量通常不会经过 NDIS LWF。示例：

```powershell
python client\port_redirect_smoke.py --ipv4-only --connect --start-server --ipv4-target-host 192.168.1.50 --ipv4-target-port 18081 --ipv4-redirect-host 192.168.1.50 --ipv4-redirect-port 18080
```

文件过滤模块使用独立驱动和独立应用入口，不复用端口重定向 IOCTL：

```powershell
python client\file_filter_cli.py list
python client\file_filter_cli.py add --path "\Device\HarddiskVolume*\Secret\*" --deny-write --deny-delete --deny-rename
python client\file_filter_cli.py stats
python client\file_filter_cli.py delete 1
```

## Procmon 风格活动监视器

`client\procmon.py` 是一个仿照 Sysinternals Process Monitor 的实时活动监视器。它
同时轮询三个内核驱动的事件环形缓冲区并按时间合并成一个可过滤的实时列表：

- 进程：`\\.\CnCProcFilter`（进程创建/退出、远程线程、镜像加载、句柄剥离）
- 文件：`\\.\CnCFileFilter`（创建、删除、重命名等，含被拦截标记）
- 注册表：`\\.\CnCRegFilter`（设值、删值、建/删/改键，含被拦截标记）

```powershell
# 图形界面
python client\procmon.py

# 无界面控制台跟踪（便于在无显示环境快速验证）
python client\procmon.py --console
```

工作方式：点“开始捕获”后，会向文件/注册表驱动发送 `SET_MONITOR` 打开监控（进程
驱动始终记录事件），随后每 400ms 轮询各驱动的 `QUERY_EVENTS` 并 `CLEAR_EVENTS`，
因此每条事件只出现一次。内核事件环固定为 256 条：如果两次轮询之间产生的事件超过
256 条（注册表监控在系统繁忙时很容易触发），最旧的事件会被丢弃。监控开销较大，仅
在捕获时启用，停止捕获会自动关闭内核监控。

驱动侧新增的接口（每个驱动各自独立）：

- `IOCTL_*_SET_MONITOR`：开/关监控（输入一个 `ULONG`，非零为开）。进程驱动始终记录，无此接口。
- `IOCTL_*_QUERY_EVENTS`：读取事件环，返回 `*_EVENTS { Version, EventCount, Events[] }`。
- `IOCTL_*_CLEAR_EVENTS`：清空事件环。

## 当前能力

- 保留原界面风格的多页签结构
- 在“网络管控”页实现规则的添加、修改、查询、删除和命中统计查看
- 通过 `\\.\NDISLWF` 调用驱动 IOCTL
- 端口重定向支持 IPv4/IPv6 的 TCP/UDP 规则；目标地址和重定向地址必须属于同一地址族

## 驱动联调前提

- 过滤驱动已正确安装并成功绑定到目标网卡
- 驱动服务已经启动
- 用户态可打开设备 `\\.\NDISLWF`

## 构建驱动

默认 WDK 路径为 `C:\WinDDK\7600.16385.1`，可运行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_ndislwf_win7.ps1
```

脚本会构建 Win7 checked/free x86/amd64，并刷新 `dist\ndislwf_win7_x64` 和 `dist\ndislwf_win7_x86`。

如果仓库路径包含中文等非 ASCII 字符，脚本会自动创建一个临时 `subst` 盘符作为 ASCII 构建路径，以避开 WDK 7600/nmake 对非 ASCII 路径的兼容问题；构建结束后会自动卸载该临时盘符。

构建完成后，每个发布目录都会生成 `manifest.json`，记录目标系统、架构、WDK 路径、文件大小和 SHA256。`dist\SHA256SUMS.txt` 汇总了两个架构包内 `netlwf.inf`、`ndislwf.sys` 和 `manifest.json` 的 SHA256。

可用下面的命令核对安装文件哈希：

```powershell
Get-FileHash dist\ndislwf_win7_x64\ndislwf.sys -Algorithm SHA256
Get-FileHash dist\ndislwf_win7_x86\ndislwf.sys -Algorithm SHA256
Get-Content dist\SHA256SUMS.txt
```

## 安装提示

- 已整理好的安装文件位于 `dist\ndislwf_win7_x64` 和 `dist\ndislwf_win7_x86`
- 64 位系统优先使用 `dist\ndislwf_win7_x64`
- 32 位系统优先使用 `dist\ndislwf_win7_x86`
- 每个目录都包含同架构的 `netlwf.inf`、`ndislwf.sys` 和 `manifest.json`
- `objchk_*` 目录是 checked/debug 构建，适合调试；日常安装建议使用 `objfre_*`
- 按示例文档中的方式，在网卡属性里通过“安装 -> 服务 -> 从磁盘安装”添加该过滤驱动
- 如果 `python client\cli.py list` 返回 `WinError 2`，表示用户态当前打不开 `\\.\NDISLWF`，通常是驱动尚未安装、未启动或设备符号链接未创建

## 建议的最小验证步骤

1. 选择一个会经过绑定网卡的本机地址，例如 `192.168.1.50` 或某个 IPv6 单播地址
2. 启动一个 TCP 服务监听该地址的重定向端口，例如 `192.168.1.50:18080`
3. 在客户端新增规则：
   - 目标地址：`192.168.1.50`
   - 目标端口：`81`
   - 重定向地址：`192.168.1.50`
   - 重定向端口：`18080`
   - 协议：`TCP`
4. 从另一台机器或会经过该网卡路径的客户端连接 `192.168.1.50:81`
5. 观察服务端是否实际收到发往 `18080` 端口的连接，并用 `python client\cli.py stats` 查看重定向计数

IPv6 可用同样方式验证，例如监听某个真实网卡 IPv6 地址的 `[IPv6]:18082`，新增 `[IPv6]:18083 -> [IPv6]:18082` 的 TCP 规则后从外部连接 `[IPv6]:18083`。`python client\port_redirect_smoke.py --connect --start-server ...` 会临时添加规则、发送测试数据、检查服务端收到的数据，并在结束时删除测试规则。

## 当前限制

- 进程过滤列表界面仅保留外观，尚未接入内核规则结构
- 导入、导出、规则排序按钮当前为占位提示
- 端口重定向不做 IPv4/IPv6 跨协议转换；一条规则内的目标地址和重定向地址必须同为 IPv4 或同为 IPv6
- 为避免破坏包完整性，分片包、LSO 发送包、IPsec offload 包以及 IPv4/IPv6 AH/ESP 包会跳过重定向，并体现在统计计数中
- 端口重定向仅改写 IP 目的地址/端口，不改写二层目的 MAC。因此只适用于"纯端口重定向"（重定向地址与目标地址相同）或重定向地址与目标地址走同一二层下一跳（同一网关）的场景；把流量重定向到另一台不同 MAC 的主机会因 MAC 未更新而无法送达
- 文件过滤规则的路径必须使用 NT 设备路径通配形式（如 `\Device\HarddiskVolume2\Secret\*`），不能用盘符形式（如 `C:\Secret\*`）；匹配大小写不敏感，规则会在内核侧统一转为大写后比较
