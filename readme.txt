========================================================================
NDISLWF IP/端口重定向驱动 使用说明
========================================================================

一、功能简介
------------------------------------------------------------------------
本项目在 Windows NDIS 6.0 Lightweight Filter (LWF) 驱动基础上扩展了
IP 地址和端口重定向功能，并提供配套命令行配置工具 redirectctl.exe：

  1. 支持 IPv4 和 IPv6（同协议族重定向：IPv4->IPv4、IPv6->IPv6）。
  2. 支持 TCP、UDP 或任意传输层协议（TCP+UDP）。
  3. 支持仅改 IP（端口填 0）、仅改端口或 IP+端口同时重定向。
  4. 支持跨网段/同网关重定向、同网段不同主机重定向（指定 --mac）。
  5. 支持本机环回重定向（目标 IP 为本机网卡 IP 时自动识别，或使用 --local）。
  6. 通过 IOCTL 动态增删查清规则（最多 64 条），无需重启驱动。


二、目录与文件说明
------------------------------------------------------------------------
  filter.c / filter.h      NDIS LWF 驱动主流程与收发包回调
  redirect.c / redirect.h  IPv4/IPv6 重定向引擎（规则表/NAT会话/校验和/LSO/本地注入）
  device.c                 控制设备 \\.\NDISLWF 与 IOCTL 分发
  filteruser.h             驱动与用户态共用的 IOCTL 及规则结构定义
  netlwf.inf               NDIS 过滤驱动安装 INF 文件
  sources / makefile       旧版 WDK 驱动构建配置
  tool\redirectctl.c       用户态命令行配置工具源码
  tool\sources / makefile  用户态工具 WDK 构建配置


三、编译方法（旧版 WDK 7600）
------------------------------------------------------------------------
假设 WDK 安装路径为 C:\WinDDK\7600.16385.1，源码位于 d:\06-个人\filter：

1. 编译驱动 ndislwf.sys
   [Win7 x64 发布版] -> objfre_win7_amd64\amd64\ndislwf.sys
     cmd /c "call C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ fre x64 WIN7 && cd /d d:\06-个人\filter && build -cZ"

   [Win7 x64 调试版] -> objchk_win7_amd64\amd64\ndislwf.sys
     cmd /c "call C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ chk x64 WIN7 && cd /d d:\06-个人\filter && build -cZ"

   [Win7 x86 发布版] -> objfre_win7_x86\i386\ndislwf.sys
     cmd /c "call C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ fre x86 WIN7 && cd /d d:\06-个人\filter && build -cZ"

2. 编译配置工具 redirectctl.exe
   [Win7 x64 发布版] -> tool\objfre_win7_amd64\amd64\redirectctl.exe
     cmd /c "call C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ fre x64 WIN7 && cd /d d:\06-个人\filter\tool && build -cZ"

   [Win7 x86 发布版] -> tool\objfre_win7_x86\i386\redirectctl.exe
     cmd /c "call C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ fre x86 WIN7 && cd /d d:\06-个人\filter\tool && build -cZ"

   注：如在 WDK Build Environment 命令行窗口中，直接进入对应目录执行
   build -cZ 即可。


四、驱动安装与更新步骤
------------------------------------------------------------------------
1. 将编译得到的 ndislwf.sys 与 netlwf.inf 放到目标机器同一目录。
   （64 位 Windows 需开启测试签名模式并对 sys 进行测试签名，或开机按 F8
   选择“禁用驱动程序签名强制”。）
2. 打开“控制面板 -> 网络和 Internet -> 网络连接”，右键目标网卡 ->“属性”。
3. 点击“安装”-> 选择“服务”->“添加”->“从磁盘安装”，选中 netlwf.inf。
4. 安装完成后确认网卡属性列表中已勾选 “NDIS Sample LightWeight Filter”。
5. 更新驱动文件时，先卸载或停止服务/禁用网卡，替换 System32\drivers\ndislwf.sys
   后重新启用网卡（或重启系统）即可生效。


五、redirectctl.exe 命令行用法
------------------------------------------------------------------------
以管理员权限运行命令行：

基本语法：
  redirectctl.exe add <ipv4|ipv6> <tcp|udp|any> <orig_ip> <orig_port> <new_ip> <new_port> [--mac <xx:xx:xx:xx:xx:xx>] [--local] [--id <rule_id>]
  redirectctl.exe del <rule_id>
  redirectctl.exe clear
  redirectctl.exe list

参数说明：
  ipv4|ipv6   地址族（也可简写为 v4|v6）
  tcp|udp|any 传输层协议（any 同时匹配 TCP 和 UDP）
  orig_ip     原始目的 IP
  orig_port   原始目的端口（0 表示匹配任意端口）
  new_ip      重定向后的目标 IP
  new_port    重定向后的目标端口（0 表示保持原端口不变）
  --mac       可选，改写以太网目的 MAC（支持 ":" 或 "-" 分隔）
              当重定向到同网段另一台主机时必须指定目标主机的 MAC
  --local     可选，强制启用本机环回重定向（当 new_ip 等于本机网卡 IP 时
              驱动会自动识别，通常无需手动指定）
  --id        可选，指定规则 ID（省略则自动分配；已有同 ID 则覆盖更新）


六、典型使用示例
------------------------------------------------------------------------
1. 跨网段/同网关重定向（无需指定 --mac）
   将发往 10.0.0.10:80 的 TCP 流量重定向到 10.0.0.20:8080：
     redirectctl.exe add ipv4 tcp 10.0.0.10 80 10.0.0.20 8080

2. 同网段不同主机重定向（需指定目标主机 MAC）
   先 ping 192.168.1.20 再通过 arp -a 获取其 MAC，然后添加规则：
     redirectctl.exe add ipv4 tcp 192.168.1.10 80 192.168.1.20 8080 --mac aa:bb:cc:dd:ee:ff

3. 本机环回重定向（重定向到当前机器自身监听的端口）
   假设本机网卡 IP 为 192.168.71.128，本地服务端监听 192.168.71.128:4321，
   将本地访问 172.16.7.115:1234 的流量重定向到本机 4321 端口：
     redirectctl.exe add ipv4 tcp 172.16.7.115 1234 192.168.71.128 4321
   （或显式附加 --local）

4. IPv6 重定向（仅改 IP，保留原端口）
     redirectctl.exe add ipv6 any 2001:db8::1 0 2001:db8::2 0 --mac 00-11-22-33-44-55

5. 查看、删除与清空规则
     redirectctl.exe list
     redirectctl.exe del 1
     redirectctl.exe clear


七、注意事项与排查
------------------------------------------------------------------------
1. 路由要求：客户端访问 orig_ip 时，系统路由表必须能将数据包路由到绑定了
   NDISLWF 的网卡（例如已配置默认网关），否则数据包在到达 LWF 之前就会被
   系统丢弃。
2. 防火墙：确保目标主机（或本机）的 Windows 防火墙放行了重定向后的目标端口。
3. 本机环回行为：使用本机环回重定向时，本地服务端 accept 到的对端源 IP 将
   显示为 orig_ip（如 172.16.7.115），属正常设计行为，用以保证双向回包均
   经过 NDIS LWF 闭环处理。
4. 设备打开失败：若提示 Failed to open \\.\NDISLWF，请确认驱动已正确安装
   运行，并以管理员身份运行 redirectctl.exe。
========================================================================
