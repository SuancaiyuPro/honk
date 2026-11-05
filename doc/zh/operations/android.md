# Android 移植构建

此 Fork 的 `android-port` 分支通过 `.github/workflows/android-arm64.yml` 构建 Android API 35 的 ARM64 原生命令行程序。构建使用仓库固定的 Rust 编译器、保留 REALITY 补丁的 BoringSSL Fork 和运行器提供的 Android NDK。`ci/android-toolchain.cmake` 将 BoringSSL 统一到 API 35，并在交叉编译时关闭上游测试和基准目标。systemd 依赖仅用于 Linux。

工作流分别检查 `--no-default-features --features clash-api` 和 `--no-default-features --features clash-api,rprx`，最终程序采用后者，包含 VLESS/VMess 处理器，不包含真实 eBPF 后端和 jemalloc。检查通过或链接成功仅证明构建兼容性，不代表 Android 透明代理已经可用。此阶段不生成 APK 或 Root 模块。

成功后，Actions 上传 `honk-android-arm64-api35`，内含 `honk-core` 和 `SHA256SUMS`；另有 `android-arm64-port-report`，保存编译日志和 ELF 解释器、动态依赖报告。独立 Linux 任务检查编译、格式和现有 socket 元数据测试。Android 启动、CA 验证、带标记下载和实际流量转发仍须在设备上验证。

## 真实 eBPF 构建探测

`android-ebpf` 分支新增 `.github/workflows/android-ebpf.yml`。它先使用仓库固定的 nightly 和校验过 SHA256 的 bpf-linker 构建独立内核对象、检查 `.BTF`，再配置 Android NDK 环境，检查并链接 ARM64/API 35 的 `clash-api,rprx,ebpf` 核心。失败时仍上传编译报告；只有检查和链接全部成功才上传实验程序。此探测不执行或挂载内核程序，也不修改独立的 KernelSU 模块。

链接成功仅证明构建兼容性。Android 加载与验证器检查、cgroup/TCX/sk_lookup 挂载、网络命名空间权限、Android fwmark 路由和实际转发仍需分别进行设备验证。验证前保持 SELinux 强制模式并关闭自动启动。现有 Linux 路径 `/run/honk-core.lock` 和 `/var/run/netns/daens` 也需要检查 Android 运行时兼容性。

一台目标设备报告 Android 17/API 37、ARM64/4 KiB 内存页、Linux 6.12.69，使用官方 KernelSU，Root 上下文为 `u:r:ksu:s0`。内核 BTF 存在，bpffs 和 cgroup v2 已挂载；BPF、BPF syscall/JIT、cgroup BPF、网络命名空间、veth 和 TC BPF 配置均已内置。这些属于已观察到的前置条件，不是程序加载或流量测试结果。

该设备为 `CONFIG_NETFILTER_NETLINK_QUEUE=y`，但未启用 `CONFIG_NF_TABLES`。当前 NFQUEUE 服务需要安装 nftables 规则，因此完整路径不能原样使用。初期 Android 实验必须显式设置 `global.nfqueue_enable: false`。这不等于关闭全部 eBPF，也不证明 UDP 已可用：依赖 NFQUEUE 的不确定 LAN UDP 暂存和分片 LAN DNS 投递仍不可用。手机本机发起的 WAN 接管采用另一条 TC 路径，仍需验证。

移动数据网卡报告 RAWIP 帧格式。上游分类器已有该类型的 `_l3` 程序，但文档明确未验证真实基带网卡流量。设备测试必须考虑现有隧道和 Android 策略路由，不能清空 Android 规则或删除其他组件的 BPF 固定对象。

首次真实后端探测成功构建了带 BTF 的内核对象并准备了嵌入文件，Aya 和 NFQUEUE 依赖也通过 Android 检查，但核心因十二处声明缺失而编译失败。现将已有命名空间定义也用于 Android；Android 缺少的 `SO_NETNS_COOKIE` 声明采用 arm64 Linux UAPI 的值 71，Linux 继续使用 libc 声明。工作流先检查原生 Linux 的 `ebpf` 编译和格式，再配置 Android。透明 TCP/UDP 构造器、已接受连接的标记清除和 anyfrom 回包 socket 现已在 Android 上复用已有的命名空间路径。这仍不是经过验证的 Android 数据路径，不能自动装入 KernelSU 模块。


## 手机前台探针

真实 eBPF 核心提供无需配置文件的独立命令：

```sh
chmod 755 /data/local/tmp/honk-ebpf/honk-core
su -c '/data/local/tmp/honk-ebpf/honk-core android-ebpf-probe' > /sdcard/honk-ebpf-probe.txt 2>&1
```

先把 `honk-android-arm64-api35-ebpf-experimental` 构建产物解压至 `/data/local/tmp/honk-ebpf`，执行前核对其中的 `SHA256SUMS`。核心已嵌入内核对象，单独附带的 `honk-ebpf.o` 用于检查。保持 SELinux 强制模式，手动前台运行；该命令不安装服务、不修改模块自启。

命令观察普通 UDP socket 和带候选标记的 UDP socket 在 `connect` 前后的 SO_MARK，默认数字目标为 `1.1.1.1:53`，不发送应用载荷。`--destination` 接受 IPv4/IPv6 地址加端口；`--mark` 接受非零十进制候选值，默认 256。透明监听器与对象参数也使用同一个候选标记。UDP connect 成功、标记未被改写，仅属于观察结果，不能证明数据包或回包可达。

独立系统线程必须先成功进入新建的网络命名空间，才能创建私有 veth 或挂载程序。探针在两种地址族的未分配文档地址上调用生产用透明 TCP/UDP 构造器，检查嵌入对象 ABI 和无隐式固定路径，加载手机的 BTF 和 maps，再让验证器加载真实 `wan_ingress_l3`、`wan_egress_l3` 程序。每个程序都在私有 veth 上创建 TCX 链接、确认链接 ID 出现在链中，关闭 FD 后确认链接消失。所有链接和 map 均不固定；线程及命名空间销毁时移除私有网卡，出错路径也会清理。不挂根 cgroup、不改主机网卡钩子、路由、规则或 sysctl。

各阶段输出 `OK` 或带上下文的 `FAIL`，任何阶段失败均返回非零退出码。`private-tcx: OK` 仅证明私有以太网 veth 上的加载、挂载和卸载，不能证明 RAWIP 报文处理。全部通过后，仍需验证 cgroup/sk_lookup 钩子、Android 网络路由、真实基带流量、TCP/UDP 上传下载和网络切换。Android 真实守护进程启动仍会明确拒绝，`--mock-ebpf` 可继续使用；`/run/honk-core.lock` 和可选 `/var/run/netns/daens` 兼容挂载适配尚待完成。

### Socket 身份实验

目标手机上，UDP `connect` 把候选标记 `0x100` 改为 `0x000c0068`，与普通 socket 相同；候选 `0x01000000` 则变为 `0x010c0068`。Android 的 [Fwmark](https://android.googlesource.com/platform/system/netd/+/refs/heads/main/include/Fwmark.h) 包含网络 ID、权限等字段。仅放宽探针、接受任意改写结果，不能证明旁路有效。

可选的 `android-ebpf-probe --socket-identity` 实验借鉴 [NetProxy 固定的 sing-box 分支](https://github.com/reF1nd/sing-box/blob/v1.15.0-alpha.13-reF1nd/common/dialer/ebpf_self_bypass_linux.go)，把 socket 身份与 fwmark 分离。honk 复用已有的原生 `SK_STORAGE`，不引入 cookie LRU 或整个 UID 的豁免。只有前台探针加载器开启实验判断；生产加载器仍保留完整标记匹配。

该实验在 NEWNET 成功后，仅通过私有 loopback 发送有界 UDP 载荷。它挂载真实 WAN L2 分类器，对客户端的精确元组设置 fence，再通过其自有 socket FD 登记身份。无身份、错误 PID、零 PID、移除身份后都必须丢弃，登记为核心自身身份时必须投递；同进程的另一个未登记 socket 仍须丢弃。独立的原有标记模式即使登记了自身身份，也必须丢弃。每例检查接收结果，已登记客户端的 socket 标记必须保持不变；成功和错误路径均关闭私有 TCX 链接并确认其消失。

显式选择此模式后，主机 UDP 标记只作为观察结果，但主机 `connect` 仍须成功；旁路成功改由私有真实报文证明。默认探针继续严格检查标记保持。`private-socket-identity: OK` 仅证明显式 FD 登记和私有 WAN UDP 旁路，不代表生产可用。守护进程启用前，还必须处理钩子安装前创建的 socket，并让旁路登记失败中止启动；现有进程名自动采集允许分配失败。TCP 已接受连接、LAN socket 查找、Android 根 cgroup 共存、网络切换和完整转发仍需独立验证。
