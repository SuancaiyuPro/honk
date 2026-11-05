# Android 移植构建

此 Fork 的 `android-port` 分支通过 `.github/workflows/android-arm64.yml` 构建 Android API 35 的 ARM64 原生命令行程序。构建使用仓库固定的 Rust 编译器、保留 REALITY 补丁的 BoringSSL Fork 和运行器提供的 Android NDK。`ci/android-toolchain.cmake` 将 BoringSSL 统一到 API 35，并在交叉编译时关闭上游测试和基准目标。systemd 依赖仅用于 Linux。

工作流分别检查 `--no-default-features --features clash-api` 和 `--no-default-features --features clash-api,rprx`，最终程序采用后者，包含 VLESS/VMess 处理器，不包含真实 eBPF 后端和 jemalloc。检查通过或链接成功仅证明构建兼容性，不代表 Android 透明代理已经可用。此阶段不生成 APK 或 Root 模块。

成功后，Actions 上传 `honk-android-arm64-api35`，内含 `honk-core` 和 `SHA256SUMS`；另有 `android-arm64-port-report`，保存编译日志和 ELF 解释器、动态依赖报告。独立 Linux 任务检查编译、格式和现有 socket 元数据测试。Android 启动、CA 验证、带标记下载和实际流量转发仍须在设备上验证。
