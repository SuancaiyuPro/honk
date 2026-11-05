# Android port builds

The fork's `android-port` branch builds the native ARM64 CLI for Android API 35 with `.github/workflows/android-arm64.yml`. It uses the pinned Rust compiler and BoringSSL fork, including its REALITY patches, and the runner's Android NDK. `ci/android-toolchain.cmake` keeps BoringSSL on API 35 and disables upstream test and benchmark targets during cross compilation. systemd remains a Linux-only dependency.

The workflow checks both `--no-default-features --features clash-api` and `--no-default-features --features clash-api,rprx`. The executable includes the latter's VLESS/VMess handlers. It excludes the real eBPF backend and jemalloc. A passing check or linked executable establishes build compatibility only; it does not establish Android transparent proxy support. No APK or root module is produced at this stage.

On success, Actions uploads `honk-android-arm64-api35` with `honk-core` and `SHA256SUMS`, and a separate `android-arm64-port-report` containing the compiler logs and ELF interpreter/dependency report. A separate Linux job checks compilation, formatting and the existing socket metadata tests. Android startup, CA verification, marked downloads and actual network forwarding still require device validation.
