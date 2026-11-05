# Android port builds

The fork's `android-port` branch builds the native ARM64 CLI for Android API 35 with `.github/workflows/android-arm64.yml`. It uses the pinned Rust compiler and BoringSSL fork, including its REALITY patches, and the runner's Android NDK. `ci/android-toolchain.cmake` keeps BoringSSL on API 35 and disables upstream test and benchmark targets during cross compilation. systemd remains a Linux-only dependency.

The workflow checks both `--no-default-features --features clash-api` and `--no-default-features --features clash-api,rprx`. The executable includes the latter's VLESS/VMess handlers. It excludes the real eBPF backend and jemalloc. A passing check or linked executable establishes build compatibility only; it does not establish Android transparent proxy support. No APK or root module is produced at this stage.

On success, Actions uploads `honk-android-arm64-api35` with `honk-core` and `SHA256SUMS`, and a separate `android-arm64-port-report` containing the compiler logs and ELF interpreter/dependency report. A separate Linux job checks compilation, formatting and the existing socket metadata tests. Android startup, CA verification, marked downloads and actual network forwarding still require device validation.

## Real eBPF build probe

The `android-ebpf` branch adds `.github/workflows/android-ebpf.yml`. It builds the standalone kernel object using the repository's pinned nightly and checksum-pinned bpf-linker before configuring the Android NDK environment, verifies `.BTF`, then checks and links `clash-api,rprx,ebpf` for ARM64/API 35. Compiler reports are uploaded even on failure; the experimental executable is uploaded only when both check and link succeed. This probe does not execute or attach kernel programs and does not modify the separate KernelSU module.

A linked binary would establish build compatibility only. Android load and verifier admission, cgroup/TCX/sk_lookup attachment, namespace permissions, Android fwmark routing and real forwarding remain separate device gates. Keep SELinux enforcing and automatic startup disabled while those gates are unverified. The existing Linux paths `/run/honk-core.lock` and `/var/run/netns/daens` also need Android runtime review.

One target device reports Android 17/API 37, ARM64/4 KiB pages, Linux 6.12.69 and official KernelSU root in `u:r:ksu:s0`. Kernel BTF is present; bpffs and cgroup v2 are mounted; BPF, BPF syscall/JIT, cgroup BPF, network namespaces, veth and TC BPF options are built in. These are observed prerequisites, not program-load or traffic-test results.

That device has `CONFIG_NETFILTER_NETLINK_QUEUE=y` but `CONFIG_NF_TABLES` disabled. The current NFQUEUE service installs an nftables ruleset, so its full path cannot work there unchanged. Initial Android experiments must explicitly set `global.nfqueue_enable: false`. This does not disable eBPF globally or prove UDP forwarding: NFQUEUE-dependent ambiguous LAN UDP staging and fragmented LAN DNS delivery remain unavailable. Host-originated WAN interception uses a separate TC path that still requires validation.

Mobile-data interfaces report RAWIP framing. The upstream classifier has an `_l3` family for this type, but its documentation explicitly excludes real modem traffic from verified coverage. Existing tunnels and Android policy rules must be accounted for during device testing; do not flush Android rules or remove other consumers' BPF pins.

The first real-backend probe built and prepared the BTF-bearing kernel object for embedding, and checked the Aya and NFQUEUE dependencies for Android, but failed core compilation with twelve missing-declaration errors. The namespace definitions now also compile for Android; its missing `SO_NETNS_COOKIE` declaration uses the arm64 Linux UAPI value 71 while Linux keeps libc's declaration. The workflow checks native Linux `ebpf` compilation and formatting before configuring Android. Transparent-socket and outbound-mark helpers still contain Linux-only guards, so this stage must not be used as a working Android datapath or automatically installed into the KernelSU module.
