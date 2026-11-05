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

The first real-backend probe built and prepared the BTF-bearing kernel object for embedding, and checked the Aya and NFQUEUE dependencies for Android, but failed core compilation with twelve missing-declaration errors. The namespace definitions now also compile for Android; its missing `SO_NETNS_COOKIE` declaration uses the arm64 Linux UAPI value 71 while Linux keeps libc's declaration. The workflow checks native Linux `ebpf` compilation and formatting before configuring Android. The transparent TCP/UDP constructors, accepted-socket mark clearing and anyfrom reply sockets now also use the existing namespace-aware path on Android. This is still not a verified Android datapath and must not be automatically installed into the KernelSU module.


## Foreground device probe

The real-eBPF executable provides a config-independent command:

```sh
chmod 755 /data/local/tmp/honk-ebpf/honk-core
su -c '/data/local/tmp/honk-ebpf/honk-core android-ebpf-probe' > /sdcard/honk-ebpf-probe.txt 2>&1
```

Extract the `honk-android-arm64-api35-ebpf-experimental` artifact into `/data/local/tmp/honk-ebpf` first. Verify its `SHA256SUMS` before execution. The executable embeds its object; the separate `honk-ebpf.o` is included for inspection. Keep SELinux enforcing. Run the command manually in the foreground; it does not install a service or change module startup.

The command observes ordinary and candidate-marked UDP sockets before/after `connect` to numeric `1.1.1.1:53`, without sending application payload. `--destination` accepts an IPv4/IPv6 socket address; `--mark` accepts a nonzero decimal candidate (default 256). The candidate is used consistently for transparent listeners and object parameters. UDP connect success and mark preservation are observations, not proof that packets or replies reach that destination.

A dedicated OS thread must successfully enter a new network namespace before it creates a private veth pair or attaches anything. It exercises production transparent TCP/UDP constructors on unassigned documentation addresses in both families, validates the embedded object ABI/absence of implicit pins, loads the device's BTF/maps, and loads the real `wan_ingress_l3`/`wan_egress_l3` programs through the verifier. For each program it creates a TCX link on the private veth, confirms the link ID appears in the chain, closes the FD and confirms disappearance. All links/maps are unpinned; thread/namespace teardown removes the private pair, including error paths. No root-cgroup hooks, host interface hooks, host routes/rules or sysctls are changed.

Each stage prints `OK` or a contextual `FAIL`; any failed stage returns a nonzero exit status. `private-tcx: OK` proves only load/attach/detach on a private Ethernet veth. It does not prove RAWIP packet processing. Even a complete successful probe leaves cgroup/sk_lookup hooks, Android network routing, physical modem traffic, TCP/UDP upload/download and network switching unverified. Real Android daemon startup remains explicitly refused; `--mock-ebpf` continues to work. `/run/honk-core.lock` and optional `/var/run/netns/daens` compatibility-mount adaptation remain pending behind that guard.
