//! Foreground device checks. Only the scope that successfully unshared NEWNET can attach.
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use aya::maps::{Array, HashMap, SkStorage};
use aya::programs::SchedClassifier;
use aya::{Ebpf, EbpfLoader};
use honk_ebpf_common::{DaeParam, RetirementFence, SocketIdentity, TuplesKey, dae_ip::In6Addr};
use socket2::{Domain, Socket, Type};

use super::{bindings, btf, layout};
use crate::ebpf::interface::{Direction, TcProgram};

pub(crate) fn run(destination: SocketAddr, mark: u32, socket_identity: bool) -> Result<()> {
    println!("honk Android eBPF probe {}", crate::VERSION);
    ensure!(mark != 0, "candidate mark must be nonzero");
    honk_outbound::util::init_bypass_mark(mark).context("initialize candidate bypass mark")?;
    let mark_result = check_host_mark(destination, mark, socket_identity);
    let reactor = tokio::runtime::Handle::current();
    let namespace = std::thread::Builder::new()
        .name("honk-ebpf-probe".into())
        .spawn(move || -> Result<()> {
            let _reactor = reactor.enter();
            let ns = "/proc/thread-self/ns/net";
            let original = std::fs::read_link(ns).context("read initial netns")?;
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).context("unshare NEWNET")?;
            ensure!(std::fs::read_link(ns)? != original, "netns did not change");
            println!("private-netns: OK");

            let ipv4 = crate::control::probe_transparent_listeners(SocketAddr::from((
                Ipv4Addr::new(192, 0, 2, 1),
                0,
            )));
            let ipv6 = crate::control::probe_transparent_listeners(SocketAddr::from((
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                0,
            )));
            let sockets4 = report("transparent-ipv4", ipv4);
            let sockets6 = report("transparent-ipv6", ipv6);
            let tcx = report("private-tcx", probe_classifiers(mark, socket_identity));
            ensure!(sockets4 && sockets6 && tcx, "private checks incomplete");
            Ok(())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("private probe thread panicked"))?;
    let namespace_ok = report("namespace-probe", namespace);
    let mark_label = if socket_identity {
        "host-udp-route (marks observational)"
    } else {
        "host-udp-mark"
    };
    let mark_ok = report(mark_label, mark_result);
    ensure!(
        namespace_ok && mark_ok,
        "see individual probe results above"
    );
    println!("probe: OK (cgroup/sk_lookup hooks and physical forwarding remain untested)");
    Ok(())
}

fn report(label: &str, result: Result<()>) -> bool {
    match result {
        Ok(()) => {
            println!("{label}: OK");
            true
        }
        Err(error) => {
            println!("{label}: FAIL {error:#}");
            false
        }
    }
}

fn observe_mark(label: &str, destination: SocketAddr, candidate: Option<u32>) -> Result<u32> {
    let socket = Socket::new(Domain::for_address(destination), Type::DGRAM, None)?;
    if let Some(mark) = candidate {
        socket.set_mark(mark).context("set SO_MARK")?;
    }
    let before = socket.mark()?;
    let connected = socket.connect(&destination.into());
    let after = socket.mark()?;
    println!("{label}: before={before:#010x} after={after:#010x}");
    connected.context("UDP connect for route lookup")?;
    Ok(after)
}

fn check_host_mark(destination: SocketAddr, candidate: u32, socket_identity: bool) -> Result<()> {
    let ordinary = observe_mark("ordinary-udp", destination, None);
    let marked = observe_mark("marked-udp", destination, Some(candidate));
    if let Err(error) = &ordinary {
        println!("ordinary-udp: FAIL {error:#}");
    }
    let marked = marked.context("candidate UDP socket")?;
    if socket_identity {
        ordinary?;
        println!("bypass-policy: native socket identity; mark equality is not bypass proof");
        return Ok(());
    }
    ensure!(
        marked == candidate,
        "candidate mark rewritten to {marked:#x}"
    );
    ensure!(ordinary? != marked, "ordinary socket has the same mark");
    Ok(())
}

fn probe_classifiers(mark: u32, socket_identity: bool) -> Result<()> {
    let mut nl = crate::netlink::NlSock::new().context("open private rtnetlink")?;
    nl.add_veth_pair("honkprobe0", "honkprobe1")
        .context("create private veth pair")?;
    let (ifindex, _) = nl.get_link("honkprobe0")?;
    let (peer, mac) = nl.get_link("honkprobe1")?;

    let object = crate::DEFAULT_BPF_OBJECT;
    layout::validate_object(object).context("check object ABI and absence of implicit pins")?;
    let (_, btf) = btf::load_kernel()?;
    let param = DaeParam {
        tproxy_port: u32::from(12346u16.to_be()),
        control_plane_pid: std::process::id(),
        dae0_ifindex: ifindex,
        dae0peer_mac: mac,
        use_redirect_peer: 1,
        dae_socket_mark: mark,
        tcp_daens_netns_id: 0,
        ..Default::default()
    };
    let mut bpf = load_probe_object(&param, peer, &btf, u8::from(socket_identity))?;
    println!("object-maps-btf: OK");

    let mut passed = true;
    for (variant, direction) in [
        (TcProgram::WanIngressL3, Direction::Ingress),
        (TcProgram::WanEgressL3, Direction::Egress),
    ] {
        let name = variant.name();
        let check = (|| -> Result<()> {
            let classifier: &mut SchedClassifier = bpf
                .program_mut(name)
                .context("missing classifier")?
                .try_into()?;
            classifier.load().context("kernel verifier")?;
            let program = classifier.fd()?.as_fd().try_clone_to_owned()?;
            let link = bindings::link_create(&program, ifindex, direction).context("attach TCX")?;
            let id = bindings::link_info(link.as_raw_fd())?.id;
            ensure!(
                bindings::query_chain(ifindex, direction)?.contains_link(id),
                "TCX link missing after attach"
            );
            drop(link);
            ensure!(
                !bindings::query_chain(ifindex, direction)?.contains_link(id),
                "TCX link still present after detach"
            );
            Ok(())
        })();
        passed &= report(name, check);
    }
    ensure!(passed, "one or more WAN L3 classifiers failed");
    if socket_identity {
        let (lo, _) = nl.get_link("lo")?;
        nl.set_link_up(lo, true)?;
        {
            let mut legacy = load_probe_object(&param, peer, &btf, 0)?;
            probe_socket_identity(&mut legacy, lo, param, false)
                .context("legacy mark negative control")?;
        }
        probe_socket_identity(&mut bpf, lo, param, true)
            .context("private socket identity bypass")?;
        println!(
            "private-socket-identity: OK (explicit FD registration; automatic capture untested)"
        );
    }
    Ok(())
}

fn load_probe_object(param: &DaeParam, peer: u32, btf: &aya::Btf, identity: u8) -> Result<Ebpf> {
    EbpfLoader::new()
        .btf(btf)
        .override_global("PARAM", param, true)
        .override_global("DAE0PEER_IFINDEX", &peer, true)
        .override_global("IPV6_SOCKETS_AVAILABLE", &1u8, true)
        .override_global("BYPASS_BY_SOCKET_IDENTITY", &identity, true)
        .load(crate::DEFAULT_BPF_OBJECT)
        .context("load unpinned maps and relocate embedded object")
}

fn probe_socket_identity(
    bpf: &mut Ebpf,
    lo: u32,
    param: DaeParam,
    identity_mode: bool,
) -> Result<()> {
    for name in ["DATAPATH_STATE_MAP", "RETIRE_ACTIVE"] {
        Array::<_, u32>::try_from(bpf.map_mut(name).context("missing readiness map")?)?
            .set(0, 1, 0)?;
    }
    let classifier: &mut SchedClassifier = bpf
        .program_mut("wan_egress_l2")
        .context("missing WAN L2 classifier")?
        .try_into()?;
    classifier
        .load()
        .context("private loopback kernel verifier")?;
    let program = classifier.fd()?.as_fd().try_clone_to_owned()?;
    let link = bindings::link_create(&program, lo, Direction::Egress)?;
    let id = bindings::link_info(link.as_raw_fd())?.id;
    ensure!(
        bindings::query_chain(lo, Direction::Egress)?.contains_link(id),
        "private loopback TCX link missing"
    );
    let result = (|| -> Result<()> {
        let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        receiver.set_read_timeout(Some(Duration::from_millis(200)))?;
        let client = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        client.connect(receiver.local_addr()?)?;
        let mark = socket2::SockRef::from(&client).mark()?;
        ensure!(
            mark != param.dae_socket_mark,
            "legacy candidate already matches the private client mark"
        );
        fence_probe_client(bpf, &client, receiver.local_addr()?)?;
        let cases: &[(&str, Option<u32>, bool)] = if identity_mode {
            &[
                ("missing", None, false),
                ("foreign", Some(param.control_plane_pid + 1), false),
                ("zero", Some(0), false),
                ("own", Some(param.control_plane_pid), true),
                ("removed", None, false),
                ("own-again", Some(param.control_plane_pid), true),
            ]
        } else {
            &[("legacy-own", Some(param.control_plane_pid), false)]
        };
        let mut registered = false;
        for &(label, pid, deliver) in cases {
            let mut storage = SkStorage::<_, SocketIdentity>::try_from(
                bpf.map_mut("SOCKET_IDENTITY")
                    .context("missing native socket storage")?,
            )?;
            if registered {
                storage.remove(&client)?;
            }
            if let Some(pid) = pid {
                storage.insert(
                    &client,
                    &SocketIdentity {
                        pid,
                        ..Default::default()
                    },
                    0,
                )?;
            }
            registered = pid.is_some();
            let payload = format!("honk-private-{label}");
            client.send(payload.as_bytes())?;
            let mut received = [0u8; 64];
            match receiver.recv(&mut received) {
                Ok(size) => ensure!(
                    deliver && &received[..size] == payload.as_bytes(),
                    "{label}: unexpected private UDP delivery"
                ),
                Err(error) => {
                    ensure!(
                        !deliver
                            && matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ),
                        "{label}: expected delivery={deliver}, receive failed: {error}"
                    );
                }
            }
            ensure!(
                socket2::SockRef::from(&client).mark()? == mark,
                "{label}: private socket mark changed"
            );
            println!("socket-identity-{label}: OK (delivery={deliver}, mark={mark:#010x})");
        }
        if identity_mode {
            let unrelated = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
            unrelated.connect(receiver.local_addr()?)?;
            fence_probe_client(bpf, &unrelated, receiver.local_addr()?)?;
            unrelated.send(b"honk-private-unrelated")?;
            let mut received = [0u8; 64];
            match receiver.recv(&mut received) {
                Ok(_) => {
                    anyhow::bail!("unregistered socket bypassed through another socket's identity")
                }
                Err(error) => ensure!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ),
                    "unrelated socket receive failed: {error}"
                ),
            }
            println!("socket-identity-unrelated: OK (delivery=false)");
        }
        Ok(())
    })();
    drop(link);
    ensure!(
        !bindings::query_chain(lo, Direction::Egress)?.contains_link(id),
        "private loopback TCX link still present after detach"
    );
    result
}

fn fence_probe_client(
    bpf: &mut Ebpf,
    client: &std::net::UdpSocket,
    destination: SocketAddr,
) -> Result<()> {
    let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (client.local_addr()?, destination)
    else {
        anyhow::bail!("private fence fixture requires IPv4 loopback sockets");
    };
    let key = TuplesKey {
        src_ip: In6Addr::from_ipv4_bytes(source.ip().octets()),
        dst_ip: In6Addr::from_ipv4_bytes(destination.ip().octets()),
        src_port: source.port(),
        dst_port: destination.port(),
        l4proto: libc::IPPROTO_UDP as u8,
        ..Default::default()
    };
    HashMap::<_, TuplesKey, RetirementFence>::try_from(
        bpf.map_mut("RETIRE_FENCE")
            .context("missing exact tuple fence map")?,
    )?
    .insert(
        key,
        RetirementFence {
            owner: 1,
            ..Default::default()
        },
        0,
    )?;
    Ok(())
}
