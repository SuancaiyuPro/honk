//! Foreground device checks. Only the scope that successfully unshared NEWNET can attach.
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};

use anyhow::{Context as _, Result, ensure};
use aya::EbpfLoader;
use aya::programs::SchedClassifier;
use honk_ebpf_common::DaeParam;
use socket2::{Domain, Socket, Type};

use super::{bindings, btf, layout};
use crate::ebpf::interface::{Direction, TcProgram};

pub(crate) fn run(destination: SocketAddr, mark: u32) -> Result<()> {
    println!("honk Android eBPF probe {}", crate::VERSION);
    ensure!(mark != 0, "candidate mark must be nonzero");
    honk_outbound::util::init_bypass_mark(mark).context("initialize candidate bypass mark")?;
    let mark_result = check_host_mark(destination, mark);
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
            let tcx = report("private-tcx", probe_classifiers(mark));
            ensure!(sockets4 && sockets6 && tcx, "private checks incomplete");
            Ok(())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("private probe thread panicked"))?;
    let namespace_ok = report("namespace-probe", namespace);
    let mark_ok = report("host-udp-mark", mark_result);
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

fn check_host_mark(destination: SocketAddr, candidate: u32) -> Result<()> {
    let ordinary = observe_mark("ordinary-udp", destination, None);
    let marked = observe_mark("marked-udp", destination, Some(candidate));
    if let Err(error) = &ordinary {
        println!("ordinary-udp: FAIL {error:#}");
    }
    let marked = marked.context("candidate UDP socket")?;
    ensure!(
        marked == candidate,
        "candidate mark rewritten to {marked:#x}"
    );
    ensure!(ordinary? != marked, "ordinary socket has the same mark");
    Ok(())
}

fn probe_classifiers(mark: u32) -> Result<()> {
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
    let mut bpf = EbpfLoader::new()
        .btf(&btf)
        .override_global("PARAM", &param, true)
        .override_global("DAE0PEER_IFINDEX", &peer, true)
        .override_global("IPV6_SOCKETS_AVAILABLE", &1u8, true)
        .load(object)
        .context("load unpinned maps and relocate embedded object")?;
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
    Ok(())
}
