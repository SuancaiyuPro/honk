use aya_ebpf::bindings::bpf_sock;
use aya_ebpf::helpers::bpf_sk_fullsock;
use aya_ebpf::programs::TcContext;

#[inline(always)]
pub fn skb_is_dae_socket(ctx: &TcContext) -> bool {
    if crate::maps::BYPASS_BY_SOCKET_IDENTITY.load() != 0 {
        let socket = unsafe { (*crate::ctx::raw_skb(ctx)).__bindgen_anon_2.sk };
        return unsafe { crate::socket_identity::is_control_plane_socket(socket.cast()) };
    }
    let expected = crate::maps::PARAM.load().dae_socket_mark;
    expected != 0 && unsafe { (*crate::ctx::raw_skb(ctx)).mark == expected }
}

#[inline(always)]
pub fn bpf_sock_is_dae_socket(sock: *const bpf_sock) -> bool {
    if sock.is_null() {
        return false;
    }
    let fullsock = unsafe { bpf_sk_fullsock(sock as *mut _) };
    if fullsock.is_null() {
        return false;
    }
    if crate::maps::BYPASS_BY_SOCKET_IDENTITY.load() != 0 {
        return unsafe { crate::socket_identity::is_control_plane_socket(fullsock.cast()) };
    }
    unsafe { (*fullsock).mark == crate::maps::PARAM.load().dae_socket_mark }
}
