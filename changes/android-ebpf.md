Internal

- Add an Android ARM64 real-eBPF compile/link probe and expose the existing namespace primitives and missing socket-option declaration on Android. Device loading, transparent sockets and forwarding remain unverified.
- Use the transparent TCP/UDP listener and reply-socket implementations on Android and keep physical forwarding gated during on-device validation.
