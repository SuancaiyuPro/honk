#![cfg(feature = "ebpf")]

use std::process::Command;

fn probe(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_honk-core"))
        .args([
            "--config",
            "/nonexistent/honk-probe-config.dae",
            "android-ebpf-probe",
        ])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn help_needs_no_config_or_kernel_permissions() {
    let output = probe(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("--destination"));
    assert!(stdout.contains("--mark"));
    assert!(!stdout.contains("private-netns:"));
}

#[test]
fn zero_mark_fails_before_socket_or_namespace_work() {
    let output = probe(&["--mark", "0"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("candidate mark must be nonzero"),
        "{stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("ordinary-udp:"));
    assert!(!stdout.contains("private-netns:"));
}

#[test]
fn hostname_destination_fails_before_network_work() {
    let output = probe(&["--destination", "example.com:53"]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("invalid value")
    );
    assert!(output.stdout.is_empty());
}
