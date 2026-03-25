use std::sync::Arc;
use std::time::Duration;

use expect_test::expect;
use rstest::rstest;
use test_utils::find_unused_ports;
use testsuite::cli::{
    assert_stderr_eq, jetsocat_assert_cmd, jetsocat_tokio_cmd, wait_for_port_bound, wait_for_tcp_port,
};

#[cfg(windows)]
const WINDOWS_NAMED_PIPE_WAIT_DURATION: Duration = Duration::from_millis(600);

#[cfg(not(windows))]
const ASSERT_CMD_TIMEOUT: Duration = Duration::from_millis(600);
#[cfg(windows)]
const ASSERT_CMD_TIMEOUT: Duration = Duration::from_millis(1300);

#[cfg(not(windows))]
const MCP_REQUEST_SETTLE_DURATION: Duration = Duration::from_millis(600);
#[cfg(windows)]
const MCP_REQUEST_SETTLE_DURATION: Duration = Duration::from_millis(1300);

#[cfg(windows)]
async fn wait_for_windows_named_pipe_server() {
    tokio::time::sleep(WINDOWS_NAMED_PIPE_WAIT_DURATION).await;
}

#[cfg(not(windows))]
async fn wait_for_windows_named_pipe_server() {}

#[test]
fn no_args_shows_help() {
    let output = jetsocat_assert_cmd().assert().success();
    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("jetsocat [subcommand]"));
}

#[test]
fn all_subcommands() {
    let test_cases = [
        ("forward", "jetsocat forward <PIPE A> <PIPE B>"),
        ("f", "jetsocat forward <PIPE A> <PIPE B>"),
        ("jmux-proxy", "jetsocat jmux-proxy <PIPE> [<LISTENER> ...]"),
        ("jp", "jetsocat jmux-proxy <PIPE> [<LISTENER> ...]"),
        ("jmux", "jetsocat jmux-proxy <PIPE> [<LISTENER> ...]"),
        ("mcp-proxy", "jetsocat mcp-proxy <REQUEST PIPE> <MCP TRANSPORT>"),
        ("mcp", "jetsocat mcp-proxy <REQUEST PIPE> <MCP TRANSPORT>"),
    ];

    for (subcommand, help_substr) in test_cases {
        let output = jetsocat_assert_cmd().args([subcommand, "--help"]).assert().success();
        let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();
        assert!(stdout.contains(help_substr));
    }
}

#[rstest]
#[case::default(&[], &[], true)]
#[case::cli_always(&["--color=always"], &[], true)]
#[case::cli_never(&["--color=never"], &[], false)]
#[case::cli_auto(&["--color=auto"], &[], true)]
#[case::cli_always_and_env(&["--color=always"], &[("NO_COLOR", "")], true)]
#[case::cli_auto_and_env(&["--color=auto"], &[("NO_COLOR", "")], true)]
#[case::env_no_color(&[], &[("NO_COLOR", ""), ("FORCE_COLOR", "1")], false)]
#[case::env_term_dumb(&[], &[("TERM", "dumb")], false)]
#[case::env_term_other(&[], &[("TERM", "other")], true)]
#[case::env_force_color_0(&[], &[("FORCE_COLOR", "0")], false)]
#[case::env_force_color_1(&[], &[("FORCE_COLOR", "1"), ("TERM", "dumb")], true)]
fn log_term_coloring(#[case] args: &[&str], #[case] envs: &[(&str, &str)], #[case] expect_ansi: bool) {
    let output = jetsocat_assert_cmd()
        .timeout(ASSERT_CMD_TIMEOUT)
        .args(["forward", "-", "-", "--log-term"])
        .args(args)
        .envs(envs.iter().copied())
        .assert()
        .success();

    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    if expect_ansi {
        assert!(stdout.contains(" [32m INFO[0m [2mjetsocat[0m"), "{stdout}");
    } else {
        assert!(stdout.contains("  INFO jetsocat"), "{stdout}");
    }
}

#[rstest]
#[case::default(&[], &[], false)]
#[case::cli_always(&["--color", "always"], &[], true)]
#[case::cli_never(&["--color", "never"], &[], false)]
#[case::cli_auto(&["--color", "auto"], &[], false)]
#[case::cli_always_and_env(&["--color", "always"], &[("NO_COLOR", "1")], true)]
#[case::cli_auto_and_env(&["--color", "auto"], &[("FORCE_COLOR", "1")], false)]
#[case::env_no_color(&[], &[("NO_COLOR", "1"), ("FORCE_COLOR", "1")], false)]
#[case::env_term_dumb(&[], &[("TERM", "dumb")], false)]
#[case::env_term_other(&[], &[("TERM", "other")], false)]
#[case::env_force_color_0(&[], &[("FORCE_COLOR", "0")], false)]
#[case::env_force_color_1(&[], &[("FORCE_COLOR", "1"), ("TERM", "dumb")], true)]
fn log_file_coloring(#[case] args: &[&str], #[case] envs: &[(&str, &str)], #[case] expect_ansi: bool) {
    let tempdir = tempfile::tempdir().unwrap();
    let log_file_path = tempdir.path().join("jetsocat.log");

    jetsocat_assert_cmd()
        .timeout(ASSERT_CMD_TIMEOUT)
        .args(["forward", "-", "-", "--log-file", log_file_path.to_str().unwrap()])
        .args(args)
        .envs(envs.iter().copied())
        .assert()
        .success();

    let logs = std::fs::read_to_string(log_file_path).unwrap();

    if expect_ansi {
        assert!(logs.contains(" [32m INFO[0m [2mjetsocat[0m"), "{logs}");
    } else {
        assert!(logs.contains("  INFO jetsocat"), "{logs}");
    }
}

#[tokio::test]
async fn forward_hello_world() {
    // Find an available port.
    let port = find_unused_ports(1)[0];

    // Start jetsocat listener in background using JETSOCAT_ARGS.
    let mut listener = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward tcp-listen://127.0.0.1:{port} 'cmd://echo hello world' --no-proxy"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start jetsocat listener");

    wait_for_port_bound(port).await.expect("listener ready");

    // Connect to the listener and read the output using assert_cmd.
    let client_output = jetsocat_assert_cmd()
        .env("JETSOCAT_ARGS", format!("forward - tcp://127.0.0.1:{port}"))
        .timeout(ASSERT_CMD_TIMEOUT)
        .assert();

    // Kill the listener.
    let _ = listener.start_kill();
    let _ = listener.wait().await;

    // Check that we got the expected output.
    #[cfg(windows)]
    client_output.success().stdout("hello world\r\n");
    #[cfg(unix)]
    client_output.success().stdout("hello world\n");
}

#[tokio::test]
async fn jmux_proxy_read_hello_world() {
    // Find 3 available ports at once to avoid conflicts.
    let ports = find_unused_ports(3);
    let echo_server_port = ports[0];
    let jmux_server_port = ports[1];
    let proxy_listen_port = ports[2];

    // Start echo server first.
    let mut echo_server = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward tcp-listen://127.0.0.1:{echo_server_port} 'cmd://echo hello world' --no-proxy"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start echo server");

    wait_for_port_bound(echo_server_port).await.expect("echo server ready");

    // Start JMUX server that will accept JMUX connections.
    let mut jmux_server = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("jmux-proxy tcp-listen://127.0.0.1:{jmux_server_port} --allow-all --no-proxy"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start JMUX server");

    wait_for_port_bound(jmux_server_port).await.expect("JMUX server ready");

    // Start JMUX client proxy that connects to the JMUX server and provides a local TCP listener.
    // This creates a tunnel: client -> proxy_listen_port -> jmux_server_port -> echo_server_port
    let mut jmux_client = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!(
                "jmux-proxy tcp://127.0.0.1:{jmux_server_port} tcp-listen://127.0.0.1:{proxy_listen_port}/127.0.0.1:{echo_server_port} --no-proxy",
            ),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start JMUX client");

    wait_for_port_bound(proxy_listen_port)
        .await
        .expect("JMUX client proxy ready");

    // Connect to the JMUX client's local listener.
    let client_output = jetsocat_assert_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward - tcp://127.0.0.1:{proxy_listen_port}"),
        )
        .timeout(ASSERT_CMD_TIMEOUT)
        .assert();

    // Kill all processes.
    let _ = jmux_client.start_kill();
    let _ = jmux_server.start_kill();
    let _ = echo_server.start_kill();
    let _ = jmux_client.wait().await;
    let _ = jmux_server.wait().await;
    let _ = echo_server.wait().await;

    // Check that we got the expected output through the JMUX proxy.
    #[cfg(windows)]
    client_output.success().stdout("hello world\r\n");
    #[cfg(unix)]
    client_output.success().stdout("hello world\n");
}

#[tokio::test]
async fn jmux_proxy_write_hello_world() {
    use tokio::io::AsyncReadExt as _;

    // Find 3 available ports at once to avoid conflicts.
    let ports = find_unused_ports(3);
    let read_server_port = ports[0];
    let jmux_server_port = ports[1];
    let proxy_listen_port = ports[2];

    // Start read server first.
    let mut read_server = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward tcp-listen://127.0.0.1:{read_server_port} stdio --no-proxy"),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start read server");

    wait_for_port_bound(read_server_port).await.expect("read server ready");

    // Start JMUX server that will accept JMUX connections.
    let mut jmux_server = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("jmux-proxy tcp-listen://127.0.0.1:{jmux_server_port} --allow-all --no-proxy"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start JMUX server");

    wait_for_port_bound(jmux_server_port).await.expect("JMUX server ready");

    // Start JMUX client proxy that connects to the JMUX server and provides a local TCP listener.
    let mut jmux_client = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!(
                "jmux-proxy tcp://127.0.0.1:{jmux_server_port} tcp-listen://127.0.0.1:{proxy_listen_port}/127.0.0.1:{read_server_port} --no-proxy",
            ),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start JMUX client");

    wait_for_port_bound(proxy_listen_port)
        .await
        .expect("JMUX client proxy ready");

    // Connect to the JMUX client's local listener.
    jetsocat_assert_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward tcp://127.0.0.1:{proxy_listen_port} 'cmd://echo hello world' --no-proxy"),
        )
        .timeout(ASSERT_CMD_TIMEOUT)
        .assert()
        .success();

    // Kill all processes.
    let _ = jmux_client.start_kill();
    let _ = jmux_server.start_kill();
    let _ = read_server.start_kill();
    let _ = jmux_client.wait().await;
    let _ = jmux_server.wait().await;
    let _ = read_server.wait().await;

    // Check that the read server received the payload.
    let mut read_server_stdout = String::new();
    read_server
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut read_server_stdout)
        .await
        .unwrap();
    assert_eq!(read_server_stdout.trim(), "hello world");
}

#[test]
fn doctor_no_args_is_valid() {
    jetsocat_assert_cmd().arg("doctor").assert().success();
}

#[test]
fn doctor_verify_chain_with_json_output() {
    // Chain checks that are expected to fail because the leaf certificate is expired.
    // On Windows, only the schannel backend runs (CI builds with native-tls, not rustls).
    let expected_chain_failures: &[&str] = if cfg!(windows) {
        &["schannel_check_chain"]
    } else {
        &["rustls_check_chain"]
    };

    let tempdir = tempfile::tempdir().unwrap();
    let chain_file_path = tempdir.path().join("expired-devolutions-net-chain.pem");
    std::fs::write(&chain_file_path, EXPIRED_DEVOLUTIONS_NET_CHAIN).unwrap();

    let output = jetsocat_assert_cmd()
        .args([
            "doctor",
            "--chain",
            chain_file_path.to_str().unwrap(),
            "--subject-name",
            "devolutions.net",
            "--format",
            "json",
        ])
        .assert()
        .failure();

    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    // Ensure that each line is a JSON object containing all the expected fields.
    for line in stdout.lines() {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();

        // Required fields.
        assert!(entry["name"].is_string());
        assert!(entry["success"].is_boolean());

        // Optional fields.
        for (key, value) in entry.as_object().unwrap() {
            match key.as_str() {
                "name" | "success" => { /* verified above */ }
                "output" => assert!(value.is_string()),
                "error" => assert!(value.is_string()),
                "warning" => assert!(value.is_string()),
                "help" => assert!(value.is_string()),
                "links" => assert!(value.is_array()),

                // Make sure there is no unintended key in the serialized payload.
                _ => panic!("unexpected key: {key}"),
            }
        }

        let name = entry["name"].as_str().unwrap();

        if expected_chain_failures.contains(&name) {
            // Since the leaf certificate is expired, chain checks should fail.
            assert!(!entry["success"].as_bool().unwrap(), "{name} should have failed");
        } else {
            // All the other checks should succeed.
            assert!(entry["success"].as_bool().unwrap(), "{name} should have succeeded");
        }
    }

    const EXPIRED_DEVOLUTIONS_NET_CHAIN: &str = "
-----BEGIN CERTIFICATE-----
MIIHjDCCBXSgAwIBAgIQA+YDg5H+4+jZc0rMWYNN1zANBgkqhkiG9w0BAQsFADBc
MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xNDAyBgNVBAMT
K0dlb1RydXN0IEdsb2JhbCBUTFMgUlNBNDA5NiBTSEEyNTYgMjAyMiBDQTEwHhcN
MjUwNTA3MDAwMDAwWhcNMjUxMTA0MjM1OTU5WjAaMRgwFgYDVQQDEw9kZXZvbHV0
aW9ucy5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDT4diIqDe8
YF5wuSq8jDBOF5fx2nRddscoeEnhyiCktaoXMWy+3CMh3dxDdqy4WUVInmC9AsXa
/1VyT95XbUtxXTZbN+vW6N6/8Al+d5d/fct7wMnIh/ZWyJvDprVvI1zDnuudLXjR
8m5R9yxa9wivX/NUIoPp6++qDR905BTayf0DrmdnTEAWu++xEJi7NtE2MAH/fcHd
/MDpzKMCym9aS38IKFZNhwBxXMPuqmGC5eHjJ/YLDUWNuAyyD1AOZoYOxjOA0K10
v1Tva02xwi0vh73uYoQvDQmOMAOTN6FFN6wHXYF2xZi5dI68HJnYa9laszorPs/B
2SOUGIG1280NAgMBAAGjggOKMIIDhjAfBgNVHSMEGDAWgBSltNbrNsTna6bfxGQL
ASogBLhmIzAdBgNVHQ4EFgQUwGsZkQ58uMYU+jeMNgc1SfbfkCgwGgYDVR0RBBMw
EYIPZGV2b2x1dGlvbnMubmV0MD4GA1UdIAQ3MDUwMwYGZ4EMAQIBMCkwJwYIKwYB
BQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8EBAMC
BaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGfBgNVHR8EgZcwgZQw
SKBGoESGQmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9HZW9UcnVzdEdsb2JhbFRM
U1JTQTQwOTZTSEEyNTYyMDIyQ0ExLmNybDBIoEagRIZCaHR0cDovL2NybDQuZGln
aWNlcnQuY29tL0dlb1RydXN0R2xvYmFsVExTUlNBNDA5NlNIQTI1NjIwMjJDQTEu
Y3JsMIGHBggrBgEFBQcBAQR7MHkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
Z2ljZXJ0LmNvbTBRBggrBgEFBQcwAoZFaHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
Y29tL0dlb1RydXN0R2xvYmFsVExTUlNBNDA5NlNIQTI1NjIwMjJDQTEuY3J0MAwG
A1UdEwEB/wQCMAAwggF9BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB3ABLxTjS9U3JM
hAYZw48/ehP457Vih4icbTAFhOvlhiY6AAABlqw1+UoAAAQDAEgwRgIhAK1rv7SB
+jm8Qy1YbH6ye6D/QhV9UIb/naDS1xbyazxIAiEAmy3tsZ38AwMsHGXjYTn2ONiN
4rIO6W4ESWbmopwmvT8AdQDtPEvW6AbCpKIAV9vLJOI4Ad9RL+3EhsVwDyDdtz4/
4AAAAZasNfmFAAAEAwBGMEQCIBOIOKPB2twwfv7NfboUHZZtC1sOXiYa4jYzqwpk
S06kAiAwEM/shWHMYfV5quqQuJQ2Ru0iFKigAjxN4g3NDMU4KgB1AKRCxQZJYGFU
jw/U6pz7ei0mRU2HqX8v30VZ9idPOoRUAAABlqw1+ZoAAAQDAEYwRAIgRNq7xMon
czeiHM+1ruQeN0OUZjI+PM+H9RGtFCm7Y6wCICq0jMeJCkwJas+oCsbKolEA5737
pGcv+X94dwYwZ824MA0GCSqGSIb3DQEBCwUAA4ICAQCuLE+wNbMBu7YgW8XUfblH
zuL9Xb70CaEdQelfGIMrMAHVo30TkG3kyP4N241wbqH8CXWuYDYf/QW8tmiPFb/G
qjBbY/NhGMYMUqTG3u3rziuftgxi+OGducepUfTEgLLTFg03M25UpnHP8+EXhR/d
YchKc+YGtM9EWUXn8/EDFra1zpX9rxzEplvlQWYhYQcLAVezwMIo6UlauFj7dIq9
PIdUrnA09Rd3vYTIvGVlj8bTuTYTWdn2XthGq2rhzPNUorjh46xjmKet9+De7+n3
Z2Xvvv+iPr1JKRVB3qVPMJGCWWCFhl8iiRWwQ06pzgH9MQVezK0IABy5J2gxF0yB
MG5TiQpZdB2Nzi6qyzoK5EzXdaOjXH7CNWaw5ucWvQT3GoZeqRcVyFkE96iMRwJk
qQJ1mT3qDeqGshspR4Zo+wLcnfCPW9M0Mf/y/MGtlWMYvZ90jawO97s+bE2EXCt0
cDfm2stigBGm9EGx4zfMjWJ5PEtfBFdG0LMAaw7gySQUi2MTrK/oEmS6e0EOwK5F
f2AVMEB2Vc/YlNRvZR0YDY8q7VV2SI1SkCdXNNDyzzyA8IL6JGCe52cyiCIurXsT
Z+qKTR86hhmsa5bMSygfBjxTHUqTUjuqf5brc2beyvvZs7R9FhUqNLmGrIb+tdjj
VQoGRDW+K3J2NzNPL6XuYg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFyzCCBLOgAwIBAgIQD2IvbyHC/11SH3I6HUfWLTANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0yMjA1MDQwMDAwMDBaFw0zMTExMDkyMzU5NTlaMFwxCzAJBgNVBAYTAlVT
MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE0MDIGA1UEAxMrR2VvVHJ1c3QgR2xv
YmFsIFRMUyBSU0E0MDk2IFNIQTI1NiAyMDIyIENBMTCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBAOi2w4fkhoZPCI6L7nLMjvJTFg2rvXa7JPgQtpm9Ls4Z
9u2/SuiTDcjnGfjMYq9uTdBsiRjCC8fh3HsrPMCCAvfAf7bY349rOV4XWTGXZ2RS
UE20zKyhiF1Z+SkySD5+9yxzLNEyb+JXN8LLLcyB2Hw79jEq6v09+8zL5Ip3wFz9
+Uc3Tx4LVwTvW50pGMHFl3xpjO7iQS2RCkNcHHdqfEEkKy8EStVGA27aYYuHbgdx
ivjv0Axx3M4NrWfO8tGj8w0t8LhKDTuk/gFOI4klRcHRjcuH6giK6mkM3qpGGQLW
+Zc7Q93NFXalE5Qzn5/JESIcSPFDOezoAi9fMdtEa7Qj9/yCaUx5S14l66zlE1Od
y5hzpQBOlsw9KjJxsfpc4LQTB8aDaNjSqzLpwj6XlsRjaRon9GSS1q6HDYI3o8pR
x03xM1k7JTgiyyRO+84PVjLUOxy6u4SrEXRM0jdtxqnzfwW2CFsKo+5xHZB9xt5m
82zwUzY7+VOHEg8YpJxS2N6HR6QBvxo/6pgyfdmwAjiOGhA1GfHvQWf2vyHNguLq
1Jn4gr0b27HMZl6yqquv9O9XgDjPk147eym8GbN6AmBBke0HXR8fPwier1spgIoB
W3txZY6OiJr/JRl2n5MnUZ3QdyFfvzfkuBWwVCI7WI4gVJmhkOMeG9grhIRPm+zH
AgMBAAGjggGCMIIBfjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSltNbr
NsTna6bfxGQLASogBLhmIzAfBgNVHSMEGDAWgBQD3lA1VtFMu2bwo+IbG8OXsj3R
VTAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
cnQuY29tMEAGCCsGAQUFBzAChjRodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
RGlnaUNlcnRHbG9iYWxSb290Q0EuY3J0MEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6
Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwPQYD
VR0gBDYwNDALBglghkgBhv1sAgEwBwYFZ4EMAQEwCAYGZ4EMAQIBMAgGBmeBDAEC
AjAIBgZngQwBAgMwDQYJKoZIhvcNAQELBQADggEBAJ5ytcBRxwtzXW/S2tOySJu4
bhFRUuYRF91SMDUX8aX8Z/JIdLZb1+d6LIaiVkybFKYL8K2xual6/NL0tcI0T3Nw
/QNwS12NrfbS/th9aus7kiSbnNbkM2sc61vx9lF0qYklhJzSOkUPPSyq4Bdhg8G6
puAqrvQNqxNNMTTyMs5KNJdpLMEdIKdelM+9KKEMy9/jWGuLoNr8BvjkDx19VQSI
MCrwTFiQSC3sMkZQrCgZIwnQbf2ynOSMDutLoja5uKB7l+vbH2qSPFf3vD2HoTH7
S8+k0HfXb/f7ZSM5GDln3DTbBPI2qmmMiwFZJOMuYAQP1cyP8ywlhfdEdKVcW6E=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----";
}

#[test]
fn doctor_missing_san_and_eku() {
    // Checks that are expected to fail because the certificate is missing SAN and EKU.
    // On non-Windows, rustls runs: end entity cert check also fails because rustls requires SAN.
    // On Windows (native-tls/schannel only), schannel end entity cert check succeeds (CN fallback).
    let expected_failures: &[&str] = if cfg!(windows) {
        &[
            "schannel_check_chain",
            "schannel_check_san_extension",
            "schannel_check_server_auth_eku",
        ]
    } else {
        &[
            "rustls_check_end_entity_cert",
            "rustls_check_chain",
            "rustls_check_san_extension",
            "rustls_check_server_auth_eku",
        ]
    };

    // Checks expected to carry a warning about TlsVerifyStrict.
    let expected_warnings: &[&str] = if cfg!(windows) {
        &["schannel_check_san_extension", "schannel_check_server_auth_eku"]
    } else {
        &["rustls_check_san_extension", "rustls_check_server_auth_eku"]
    };

    let tempdir = tempfile::tempdir().unwrap();
    let chain_file_path = tempdir.path().join("no-san-no-eku.pem");
    std::fs::write(&chain_file_path, CERT_WITHOUT_SAN_OR_EKU).unwrap();

    let output = jetsocat_assert_cmd()
        .args([
            "doctor",
            "--chain",
            chain_file_path.to_str().unwrap(),
            "--subject-name",
            "test.example.com",
            "--format",
            "json",
        ])
        .assert()
        .failure();

    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    for line in stdout.lines() {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();

        let name = entry["name"].as_str().unwrap();
        let success = entry["success"].as_bool().unwrap();

        if expected_failures.contains(&name) {
            assert!(!success, "{name} should have failed");
        } else {
            assert!(success, "{name} should have succeeded");
        }

        if expected_warnings.contains(&name) {
            assert!(
                entry["warning"].is_string(),
                "{name} should have a warning about TlsVerifyStrict"
            );
            let warning = entry["warning"].as_str().unwrap();
            assert!(
                warning.contains("TlsVerifyStrict"),
                "{name}: warning should mention TlsVerifyStrict, got: {warning}"
            );
        }
    }

    // This certificate is a basic self-signed cert generated with:
    //   openssl req -x509 -newkey rsa:2048 -keyout /dev/null -nodes -subj "/CN=test.example.com" -days 3650
    // It has no Subject Alternative Name (SAN) extension and no Extended Key Usage (EKU) extension.
    // The doctor should report warnings for both missing properties.
    const CERT_WITHOUT_SAN_OR_EKU: &str = "
-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUfFwD6PaeQUaW/b9RAunIbruFiOMwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjAzMTkwMjQ4MTda
Fw0zNjAzMTYwMjQ4MTdaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCVm3m0BFIhYJmxs1yt+QhHVz+T
YdJlY7tsJmaqR9mtV5BW3rLRL1W+dQJ3cSuBLAtE6BWWhec/guRMxR2nwsJ+8GFo
G83AE+ulehST+Ymh7LTTD4jHex6bZM0L132wWUkskkFhYzqQiXHBqKkuAmmcOe9l
gy+tvV4nIlta2vKC7U+1W3cixJS1Anu/BOvy08XctUwRtAxQsSbvFawE1sqGYD95
sGNraE3w74kc0jRsldv0zGclsW463GQhVlHRu/56SW5DGSXdxhsZXKsChEubphZ5
u7s0OB8XEqyr4kAJVfmFsdr2xavxkuwW6vuO6CDhrV6bZRYgNnFbVKf1HLjDAgMB
AAGjUzBRMB0GA1UdDgQWBBQsVvQ0YMe8qMcT1L/XSV4q78G8lzAfBgNVHSMEGDAW
gBQsVvQ0YMe8qMcT1L/XSV4q78G8lzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQAIE5Fy7xFodiOGSSRwhXL90bMa477nONobhF6rdeRaH47H0Sru
Nj0WvwWgv6QYWvMk40xvCGcOJl8ZO18KxrHV3tKAWv92VWhKcSXXYIVJdrEdi5z1
qRjFhOl8Bk6jlUomjk2CwbaBjxZctUSM/bpc+szOipSPf7VYA340iWVpb1frmZMW
Oz1dDMCILaSldUlmPXL9g5VntW6Rr7zfLqyeUwq0BV22O9l349Kbu3i9EifWerAf
D7Evd6eXm50umoqlchupHZFRmIJCiHrg7vWwXdJQtgP8zYqh7uZIIbHsLHBJAlR3
4p6zIygy/wRS/nQb/Y+kFRN+uRdfVB7eftRJ
-----END CERTIFICATE-----";
}

// Three-cert test PKI generated with:
// $ openssl req -x509 -newkey rsa:2048 -keyout root_key.pem -nodes -subj "//CN=Test Root CA" -days 3650 -out root_cert.pem
// $ openssl req -newkey rsa:2048 -keyout int_key.pem -nodes -subj "//CN=Test Intermediate CA" -out int_csr.pem
// $ openssl x509 -req -in int_csr.pem -CA root_cert.pem -CAkey root_key.pem -CAcreateserial -days 3650 -extensions v3_ca -extfile int_ext.cnf -out int_cert.pem
// $ openssl req -newkey rsa:2048 -keyout leaf_key.pem -nodes -subj "//CN=test.example.com" -out leaf_csr.pem
// $ openssl x509 -req -in leaf_csr.pem -CA int_cert.pem -CAkey int_key.pem -CAcreateserial -days 3650 -extensions v3_leaf -extfile leaf_ext.cnf -out leaf_cert.pem
const TEST_ROOT_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUZxRRVbwY49ChgWyQHTm3Xa/oS5wwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MDMyNTAxMjAyNloXDTM2
MDMyMjAxMjAyNlowFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmwVhUvsKSDUeBL6yRcR9x55uQ2DDlFFZIbdW
TSB3b3w3POkqSGNy/Fh6CRmaKlmoJqzXLMzs/VxEkGJ0wGeCDAAwf2NlTEQK8gun
ZrZqD8R7dwX79Iw20GMtR2pr1ioVLaSnugat7T8wV0Cuys9owKapqglAKlgRiFSj
v62TdBJt1XLhVREIfSG5KFo5onGcN3M9g1McoPjR6xmVCaedM2ozIYksZAz+/63Q
YXlMS9+wCJPrEkF+YS9Woc2jASg8a6GAaYVkB9Hw6hTpULMYGPr1riO9GDlDsbC7
QhY9mPFIDd9q8DG9eJPqfOqnw50dMsWEGxqTcFdpEAfARxtGBQIDAQABo1MwUTAd
BgNVHQ4EFgQU2YZ7YewgHYX8IJSlm7g43MeGySowHwYDVR0jBBgwFoAU2YZ7Yewg
HYX8IJSlm7g43MeGySowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAG7HyQhtmP3CHFEHfypNHBRbBjM1tuuiXbepEslfK/hs7fO2Otcicppx/XaWe
QWnGtM6bIK8lqG6wru8B/2EyWMENTxU0awYVQt7UK464APuteVuLBIdh07CY+PBE
7bUKIUEtZbz471KTWKAL4x54g+C8pUqzTzyqxYuqMeIyOftPxcBdpFa4zYc3JVui
tNzrw4eJJWshQeaKRQCtySPwB/MzeCreqEhy/VItZQDipjw/Dw/+ZQT8PfBZO5kS
bzZZAriTbbObEvX8EJVMoFfgmQO2+zKbe5X2T7xS36EYLWg9noJ2qR/heKAzVoiD
tuoCF30p15RTxDebu/VTTt/ZVg==
-----END CERTIFICATE-----";
const TEST_INTERMEDIATE_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIUKaBPb8wiSebGgbVL9B8Rt+kevXAwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMVGVzdCBSb290IENBMB4XDTI2MDMyNTAxMjA0N1oXDTM2
MDMyMjAxMjA0N1owHzEdMBsGA1UEAwwUVGVzdCBJbnRlcm1lZGlhdGUgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6S5phbyiAPSiGr7IEFZVu2V6P
bivNGSIHG8QLa/FbsC0V1bRlf04YeImMSIG5915vOEhIN+UxFDy7CRSJhwimiLR8
6xrsjLKchtBhupR5PmMKo0BvaH3jZw7GorUiLDydx+LI4F+Wrk0JJMLJxfeoVBOK
jzKYlSu6rP5XZa9gLYwrw882YdGospl7ElHAYyTNG8PE1inVmThI4gOYgH7FaPXE
aLNqA2t4mSbLTLX1OJZRYF2toRP1hWXCXOi0hbnaeVbgLbvP+TmRAGNCQlt1GXUO
JJG3AnYer/LQEjoOIzt3MtjtoWWKLk4BebqzwyIxYFW6g9eeft6tvP1ssGMBAgMB
AAGjYzBhMB0GA1UdDgQWBBS0lZqvKVLibCLjthjp+PiiP65vRzAfBgNVHSMEGDAW
gBTZhnth7CAdhfwglKWbuDjcx4bJKjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAOFzRVPQ3d6Cu6EghguFbdxmupBI8
dbaQfENj5hvrJolETb/nimEPPBl3AqxikhPgPBLjAfHSRFd/d6MxQ5U3XvgPdPGz
IeJR5Xxqq0+zLXOY/bx4z4+XqBnaQgXkdCDKDgoXZqOM6aTu38DCA5WXqq6LGl1u
PhR5mQZONOWQcfz8yRjoYWvJByAJqEloGa1aqiLo/NsmDxRRifEtmTlQZHVWjtdn
MQq/TBNHx8FXzsLOFfP7lwmvQE1tWL+3oHh87SgOb1k+NvXPEzN8AtP2vubEosdL
NFv0crwYecXxZllEPg50gQotPx+zwblyteRaMiuHOkPCFhcxsGbl1279cg==
-----END CERTIFICATE-----";
const TEST_LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDXDCCAkSgAwIBAgIUMPgKPFE7dy3fDXDMbKPYuu2BYtEwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUVGVzdCBJbnRlcm1lZGlhdGUgQ0EwHhcNMjYwMzI1MDEy
MTA1WhcNMzYwMzIyMDEyMTA1WjAbMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmoEQjemF/jx9NIUwEXu5
nnGkjFJ5WWrBeHj+myudFMnbuh5H2bcHCD67Ul2q0+yYRVW95vf5X4BDV9q8PMfu
v/snVChbTU7IY/EgR+3CcKpJHRMS84duvB8Tuyu7PtcMQmPOOioCdg+MIF4v0qJd
eO+wAzdgscIUGh0EX4bUF5Nk0mj/7pOOG4gu00FPIaiqCWk2phRStm4jjOeyHJ25
kt6GE4q38Jb7ZcdhmGv8cLNA1ZRenwWb0Xt6Fn5e2LGiUFpr0HVWPlL0Ul24we4D
CZHdiVf+Q/0VJzxvC4D8bkwHGGmyB93eSKtre88ncbLdSM5baEusVU73XVXvpAqo
QwIDAQABo4GTMIGQMBsGA1UdEQQUMBKCEHRlc3QuZXhhbXBsZS5jb20wEwYDVR0l
BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYD
VR0OBBYEFJPQQRCPWmnWzS+9tKHrQHy9TWu4MB8GA1UdIwQYMBaAFLSVmq8pUuJs
IuO2GOn4+KI/rm9HMA0GCSqGSIb3DQEBCwUAA4IBAQCZIlzIboOSstiqfkTJEhKm
lk7NPRvloDj3CKw7HFITfly4jMXHabf2kuBwiCdtGNALFbfCllxl7MsoTBzUOvDv
inAx1srqD1uQeXQvH1DFDeioj5fFM6fbkmNvElxe9NJ2rJzkrEiqOF11RuWdX8n6
jbvTXzmri8qgr1bppTbojubVecSzXdDJVepXzKBTxPdyGnFCSO8yGj/FB0EvCkHo
HfiS7YOPqRb4fQZl+QPimeYSNkDNk2McIDjAIF+A+cB2RPA0MfrmDoxAHR1j0S8e
ni3u97ReFRox/Q2JNuNORjxnyAmZdj/1ZJtdB7MuSkVt+DutROM2td4NgdqQro+a
-----END CERTIFICATE-----";

// Self-signed certificate (CA:FALSE) with SAN (DNS:test.example.com) and serverAuth EKU.
// Generated with:
// $ openssl req -x509 -newkey rsa:2048 -keyout /dev/null -nodes -subj "//CN=test.example.com" -days 3650 \
//     -addext "subjectAltName=DNS:test.example.com" -addext "extendedKeyUsage=serverAuth" \
//     -addext "basicConstraints=CA:FALSE" -out self_signed.pem
const TEST_SELF_SIGNED_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIUWSfPt3StVv7BCYgCOGD3wln5YeEwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjAzMjUxMDU1NTla
Fw0zNjAzMjIxMDU1NTlaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfc164NgUyOg3LNuGReuJdUBpT
dFmUHcS5VbpVcy1VQ95DNbbWX9JY04RXKLhLBftY4cralM89u8vKkVvl5Vas6NTb
tLYk/ljCww2gL9PFr6Zf9ZgqmjOw3opD8jTygngiVi+VzFfogKapcVpsAiYMTy9J
y1d3tgdXzIbHclsvqsB0V976iGSlIKRfPOhlQ6e89v8X80YNLTz700lH0N0wjg1E
iOjyF8pNhrGyPQPo4cjo6SDIzjWs3bFU7lcPCrhfnA8epYlERZqBprY9dWm6mYXu
k0QXGGP+i56EMHRI9YRfUd5fhpAjq2yx44+WsT8FfqG5HK3dCULvi7wvHTgTAgMB
AAGjfzB9MB0GA1UdDgQWBBTZFRHl5Eopt7M5WEb8ydBUjKUR3TAfBgNVHSMEGDAW
gBTZFRHl5Eopt7M5WEb8ydBUjKUR3TAbBgNVHREEFDASghB0ZXN0LmV4YW1wbGUu
Y29tMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEL
BQADggEBAJAleJ0BiHcAeXg0vqb3zYs7yX+CObQSMILMNAy4N+E1fvCH50Vs6U7D
SdGAOuSXFsV7Ahaag0yhOF+KKuB0f3tAKknJb1ElGDBK3JKVqmEDraaolqUVmPKb
BH4jlmRUP4eDxyOf8qB0P2c7CyHzUjc7nRiCNXekUpjyEiC6K4Y+8bgQHkHeCyFy
OUve99jR7FDqXEaajeMSzeQqnM2BFRKdsnPU1wI1IycYzaWjtnonOjkwEWTEifTN
ba9cEJpxx21iE+QeG7JrsQWLTBf27heBajlYBFvEDbemIbf3nchYmpZYEmXqy1PE
XhjDtMbheBXBE0CCjhh+DOKrpb+CmKM=
-----END CERTIFICATE-----";

#[rstest]
// leaf only — no intermediate presented
#[case::leaf_only(&[TEST_LEAF_CERT_PEM], true)]
// leaf + root but no intermediate — root should be stripped by the heuristic
#[case::leaf_plus_root(&[TEST_LEAF_CERT_PEM, TEST_ROOT_CA_PEM], true)]
// leaf + intermediate (no root) — the normal server config; chain is structurally complete
#[case::complete_chain(&[TEST_LEAF_CERT_PEM, TEST_INTERMEDIATE_CA_PEM], false)]
// leaf + intermediate - root — the root certificate is typically not required, but is not harmful (ignored by the client); chain is structurally complete
#[case::complete_plus_root(&[TEST_LEAF_CERT_PEM, TEST_INTERMEDIATE_CA_PEM, TEST_ROOT_CA_PEM], false)]
// self-signed certificate — issuer == subject, no intermediate expected
#[case::self_signed(&[TEST_SELF_SIGNED_PEM], false)]
fn doctor_intermediate_cert_detection(#[case] chain_parts: &[&str], #[case] expect_missing_intermediate: bool) {
    let read_chain_name = if cfg!(windows) {
        "schannel_read_chain"
    } else {
        "rustls_read_chain"
    };
    let chain_check_name = if cfg!(windows) {
        "schannel_check_chain"
    } else {
        "rustls_check_chain"
    };

    let chain_pem = chain_parts.join("\n");
    let tempdir = tempfile::tempdir().unwrap();
    let chain_file_path = tempdir.path().join("chain.pem");
    std::fs::write(&chain_file_path, &chain_pem).unwrap();

    let output = jetsocat_assert_cmd()
        .args([
            "doctor",
            "--chain",
            chain_file_path.to_str().unwrap(),
            "--subject-name",
            "test.example.com",
            "--format",
            "json",
        ])
        .assert()
        .failure();

    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    let mut saw_read_chain = false;
    let mut saw_chain_check = false;

    for line in stdout.lines() {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        let name = entry["name"].as_str().unwrap();

        if name == read_chain_name {
            saw_read_chain = true;

            // The read step attaches an early warning based on raw file contents,
            // before any chain-building that might auto-fill missing intermediates.
            let warning = entry["warning"].as_str().unwrap_or("");
            assert_eq!(
                warning.to_lowercase().contains("intermediate"),
                expect_missing_intermediate,
                "{name}: unexpected warning content for expect_missing_intermediate={expect_missing_intermediate}, got: {warning:?}",
            );
        } else if name == chain_check_name {
            saw_chain_check = true;

            // Always fails, because the root CA is never trusted in these tests.
            assert!(!entry["success"].as_bool().unwrap(), "{name} should have failed");

            let help = entry["help"]
                .as_str()
                .unwrap_or_else(|| panic!("{name} should have a help message"));
            assert_eq!(
                help.to_lowercase()
                    .contains("intermediate certificate is likely missing"),
                expect_missing_intermediate,
                "{name}: unexpected help content for expect_missing_intermediate={expect_missing_intermediate}, got: {help:?}",
            );
        }
    }

    assert!(saw_read_chain, "diagnostic '{read_chain_name}' was never emitted");
    assert!(saw_chain_check, "diagnostic '{chain_check_name}' was never emitted");
}

#[test]
fn doctor_invalid_server_port() {
    let output = jetsocat_assert_cmd()
        .args([
            "doctor",
            "--subject-name",
            "devolutions.net",
            "--server-port",
            "invalid",
        ])
        .assert()
        .failure()
        .code(1);

    assert_stderr_eq(
        &output,
        expect![[r#"
            invalid 'server-port'

            Caused by:
                Value type mismatch
        "#]],
    );
}

#[test]
fn env_args_single_quoted_arguments() {
    jetsocat_assert_cmd()
        .env("JETSOCAT_ARGS", "forward 'cmd://printf helloworld' stdio")
        .assert()
        .success();
}

#[test]
fn env_args_double_quoted_arguments() {
    jetsocat_assert_cmd()
        .env("JETSOCAT_ARGS", "forward \"cmd://printf helloworld\" stdio")
        .assert()
        .success();
}

#[test]
fn jetsocat_log_environment_variable() {
    let tempdir = tempfile::tempdir().unwrap();
    let outfile = tempdir.path().join("outfile");

    let output = jetsocat_assert_cmd()
        .env("JETSOCAT_LOG", "debug")
        .env(
            "JETSOCAT_ARGS",
            format!(
                "forward cmd://'echo hello' 'write-file://{}' --log-term",
                outfile.display()
            ),
        )
        .timeout(ASSERT_CMD_TIMEOUT)
        .assert();

    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();
    assert!(stdout.contains("DEBUG"));
    assert!(stdout.contains("hello"));

    let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
    assert!(!stderr.contains("bad"));
    assert!(!stderr.contains("invalid"));
    assert!(!stderr.contains("unknown"));

    let file_contents = std::fs::read_to_string(outfile).unwrap();
    assert_eq!(file_contents.trim(), "hello");
}

#[test]
fn forward_missing_args() {
    let output = jetsocat_assert_cmd().arg("forward").assert().failure().code(1);
    assert_stderr_eq(
        &output,
        expect![[r#"
        <PIPE A> is missing
    "#]],
    );
}

#[test]
fn forward_missing_second_arg() {
    let output = jetsocat_assert_cmd()
        .args(["forward", "stdio"])
        .assert()
        .failure()
        .code(1);
    assert_stderr_eq(
        &output,
        expect![[r#"
        <PIPE B> is missing
    "#]],
    );
}

#[test]
fn forward_valid_pipe_formats() {
    // These should parse successfully but fail at execution.
    // We're only testing argument parsing here.

    let test_cases = [
        ("stdio", "-"),
        ("stdio", "stdio"),
        ("-", "stdio"),
        ("cmd://echo", "stdio"),
        ("tcp://localhost:80", "stdio"),
        ("tcp-listen://127.0.0.1:8080", "stdio"),
        ("read-file:///dev/null", "stdio"),
        ("write-file:///tmp/test", "stdio"),
        ("ws://localhost:8080", "stdio"),
        ("wss://localhost:8080", "stdio"),
        ("ws-listen://127.0.0.1:8080", "stdio"),
        ("np:///tmp/test.sock", "stdio"),
        ("np-listen:///tmp/test.sock", "stdio"),
    ];

    for (pipe_a, pipe_b) in test_cases {
        let output = jetsocat_assert_cmd()
            .args(["forward", pipe_a, pipe_b])
            .timeout(Duration::from_millis(50))
            .assert();

        // Should not fail with argument parsing errors (exit code 1 from parse errors).
        // May fail with runtime errors but that's different.
        let actual_exit_code = output.get_output().status.code();

        // If it exits immediately with code 1, check it's not a parse error.
        if let Some(1) = actual_exit_code {
            let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
            assert!(
                !stderr.contains("bad <PIPE")
                    && !stderr.contains("unknown pipe scheme")
                    && !stderr.contains("invalid format"),
                "unexpected parse error for pipes '{pipe_a}' and '{pipe_b}': {stderr}",
            );
        }
    }
}

#[test]
fn forward_negative_repeat_count() {
    let output = jetsocat_assert_cmd()
        .args(["forward", "stdio", "-", "--repeat-count", "-1"])
        .assert()
        .failure()
        .code(1);

    assert_stderr_eq(
        &output,
        expect![[r#"
            invalid 'repeat-count'

            Caused by:
                Value type mismatch
        "#]],
    );
}

#[rstest]
#[tokio::test]
async fn mcp_proxy_smoke_test(#[values(true, false)] http_transport: bool) {
    use testsuite::mcp_client::McpClient;
    use testsuite::mcp_server::{DynMcpTransport, HttpTransport, McpServer, NamedPipeTransport};

    // Configure MCP server transport.
    let (transport, pipe) = if http_transport {
        let http_transport = HttpTransport::bind().await.unwrap();
        let server_url = http_transport.url();
        (DynMcpTransport::new_box(http_transport), server_url)
    } else {
        let np_transport = NamedPipeTransport::bind().unwrap();
        let name = np_transport.name().to_owned();
        (DynMcpTransport::new_box(np_transport), format!("np://{name}"))
    };

    // Start MCP server.
    let server = McpServer::new(transport);
    let _server_handle = server.start().expect("start MCP server");

    if !http_transport {
        wait_for_windows_named_pipe_server().await;
    }

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(["mcp-proxy", "stdio", &pipe])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start jetsocat mcp-proxy");

    // Get stdin/stdout handles for MCP client.
    let stdin = jetsocat_process.stdin.take().expect("get stdin");
    let stdout = jetsocat_process.stdout.take().expect("get stdout");

    // Initialize MCP client with jetsocat's stdin/stdout.
    let mut mcp_client = McpClient::new(Box::pin(stdout), Box::pin(stdin));

    // Connect to MCP server through jetsocat proxy.
    let init_result = mcp_client.connect().await.expect("connect to MCP server");
    expect![[r#"
        InitializeResult {
            protocol_version: "2025-06-18",
            capabilities: Object {
                "tools": Object {
                    "listChanged": Bool(false),
                },
            },
            server_info: Object {
                "name": String("testsuite-mcp-server"),
                "version": String("1.0.0"),
            },
        }
    "#]]
    .assert_debug_eq(&init_result);

    // List available tools.
    let tools_result = mcp_client.list_tools().await.expect("list tools");
    // Empty, because we didn’t configure any on the MCP server.
    expect![["
        ToolsListResult {
            tools: [],
        }
    "]]
    .assert_debug_eq(&tools_result);
}

#[rstest]
#[tokio::test]
async fn mcp_proxy_with_tools(#[values(true, false)] http_transport: bool) {
    use testsuite::mcp_client::{McpClient, ToolCallParams};
    use testsuite::mcp_server::{
        CalculatorTool, DynMcpTransport, EchoTool, HttpTransport, McpServer, NamedPipeTransport, ServerConfig,
    };

    // Configure MCP server transport.
    let (transport, pipe) = if http_transport {
        let http_transport = HttpTransport::bind().await.unwrap();
        let server_url = http_transport.url();
        (DynMcpTransport::new_box(http_transport), server_url)
    } else {
        let np_transport = NamedPipeTransport::bind().unwrap();
        let name = np_transport.name().to_owned();
        (DynMcpTransport::new_box(np_transport), format!("np://{name}"))
    };

    // Start MCP server.
    let server =
        McpServer::new(transport).with_config(ServerConfig::new().with_tool(EchoTool).with_tool(CalculatorTool));
    let _server_handle = server.start().expect("start MCP server");

    if !http_transport {
        wait_for_windows_named_pipe_server().await;
    }

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(["mcp-proxy", "stdio", &pipe])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start jetsocat mcp-proxy");

    // Get stdin/stdout handles for MCP client.
    let stdin = jetsocat_process.stdin.take().expect("get stdin");
    let stdout = jetsocat_process.stdout.take().expect("get stdout");

    // Initialize MCP client with jetsocat's stdin/stdout.
    let mut mcp_client = McpClient::new(Box::pin(stdout), Box::pin(stdin));

    // Connect to MCP server through jetsocat proxy.
    mcp_client.connect().await.expect("connect to MCP server");

    // List available tools.
    let tools_result = mcp_client.list_tools().await.expect("list tools");
    expect![[r#"
        ToolsListResult {
            tools: [
                Object {
                    "description": String("Echo back the input"),
                    "inputSchema": Object {
                        "properties": Object {
                            "message": Object {
                                "type": String("string"),
                            },
                        },
                        "required": Array [
                            String("message"),
                        ],
                        "type": String("object"),
                    },
                    "name": String("echo"),
                },
                Object {
                    "description": String("Perform basic math operations"),
                    "inputSchema": Object {
                        "properties": Object {
                            "a": Object {
                                "type": String("number"),
                            },
                            "b": Object {
                                "type": String("number"),
                            },
                            "operation": Object {
                                "enum": Array [
                                    String("add"),
                                    String("subtract"),
                                    String("multiply"),
                                    String("divide"),
                                ],
                                "type": String("string"),
                            },
                        },
                        "required": Array [
                            String("operation"),
                            String("a"),
                            String("b"),
                        ],
                        "type": String("object"),
                    },
                    "name": String("calculator"),
                },
            ],
        }
    "#]]
    .assert_debug_eq(&tools_result);

    let echo_result = mcp_client.call_tool(ToolCallParams::echo("hello world")).await.unwrap();
    expect![[r#"
        ToolCallResult {
            content: [
                Object {
                    "text": String("hello world"),
                    "type": String("text"),
                },
            ],
            is_error: Some(
                false,
            ),
        }
    "#]]
    .assert_debug_eq(&echo_result);

    let calculate_result = mcp_client
        .call_tool(ToolCallParams::calculate("add", 2.0, 3.0))
        .await
        .unwrap();
    expect![[r#"
        ToolCallResult {
            content: [
                Object {
                    "text": String("5"),
                    "type": String("text"),
                },
            ],
            is_error: Some(
                false,
            ),
        }
    "#]]
    .assert_debug_eq(&calculate_result);
}

#[rstest]
#[tokio::test]
async fn mcp_proxy_notification(#[values(true, false)] http_transport: bool) {
    use testsuite::mcp_client::McpClient;
    use testsuite::mcp_server::{DynMcpTransport, HttpTransport, McpServer, NamedPipeTransport, ServerConfig};

    let probe = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Configure MCP server transport.
    let (transport, pipe) = if http_transport {
        let http_transport = HttpTransport::bind().await.unwrap();
        let server_url = http_transport.url();
        (DynMcpTransport::new_box(http_transport), server_url)
    } else {
        let np_transport = NamedPipeTransport::bind().unwrap();
        let name = np_transport.name().to_owned();
        (DynMcpTransport::new_box(np_transport), format!("np://{name}"))
    };

    // Start MCP server.
    let notification_handler = {
        let probe = Arc::clone(&probe);
        move |method: &str, _: serde_json::Value| {
            assert_eq!(method, "notifications/it-works");
            probe.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    };
    let server =
        McpServer::new(transport).with_config(ServerConfig::new().with_notification_handler(notification_handler));
    let _server_handle = server.start().expect("start MCP server");

    if !http_transport {
        wait_for_windows_named_pipe_server().await;
    }

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(["mcp-proxy", "stdio", &pipe])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start jetsocat mcp-proxy");

    // Get stdin/stdout handles for MCP client.
    let stdin = jetsocat_process.stdin.take().expect("get stdin");
    let stdout = jetsocat_process.stdout.take().expect("get stdout");

    // Initialize MCP client with jetsocat's stdin/stdout.
    let mut mcp_client = McpClient::new(Box::pin(stdout), Box::pin(stdin));

    // Connect to MCP server through jetsocat proxy.
    mcp_client.connect().await.expect("connect to MCP server");

    // Send a notification.
    mcp_client
        .send_notification("notifications/it-works", None)
        .await
        .expect("send notification");

    // For sanitiy, list available tools.
    mcp_client.list_tools().await.expect("list tools");

    // Wait for the handler to be called.
    tokio::time::sleep(Duration::from_millis(75)).await;

    // Check the probe.
    assert!(probe.load(std::sync::atomic::Ordering::SeqCst));
}

async fn execute_mcp_request(request: &str) -> String {
    use testsuite::mcp_server::{DynMcpTransport, HttpTransport, McpServer};
    use tokio::io::AsyncWriteExt as _;

    // Start MCP server.
    let transport = HttpTransport::bind().await.unwrap();
    let server_url = transport.url();
    let server = McpServer::new(DynMcpTransport::new_box(transport));
    let server_handle = server.start().expect("start MCP server");

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(["mcp-proxy", "stdio", &server_url, "--log-term", "--color=never"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start jetsocat mcp-proxy");

    // Get stdin/stdout handles for MCP client.
    let mut stdin = jetsocat_process.stdin.take().expect("get stdin");

    // Write the request.
    stdin.write_all(request.as_bytes()).await.unwrap();

    tokio::time::sleep(MCP_REQUEST_SETTLE_DURATION).await;

    // Shutdown the MCP server.
    server_handle.shutdown();

    // Terminate the Jetsocat process.
    jetsocat_process.start_kill().unwrap();

    let output = jetsocat_process.wait_with_output().await.unwrap();
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
async fn mcp_proxy_malformed_request_with_id() {
    let stdout = execute_mcp_request("{\"jsonrpc\":\"2.0\",\"decoy\":\":\",\"id\":1\n").await;
    assert!(stdout.contains("malformed JSON-RPC message"), "{stdout}");
    assert!(stdout.contains("Unexpected EOF"), "{stdout}");
    assert!(stdout.contains("id=1"), "{stdout}");
}

#[tokio::test]
async fn mcp_proxy_malformed_request_no_id() {
    let stdout = execute_mcp_request("{\"jsonrpc\":\"2.0\",}\n").await;
    assert!(stdout.contains("malformed JSON-RPC message"), "{stdout}");
    assert!(stdout.contains("Invalid character"), "{stdout}");
    assert!(!stdout.contains("id=1"), "{stdout}");
}

#[tokio::test]
async fn mcp_proxy_http_error() {
    use testsuite::mcp_client::McpClient;
    use testsuite::mcp_server::{DynMcpTransport, HttpError, HttpTransport, McpServer};

    // Start MCP server.
    let transport = HttpTransport::bind().await.unwrap().with_error_response(
        "initialize",
        HttpError {
            status_code: 418,
            body: "I'm a tea pot".to_owned(),
        },
    );
    let server_url = transport.url();
    let server = McpServer::new(DynMcpTransport::new_box(transport));
    let _server_handle = server.start().expect("start MCP server");

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(["mcp-proxy", "stdio", &server_url])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start jetsocat mcp-proxy");

    // Get stdin/stdout handles for MCP client.
    let stdin = jetsocat_process.stdin.take().expect("get stdin");
    let stdout = jetsocat_process.stdout.take().expect("get stdout");

    // Initialize MCP client with jetsocat's stdin/stdout.
    let mut mcp_client = McpClient::new(Box::pin(stdout), Box::pin(stdin));

    // Connect to MCP server through jetsocat proxy.
    let error = mcp_client.connect().await.unwrap_err();
    let error_string = error.to_string();
    assert!(error_string.contains("-32099"), "{error}");
    assert!(error_string.contains("status code 418"), "{error}");
}

#[tokio::test]
async fn mcp_proxy_terminated_on_broken_pipe() {
    use testsuite::mcp_client::McpClient;
    use testsuite::mcp_server::{DynMcpTransport, McpServer, NamedPipeTransport};
    // use tokio::io::AsyncReadExt as _; // TODO

    // Configure MCP server transport (named pipe only).
    let np_transport = NamedPipeTransport::bind().unwrap();
    let name = np_transport.name().to_owned();
    let pipe = format!("np://{name}");

    // Start MCP server.
    let server = McpServer::new(DynMcpTransport::new_box(np_transport));
    let server_handle = server.start().expect("start MCP server");

    wait_for_windows_named_pipe_server().await;

    // Start jetsocat mcp-proxy with stdio pipe.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(["mcp-proxy", "stdio", &pipe]) // TODO: add "--log-term"
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        // .stderr(std::process::Stdio::piped()) // TODO: Once Jetsocat logs to stderr.
        .kill_on_drop(true)
        .spawn()
        .expect("start jetsocat mcp-proxy");

    // Get stdin/stdout handles for MCP client.
    let stdin = jetsocat_process.stdin.take().expect("get stdin");
    let stdout = jetsocat_process.stdout.take().expect("get stdout");
    // let mut stderr = jetsocat_process.stderr.take().expect("get stderr"); // TODO

    // Initialize MCP client with jetsocat's stdin/stdout.
    let mut mcp_client = McpClient::new(Box::pin(stdout), Box::pin(stdin));

    // Connect to MCP server through jetsocat proxy.
    mcp_client.connect().await.expect("connect to MCP server");

    // Stop the MCP server.
    server_handle.shutdown();

    // Wait for the named pipe instance to be torn down on Windows.
    wait_for_windows_named_pipe_server().await;

    // Try to send a request - this should fail with a broken pipe error.
    // The proxy will detect this and send an error response, then close.
    let result = mcp_client.list_tools().await;

    // Since Jetsocat is continuously reading on the pipe, it quickly detects the pipe is broken and stops itself with an error.
    // Our MCP client in turns try to write from stdout / read to stdin, and this fails with a BrokenPipe on our side.
    let error = result.unwrap_err();
    let error_debug_fmt = format!("{error:?}");
    #[cfg(windows)]
    assert!(error_debug_fmt.contains("The pipe is being closed"));
    #[cfg(not(windows))]
    assert!(error_debug_fmt.contains("Broken pipe (os error 32)"));

    // TODO: Once Jetsocat print the logs to stderr.
    // let mut stderr_str = String::new();
    // stderr.read_to_string(&mut stderr_str).await.expect("read_to_string");
    // stderr_str.contains(r#"Fatal error reading from peer, stopping proxy error="connection closed""#);

    // The jetsocat process should exit gracefully after detecting broken pipe.
    let exit_status = tokio::time::timeout(Duration::from_secs(2), jetsocat_process.wait()).await;
    assert!(exit_status.is_ok(), "Proxy should exit after detecting broken pipe");

    // Verify it exited with success (graceful shutdown, not a crash).
    let status = exit_status.unwrap().unwrap();
    assert!(status.success(), "Proxy should exit successfully, not crash");
}

/// SOCKS5 client → SOCKS5 listener → JMUX tunnel → TCP echo server.
#[rstest]
#[tokio::test]
async fn socks5_to_jmux(#[values(false, true)] use_websocket: bool) {
    use proxy_socks::Socks5Stream;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    let round_trip_timeout = Duration::from_secs(15);

    let ports = find_unused_ports(3);
    let echo_port = ports[0];
    let jmux_server_port = ports[1];
    let socks5_port = ports[2];

    // Bind the echo server before spawning anything else so the port is ready immediately.
    let echo_listener = TcpListener::bind(("127.0.0.1", echo_port)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let (socket, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = socket.into_split();
                tokio::io::copy(&mut r, &mut w).await.ok();
            });
        }
    });

    // Start JMUX server subprocess.
    let jmux_pipe = if use_websocket {
        format!("ws-listen://127.0.0.1:{jmux_server_port}")
    } else {
        format!("tcp-listen://127.0.0.1:{jmux_server_port}")
    };
    let _jmux_server = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("jmux-proxy {jmux_pipe} --allow-all --no-proxy"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start JMUX server");

    // NOTE: Cannot use wait_for_tcp_port here — TcpListen/WebSocketListen accept exactly one
    // connection, so connecting would consume the slot before the real JMUX client arrives.
    // Instead, probe by attempting to bind the same port: AddrInUse means the server owns it.
    wait_for_port_bound(jmux_server_port).await.expect("JMUX server ready");

    // Start JMUX client subprocess exposing a SOCKS5 listener.
    let peer_pipe = if use_websocket {
        format!("ws://127.0.0.1:{jmux_server_port}")
    } else {
        format!("tcp://127.0.0.1:{jmux_server_port}")
    };
    let _jmux_client = jetsocat_tokio_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("jmux-proxy {peer_pipe} socks5-listen://127.0.0.1:{socks5_port} --no-proxy"),
        )
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start JMUX client with SOCKS5 listener");

    wait_for_tcp_port(socks5_port).await.expect("SOCKS5 proxy ready");

    // Connect via SOCKS5 through the JMUX tunnel to the echo server and verify round-trip.
    // Bound by a timeout so that a broken shutdown path doesn't hang CI indefinitely.
    timeout(round_trip_timeout, async {
        let stream = TcpStream::connect(("127.0.0.1", socks5_port)).await.unwrap();
        let stream = Socks5Stream::connect(stream, format!("127.0.0.1:{echo_port}"))
            .await
            .expect("SOCKS5 connect");
        let (mut reader, mut writer) = tokio::io::split(stream);

        let payload = b"hello socks5 to jmux";
        writer.write_all(payload).await.unwrap();
        writer.shutdown().await.unwrap();

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, payload);
    })
    .await
    .expect("round-trip timed out");
}
