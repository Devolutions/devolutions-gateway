use std::io::Read;
use std::time::Duration;

use expect_test::expect;
use rstest::rstest;
use test_utils::find_unused_ports;
use testsuite::cli::{assert_stderr_eq, jetsocat_assert_cmd, jetsocat_cmd, jetsocat_tokio_cmd};

const LISTENER_WAIT_DURATION: Duration = Duration::from_millis(50);
const COMMAND_TIMEOUT: Duration = Duration::from_millis(150);

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
        let output = jetsocat_assert_cmd().args(&[subcommand, "--help"]).assert().success();
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
        .timeout(Duration::from_millis(100))
        .args(&["forward", "-", "-", "--log-term"])
        .args(args)
        .envs(envs.iter().cloned())
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
        .timeout(Duration::from_millis(100))
        .args(&["forward", "-", "-", "--log-file", log_file_path.to_str().unwrap()])
        .args(args)
        .envs(envs.iter().cloned())
        .assert()
        .success();

    let logs = std::fs::read_to_string(log_file_path).unwrap();

    if expect_ansi {
        assert!(logs.contains(" [32m INFO[0m [2mjetsocat[0m"), "{logs}");
    } else {
        assert!(logs.contains("  INFO jetsocat"), "{logs}");
    }
}

#[test]
fn forward_hello_world() {
    // Find an available port.
    let port = find_unused_ports(1)[0];

    // Start jetsocat listener in background using JETSOCAT_ARGS.
    let mut listener = jetsocat_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward tcp-listen://127.0.0.1:{port} 'cmd://echo hello world' --no-proxy"),
        )
        .spawn()
        .expect("failed to start jetsocat listener");

    // Give the listener time to start.
    std::thread::sleep(LISTENER_WAIT_DURATION);

    // Connect to the listener and read the output using assert_cmd.
    let client_output = jetsocat_assert_cmd()
        .env("JETSOCAT_ARGS", format!("forward - tcp://127.0.0.1:{port}"))
        .timeout(COMMAND_TIMEOUT)
        .assert();

    // Kill the listener.
    let _ = listener.kill();

    // Check that we got the expected output.
    #[cfg(windows)]
    client_output.success().stdout("hello world\r\n");
    #[cfg(unix)]
    client_output.success().stdout("hello world\n");
}

#[test]
fn jmux_proxy_read_hello_world() {
    // Find 3 available ports at once to avoid conflicts.
    let ports = find_unused_ports(3);
    let echo_server_port = ports[0];
    let jmux_server_port = ports[1];
    let proxy_listen_port = ports[2];

    // Start echo server first.
    let mut echo_server = jetsocat_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward tcp-listen://127.0.0.1:{echo_server_port} 'cmd://echo hello world' --no-proxy"),
        )
        .spawn()
        .expect("failed to start echo server");

    // Give the echo server time to start.
    std::thread::sleep(LISTENER_WAIT_DURATION);

    // Start JMUX server that will accept JMUX connections.
    let mut jmux_server = jetsocat_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("jmux-proxy tcp-listen://127.0.0.1:{jmux_server_port} --allow-all --no-proxy"),
        )
        .spawn()
        .expect("failed to start JMUX server");

    // Give the JMUX server time to start.
    std::thread::sleep(LISTENER_WAIT_DURATION);

    // Start JMUX client proxy that connects to the JMUX server and provides a local TCP listener.
    // This creates a tunnel: client -> proxy_listen_port -> jmux_server_port -> echo_server_port
    let mut jmux_client = jetsocat_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!(
                "jmux-proxy tcp://127.0.0.1:{jmux_server_port} tcp-listen://127.0.0.1:{proxy_listen_port}/127.0.0.1:{echo_server_port} --no-proxy",
            ),
        )
        .spawn()
        .expect("failed to start JMUX client");

    // Give the JMUX client time to establish connection and set up listener.
    std::thread::sleep(LISTENER_WAIT_DURATION);

    // Connect to the JMUX client's local listener.
    let client_output = jetsocat_assert_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward - tcp://127.0.0.1:{proxy_listen_port}"),
        )
        .timeout(COMMAND_TIMEOUT)
        .assert();

    // Kill all processes.
    let _ = jmux_client.kill();
    let _ = jmux_server.kill();
    let _ = echo_server.kill();

    // Check that we got the expected output through the JMUX proxy.
    #[cfg(windows)]
    client_output.success().stdout("hello world\r\n");
    #[cfg(unix)]
    client_output.success().stdout("hello world\n");
}

#[test]
fn jmux_proxy_write_hello_world() {
    // Find 3 available ports at once to avoid conflicts.
    let ports = find_unused_ports(3);
    let read_server_port = ports[0];
    let jmux_server_port = ports[1];
    let proxy_listen_port = ports[2];

    // Start read server first.
    let mut read_server = jetsocat_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward tcp-listen://127.0.0.1:{read_server_port} stdio --no-proxy"),
        )
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to start read server");

    // Give the read server time to start.
    std::thread::sleep(LISTENER_WAIT_DURATION);

    // Start JMUX server that will accept JMUX connections.
    let mut jmux_server = jetsocat_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("jmux-proxy tcp-listen://127.0.0.1:{jmux_server_port} --allow-all --no-proxy"),
        )
        .spawn()
        .expect("failed to start JMUX server");

    // Give the JMUX server time to start.
    std::thread::sleep(LISTENER_WAIT_DURATION);

    // Start JMUX client proxy that connects to the JMUX server and provides a local TCP listener.
    let mut jmux_client = jetsocat_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!(
                "jmux-proxy tcp://127.0.0.1:{jmux_server_port} tcp-listen://127.0.0.1:{proxy_listen_port}/127.0.0.1:{read_server_port} --no-proxy",
            ),
        )
        .spawn()
        .expect("failed to start JMUX client");

    // Give the JMUX client time to establish connection and set up listener.
    std::thread::sleep(LISTENER_WAIT_DURATION);

    // Connect to the JMUX client's local listener.
    jetsocat_assert_cmd()
        .env(
            "JETSOCAT_ARGS",
            format!("forward tcp://127.0.0.1:{proxy_listen_port} 'cmd://echo hello world'"),
        )
        .timeout(COMMAND_TIMEOUT)
        .assert();

    // Kill all processes.
    let _ = jmux_client.kill();
    let _ = jmux_server.kill();
    let _ = read_server.kill();

    // Check that the read server received the payload.
    let mut read_server_stdout = String::new();
    read_server
        .stdout
        .unwrap()
        .read_to_string(&mut read_server_stdout)
        .unwrap();
    assert_eq!(read_server_stdout.trim(), "hello world");
}

#[test]
#[cfg_attr(windows, ignore = "does not pass on Windows")] // FIXME
fn doctor_no_args_is_valid() {
    jetsocat_assert_cmd().arg("doctor").assert().success();
}

#[test]
#[cfg_attr(windows, ignore = "does not pass on Windows")] // FIXME
fn doctor_verify_chain_with_json_output() {
    let tempdir = tempfile::tempdir().unwrap();
    let chain_file_path = tempdir.path().join("devolutions-net-chain.pem");
    std::fs::write(&chain_file_path, DEVOLUTIONS_NET_CHAIN).unwrap();

    let output = jetsocat_assert_cmd()
        .args(&[
            "doctor",
            "--chain",
            chain_file_path.to_str().unwrap(),
            "--subject-name",
            "devolutions.net",
            "--format",
            "json",
        ])
        .assert()
        .success();

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
                "help" => assert!(value.is_string()),
                "links" => assert!(value.is_array()),

                // Make sure there is no unintended key in the serialized payload.
                _ => panic!("unexpected key: {key}"),
            }
        }
    }

    const DEVOLUTIONS_NET_CHAIN: &str = "
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
fn doctor_invalid_server_port() {
    let output = jetsocat_assert_cmd()
        .args(&[
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
        .timeout(COMMAND_TIMEOUT)
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
        .args(&["forward", "stdio"])
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
            .args(&["forward", pipe_a, pipe_b])
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
        .args(&["forward", "stdio", "-", "--repeat-count", "-1"])
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

    // Give the server time to start.
    tokio::time::sleep(LISTENER_WAIT_DURATION).await;

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(&["mcp-proxy", "stdio", &pipe])
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

    // Give the server time to start.
    tokio::time::sleep(LISTENER_WAIT_DURATION).await;

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(&["mcp-proxy", "stdio", &pipe])
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

    let probe = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

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
        let probe = probe.clone();
        move |method: &str, _: serde_json::Value| {
            assert_eq!(method, "notifications/it-works");
            probe.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    };
    let server =
        McpServer::new(transport).with_config(ServerConfig::new().with_notification_handler(notification_handler));
    let _server_handle = server.start().expect("start MCP server");

    // Give the server time to start.
    tokio::time::sleep(LISTENER_WAIT_DURATION).await;

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(&["mcp-proxy", "stdio", &pipe])
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
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Check the probe.
    assert_eq!(probe.load(std::sync::atomic::Ordering::SeqCst), true);
}

async fn execute_mcp_request(request: &str) -> String {
    use testsuite::mcp_server::{DynMcpTransport, HttpTransport, McpServer};
    use tokio::io::AsyncWriteExt as _;

    // Start MCP server.
    let transport = HttpTransport::bind().await.unwrap();
    let server_url = transport.url();
    let server = McpServer::new(DynMcpTransport::new_box(transport));
    let server_handle = server.start().expect("start MCP server");

    // Give the server time to start.
    tokio::time::sleep(LISTENER_WAIT_DURATION).await;

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(&["mcp-proxy", "stdio", &server_url, "--log-term", "--color=never"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start jetsocat mcp-proxy");

    // Get stdin/stdout handles for MCP client.
    let mut stdin = jetsocat_process.stdin.take().expect("get stdin");

    // Write the request.
    stdin.write_all(request.as_bytes()).await.unwrap();

    tokio::time::sleep(COMMAND_TIMEOUT).await;

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
    assert!(stdout.contains("Malformed JSON-RPC request from client"), "{stdout}");
    assert!(stdout.contains("Unexpected EOF"), "{stdout}");
    assert!(stdout.contains("id=1"), "{stdout}");
}

#[tokio::test]
async fn mcp_proxy_malformed_request_no_id() {
    let stdout = execute_mcp_request("{\"jsonrpc\":\"2.0\",}\n").await;
    assert!(stdout.contains("Malformed JSON-RPC request from client"), "{stdout}");
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
            body: "I’m a tea pot".to_owned(),
        },
    );
    let server_url = transport.url();
    let server = McpServer::new(DynMcpTransport::new_box(transport));
    let _server_handle = server.start().expect("start MCP server");

    // Give the server time to start.
    tokio::time::sleep(LISTENER_WAIT_DURATION).await;

    // Start jetsocat mcp-proxy with stdio pipe and HTTP transport.
    let mut jetsocat_process = jetsocat_tokio_cmd()
        .args(&["mcp-proxy", "stdio", &server_url])
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
