# devolutions-gateway

[![Build Status](https://github.com/Devolutions/devolutions-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Devolutions/devolutions-gateway/actions/workflows/ci.yml)

A blazing fast relay server adaptable to different protocols and desired levels of traffic inspection.

Use `cargo build --release` to build a release version of `devolutions-gateway` locally.

## Command-line Interface

```
USAGE:
    devolutions-gateway [FLAGS] [OPTIONS]

FLAGS:
    -h, --help
            Prints help information

        --service
            Enable service mode

    -v, --version
            Prints version information


OPTIONS:
        --api-key <KEY>
            The API key used by the server to authenticate client queries. [env: DGATEWAY_API_KEY=]

        --capture-path <PATH>
            Path to the pcap files. If not set, no pcap files will be created. WaykNow and RDP protocols can be saved.
            [env: DGATEWAY_CAPTURE_PATH=]

        --certificate-data <DATA>
            Certificate data, base64-encoded X509 DER. [env: DGATEWAY_CERTIFICATE_DATA=]

        --certificate-file <FILE>
            Path to the certificate file. [env: DGATEWAY_CERTIFICATE_FILE=]

        --delegation-private-key-data <DATA>
            Private key data, base64-encoded PKCS10. [env: DGATEWAY_DELEGATION_PRIVATE_KEY_DATA=]

        --delegation-private-key-file <FILE>
            Path to the private key file. [env: DGATEWAY_DELEGATION_PRIVATE_KEY_FILE=]

        --farm-name <FARM-NAME>
            Farm name [env: DGATEWAY_FARM_NAME=]

        --hostname <HOSTNAME>
            Specific name to reach that instance of Devolutions Gateway. [env: DGATEWAY_HOSTNAME=]

    -l, --listener <URL>...
            An URL on which the server will listen on. The external URL returned as candidate can be specified after the
            listener, separated with a comma. <scheme>://<local_iface_ip>:<port>,<scheme>://<external>:<port> If it is
            not specified, the external url will be <scheme>://<hostname>:<port> where <hostname> is the value of the
            hostname parameter. [env: DGATEWAY_LISTENERS=]

        --log-file <LOG_FILE>
            A file with logs

        --private-key-data <DATA>
            Private key data, base64-encoded PKCS10. [env: DGATEWAY_PRIVATE_KEY_DATA=]

        --private-key-file <FILE>
            Path to the private key file. [env: DGATEWAY_PRIVATE_KEY_FILE=]

        --provisioner-public-key-data <DATA>
            Public key data, base64-encoded PKCS10. [env: DGATEWAY_PROVISIONER_PUBLIC_KEY_DATA=]

        --provisioner-public-key-file <FILE>
            Path to the public key file. [env: DGATEWAY_PROVISIONER_PUBLIC_KEY_FILE=]

    -r, --routing-url <URL>
            An address on which the server will route all packets.
            Format: <scheme>://<ip>:<port>.
            Supported schemes: tcp, tls.
            If it is not specified, the JET protocol will be used.
```

## Sample Usage

### RDP routing

Devolutions Gateway can redirect RDP traffic authorized by a JWT (Json Web Token) both signed (JWS) and encrypted (JWE).

The key used to sign must be known by the Gateway. You can provide the public
key to use using `--provisioner-public-key-file` with a path to a PEM file; or `--provisioner-public-key-data`
with a base64-encoded pkcs10 value.
The provisioner can then use its private key to sign a JWT and authorize RDP routing.

The key used for token encryption is provided using `--delegation-private-key-data` or `--delegation-private-key-file`
similarly to the provisioner key.
The public counter part of the delegation key must then be used for token encryption.

#### JWT structure and claims

Devolutions Gateway is expecting a nested JWT.

1. A set of claims are signed using JWS (Json Web Signature) into a compact JWT. Use of RSASSA-PKCS-v1_5 using SHA-256 (`RS256`) is recommended.
2. This signed token is then wrapped inside another token using JWE (Json Web Encryption) in compact form as well.
    Use of RSAES OAEP using SHA-256 and MGF1 with SHA-256 (`RSA-OAEP-256`) and AES GCM using 256-bit key (`A256GCM`) is recommended.

Required claims for both RDP-TCP and RDP-TLS modes:

- `dst_hst` (String): target RDP host
- `jet_cm` (String): identity connection mode used for Jet association This must be set to `fwd`.
- `jet_ap` (string): application protocol used over Jet transport. This must be set to `rdp`.
- `exp` (Integer): a UNIX timestamp for "expiration"
- `nbf` (Integer): a UNIX timestamp for "not before"

Required claims for RDP-TLS mode:

- Proxy credentials (client ↔ jet)

    - `prx_usr` (String): proxy username,
    - and `prx_pwd` (String): proxy password

- Target credentials (jet ↔ server)

    - `dst_usr`: (String): host username,
    - and `dst_pwd`: (String): host password

If any claim required for RDP-TLS is missing RDP routing will start in **RDP-TCP** mode with no TLS inspection and thus no credentials proxying.

If all the optional claims are provided RDP routing will start in **RDP-TLS** mode with TLS inspection and credentials proxying (⚠ currently _instable_).

#### Token generation utilities

JWT generation should be facilitated by a provider (such as the [WaykDen](https://github.com/Devolutions/WaykDen-ps)).
However, you can easily generate a JWT for testing purposes by using CLI tools provided in `/tools` folder.

##### tokengen

A native CLI. No binary provided; you will need a Rust toolchain to build yourself. See [Install Rust](https://www.rust-lang.org/tools/install).

```
$ cargo build --package tokengen --release
```

The binary is produced inside a `target/release` folder.

RDP-TCP example:

```
$ ./tokengen --provider-private-key /path/to/provisioner/private/key.pem forward --dst-hst 192.168.122.70 --jet-ap rdp
```

RDP-TLS example:

```
$ ./tokengen --provider-private-key /path/to/provisioner/private/key.pem --delegation-public-key /path/to/delegation/public/key.pem rdp-tls --dst-hst 192.168.122.70 --prx-usr proxy_username --prx-pwd proxy_password --dst-usr host_username --dst-pwd host_password
```

##### rdp_token.sh

A bash script. Requires [smallstep CLI's tool](https://github.com/smallstep/cli).
Check out the [installation](https://github.com/smallstep/cli#installation) section.

RDP-TCP example:

```
$ ./rdp_token.sh 15 /path/to/private/provisioner/private/key.pem /path/to/public/delegation/public/key.pem target_address
```

RDP-TLS example:

```
$ ./rdp_token.sh 15 /path/to/private/provisioner/private/key.pem /path/to/public/delegation/public/key.pem target_address proxy_username proxy_password host_username host_password
```

#### Inject token in RDP connection using MSTSC

1. Open MSTSC

2. Enter a JET address in the "computer" field

3. Press the "Save As..." button under the "Connection settings" panel to save ".RDP" file to you PC

4. Open saved ".RDP" file with a text editor

5. Append string "pcb:s:"  to the end of the file (e.g: pcb:s:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj...)

6. Save file

7. In MSTSC press "Open..." and select your edited file

8. Done. You can start the connection

#### Inject token in RDP connection using FreeRdp

Using FreeRDP, token can be provided using `/pcb` argument with `xfreerdp`.
(e.g: /pcb:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj...)

## Troubleshooting

### Connection from Microsoft Windows 7/8/8.1/Server 2008/Server 2012 clients

1. For Window 7 and Windows Server 2008: Install latest updates. Make sure to
   install the update that adds
   [support for TLS 1.1 and TLS 1.2](https://support.microsoft.com/en-au/help/3080079/update-to-add-rds-support-for-tls-1-1-and-tls-1-2-in-windows-7-or-wind).
   This is not required for newer Windows editions - they support TLS 1.1 and TLS 1.2 by default.

1. Add following cipher suites to the SSL Cipher Suite order:
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.

    To add cipher suites, use the group policy setting SSL Cipher Suite Order
    under Computer Configuration > Administrative Templates > Network > SSL
    Configuration Settings.
    [TLS Cipher Suites in Windows 7](https://docs.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-7).

### Redirection to Microsoft Windows 7/8/8.1/Server 2008/Server 2012 server

Unfortunately, Microsoft Windows 7/8/8.1/Server 2008/Server 2012 machines
cannot accept connections from [rustls](https://crates.io/crates/rustls)
client. Support for required cipher suits was not implemented until Windows 10.
