# devolutions-gateway

[![Build Status](https://travis-ci.com/vaffeine/devolutions-jet.svg?token=FxErzCAno8oL7CSUGoD1&branch=rdp)](https://travis-ci.com/vaffeine/devolutions-jet)
[![codecov](https://codecov.io/gh/vaffeine/devolutions-jet/branch/rdp/graph/badge.svg?token=eXgEoo0BnD)](https://codecov.io/gh/vaffeine/devolutions-jet)

A blazing fast relay server adaptable to different protocols and desired levels of traffic inspection.

Use `cargo run` to build and run devolutions-gateway locally with default options.

## Command-line Interface

```
USAGE:
    devolutions-jet [FLAGS] [OPTIONS] --jet-instance <NAME>

FLAGS:
    -h, --help
            Prints help information

        --rdp
            Enable RDP/TCP and RDP/TLS in all TCP listeners (temporary)

        --unrestricted
            Remove API key validation on some HTTP routes

    -v, --version
            Prints version information


OPTIONS:
        --api-key <KEY>
            The API key used by the server to authenticate client queries. [env: JET_API_KEY]

        --certificate-data <DATA>
            Certificate data, base64-encoded X509 DER. [env: JET_CERTIFICATE_DATA]

        --certificate-file <FILE>
            Path to the certificate file. [env: JET_CERTIFICATE_FILE]

        --delegation-private-key-data <DATA>
            Private key data, base64-encoded PKCS10. [env: JET_DELEGATION_PRIVATE_KEY_DATA]

        --delegation-private-key-file <FILE>
            Path to the private key file. [env: JET_DELEGATION_PRIVATE_KEY_FILE]

        --http-listener-url <URL>
            HTTP listener URL. [env: JET_HTTP_LISTENER_URL]  [default: http://0.0.0.0:10256]

        --jet-instance <NAME>
            Specific name to reach that instance of JET. [env: JET_INSTANCE]

    -l, --listener <URL>...
            An URL on which the server will listen on. The external URL returned as candidate can be specified after the
            listener, separated with a comma. <scheme>://<local_iface_ip>:<port>,<scheme>://<external>:<port> If it is
            not specified, the external url will be <scheme>://<jet_instance>:<port> where <jet_instance> is the value
            of the jet-instance parameter. [env: JET_LISTENERS]
        --log-file <LOG_FILE>
            A file with logs

        --pcap-files-path <PATH>
            Path to the pcap files. If not set, no pcap files will be created. WaykNow and RDP protocols can be saved.

        --private-key-data <DATA>
            Private key data, base64-encoded PKCS10. [env: JET_PRIVATE_KEY_DATA]

        --private-key-file <FILE>
            Path to the private key file. [env: JET_PRIVATE_KEY_FILE]

    -p, --protocol <PROTOCOL_NAME>
            Specify the application protocol used. Useful when pcap file is saved and you want to avoid application
            message in two different tcp packet. If protocol is unknown, we can't be sure that application packet is not
            split between 2 tcp packets. [possible values: wayk, rdp]
        --provisioner-public-key-data <DATA>
            Public key data, base64-encoded PKCS10. [env: JET_PROVISIONER_PUBLIC_KEY_DATA]

        --provisioner-public-key-file <FILE>
            Path to the public key file. [env: JET_PROVISIONER_PUBLIC_KEY_FILE]

    -r, --routing-url <URL>
            An address on which the server will route all packets.
            Format: <scheme>://<ip>:<port>.
            Supported schemes: tcp, tls.
            If it is not specified, the JET protocol will be used.
```

## Sample Usage

### Routing to a specific URL

1. Run Wayk Now on 2 hosts to be able to open a Wayk session between those 2 hosts.
    * Download Wayk Now [here](https://wayk.devolutions.net/home/download)

1. Start devolutions-gateway and specify the routing URL where x.x.x.x is the IP of your Wayk server host. You can easily get the host IP in the source ID drop down list in Wayk Now.
    ```
    $ cargo run -- -r tls://x.x.x.x:4489
    ```
    * If you want to save the network traffic in a PCAP file, you can add the pcap-files-path parameter. The command will look to something like this:
        ```
        $ cargo run -- -r tls://x.x.x.x:4489 --pcap-files-path c:\waykTraffic\ -p wayk
        ```

1. On the same host where devolutions-gateway is running, open wayk and connect to 127.0.0.1:8080
    * The connection should start. A dummy certificate will be shown. You can accept it and the Wayk connection should start.

### RDP routing

The Jet can redirect RDP traffic authorized by a JWT (Json Web Token) both signed (JWS) and encrypted (JWE).

The key used to sign must be known by the Jet. You can provide the Jet with the public
key to use using `--provisioner-public-key-file` with a path to a PEM file; or `--provisioner-public-key-data`
with a base64-encoded pkcs10 value.
The provisioner can then use its private key to sign a JWT and authorize Jet RDP routing.

The key used for token encryption is provided to Jet using `--delegation-private-key-data` or `--delegation-private-key-file`
similarly to the provisioner key.
The public counter part of the delegation key must then be used for token encryption.

#### JWT structure and claims

The Jet is expecting a nested JWT.

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
$ ./tokengen --dst-hst 192.168.122.70 --provider-private-key /path/to/private/provisioner/private/key.pem rdp-tcp
```

RDP-TLS example:

```
$ ./tokengen --dst-hst 192.168.122.70 --provider-private-key /path/to/private/provisioner/private/key.pem rdp-tls --jet-public-key /path/to/public/delegation/public/key.pem --prx-usr proxy_username --prx-pwd proxy_password --dst-usr host_username --dst-pwd host_password
```

##### rdp_token.sh

A bash script. Requires [smallstep CLI's tool](https://github.com/smallstep/cli).
Check out the [installation](https://github.com/smallstep/cli#installation) section.

RDP-TCP example:

```
$ ./rdp_token.sh 15 /path/to/private/provisioner/private/key.pem /path/to/public/delegation/public/key.pem 192.168.122.70
```

RDP-TLS example:

```
$ ./rdp_token.sh 15 /path/to/private/provisioner/private/key.pem /path/to/public/delegation/public/key.pem 192.168.122.70 proxy_username proxy_password host_username host_password
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
