# Devolutions Gateway

[![Build Status](https://github.com/Devolutions/devolutions-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Devolutions/devolutions-gateway/actions/workflows/ci.yml)

A blazing fast relay server adaptable to different protocols and desired levels of traffic inspection.

Use `cargo build --release` to build a release version of `devolutions-gateway` locally.

## Configuration

Devolutions Gateway is configured using a JSON document.
The file must be named `gateway.json` and exist under the following path:

- `%ProgramData%\Devolutions\Gateway\` under Windows,
- `/Library/Application Support/devolutions-gateway/` under macOS, or
- `/etc/devolutions-gateway/` under Linux.

This path may be overridden using the `DGATEWAY_CONFIG_PATH` environment variable.

A default template with minimal options is generated in this location if the file doesn't exist yet.

Currently, stable options are:

- `Id`: this Gateway's UUID,

- `Hostname`: this Gateway's hostname (used when inferring external URLs),

- `ProvisionerPublicKeyFile`: path to the provisioner public key (used to verify tokens without any specific restriction),

- `SubProvisionerPublicKey`: a JSON object describing the sub provisioner public key (may only be used to verify tokens when establishing a session).
    The schema is:

    * `Id`: the key ID for this subkey,
    * `Value`: the binary-to-text-encoded key data,
    * `Format`: the format used for the key data (`Spki` or `Rsa`),
    * `Encoding`: the binary-to-text encoding used for the key data (`Multibase`, `Base64`, `Base64Pad`, `Base64Url`, `Base64UrlPad`),

- `DelegationPrivateKeyFile`: path to the delegation private key (used to decipher sensitive data from tokens),

- `TlsCertificateSource`: source for the TLS certificate. Possible values are `External` (default) and `System`,

- `TlsCertificateSubjectName`: subject name of the certificate to use for TLS when using system source,

- `TlsCertificateStoreName`: name of the System Certificate Store to use for TLS,

- `TlsCertificateStoreLocation`: location of the System Certificate Store to use for TLS,

- `TlsCertificateFile`: path to the certificate to use for TLS,

- `TlsPrivateKeyFile`: path to the private key to use for TLS,

- `Listeners`: array of listener URLs.
    Each element has the following schema: 

    * `InternalUrl`: internal URL for this listener, a socket bound to the specified address (IP address, and port number) will be created, 

    * `ExternalUrl`: external URL for this listener, accessing this URL from outside should ultimately redirect to the service.
        This holds no meaning for the service itself, but the value will be advertised by the `/jet/diagnostics/configuration` HTTP route.
        This route can be used by other systems to automatically discover the remaining access URIs.

    For both values, host segment may be abridged with `*`.

    When used in internal URLs, `*` will cause two listeners to be created with `*` expanded into:
    - the IPv4 wildcard bind address `0.0.0.0`, for listening to any IPv4 address, and
    - the IPv6 wildcard bind address `[::]`, for listening to any IPv6 address.

    When used in external URLs, `*` will be expanded into the value of `Hostname`.

- `Subscriber`: subscriber configuration:
    
    * `Url`: HTTP URL where notification messages are to be sent,
    * `Token`: bearer token to use when making HTTP requests.

- `RecordingPath`: path to the recordings folder,

- `Ngrok`: JSON object describing the ngrok configuration for ingress listeners:

    * `AuthToken`: specifies the authentication token used to connect to the ngrok service,
    * `HeartbeatInterval`: how often the service should heartbeat to the ngrok servers defined as a number in seconds,
    * `HeartbeatTolerance`: reconnect the agent tunnel session if the server does not respond to a heartbeat within this
        tolerance defined as a number on seconds,
    * `Metadata`: opaque, user-supplied string that will be returned as part of the ngrok API response to the list
        online sessions resource for all tunnels started by Devolutions Gateway service,
    * `ServerAddr`: this is the URL of the ngrok server to connect to. You should only set this if you are using a
        custom ingress URL,
    * `Tunnels`: a map of ngrok tunnels. The key is the name of the tunnel and value is a JSON object whose schema depends on tunnel protocol.

        Common options are:

        * `AllowCidrs`: array of CIDRs, rejects connections that do not match the given CIDRs,
        * `DenyCidrs`: array of CIDRS, rejects connections that match the given CIDRs and allows all other CIDRs,
        * `Metadata`: arbitrary user-defined metadata that will appear in the ngrok service API when listing tunnel sessions.

        Other options for an HTTP tunnel are:

        * `Proto`: MUST be set to `http`,
        * `Domain`: the domain to request, as registered in the ngrok dashboard,
        * `Metadata`: arbitrary user-defined metadata that will appear in the ngrok service API when listing tunnel sessions,
        * `CircuitBreaker`: a float number, reject requests when 5XX responses exceed this ratio,
        * `Compression`: boolean, gzip compress HTTP responses from your web service,

        Other options for a TCP tunnel are:

        * `Proto`: MUST be set to `tcp`,
        * `RemoteAddr`: bind the remote TCP address and port, as registered in the ngrok dashboard,

        Note that in order to accept connections from outside, you must at least configure `AllowCidrs`.
        The most permissive CIDR is the "zero-address" `0.0.0.0/0`, and defines an IP block containing all possible IP addresses.

- `VerbosityProfile`: Verbosity profile (pre-defined tracing directives)

    Possible values are:

    * `Default`: the default profile
    * `Debug`: recommended profile for developers
    * `Tls`: verbose logging for TLS troubleshooting
    * `All`: extra-verbose profile, showing all traces
    * `Quiet`: only show warnings and errors

## Sample Usage

### RDP routing

Devolutions Gateway can redirect RDP traffic authorized by a JWT (Json Web Token) both signed (JWS) and encrypted (JWE).

The key used to sign must be known by the Gateway.
This key is provided through the `ProvisionerPublicKeyFile` option in the configuration file.
The provisioner can then use its private key to sign a JWT and authorize RDP routing.

Similarly, The key used for token decryption is provided through the `DelegationPrivateKeyFile` option.
The public counterpart of the delegation key must then be used for token encryption.

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

JWT generation should be facilitated by a provisioner (such as [Devolutions Server](https://devolutions.net/server) or [Devolutions Password Hub](https://devolutions.net/password-hub)).
However, you can easily generate a JWT for testing purposes by using CLI tools provided in `/tools` folder.

##### tokengen

A native CLI. No binary provided; you will need a Rust toolchain to build yourself. See [Install Rust](https://www.rust-lang.org/tools/install).

```
$ cargo build --package tokengen --release
```

The binary is produced inside a `target/release` folder.

RDP-TCP example:

```
$ ./tokengen --provisioner-key /path/to/provisioner/private/key.pem forward --dst-hst 192.168.122.70 --jet-ap rdp
```

RDP-TLS example:

```
$ ./tokengen --provisioner-key /path/to/provisioner/private/key.pem --delegation-key /path/to/delegation/public/key.pem rdp-tls --dst-hst 192.168.122.70 --prx-usr proxy_username --prx-pwd proxy_password --dst-usr host_username --dst-pwd host_password
```

#### Inject token in RDP connection using MSTSC

1. Open MSTSC

2. Enter a JET address in the "computer" field

3. Press the "Save As..." button under the "Connection settings" panel to save ".RDP" file to you PC

4. Open saved ".RDP" file with a text editor

5. Append string "pcb:s:" to the end of the file (e.g: pcb:s:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj...)

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
cannot accept connections from [rustls](https://crates.io/crates/rustls) client.
Support for required cipher suits was not implemented until Windows 10.

## Continuous Integration and Delivery

See the dedicated [README](.github/workflows/README.md) in the `workflows` directory.