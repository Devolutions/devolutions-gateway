# Devolutions Gateway

[![Build Status](https://github.com/Devolutions/devolutions-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Devolutions/devolutions-gateway/actions/workflows/ci.yml)

A blazing fast relay server adaptable to different protocols and desired levels of traffic inspection.

## Install

### From our website (recommended)

You can download either the Devolutions Server Management Console or the offline Windows Installer
from the [official Devolutions website][official_website]. Only releases that have successfully
passed our quality assurance team's acceptance testing are accessible through this channel.

### From GitHub

Signed binaries and installers for all versions can be conveniently obtained from the
[GitHub releases page][github_release]. It's important to note that these are made available
immediately, without going through the acceptance testing process of our quality assurance team.

### From sources

Ensure that you have [the Rust toolchain installed][install_rust] and then clone this repository and run:

```shell
cargo install --path ./devolutions-gateway
```

To enable enhanced in-memory credential protection (mlock via libsodium), build with the `mlock` feature:

```shell
cargo install --path ./devolutions-gateway --features mlock
```

> **Note:** The `mlock` feature requires [libsodium][libsodium] to be installed.
> On Windows, it is found automatically via vcpkg.
> On Linux and macOS, install it using your system package manager (e.g., `apt install libsodium-dev` or `brew install libsodium`).
> Production builds should always include the `mlock` feature.
> Without it, a startup warning is emitted in release builds.

## Configuration

Devolutions Gateway is configured using a JSON document.
The recommended way to modify this document is to use [the PowerShell module][psmodule],
but it is nonetheless possible to modify it manually or by any other means that are convenient for you.

The file containing this JSON document must be named `gateway.json` and exist under the following path,
depending on your platform:

| Platform       | Path                                                |
| -------------- | --------------------------------------------------- |
| Windows        | `%ProgramData%\Devolutions\Gateway\`                |
| Linux          | `/etc/devolutions-gateway/`                         |
| macOS (Darwin) | `/Library/Application Support/devolutions-gateway/` |

This path may be overridden using the `DGATEWAY_CONFIG_PATH` environment variable.

A default template with minimal options is generated at this location on startup if the file doesn't exist yet.

Stable options are:

- **Id** (_UUID_): This Gateway's UUID.

- **Hostname** (_String_): This Gateway's hostname (used when inferring external URLs).

- **ProvisionerPublicKeyFile** (_FilePath_): Path to the provisioner public key which is used to verify tokens
    without any specific restriction.

- **ProvisionerPrivateKeyFile** (_FilePath_): Path to the provisioner private key which is used to generate session
    tokens when using the standalone web application.

- **SubProvisionerPublicKey** (_Object_): A JSON object describing the sub provisioner public key which may only be used to verify
    tokens when establishing a session.
    
    The schema is:

    * **Id** (_UUID_): The key ID for this subkey.
    * **Value** (_String_): The binary-to-text-encoded key data.

    * **Format** (_String_): The format used for the key data.
        
        Possible values:
        
        * `Spki` (default)
        * `Pkcs1`

    * **Encoding** (_String_): The binary-to-text encoding used for the key data.

        Possible values:
        
        * `Multibase` (default)
        * `Base64`
        * `Base64Pad`
        * `Base64Url`
        * `Base64UrlPad`

- **DelegationPrivateKeyFile** (_FilePath_): Path to the delegation private key which is used to
    decipher sensitive data from tokens.

- **TlsCertificateSource** (_String_): Source for the TLS certificate.

    Possible values:

    * `External` (default): Retrieve a certificate stored on the file system.
        See the options **TlsCertificateFile**, **TlsPrivateKeyFile** and **TlsPrivateKeyPassword**.
    
    * `System`: Retrieve the certificate managed by the system certificate store. 
        See the options **TlsCertificateSubjectName**, **TlsCertificateStoreName** and **TlsCertificateStoreLocation**.

- **TlsCertificateSubjectName** (_String_): Subject name of the certificate to use for TLS when using system source.

- **TlsCertificateStoreName** (_String_): Name of the System Certificate Store to use for TLS (default is `My`).

- **TlsCertificateStoreLocation** (_String_): Location of the System Certificate Store to use for TLS.

    Possible values:

    * `CurrentUser` (default)
    * `CurrentService`
    * `LocalMachine`

- **TlsCertificateFile** (_FilePath_): Path to the certificate to use for TLS.

- **TlsPrivateKeyFile** (_FilePath_): Path to the private key to use for TLS.

- **TlsPrivateKeyPassword** (_String_): Password to use for decrypting the TLS private key.

    It's important to understand that using this option in order to use an encrypted private key
    does not inherently enhance security beyond using a plain, unencrypted private key. In fact,
    storing the password in plain text within the configuration file is _discouraged_ because it
    provides minimal security advantages over the unencrypted private key. If an unauthorized person
    gains access to both the configuration file and the private key, they can easily retrieve the
    password, making it as vulnerable as an unencrypted private key. To bolster security, consider
    additional measures like securing access to the files or using the system certificate store (see
    **TlsCertificateSource** option).

- **TlsVerifyStrict** (_Boolean_): Enables strict TLS certificate verification (default is `false`).

    When enabled (`true`), the client performs additional checks on the server certificate,
    including:

    - Ensuring the presence of the **Subject Alternative Name (SAN)** extension.
    - Verifying that the **Extended Key Usage (EKU)** extension includes `serverAuth`.

    Certificates that do not meet these requirements are increasingly rejected by modern clients
    (e.g., Chrome, macOS). Therefore, we strongly recommend using certificates that comply with
    these standards.

- **CredSspCertificateFile** (_FilePath_): Path to the certificate to use for CredSSP credential injection.
    When set, this certificate is presented to the client during proxy-based credential injection instead
    of the main TLS certificate. If unset, the TLS certificate is used.

- **CredSspPrivateKeyFile** (_FilePath_): Path to the private key to use for CredSSP credential injection.
    Required when **CredSspCertificateFile** is set (unless using a PFX/PKCS12 file which bundles the private key).

- **CredSspPrivateKeyPassword** (_String_): Password to use for decrypting the CredSSP private key or PFX/PKCS12 file.

- **Listeners** (_Array_): Array of listener URLs.

    Each element has the following schema: 

    * **InternalUrl** (_URL_): Internal URL for this listener, a socket bound to the specified address
        (IP address, and port number) will be created.

    * **ExternalUrl** (_URL_): External URL for this listener, accessing this URL from outside should
        ultimately redirect to the service. This holds no meaning for the service itself, but the value
        will be advertised by the `GET /jet/diagnostics/configuration` HTTP endpoint.
        This route can be used by other systems to automatically discover the remaining access URLs.

    For both values, host segment may be abridged with `*`.

    When used in internal URLs, `*` will cause two listeners to be created with `*` expanded into:
    - the IPv4 wildcard bind address `0.0.0.0`, for listening to any IPv4 address, and
    - the IPv6 wildcard bind address `[::]`, for listening to any IPv6 address.

    When used in external URLs, `*` will be expanded into the value of `Hostname`.

- **Subscriber** (_Object_): Subscriber API configuration.
    
    * **Url** (_URL_): HTTP URL where notification messages are to be sent.
    * **Token** (_String_): bearer token to use when making HTTP requests.

- **RecordingPath** (_FilePath_): Path to the recordings folder.

- **Ngrok** (_Object_): JSON object describing the ngrok configuration for ingress listeners.

    * **AuthToken** (_String_): Specifies the authentication token used to connect to the ngrok service.
    * **HeartbeatInterval** (_Integer_): How often the service should heartbeat to the ngrok servers defined as a number in seconds.
    * **HeartbeatTolerance** (_Integer_): Reconnect the agent tunnel session if the server does not respond to a heartbeat within this
        tolerance defined as a number in seconds.
    * **Metadata** (_String_): Opaque, user-supplied string that will be returned as part of the ngrok API response to the list
        online sessions resource for all tunnels started by Devolutions Gateway service.
    * **ServerAddr** (_URL_): This is the URL of the ngrok server to connect to. You should only set this if you are using a
        custom ingress URL.

    * **Tunnels** (_Map_): A map of ngrok tunnels. The key is the name of the tunnel and value is a JSON object whose schema
        depends on tunnel protocol.

        Common options are:

        * **AllowCidrs** (_Array_): Array of CIDRs, rejects connections that do not match the given CIDRs.
        * **DenyCidrs** (_Array_): Array of CIDRS, rejects connections that match the given CIDRs and allows all other CIDRs.
        * **Metadata** (_String_): Arbitrary user-defined metadata that will appear in the ngrok service API when listing tunnel sessions.

        Other options for an HTTP tunnel are:

        * **Proto** (_String_): MUST be set to `http`.
        * **Domain** (_String_): The domain to request, as registered in the ngrok dashboard.
        * **CircuitBreaker** (_Ratio_): Reject requests when 5XX responses exceed this ratio.
        * **Compression** (_Boolean_): Enable gzip compression for HTTP responses.

        Other options for a TCP tunnel are:

        * **Proto** (_String_): MUST be set to `tcp`.
        * **RemoteAddr** (_String_): Bind the remote TCP address and port, as registered in the ngrok dashboard.

        Note that in order to accept connections from outside, you must at least configure `AllowCidrs`.
        The most permissive CIDR is the "zero-address" `0.0.0.0/0`, and defines an IP block containing all possible IP addresses.

- **WebApp** (_Object_): JSON object describing the standalone web application configuration.

    * **Enabled** (_Boolean_): Whether to enable or disable the standalone web application.
        When enabled, the **ProvisionerPrivateKeyFile** option must be set.

    * **Authentication** (_String_): The authentication method for accessing the web application.

        Possible values:
        
        * `Custom`: Requires a username/password pair.
        * `None`: Disable authentication, anyone can access the web application.

    * **AppTokenMaximumLifetime** (_Integer_): The maximum lifetime granted to web application tokens
        defined as a number in seconds (default is `28800` for 8 hours).

    * **LoginLimitRate** (_Integer_): The maximum number of login requests for a given username/IP pair
        over a minute (default is `10`).

    * **UsersFile** (_FilePath_): Path to the users file which holds the list of users authorized to access
        the web application when using the `Custom` authentication method (default is `users.txt`).

        For each line such as `<user>:<hash>`:

        * `<user>`: The name of the user.

        * `<hash>`: Hash of the password in the [PHC string format][phc-string].
            Currently, the only supported hash algorithm is [Argon2][argon2-wikipedia].
            It’s possible to use the online tool [argon2.online][argon2-online] to generate a hash.

        Blank lines and lines starting by `#` are ignored.

    * **StaticRootPath** (_FilePath_): Path to the static files for the standalone web application.
        This is an advanced option which should typically not be changed.

- **Proxy** (_Object_): HTTP/SOCKS proxy configuration for outbound requests.
    Supports three modes: Off (never use proxy), System (auto-detect), Manual (explicit configuration).

    * **Mode** (_String_): Proxy mode (default is `System`).
        - `Off`: Never use a proxy, ignore environment variables
        - `System`: Auto-detect proxy from environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY)
            or system settings (per-user and machine-wide settings with WinHTTP fallback on Windows,
            `/etc/sysconfig/proxy` on RHEL/SUSE systems, SCDynamicStoreCopyProxies() on macOS)
        - `Manual`: Use explicitly configured proxy URLs

    * **Http** (_URL_): HTTP proxy URL for `http://` requests (e.g., `http://proxy.corp:8080`).
        Only used when Mode is `Manual`.

    * **Https** (_URL_): HTTPS proxy URL for `https://` requests (e.g., `http://proxy.corp:8080`).
        Only used when Mode is `Manual`.

    * **All** (_URL_): Fallback proxy URL for all protocols (e.g., `socks5://proxy.corp:1080`).
        Only used when Mode is `Manual`.
        The URL scheme determines the proxy type:
        - `http://proxy.corp:8080` - HTTP CONNECT proxy
        - `socks5://proxy.corp:1080` - SOCKS5 proxy
        - `socks4://proxy.corp:1080` - SOCKS4 proxy

    * **Exclude** (_Array of Strings_): Bypass list with NO_PROXY semantics (only used when Mode is `Manual`).
        Supports:
        - Wildcard: `*` (bypass proxy for all targets)
        - Exact hostname: `localhost`, `example.com`
        - Domain suffix: `.corp.local` (matches `foo.corp.local`)
        - IP address: `127.0.0.1`
        - CIDR range: `10.0.0.0/8`, `192.168.0.0/16`

    Authentication can be included in proxy URLs: `http://username:password@proxy.corp:8080`

    See the [Cookbook](./docs/COOKBOOK.md) for configuration examples.

- **VerbosityProfile** (_String_): Logging verbosity profile (pre-defined tracing directives).

    Possible values:

    * `Default` (default): The default profile.
    * `Debug`: Recommended profile for developers.
    * `Tls`: Verbose logging for TLS troubleshooting.
    * `All`: Extra-verbose profile, showing all traces.
    * `Quiet`: Only show warnings and errors.

[phc-string]: https://github.com/P-H-C/phc-string-format/blob/5f1e4ec633845d43776849f503f8ce8314b5290c/phc-sf-spec.md
[argon2-wikipedia]: https://en.wikipedia.org/wiki/Argon2
[argon2-online]: https://argon2.online/

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
cannot accept connections from [rustls] client.
Support for required cipher suits was not implemented until Windows 10.

### `NoCipherSuitesInCommon` error on Windows with a custom SChannel configuration

If you tried to to explicitly enable hashing algorithms like `SHA256` in registry keys under
`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes`, it turns out that this will…
disable them, even if you set `Enabled` to `1`. For example, if the only hashing algorithm that
is not explicitly set is `SHA1`, the SChannel client only advertises `SHA1`, which is not supported
anymore by default.

See [this page from Microsoft documentation][microsoft_tls] to learn how to properly configure SChannel.

## Knowledge base

Read more on [our knowledge base](https://docs.devolutions.net/kb/devolutions-gateway/).

## Cookbook

See [COOKBOOK.md](./docs/COOKBOOK.md).

## Continuous Integration and Delivery

See the dedicated [README.md file](./.github/workflows/README.md) in the `workflows` directory.

<!-- links -->

[official_website]: https://devolutions.net/gateway/download/
[github_release]: https://github.com/Devolutions/devolutions-gateway/releases
[install_rust]: https://www.rust-lang.org/tools/install
[libsodium]: https://libsodium.org/
[psmodule]: https://www.powershellgallery.com/packages/DevolutionsGateway/
[rustls]: https://crates.io/crates/rustls
[microsoft_tls]: https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
