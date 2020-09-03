# devolutions-jet

[![Build Status](https://travis-ci.com/vaffeine/devolutions-jet.svg?token=FxErzCAno8oL7CSUGoD1&branch=rdp)](https://travis-ci.com/vaffeine/devolutions-jet)
[![codecov](https://codecov.io/gh/vaffeine/devolutions-jet/branch/rdp/graph/badge.svg?token=eXgEoo0BnD)](https://codecov.io/gh/vaffeine/devolutions-jet)

A blazing fast relay server adaptable to different protocols and desired levels of traffic inspection.

Use `cargo run` to build and run devolutions-jet locally with default options.

## Command-line Interface

```
USAGE:
    devolutions-jet.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help
            Prints help information

        --unrestricted
            This flag remove the api_key validation on some http routes

    -v, --version
            Prints version information

OPTIONS:
        --api-key <JET_API_KEY>
            The api key used by the server to authenticate client queries.

        --certificate-data <JET_CERTIFICATE_DATA>
            Certificate data, base64-encoded X509 der.

        --certificate-file <JET_CERTIFICATE_FILE>
            Path to the certificate file.

        --http-listener-url <HTTP_LISTENER_URL>
            HTTP listener url. [default: http://0.0.0.0:10256]

    -i, --identities-file <IDENTITIES_FILE>

            JSON-file with a list of identities: proxy credentials, target credentials, and target destination.
            Every credential must consist of 'username' and 'password' fields with a string,
            and optional field 'domain', which also a string if it is present (otherwise - null).
            The proxy object must be present with a 'proxy' name, the target object with a 'target' name.
            The target destination must be a string with a target URL and be named 'destination'.
            identities_file example:
            '[
                {
                    "proxy":{
                        "username":"ProxyUser1",
                        "password":"ProxyPassword1",
                        "domain":null
                    },
                    "target":{
                        "username":"TargetUser1",
                        "password":"TargetPassword1",
                        "domain":null
                    },
                    "destination":"192.168.1.2:3389"
                },
                {
                    "proxy":{
                        "username":"ProxyUser2",
                        "password":"ProxyPassword2",
                        "domain":"ProxyDomain2"
                    },
                    "target":{
                        "username":"TargetUser1",
                        "password":"TargetPassword2",
                        "domain":"TargetDomain2"
                    },
                    "destination":"192.168.1.3:3389"
                }
            ]'"

        --jet-instance <JET_INSTANCE>
            Specific name to reach that instance of JET.

    -l, --listener <LISTENER_URL>...
            An URL on which the server will listen on. The external URL returned as candidate can be specified after the
            listener, separated with a comma. <scheme>://<local_iface_ip>:<port>,<scheme>://<external>:<port>If it is
            not specified, the external url will be <scheme>://<jet_instance>:<port> where <jet_instance> is the value
            of the jet-instance parameter.
        --log-file <LOG_FILE>
            A file with logs

    -f, --pcap-files-path <PCAP_FILES_PATH>
            Path to the pcap files. If not set, no pcap files will be created. WaykNow and RDP protocols can be saved.

        --private-key-data <JET_PRIVATE_KEY_DATA>
            Private key data, base64-encoded pkcs10.

        --private-key-file <JET_PRIVATE_KEY_FILE>
            Path to the private key file.

    -p, --protocol <PROTOCOL_NAME>
            Specify the application protocol used. Useful when pcap file is saved and you want to avoid application
            message in two different tcp packet. If protocol is unknown, we can't be sure that application packet is not
            split between 2 tcp packets. [possible values: wayk, rdp]
        --provisioner-public-key-data <JET_PROVISIONER_PUBLIC_KEY_DATA>
            Public key data, base64-encoded pkcs10.

        --provisioner-public-key-file <JET_PROVISIONER_PUBLIC_KEY_FILE>
            Path to the public key file.

    -r, --routing-url <ROUTING_URL>
            An address on which the server will route all packets. Format: <scheme>://<ip>:<port>. Scheme supported :
            tcp and tls. If it is not specified, the JET protocol will be used.
```

## Sample Usage

### Routing to a specific URL

1. Run Wayk Now on 2 hosts to be able to open a Wayk session between those 2 hosts.
    * Download Wayk Now [here](https://wayk.devolutions.net/home/download)

1. Start devolutions-jet and specify the routing URL where x.x.x.x is the IP of your Wayk server host. You can easily get the host IP in the source ID drop down list in Wayk Now.
    ```
    $ cargo run -- -r tls://x.x.x.x:4489
    ```
    * If you want to save the network traffic in a PCAP file, you can add the pcap-files-path parameter. The command will look to something like this:
        ```
        $ cargo run -- -r tls://x.x.x.x:4489 --pcap-files-path c:\waykTraffic\ -p wayk
        ```

1. On the same host where devolutions-jet is running, open wayk and connect to 127.0.0.1:8080
    * The connection should start. A dummy certificate will be shown. You can accept it and the Wayk connection should start.

### RDP routing (WIP)

The devolutions-jet can redirect RDP traffic. Validation is performed using a JWT (Json Web Token).
The key used to sign the JWT should be known by the jet. You can provide the jet with the public
key to use using `--provisioner-public-key-file` with a path to a PEM file; or `--provisioner-public-key-data`
with a base64-encoded pkcs10 value. *Validation is currently skipped if the key is missing*.

### Use JWT token for RDP connection in MSTSC

    1. Open MSTSC

    2. Enter a JET address in the "computer" field

    3. Press the "Save As..." button under the "Connection settings" panel to save ".RDP" file to you PC

    4. Open saved ".RDP" file with a text editor

    5. Append string "pcb:s:"  to the end of the file (e.g: pcb:s:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj...)

    6. Save file

    7. In MSTSC press "Open..." and select your edited file

    8. Done. You can start the connection

### Use JWT token for RDP connection in FreeRdp

Using FreeRDP, token can be provided using `/pcb` argument with `xfreerdp`.
(e.g: /pcb:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj...)

### JWT token generation for testing

This feature should be facilitated by a provider (such as the [WaykDen](https://github.com/Devolutions/WaykDen-ps))
generating JWTs for you.
However, you can easily generate a JWT for testing purposes by using CLI
utilities such as [smallstep CLI's tool](https://github.com/smallstep/cli).
Check out the [installation](https://github.com/smallstep/cli#installation) section.
You can also use the interactive Debugger from [jwt.io](https://jwt.io/).

For a JWT valid 10 minutes from now using `<private key>` (path to the provider key)
to be used for connecting at the `<target address>` you can type:
```
echo "{ \"dst_hst\": \"<target address>\", \"jet_ap\": \"rdp\" }" | step-cli crypto jwt sign - -nbf $(date "+%s") -exp $(date -d "10 minutes" "+%s") -subtle -key <private key>
```
(don't forget to replace `<target address>` and `<private key>` by your values)

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
