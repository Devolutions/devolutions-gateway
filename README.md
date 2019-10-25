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
            Path to the pcap files. If not set, no pcap files will be created. Wayk Now and RDP protocols can be saved.

    -p, --protocol <PROTOCOL_NAME>
            Specify the application protocol used. Useful when pcap file is saved and you want to avoid application
            message in two different tcp packet. If protocol is unknown, we can't be sure that application packet is not
            split between 2 tcp packets. [possible values: wayk, rdp]
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
