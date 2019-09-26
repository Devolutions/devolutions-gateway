# devolutions-jet

[![Build Status](https://travis-ci.com/vaffeine/devolutions-jet.svg?token=FxErzCAno8oL7CSUGoD1&branch=rdp)](https://travis-ci.com/vaffeine/devolutions-jet)
[![codecov](https://codecov.io/gh/vaffeine/devolutions-jet/branch/rdp/graph/badge.svg?token=eXgEoo0BnD)](https://codecov.io/gh/vaffeine/devolutions-jet)

A blazing fast relay server adaptable to different protocols and desired levels of traffic inspection.

Use `cargo run` to build and run devolutions-jet locally with default options.

## Command-line Interface

```
USAGE:
    devolutions-jet.exe [OPTIONS]

FLAGS:
    -h, --help
            Prints help information

    -v, --version
            Prints version information


OPTIONS:
    -i, --identities_file <IDENTITIES_FILE>

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

    -u, --url <LISTENER_URL>
            An address on which the server will listen on. Format: <scheme>://<local_iface_ip>:<port> [default:
            tcp://0.0.0.0:8080]
    -l, --log_file <LOG_FILE>                  
            A file with logs

    -f, --pcap_file <PCAP_FILENAME>
            Path of the file where the pcap file will be saved. If not set, no pcap file will be created. WaykNow and
            RDP protocols can be saved.
    -p, --protocol <PROTOCOL_NAME>
            Specify the application protocol used. Useful when pcap file is saved and you want to avoid application
            message in two different tcp packet. If protocol is unknown, we can't be sure that application packet is not
            split between 2 tcp packets. [possible values: wayk, rdp]
    -r, --routing_url <ROUTING_URL>
            An address on which the server will route all packets. Format: <scheme>://<ip>:<port>. Scheme supported :
            tcp and tls. If it is not specified, the JET protocol will be used.

```

## Sample Usage

### Routing to a specific URL

1. Run WaykNow on 2 hosts to be able to open a wayk session between those 2 hosts.  
1.1 Download wayknow [here](https://wayk.devolutions.net/home/download)

2. Start devolutions-jet and specify the routing url where x.x.x.x is the IP of your wayk server host. You can easily get the host ip in the source id drop down list in WaykNow.
    ```
    $ cargo run -- -r tls://x.x.x.x:4489
    ```

    1. If you want to save the network trafic in a pcap file, you can add the pcap_filename parameter. The command will look to something like this:
        ```
        $ cargo run -- -r tls://x.x.x.x:4489 -f c:\waykTraffic.pcap -p wayk
        ```

3. On the same host where devolutions-jet is running, open wayk and connect to 127.0.0.1:8080 
    * The connection should start. A dummy certificate will be shown. You can accept it and the wayk connection should start. 
