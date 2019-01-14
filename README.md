# devolutions-jet

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
    -u, --url <LISTENER_URL>
            An address on which the server will listen on. Format: <scheme>://<local_iface_ip>:<port> [default:
            tcp://0.0.0.0:8080]
    -p, --pcap <PCAP_FILENAME>
            Path of the file where the pcap file will be saved. If not set, no pcap file will be created.
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
        $ cargo run -- -r tls://x.x.x.x:4489 -p c:\waykTraffic.pcap
        ```

3. On the same host where devolutions-jet is running, open wayk and connect to 127.0.0.1:8080 
    * The connection should start. A dummy certificate will be shown. You can accept it and the wayk connection should start. 
