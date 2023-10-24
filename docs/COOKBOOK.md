# Devolutions Gateway Cookbook

Developer-oriented cookbook for testing purposes.

- [RDP routing](#rdp-routing)
- [WebSocket-to-TCP tunnel using jetsocat](#websocket-to-tcp-tunnel-using-jetsocat)

## RDP routing

Devolutions Gateway can redirect RDP traffic authorized by a JWT (Json Web Token) signed (JWS) and
optionally encrypted (JWE).

The key used to sign must be known by the Devolutions Gateway.
This key is provided through the `ProvisionerPublicKeyFile` option in the configuration file.
The provisioner can then use its private key to sign a JWT and authorize RDP routing.

Similarly, The key used for token decryption is provided through the `DelegationPrivateKeyFile` option.
The public counterpart of the delegation key must then be used for token encryption.

### JWT structure and claims

Devolutions Gateway is expecting signed claims using JWS (Json Web Signature) as a compact JWT.
Use of RSASSA-PKCS-v1_5 using SHA-256 (`RS256`) is recommended.

Required claims:

- `dst_hst` (String): target RDP host
- `jet_cm` (String): identity connection mode used for Jet association This must be set to `fwd`.
- `jet_ap` (string): application protocol used over Jet transport. This must be set to `rdp`.
- `exp` (Integer): a UNIX timestamp for "expiration"
- `nbf` (Integer): a UNIX timestamp for "not before"

This token may be encrypted and wrapped inside another JWT using JWE (Json Web Encryption), in compact form as well.
Use of RSAES OAEP using SHA-256 and MGF1 with SHA-256 (`RSA-OAEP-256`) and AES GCM using 256-bit key (`A256GCM`) is
recommended.

### Token generation utilities

JWT generation should be facilitated by a provisioner (such as [Devolutions Server](https://devolutions.net/server)
or [Devolutions Password Hub](https://devolutions.net/password-hub)).
However, you can easily generate a JWT for testing purposes by using CLI tools provided in `/tools` folder.

#### tokengen

A native CLI. No binary provided; you will need a Rust toolchain to build yourself. See [Install Rust](install_rust).

```
$ cargo build --package tokengen --release
```

The binary is produced inside a `target/release` folder.

Example:

```
$ ./tokengen --provisioner-key /path/to/provisioner/private/key.pem forward --dst-hst 192.168.122.70 --jet-ap rdp
```

### Inject token in RDP connection using MSTSC

1. Open MSTSC

2. Enter a JET address in the "computer" field

3. Press the "Save As..." button under the "Connection settings" panel to save ".RDP" file to you PC

4. Open saved ".RDP" file with a text editor

5. Append string "pcb:s:" to the end of the file (e.g: pcb:s:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj...)

6. Save file

7. In MSTSC press "Open..." and select your edited file

8. Done. You can start the connection

### Inject token in RDP connection using FreeRdp

Using FreeRDP, token can be provided using `/pcb` argument with `xfreerdp`.
(e.g: /pcb:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj...)

## WebSocket-to-TCP tunnel using jetsocat

Our CLI-based toolkit `jetsocat` can be used to create a network tunnel bridging a WebSocket connection
with a TCP connection. This is useful when debugging the Devolutions Gateway service.

This section describes how to create the following tunnel:

```
(jetsocat as client) <--WS/TCP/IP--> (Devolutions Gateway) <--TCP/IP--> (jetsocat as server)
```

### Devolutions Gateway service

Configure and start the Devolutions Gateway service (see top-level README.md file).

### Server TCP endpoint

Start jetsocat to act as our server endpoint:

```shell
cargo run -p jetsocat -- forward tcp-listen://127.0.0.1:9999 -
```

Received payload will be printed to the standard output.

### WebSocket client

Generate a session forwarding token using `tokengen` (or alternatively, the `New-DGatewayToken` cmdlet):

```shell
cargo run --manifest-path=./tools/tokengen/Cargo.toml --provisioner-key <path/to/provisioner.key> forward --dst-hst 127.0.0.1:9999 --jet-aid 123e4567-e89b-12d3-a456-426614174000
```

```pwsh
New-DGatewayToken -Type ASSOCIATION -DestinationHost 127.0.0.1:9999 -ApplicationProtocol unknown -AssociationId 123e4567-e89b-12d3-a456-426614174000
```

Finally, run the following command to connect to the Devolutions Gateway service and open a WebSocket-to-TCP tunnel:

```shell
cargo run -p jetsocat -- forward - "ws://127.0.0.1:7171/jet/fwd/tcp/123e4567-e89b-12d3-a456-426614174000?token=<TOKEN>"
```

Try entering text and see it printed on the other side.

