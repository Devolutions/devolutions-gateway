# Devolutions Gateway Cookbook

Developer-oriented cookbook for testing purposes.

- [RDP routing](#rdp-routing)
- [WebSocket-to-TCP tunnel using jetsocat](#websocket-to-tcp-tunnel-using-jetsocat)
- [Standalone web application custom authentication](#standalone-web-application-custom-authentication)

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

## Standalone web application custom authentication

This section demonstrates how to use `curl` to test the `/jet/webapp/app-token` and `/jet/webapp/session-token` endpoints.

The standalone web application must be enabled and configured to use the custom authentication mode.

```json
"WebApp": {
  "Enabled": true,
  "Authentication": "Custom"
}
```

A `users.txt` file is expected as well.
For instance, with a user named `David` protected by the password `abc`:

```
David:$argon2id$v=19$m=16,t=2,p=1$U0tDR3NSSjlBaVJMRmV0Tg$4KRKy3UsOganH/qTYVvOQg
```

It’s possible to retrieve a web application token using the `POST /jet/webapp/app-token` endpoint.

If the `Authorization` header is absent of the request, the server responds with a challenge:

```shell
$ curl -v http://127.0.0.1:7171/jet/webapp/app-token --json '{ "content_type": "WEBAPP", "subject": "David" }'
*   Trying 127.0.0.1:7171...
* Connected to 127.0.0.1 (127.0.0.1) port 7171
> POST /jet/webapp/app-token HTTP/1.1
> Host: 127.0.0.1:7171
> User-Agent: curl/8.5.0
> Content-Type: application/json
> Accept: application/json
> Content-Length: 48
>
< HTTP/1.1 401 Unauthorized
< www-authenticate: Basic realm="DGW Custom Auth", charset="UTF-8"
< access-control-allow-origin: *
< vary: origin
< vary: access-control-request-method
< vary: access-control-request-headers
< content-length: 0
< date: Fri, 22 Dec 2023 16:34:12 GMT
<
* Connection #0 to host 127.0.0.1 left intact
```

Notice the `WWW-Authenticate` header which advertises the configured authentication mode.

By requesting again with an appropriate `Authorization` header, a token is returned:

```shell
$ curl -v http://127.0.0.1:7171/jet/webapp/app-token --json '{ "content_type": "WEBAPP", "subject": "David" }' -H "Authorization: Basic RGF2aWQ6YWJj"
*   Trying 127.0.0.1:7171...
* Connected to 127.0.0.1 (127.0.0.1) port 7171
> POST /jet/webapp/app-token HTTP/1.1
> Host: 127.0.0.1:7171
> User-Agent: curl/8.5.0
> Authorization: Basic RGF2aWQ6YWJj
> Content-Type: application/json
> Accept: application/json
> Content-Length: 48
>
< HTTP/1.1 200 OK
< content-type: text/plain; charset=utf-8
< cache-control: no-cache, no-store
< content-length: 548
< access-control-allow-origin: *
< vary: origin
< vary: access-control-request-method
< vary: access-control-request-headers
< date: Fri, 22 Dec 2023 16:34:46 GMT
<
* Connection #0 to host 127.0.0.1 left intact
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IldFQkFQUCJ9.eyJqdGkiOiIyODU5NjZhZi04M2VlLTRlNTEtYWYwOS01YWMwZTNjMzQyOTEiLCJpYXQiOjE3MDMyNjI4ODYsIm5iZiI6MTcwMzI2Mjg4NiwiZXhwIjoxNzAzMjkxNjg2LCJzdWIiOiJEYXZpZCJ9.ZO-bbuJpnoOMChbMEHsLj8gIXpcflJQ7DMIS4wo2dgEK4xnCxEJ4AdXVquYnZmGgg7-L1bhgKRi5EM35QFoYrnQDkMfSb6cVROGdp9Lg1-AgGA94Tw8Btq2bWXBJGES67cNFkdN-HJ07ixWKqpRz0wA4yZjn_8Z5B5K_S2_BP7IxfO7ckV_NqQzpaa94oH8XrdX_7dXwG6m-bXkNLOvAzyXHXFQkpb7l9-_CabJ6ZlJpdHcHJ4Tekx1_cHUW7haSyTd1Dp_VWIlnKhaqOcN3BRJ0aW9QaxR7JgSU1k9NWuZL3S5Au_SXUiYrOk2TdNkGDBptImkQhlSim6P4_OXacA
```

It’s then possible to retrieve a session token:

```shell
$ curl -v http://127.0.0.1:7171/jet/webapp/session-token --json '{ "content_type": "ASSOCIATION", "protocol": "rdp", "destination": "tcp://localhost:8888", "lifetime": 60, "session_id": "123e4567-e89b-12d3-a456-426614174000" }' -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IldFQkFQUCJ9.eyJqdGkiOiIyODU5NjZhZi04M2VlLTRlNTEtYWYwOS01YWMwZTNjMzQyOTEiLCJpYXQiOjE3MDMyNjI4ODYsIm5iZiI6MTcwMzI2Mjg4NiwiZXhwIjoxNzAzMjkxNjg2LCJzdWIiOiJEYXZpZCJ9.ZO-bbuJpnoOMChbMEHsLj8gIXpcflJQ7DMIS4wo2dgEK4xnCxEJ4AdXVquYnZmGgg7-L1bhgKRi5EM35QFoYrnQDkMfSb6cVROGdp9Lg1-AgGA94Tw8Btq2bWXBJGES67cNFkdN-HJ07ixWKqpRz0wA4yZjn_8Z5B5K_S2_BP7IxfO7ckV_NqQzpaa94oH8XrdX_7dXwG6m-bXkNLOvAzyXHXFQkpb7l9-_CabJ6ZlJpdHcHJ4Tekx1_cHUW7haSyTd1Dp_VWIlnKhaqOcN3BRJ0aW9QaxR7JgSU1k9NWuZL3S5Au_SXUiYrOk2TdNkGDBptImkQhlSim6P4_OXacA"
*   Trying 127.0.0.1:7171...
* Connected to 127.0.0.1 (127.0.0.1) port 7171
> POST /jet/webapp/session-token HTTP/1.1
> Host: 127.0.0.1:7171
> User-Agent: curl/8.5.0
> Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IldFQkFQUCJ9.eyJqdGkiOiIyODU5NjZhZi04M2VlLTRlNTEtYWYwOS01YWMwZTNjMzQyOTEiLCJpYXQiOjE3MDMyNjI4ODYsIm5iZiI6MTcwMzI2Mjg4NiwiZXhwIjoxNzAzMjkxNjg2LCJzdWIiOiJEYXZpZCJ9.ZO-bbuJpnoOMChbMEHsLj8gIXpcflJQ7DMIS4wo2dgEK4xnCxEJ4AdXVquYnZmGgg7-L1bhgKRi5EM35QFoYrnQDkMfSb6cVROGdp9Lg1-AgGA94Tw8Btq2bWXBJGES67cNFkdN-HJ07ixWKqpRz0wA4yZjn_8Z5B5K_S2_BP7IxfO7ckV_NqQzpaa94oH8XrdX_7dXwG6m-bXkNLOvAzyXHXFQkpb7l9-_CabJ6ZlJpdHcHJ4Tekx1_cHUW7haSyTd1Dp_VWIlnKhaqOcN3BRJ0aW9QaxR7JgSU1k9NWuZL3S5Au_SXUiYrOk2TdNkGDBptImkQhlSim6P4_OXacA
> Content-Type: application/json
> Accept: application/json
> Content-Length: 161
>
< HTTP/1.1 200 OK
< content-type: text/plain; charset=utf-8
< cache-control: no-cache, no-store
< content-length: 762
< access-control-allow-origin: *
< vary: origin
< vary: access-control-request-method
< vary: access-control-request-headers
< date: Fri, 22 Dec 2023 16:35:51 GMT
<
* Connection #0 to host 127.0.0.1 left intact
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkFTU09DSUFUSU9OIn0.eyJkc3RfYWx0IjpbXSwiZHN0X2hzdCI6InRjcDovL2xvY2FsaG9zdDo4ODg4IiwiZXhwIjoxNzAzMjYzMDExLCJpYXQiOjE3MDMyNjI5NTEsImpldF9haWQiOiIxMjNlNDU2Ny1lODliLTEyZDMtYTQ1Ni00MjY2MTQxNzQwMDAiLCJqZXRfYXAiOiJyZHAiLCJqZXRfY20iOiJmd2QiLCJqZXRfZmx0IjpmYWxzZSwiamV0X3JlYyI6ZmFsc2UsImpldF90dGwiOjAsImp0aSI6ImMyZjAzMmU4LWNlZGMtNDk5Zi05ODYyLWExZWFlNjU5NGNiNCIsIm5iZiI6MTcwMzI2Mjk1MX0.WRwnQR-o6UNvIDCiskvOPiQ5XStriaGl4c4UfhZPdZY9hSN4nLajP_inWjbVR8V8h-WcuWZEo_p-s_0Ze6OnEpJ94HRw8e_ANEJ3JWCMrWB7MypWT4V3khPCk-SL29V-if2VUpwPq6Oc9ugpatCxHAJRcUD4FYxr1cy85jU__E3DwOceqGL1OUStfPVw5zqZvJQmZ2ndNO8K_6NhfC2PRSwmMYPPR_vKDeBFShSFQSHCWv2-X3Og5Mjm6R7vyMbvfKY7fs2zRQxwZBoUEaLhEimhqeVcsDH3dF8deN5DbnQ1nq2Eu_eWoJ4y3tBmwaZPMvIDHPq3STZRgehFkY5pqw
```

## Preflight API

Generate a scope token with the scope `gateway.preflight` or `*` using `tokengen` (or alternatively, the `New-DGatewayToken` cmdlet):

```shell
tokengen --provisioner-key <path/to/provisioner.key> scope 'gateway.preflight'
```

```pwsh
New-DGatewayToken -Type SCOPE -Scope 'gateway.preflight'
```

Perform preflight operations using `curl`:

```shell
$ curl "127.0.0.1:7171/jet/preflight?token=$(cargo run --manifest-path ./tools/tokengen/Cargo.toml '--' sign --provisioner-key ./config/provisioner.key scope "gateway.preflight")" \
  -X POST -H "Content-Type: application/json" \
  --data '[
    {"id": "a86ae982-e4be-4f84-8ff2-893d66df9bdd", "kind": "get-version"},
    {"id": "ef1a3ae9-e55d-48b8-92b0-ae67c29b2e4e", "kind": "push-token", "token": "hello", "token_id": "3d1d3c45-e377-4713-b8d5-45b07514cf22"},
    {"id": "55821d24-d1df-481c-8b88-66c06f879835", "kind": "lookup-host", "host_to_lookup": "devolutions.net"},
    {"id": "8ec4ab6b-39a5-411d-b191-54df2d976820", "kind": "get-running-session-count"},
    {"id": "e02d8678-1bc8-4548-b555-548d663ffa1e", "kind": "unexisting-operation"}
  ]'
```

And here is how the response may look like:

```
[
  {"operation_id":"e02d8678-1bc8-4548-b555-548d663ffa1e","kind":"alert","alert_status":"unsupported-operation","alert_message":"unsupported operation: unexisting-operation"},
  {"operation_id":"a86ae982-e4be-4f84-8ff2-893d66df9bdd","kind":"version","version":"2025.1.4"},
  {"operation_id":"8ec4ab6b-39a5-411d-b191-54df2d976820","kind":"running-session-count","running_session_count":0},
  {"operation_id":"55821d24-d1df-481c-8b88-66c06f879835","kind":"resolved-host","resolved_host":"devolutions.net","resolved_addresses":["20.22.31.128"]}
]
```
