# General API overview

# Formats

Various formats are used across the Gateway's endpoints and token payloads.

### URL

The good old Uniform Resource Locator format.

In C#, the `Uri` type should be used (a URL is a specific type of URI).

### `TargetAddr`

Similar to URL, but doesn't contain any route.

Canonical form is `<SCHEME>://<ADDR>:<PORT>`

If absent, scheme is tcp by default.
Port may be omitted as well if a default port is known through another field specifying an `ApplicationProtocol`.

### `DateTime`

RFC 3339 date time format.

Examples:

- `1996-12-19T16:39:57-08:00`
- `2018-01-26T18:30:09.453+00:00`
- `2018-01-26T18:30:09.453Z`
- `2018-01-26T18:30:09Z`

This is compatible with ISO 8601 format.

A library should be used to parse these appropriately. In C#, the `DateTime` type should be used.

### UUID

Universally unique identifier, also called globally unique identifier (GUID).

In C# the `Guid` type should be used.

### ApplicationProtocol

Known value are:

- `rdp`
- `ssh`
- `ssh-pwsh`
- `sftp`
- `scp`
- `ard`
- `vnc`
- `winrm-http-pwsh`
- `winrm-https-pwsh`
- `http`
- `https`

Any other value is accepted as well, but, notably, default application port is unknown and will be required when providing a `TargetAddr`.

# Tokens

## Visualization / inspection

To inspect generated tokens, you can use [jwt.io](https://jwt.io/). The demonstration tool in
the home page decodes and show header and payload contents. Also, by moving your mouse above a
timestamp, a human-readable date will be displayed.

Alternatively, Smallstep's [CLI tool](https://smallstep.com/docs/step-cli) is recommended. JWT may
be inspected with the following command:

```shell
echo $TOKEN | step crypto jwt inspect --insecure
```

## Content types

For all tokens, content type should be specified in the header through the cty header parameter.

e.g.:

```json5
{
// The content type to be set by user
"cty": "ASSOCIATION",
"typ": "JWT" // (automatically set by JWT library)
// May contains a few other fields handled by JWT library…
}
```

Supported content types includes:

- `ASSOCIATION`
- `SCOPE`
- `KDC`
- `JMUX`
- `JRL`
- `JREC`

## Global private claims

Devolutions Gateway uses various [private claims](https://www.rfc-editor.org/rfc/rfc7519#section-4.3). Some of these are global and may be used in any token.

- `jet_gw_id` (string, UUID): when this claim is specified, a given token can only be used on a Gateway with the very same ID.

## Generate tokens for testing purposes

Token generation for Devolutions Gateway may be done using any JWT generator tool, but it is recommended to use the dedicated tools for simplicity.

Either the [PowerShell module](https://www.powershellgallery.com/packages/DevolutionsGateway), or the [tokengen](../tools/tokengen) tool to be found in the git repository may be used.

For the following step, I'll assume the PowerShell module is used.

### ASSOCIATION

#### Claims

```json5
{
 // Session ID
 "jet_aid": string (UUID),
 "jet_ap": string (ApplicationProtocol),
 "jet_cm": string ("fwd" | "rdv"),
 // Ignored if jet_cm = "rdv"
 "dst_hst": string (TargetAddr),
 // Ignored if dst_alt = "rdv"
 "dst_alt": [string (TargetAddr), …],
 // Optional
 "jet_rec": boolean,
 // Optional
 "jet_flt": boolean,
 // Optional, but it is recommended to always scope to a specific Gateway ID
 "jet_gw_id": string (UUID),
 "iat": integer (i64),
 "nbf": integer (i64),
 "exp": integer (i64),
 // Token's unique ID
 "jti": string (UUID)
}
```

#### Command

```shell
New-DGatewayToken -Type ASSOCIATION -DestinationHost <TARGET HOST> -ApplicationProtocol <APPLICATION PROTOCOL>
```

#### Inject token in RDP connection using MSTSC

1. Open MSTSC
2. Enter Gateway's address in the "computer" field (look for the TCP listener)
3. Press the "Save As..." button under the "Connection settings" panel to save ".rdp" file to you PC
4. Open saved ".rdp" file with a text editor
5. Append string "pcb:s:" to the end of the file (e.g: `pcb:s:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj…`)
6. Save file
7. In MSTSC press "Open..." and select your edited file
8. You can start the connection

#### Inject token in RDP connection using FreeRdp

Using FreeRDP, token can be provided using `/pcb` argument with `xfreerdp` (e.g: `/pcb:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOj…`)

### JMUX

#### Claims

```json5
{
 // Main target host
 "dst_hst": string (TargetAddr),
 // Additional target hosts
 "dst_addl": [string (TargetAddr), …],
 "jet_ap": string (ApplicationProtocol),
 // Session ID
 "jet_aid": string (UUID),
 // Optional, but it is recommended to always scope to a specific Gateway ID
 "jet_gw_id": string (UUID),
 "iat": integer (i64),
 "nbf": integer (i64),
 "exp": integer (i64),
 // Token's unique ID
 "jti": string (UUID)
}
```

#### Command

```shell
New-DGatewayToken -Type JMUX -DestinationHost <TARGET HOST> -ApplicationProtocol <APPLICATION PROTOCOL>
```

#### Manual injection with Jetsocat

[Jetsocat](../jetsocat) is a WebSocket toolkit developed alongside Devolutions Gateway.
Currently, it is used by RDM to convert SOCKS5 and HTTP(S) proxy requests into [JMUX](./JMUX-spec.md) requests
(for Web Entries and Remote PowerShell through WinRM).
JMUX is a wire protocol for multiplexing connections or streams into a single connection.
This protocol is understood by Devolutions Gateway and the single connection is authenticated with the JMUX token.

Download a Jetsocat binary from [the latest CI actions' artifacts](https://github.com/Devolutions/devolutions-gateway/actions/workflows/ci.yml) (click on a run and scroll down to the "artifacts" section). This binary can be invoked from the command line interface:

```shell
jetsocat jmux-proxy --log-term "<GATEWAY WS(S) LISTENER>/jmux?token=<TOKEN>" socks5-listen://127.0.0.1:<SOCKS5 port>
```

Once jetsocat is successfully connected to the Devolutions Gateway, you can configure your browser to use jetsocat as a SOCKS5 proxy server and ensure everything is working as expected.

### SCOPE

#### Claims

```json5
{
 "scope": string,
 // Optional, but it is recommended to always scope to a specific Gateway ID
 "jet_gw_id": string (UUID),
 "iat": integer (i64),
 "nbf": integer (i64),
 "exp": integer (i64),
 // Token's unique ID
 "jti": string (UUID)
}
```

#### Command

```shell
New-DGatewayToken -Type SCOPE -Scope <SCOPE NAME>
```

#### Manual injection with curl

```shell
curl -X <METHOD> -H "Authorization: Bearer <SCOPE TOKEN>" <URL>
```

### KDC

KDC tokens are long-lived (big interval between `exp` and `nbf` claims).

#### Claims

```json5
{
 // Kerberos realm.
 // e.g.: ad.it-help.ninja
 // Should be lowercased (actual validation is case-insensitive though).
 "krb_realm": string,
 // Kerberos KDC address.
 // e.g.: tcp://IT-HELP-DC.ad.it-help.ninja:88
 // Default scheme is `tcp`.
 // Default port is `88`.
 "krb_kdc": string (TargetAddr),
 // Optional, but it is recommended to always scope to a specific Gateway ID
 "jet_gw_id": string (UUID),
 "iat": integer (i64),
 "nbf": integer (i64),
 "exp": integer (i64),
 // Token's unique ID
 "jti": string (UUID)
}
```

#### Command

See [tokengen](../tools/tokengen).

#### Samples

Implicit scheme and port:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IktEQyJ9.eyJleHAiOjE2NTE2OTgxNjYsImp
0aSI6ImQ5NmYxN2JhLTYwZjItNDMzNC1iNWZmLTc3YzRhNzUxMjc1YiIsImtyYl9rZGMiOiJJVC1IRUx
QLURDLmFkLml0LWhlbHAubmluamEiLCJrcmJfcmVhbG0iOiJhZC5pdC1oZWxwLm5pbmphIiwibmJmIjo
xNjQ5MTA2MTY2fQ.RayfK9iYDBEa58k67oEx9RVAYxP1tnU-
8WzR6NqiVs4jhKXEih7p6AWuHfGKNlctEc_luSfF8qZYCij4bOow2SK_Hsz0fcg1hQlLaJQvbm7SemQ2
9P6YOTyC_29v4LwHhKYN_-Z24PKl3z4P7XPDju4THguKtxIhGeXUHD5bztv38cycfsvDt8T05CiI_SRV
op6NEVlzq0vuu4h0teumeH5HCvifk1At5xKRicRFcj9RD6iWejYXezGAW-
PyUNpn0LqmjCeZmqyiKXjjxqwQTHwfte7tsyvICJUZLC_yVauRDkNYOSy6woX3Dwg3CePcqbywENMeZ-
w6D4SVtXyn7g
```

```json5
{
 "alg": "RS256",
 "typ": "JWT",
 "cty": "KDC"
}
.
{
 "exp": 1651698166,
 "jti": "d96f17ba-60f2-4334-b5ff-77c4a751275b",
 "krb_kdc": "IT-HELP-DC.ad.it-help.ninja",
 "krb_realm": "ad.it-help.ninja",
 "nbf": 1649106166
}
.
<signature>
```

Same destination, but explicit scheme and port:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IktEQyJ9.eyJleHAiOjE2NTE2OTc5MzEsImp
0aSI6ImUzNDlmYWFiLTcyNzktNDU3OS1iMzJmLTllM2MyZmVjMjdjNSIsImtyYl9rZGMiOiJ0Y3A6Ly9
JVC1IRUxQLURDLmFkLml0LWhlbHAubmluamE6ODgiLCJrcmJfcmVhbG0iOiJhZC5pdC1oZWxwLm5pbmp
hIiwibmJmIjoxNjQ5MTA1OTMxfQ.QAOBy1ztOphlhuhHp8PS8KuGgYiRH5aKZ0Vh3FeJbuRbyLHEVU2u
y7a7VlI-t10qqsRtRk5j7FM2FoSfHtaSo4I-c1Cdry_ufSUl_MDsTug2EmqUo9zRh-JcC-
sHjO4nyiiuoKPBR-n43786TSXmApHXWSX2TVdnEnJVRjRUKLRCapqlAxK4bY-sRQJfsJu0Tb4JW-
kNPi21F67jl7evG7pjJN3rq0WhcBsPtzfrrXfuJ1urJpvxcpslL3fnH45FSYlUyaLuJ4gL29gm3WIB8q
yZDVTUDcEvoJxqflGK3xQppG_1SbEf6ngD3a4SS1YT7tyO94mO6NhWwMAvzzRLZQ
```

```json5
{
 "alg": "RS256",
 "typ": "JWT",
 "cty": "KDC"
}
.
{
 "exp": 1651697931,
 "jti": "e349faab-7279-4579-b32f-9e3c2fec27c5",
 "krb_kdc": "tcp://IT-HELP-DC.ad.it-help.ninja:88",
 "krb_realm": "ad.it-help.ninja",
 "nbf": 1649105931
}
.
<signature>
```

UDP protocol is supported too:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IktEQyJ9.eyJleHAiOjE2NTE2OTgwMDgsImp
0aSI6IjMyMTg0OWQxLThjN2UtNDJjNy05YzlmLWIxNDk2ZWFkMTZjYiIsImtyYl9rZGMiOiJ1ZHA6Ly9
JVC1IRUxQLURDLmFkLml0LWhlbHAubmluamE6MjIyMiIsImtyYl9yZWFsbSI6ImFkLml0LWhlbHAubml
uamEiLCJuYmYiOjE2NDkxMDYwMDh9.SS7oX5-
g72Fv6FYfXvkWwOdDg1Sh0nddVUsx0J7EedhWyF0i39hxy2pTk9cEIubqcetmWMQyZJzS8U32FXKlQAB
ZNjzQzID_6NMVe0Bnl1etjac17l_rubnGZRt017oKCjXA_SYpVLxALyTRF9gb2uPmdrPSJ_jfpAqikOk
ml_eFIkUWSfZisY8Nd-ehUh_JMAHqboJyFyLeRvnOTe4R7gepKKNASKp42-4-f44WD9hIlySogTh-
IujZpMp57hDFABfDFRn9qX8v1bJBBxFc0ubBRahurs3JAu8lWFK_4EC3e9PmvEZHwP7yPCOR_dSEWzEz
2JtfoQypRHAOQ4jFng
```

```json5
{
 "alg": "RS256",
 "typ": "JWT",
 "cty": "KDC"
}
​.
{
 "exp": 1651698008,
 "jti": "321849d1-8c7e-42c7-9c9f-b1496ead16cb",
 "krb_kdc": "udp://IT-HELP-DC.ad.it-help.ninja:2222",
 "krb_realm": "ad.it-help.ninja",
 "nbf": 1649106008
}
.
<signature>
```

### JRL (JWT Revocation List)

This token is long-lived as well and contains the list of banned values for specific claims.
It is pushed to the Devolutions Gateway which will persist it on the file system, and should also
be stored at the provisioner level (e.g.: DVLS) so it can be pushed again in case of failure,
pushed later to a newly configured gateway and revocation list freshness can be checked / diagnosed
using the `GET /jet/jrl` route.

#### Claims

```json5
{
 // Token's unique ID
 "jti": string (UUID),
 // JWT "Issued At" claim.
 // Revocation list is saved only for the more recent token.
 "iat": integer (i64),
 // The JWT revocation list as a claim-values map
 "jrl": {
  "<claim name>": [<claim_value>, …],
  …
 },
}
```

While `nbf` and `exp` claims are optional, `iat` (Issued At) is absolutely
required. Devolutions Gateway accepts a JRL token only and only if it is newer
than the current one.

If exp claim is present, it should be reasonably far in the future. Indeed, this
token might be pushed again after its initial creation. In general, exp should
not be included to prevent a few headaches at the provisioner level: when
pushing the revocation list again, it's okay to generate a fresh token using
the very same list if the latest one is expired, but this will require to push
the newly created token to all existing gateways as well (so that all Gateways'
revocation list is considered "fresh"). This is not expected to be fun when _a
lot of gatewaysᵀᴹ_ are configured.

#### Sample

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpSTCJ9.eyJpYXQiOjE2NDkxMDk0NzEsImp
ybCI6eyJqdGkiOlsiZDk2ZjE3YmEtNjBmMi00MzM0LWI1ZmYtNzdjNGE3NTEyNzViIiwiZTM0OWZhYWI
tNzI3OS00NTc5LWIzMmYtOWUzYzJmZWMyN2M1Il19LCJqdGkiOiIxNjdjZmZkMS1lNDQ0LTQxMTItYmF
mYS1hNjRhZjFkYjJmN2QifQ.FO7M2JxmFOsVo5YJutR-
XQXEpYl2BEc0W1gn6Z3D9PRLgeAcQNDCsOnAqMVFdzRTWriZodU480DSdtYTeCFF4_h8hfAjDn274SmI
fuODAVgyMI3MZQKN6R3YmhlugVhrhRWK-
p4m2ERc_LlCjEMnRCWhOGYqhAJ3hY7MIaxcUr_GmRmEoThE--ySWPDCc1diCgBJ5q-
x1bKaT56mw_UGmVxEruUPZ3XrWgfEbwBZT6E6_oqCDx7jmdVFwN9575PgGhd8jzvU034Uv6yyLbMuX8j
d-PskbbeKTTORA-_oUPLplfMzvbS9PdzRtIf3ROqN6__AzQAGh3EP4Crg9PK5mg
```

```json5
{
 "alg": "RS256",
 "typ": "JWT",
 "cty": "JRL"
}
​.
{
 "iat": 1649109471,
 "jrl": {
  "jti": [
   "d96f17ba-60f2-4334-b5ff-77c4a751275b",
   "e349faab-7279-4579-b32f-9e3c2fec27c5"
  ]
 },
 "jti": "167cffd1-e444-4112-bafa-a64af1db2f7d"
}
.
<signature>
```

#### Command

See [tokengen](../tools/tokengen).

#### Manual injection with curl

```shell
curl -X POST -H "Authorization: Bearer <JRL TOKEN>" "<GATEWAY URL>/jet/jrl"
```

# Endpoints

## About scopes

In order to be used, some endpoints require a scope token restricted to a
specific scope (those are specified along the relevant endpoint description).
However, it's possible de generate a "wildcard" scope token by using the
wildcard scope `*`.

i.e.:

```json5
{
 "scope": "*",
 …
}
```

## OpenAPI

Endpoints are documented using [OpenAPI specification](../devolutions-gateway/openapi/doc/index.adoc).
