
# Introduction

This document specifies the JET protocol used in Devolutions Gateway for connection forwarding, proxying, tunneling, bridging.

## Glossary

The following terms are specific to this document: **MAY, SHOULD, MUST, SHOULD NOT, MUST NOT:** These terms (in all caps) are used as described in [RFC2119]. All statements of optional behavior use either MAY, SHOULD, or SHOULD NOT.

## References

### Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997, [http://www.ietf.org/rfc/rfc2119.txt](http://www.ietf.org/rfc/rfc2119.txt).

## Overview

The JET protocol bears some similarities with the SOCKS proxy protocol and the routing token packets often used in remote desktop connections for load balancing and session selection. However, all of these protocols make connections in a forward manner: the client connects to the proxy, then the proxy connects to the server and then relays the traffic. The JET protocol is designed to relay TCP traffic between a TCP client and server using only outgoing TCP connections.

## Prerequisites/Preconditions

The JET protocol requires a TCP transport.

## Applicability Statement

The JET protocol is suitable for simple, efficient relaying TCP, TLS or WebSocket traffic.

# Messages

## Transport

The JET protocol is designed to provide a simple, efficient way to relay TCP traffic between two nodes that can only perform outgoing TCP connections to the same server, using a rendezvous connection style. Alternatively, a JET packet can be sent between a client and server as a way to discover a direct route.

## Message Syntax

The following sections specify the JET protocol message syntax. All fields defined in this document use big endian byte ordering and are byte-aligned to their sizes (a field of 4 bytes starts at an offset that is a multiple of 4).

### Protocol Messages

All JET binary protocol messages sent over TCP or TLS are contained within a JET_PACKET structure. The JET WebSocket protocol makes use of HTTP requests and the WebSocket handshake request path to achieve the same goal.

### Token Format

Starting with Jet V3, associations can be authorized using JWTs signed by a trusted authority external to the jet relays. Since JWTs can be passed as a string parameter, they can be embedded in Jet messages, but they can also be adapted to be encapsulated in other protocols, such as the Authorization header of a WebSocket handshake in a browser, or the token string of the RDP preconnection PDU.

#### Validity Period

The "iat" (issued at) claim or the "nbf" (not before) claim SHOULD be used to determine the beginning of the JWT validity period, where the "nbf" claim takes precedence over the "iat" claim if present. The "exp" (expiration time) claim SHOULD be used to determine the ending of the JWT validity period. The recommended JWT validity period SHOULD be two minutes with a leeway of a few minutes (10 minutes should be relatively safe for most system clocks). JWTs used outside of their validity period MUST be considered invalid and rejected by the Jet relay.

#### Token Signature

By default, Jet JWTs SHOULD use public key algorithms instead of symmetric algorithms, to reduce the number of places where the secret required to sign the JWTs is stored. With public-key cryptography, only the authorization server needs the private key to sign the JWTs, while the jet relays only need to be configured with the corresponding public key to validate the signatures.

Usage of the "none" algorithm (unsecured JWT) SHOULD be disabled by default. However, because the "none" algorithm can prove useful for development purposes, Jet relay implementations MAY offer an option to enable it, and effectively make it possible to craft JWTs without signing them.

#### Token Encryption

Because Jet JWTs can sometimes be sent over an unsecure communication channel, some implementations MAY use [JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516) to encrypt the JWT instead of signing it. In most cases, the information contained in the JWT is not sensitive and meant to be used only once, so encryption should not be required. However, one should keep in mind that information confidentiality for all pre-TLS Jet messages, that occur in the following cases:

- TCP candidate packets
- RDP preconnection PDU

In the case of TCP candidate packets, the exchange occurs pre-TLS for the underlying application protocol. In the rendezvous connection mode, the association id and candidate ids are revealed, but these are not of a sensitive nature. In the RDP preconnection PDU, the "dst_hst" claim could reveal the internal hostname of the destination RDP server, which is still not very sensitive. For all these specific cases, JWT encryption SHOULD be considered optional and not a requirement.

The following JWT claims are considered sensitive and MUST only be used with JWT encryption:

- "dst_usr" (destination username) claim
- "dst_pwd" (destination password) claim

Since the Jet relay needs to decode the JWT contents, usage of JWT encryption requires that the private keys be configured in both the authorization server and the Jet relays. This is a limitation that defeats the purpose of public-key cryptography by sharing the private key in multiple locations, but it is the only way we can provide both signature and encryption capabilities.

#### "type" (Token Type) Claim

The "type" claim identifies the token type. This value must be set to "association". It is useful only to differentiate tokens that could be received by the server implementing the jet protocol. See the Devolutions Gateway REST API authorization section to see all other tokens.

#### "jet_cm" (Jet Connection Mode) Claim

The "jet_cm" (jet connection mode) claim identifies the connection mode used for the Jet association.

| Value | Meaning |
| --- | --- |
| "rdv" | Rendezvous connection mode |
| "fwd" | Forward-only connection mode |

If this claim is absent from the JWT, the "rdv" (Rendezvous) connection mode SHOULD be assumed.

#### "jet_ct" (Jet Connection Test) Claim

The "jet_ct" (jet connection test) claim identifies the connection test used for the Jet candidates.

| Value | Meaning |
| --- | --- |
| "keep" | Keep connection open after test |
| "close" | Close connection after test |

If this claim is absent from the JWT, the "keep" connection test value SHOULD be assumed.

#### "jet_ap" (Jet Application Protocol) Claim

The "ap" (application protocol) claim identifies the application protocol used over the Jet transport. If the jet relay is configured for protocol inspection, it SHOULD enforce usage of the advertised protocol. The known protocol values are:

| Value | Meaning | Default Port |
| --- | --- | --- |
| "none" | Unidentified protocol | - |
| "rdp" | Microsoft Remote Desktop Protocol (RDP) | 3389 |
| "vnc" | Virtual Network Computing (VNC) protocol | 5900 |
| "ard" | Apple Remote Desktop (ARD) protocol | 5900 |
| "ssh" | Secure Shell (SSH) protocol | 22 |
| "sftp" | SSH file transfer protocol | 22 |
| "scp" | SSH secure copy protocol | 22 |
| "telnet" | Telnet protocol | 23 |
| "http" | HTTP protocol | 80 |
| "https" | Secure HTTP protocol | 443 |
| "ldap" | LDAP protocol | 389 |
| "ldaps" | Secure LDAP protocol | 636 |
| "pwsh-ssh" | PowerShell Remoting over SSH | 22 |
| "winrm-http-pwsh" | PowerShell Remoting (WinRM/HTTP) | 5985 |
| "winrm-https-pwsh" | PowerShell Remoting (WinRM/HTTPS) | 5986 |
| "wayk" | Wayk remote desktop (deprecated) | 4489 |

All protocols except "none" should be identifiable by the relay server. Usage of "none" indicates to the relay server that the protocol is not identified, and therefore not inspectable according to a known protocol.

#### "jet_rec" (Jet Recording Policy) Claim

The "jet_rec" (jet recording policy) claim indicates if the session should be recorded or not. It is a boolean so possible values are true/false. If this claim is absent from the JWT, false SHOULD be used as default. If the Jet relay is unable to comply with the requested recording policy, it MUST reject the connection. For instance, if session recording is requested but the Jet relay is unable to perform session recording, the connection MUST be rejected.

| Value | Meaning |
| --- | --- |
| "none" | no recording |
| "client" | client-based recording |
| "proxy" | proxy-based recording |

#### "dst_hst" (Destination Hostname) Claim

The "dst_hst" (destination hostname) claim indicates the destination or target server that the jet relay server should connect to. The "dst_hst" value is a destination host and port of the following format:

\<host\>:\<port\>

The "dst_hst" claim is meant to be used in forward-only connection modes, where a Jet client connects to a Jet relay, and the Jet relay connects to the destination server, similar to how a reverse proxy works, or how the Remote Desktop Gateway works. The "dst_hst" claim is not meant to be used in the rendezvous connection mode, where both the Jet client and Jet server connect to the Jet relay.

#### "dst_usr" (Destination Username) Claim

The "dst_usr" (destination username) claim is used to provide the username for the Jet relay destination. It is normally used with the "dst_hst" and "dst_pwd" claims in a forward-only connection.

#### "dst_pwd" (Destination Password) Claim

The "dst_pwd" (destination password) claim is used to provide the Jet relay with a sensitive password meant to connect to its destination. This claim SHOULD normally be used with the "dst_hst" claim in a forward-only connection.

### RDP Protocol

The RDP protocol can be adapted to work with a Jet relay server by injecting a Jet JWT inside the [RDP preconnection PDU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeps/28daaf3f-d796-41a9-ba9f-995466c268a6). This packet is sent pre-TLS in the regular RDP protocol, and the value can be set using the "pcb" .rdp file setting, making it possible to inject it inside a standard RDP client like mstsc. The RDP variant of the Jet protocol simply encodes the same information contained inside a Jet connect packet inside the RDP preconnection PDU.

## Protocol details

The following section explain the abstract data model of the JET protocol, along with a detailed explanation of the sequence of events for different scenarios.

### Abstract Data Model

This section provides definitions for abstract data model elements used in the JET protocol.

#### Association

An association uniquely represents the link between a client and a server, regardless of the underlying transport used. An association contains multiple candidates from which only one will be selected after a series of connectivity tests. Once a candidate is selected, the association is essentially the same as the selected candidate it contains, and the underlying transport can be passed to the application for usage as if it were a regular transport. An association is identified by a UUID string.

# Devolutions Gateway REST API

The Devolutions Gateway has a REST API used to create association and gather candidates as explained in previous section. But it also has other available API. The following sections document all API available on the Devolutions Gateway, but also document how to be authorized in those API.

## APIs

The following sections document existing routes on the Devolutions Gateway

### JET API (/jet)

All routes under "/jet" are explained in previous section. Please refer to that section for more information. To be authorized, the request has to contain a "session" token in the AUTHORIZATION header.

### Sessions API (/sessions)

The session API is used to get all sessions. A session is an association that has started to relay traffic between client and server on a specific candidate. To be authorized, the request has to contain a "scope" token in the AUTHORIZATION header with the scope "gateway.sessions.read".

### Bridge API (/bridge)

The bridge api is used to forward an HTTP request to a specific target. To be authorized, the reqest has to contain a "bridge" token in the AUTHORIZATION header.

### Health (/health)

The health api is used to get the health of the server.

## Authentication/Authorization

To be authorized, requests have to send a JWT. The following sections document all possible tokens.

### Association token

A session token is used to create association and gather candidates. Please refer to a previous section for more details.

| Field | Meaning | Values | Mandatory |
| --- | --- | --- | --- |
| type | Token type | "association" | Yes |
| jet_aid | Association ID | Uuid | Yes |
| jet_ap | Application Protocol | "rdp", "ssh", "vnc", … | Yes |
| jet_cm | Connection Mode | "fwd" or "rdv" | Yes |
| jet_rec | Recording Policy | true/false | No (default: none) |
| dst_hst | Destination Host | String value | No |
| dst_usr | Destination Username | String value | No |
| dst_pwd | Destination Password | String value | No |

### Scope token

A scope token is used to authorize requests to access different resources. The token specifies the scope allowed by the token and only that scope can be requested by the token. Otherwise, it will be forbidden.

| Field | Meaning | Values | Mandatory |
| --- | --- | --- | --- |
| type | Token type | "scope" | Yes |
| scope | Scope allowed by the token | "gateway.sessions.read", "gateway.association.read" | Yes |

### Bridge token

A bridge token is used to authorize requests to be forwarded to a specific target via the bridge API.

| Field | Meaning | Values | Mandatory |
| --- | --- | --- | --- |
| type | Token type | "bridge" | Yes |
| target | Target where the request should be forwarded | URL | Yes |
