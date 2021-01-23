# SOCKS4, SOCKS4a, SOCKS5, SOCKS5H, HTTPS implementation for jetsocat

## Testing

Offline tests can be performed using standard `cargo test` command.

Advanced tests are provided as additional binaries.
For these, a running proxy server is required with specific configurations.

### No authentication method testing

Setup a proxy server permitting all connections (no authentication required).
Using CCProxy all you need is to open `Account Manager` pop-up and set `Permit Category` to `Permit All`.

Let's assume proxy address for SOCKS is `192.168.122.70:1080`.

SOCKS tests are run by running

```
cargo run --bin socks_test -- --addr 192.168.122.70:1080
```

### Username/Password authentication method testing

Setup a proxy server permitting only connection with a valid username / password pair.
Using CCProxy, open `Account Manager` pop-up, set `Permit Category` to `Permit Only` and `Auth Type` to `User/Password`.
You also need to have a user account with a password. Make sure no other restriction are enabled (untick `IP Address/IP Range`, `MAC Address/Hostname`…).

Let's assume proxy address for SOCKS is `192.168.122.70:1080` and credential pair is `username`/`password`.

SOCKS tests are run by running

```
cargo run --bin socks_test -- --addr 192.168.122.70:1080 --pass username --pass password
```

