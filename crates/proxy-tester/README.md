# SOCKS4, SOCKS4a, SOCKS5, SOCKS5H, HTTP(S) client-side proxy tester

Advanced tests for proxy are provided through this crate.
A running proxy server is required with specific configurations.

## No authentication method testing

Setup a proxy server permitting all connections (no authentication required).
Using CCProxy all you need is to open `Account Manager` pop-up and set `Permit Category` to `Permit All`.

Let's assume proxy address for SOCKS is `192.168.122.70:1080`.

SOCKS tests are run by running

```
$ cargo run -p proxy-tester -- --mode socks --addr 192.168.122.70:1080
```

HTTPS proxy tests are run by using

```
$ cargo run -p proxy-tester -- --mode https --addr 192.168.122.70:808
```

## Username/Password authentication method testing

Setup a proxy server permitting only connection with a valid username / password pair.
Using CCProxy, open `Account Manager` pop-up, set `Permit Category` to `Permit Only` and `Auth Type` to `User/Password`.
You also need to have a user account with a password. Make sure no other restriction are enabled (untick `IP Address/IP Range`, `MAC Address/Hostname`…).

Let's assume proxy address for SOCKS is `192.168.122.70:1080` and credential pair is `username`/`password`.

SOCKS tests are run by running

```
$ cargo run -p proxy-tester -- --mode socks --addr 192.168.122.70:1080 --user username,password
```
