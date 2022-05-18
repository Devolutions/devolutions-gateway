# HTTPS tunneling, SOCKS5 and SOCKS5H proxy demonstration server

This crate provides HTTPS tunneling and SOCKS5 server demonstrating server-side usage of `proxy-https` and `proxy-socks`.

## Testing

This server may be run using

```
$ cargo run -p proxy-server -- --socks-port 1080 --no-auth-required --https-port 8080
```

or

```
$ cargo run -p proxy-server -- --socks-port 1080 --user username,password
```

`proxy-tester` may be used to test this server (only enable socks5 tests).

```
$ cargo run -p proxy-tester -- --mode socks5 --addr localhost:1080 [--user username,password]
```

Alternatively, you can configure your browser to use it ("Network Settings" menu in Firefox).

Note that username/password authentication is not (yet) supported for HTTPS tunneling.
