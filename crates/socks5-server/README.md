# SOCKS5, SOCKS5H proxy demonstration server

This crate provides a SOCKS5 server demonstrating server-side usage of `proxy-socks`.

## Testing

This server may be run using

```
$ cargo run -p socks5-server -- --port 1080 --no-auth-required
```

or

```
$ cargo run -p socks5-server -- --port 1080 --user username,password
```

`proxy-tester` may be used to test this server (only enable socks5 tests).

```
$ cargo run -p proxy-tester -- --mode socks5 --addr localhost:1080 [--user username,password]
```

Alternatively, you can configure your browser to use it ("Network Settings" menu in Firefox).
