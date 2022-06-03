# HTTP(S), SOCKS5 and SOCKS5H proxy demonstration server

This crate provides HTTP(S) and SOCKS5 proxy server demonstrating server-side usage of `proxy-http` and `proxy-socks` crates.

## Testing

This server may be run using

```
$ cargo run -p proxy-server -- --socks-port 1080 --no-auth-required --http-port 8080
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

Note that username/password authentication is not (yet) supported for HTTP(S) tunneling.
