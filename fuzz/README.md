# Devolutions Gateway crates fuzzing

LLVM's `libFuzzer` and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) is used for fuzzing.
`cargo-fuzz` is installed using the following command:

```
$ cargo install --force cargo-fuzz
```

## JMUX fuzzing

JMUX protocol implementation is fuzzed using the `jmux_message` target.

## JET fuzzing

Jet protocol implementation is fuzzed using the `jet_message` target.

## Devolutions Gateway fuzzing

Devolutions Gateway is fuzzed through several fuzz targets.

#### `listeners_raw` target

This target is used to fuzz the listeners by sending random bytes in the stream.

#### `rdp_tls_sequence` target (TODO)

This target is used to fuzz the RDP-TLS connection sequence.
