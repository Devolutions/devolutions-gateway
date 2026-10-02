# FIPS cryptographic dependency policy

The opt-in `fips` feature builds a reduced Devolutions Gateway profile whose production dependency graph uses `aws-lc-fips-sys` as its only cryptographic implementation.
The profile is available for Linux x86-64 and Windows x86-64.

Run the policy audit for each supported target:

```powershell
./ci/check-fips-crypto-dependencies.ps1 -Target x86_64-pc-windows-msvc
./ci/check-fips-crypto-dependencies.ps1 -Target x86_64-unknown-linux-gnu
```

The script reconstructs the isolated `fips-audit` lockfile, requires `aws-lc-fips-sys`, verifies that `ring` is absent, and runs Cargo-deny against production and build dependencies.
Each target's audit must pass before that target's artifact is uploaded.

## Cryptographic boundary

The approved boundary is `aws-lc-rs` with its `fips` feature and `aws-lc-fips-sys`.
The profile routes TLS, RS256 token verification, X.509 operations, SHA-2 hashing, AES-256-GCM credential encryption, and secure random generation through that boundary.

Gateway uses pinned Picky and IronRDP revisions that separate their standard cryptography from provider-backed or parser-only FIPS paths.
The vendored rustls 0.23.43 and rustls-webpki 0.103.13 patches preserve FIPS behavior while preventing Cargo from resolving the unused non-FIPS `aws-lc-sys` bindings.
Their manifest and build-script changes activate the AWS-LC modules only through `aws-lc-fips-sys`.

`deny-fips.toml` is the authoritative list, rejecting alternate TLS providers, legacy algorithms, and standalone implementations of algorithms the validated provider already supplies.

## Build and packaging requirements

Building `aws-lc-fips-sys` requires CMake, Go, Perl, NASM, a C compiler, and libclang for `bindgen` on the build host.
On Windows, run Cargo from a shell that has *not* already initialized a Visual Studio developer environment.
The build script invokes `vcvarsall.bat` itself.
Nesting that call inside an existing developer shell panics with `Failed to run vcvarsall.bat`.

On Windows, a FIPS build links against a shared cryptographic module so the provider can run its startup integrity self-test.
Cargo leaves `aws_lc_fips_<version>_crypto.dll` in `target/<target-triple>/<profile>/build/aws-lc-fips-sys-*/out/build/artifacts/` rather than next to the executable.
Packaging must copy it beside `devolutions-gateway.exe`, or the service fails to start with `STATUS_DLL_NOT_FOUND` (`0xc0000135`).
Linux x86-64 links the module statically and needs no extra file.

Before release, run each staged FIPS artifact with the build directory absent from `PATH` to confirm that the module is resolvable.
The dependency audit cannot detect a missing module.

## Reduced functionality

Cargo features are additive, so the FIPS artifact must be built with `--no-default-features --features fips`.
The profile compiles unavailable subsystems out instead of relying only on runtime checks.

The following functionality is unavailable:

- WebSocket relay and WebSocket-based RDP, JMUX, network scan, and recording routes.
- Tokens that require stream or proxy recording.
- Agent Tunnel and its QUIC listener.
- CredSSP credential injection, credential provisioning, NTLM, Kerberos, PKU2U, KDC proxying, and RDP credential interception.
- The standalone WebApp, ngrok, native plugins, and debug-only options.
- Token signing, JWE decryption, PKCS#12 files, and Windows system-certificate-store private keys.

Use PEM certificates and private keys for TLS, set `TlsVerifyStrict` to `true` explicitly, and use provisioner RSA keys between 2048 and 8192 bits.
Configuration validation rejects unsupported options with an explicit error.

## Compliance scope

A passing dependency audit proves that the selected Cargo graph excludes the denied implementations.
It does not certify a binary or deployment.

Before distributing an artifact as FIPS compliant, verify that the exact AWS-LC version, module certificate, target platform, compiler and linker inputs, build procedure, and operating environment satisfy the applicable [CMVP security policy][cmvp].
Archive the dependency report produced with the artifact as release evidence.

Do not add Cargo-deny skips, wrapper exemptions, or version-specific exceptions to make the audit pass.
Route cryptographic operations through the validated provider, or remove the dependency path from the FIPS profile.

[cmvp]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules
