## Overview

This crate keeps device key management out of the features that use it, and is not limited to one feature.
Its design leans on authenticating a device: it hides the private key and allows only a limited set of operations.
It decides nothing about what each key is for or where its files live.
Later, features that authenticate as the device, such as Agent Tunnel, are expected to use device keys instead of their own.

## Concepts

### Device key

A device key is a key associated with a device.
Device keys are ECDSA P-256 for now; other algorithms may come.
A device key gives its public key.
A device key must remain usable for TLS client authentication, so that features can authenticate the device over transports such as QUIC.

*Avoid:* "key" on its own, which is not specific enough.

### Key store

A key store is the place where device keys are kept.

### Backend

A backend is one implementation of a key store, named after the technology it uses.
The backends are listed under [Backends](#backends).

### Key name

A key name is a prefix, `_`, then a part the caller chooses.
Every caller passes a prefix; the crate has no default prefix and does not require the rest of the name to be random.
A prefix is 1 to 64 characters from `a`–`z`, `0`–`9` and `-`.
The part after `_` is 1 to 128 characters from `a`–`z`, `0`–`9`, `-` and `_`.
Names are lowercase because Windows and macOS file names ignore case and Linux file names do not.
The lengths keep every file name the file backend derives from a key name within the 255-character limit.
The crate offers no way to rename a key, because Windows keys can't be renamed.

## Private keys

Private keys are generated inside the backend; the crate offers no import.
The crate does not let the caller export a private key; how hard export is by other means depends on the backend.
Private key material never appears in logs.
Whenever a private key is held in memory, it is protected with `secure-memory` as a best effort; callers are not told how well a key is protected.

## Access

Only the caller's account and SYSTEM (root on Linux and macOS) can access a device key; this is the access rule.
Opening a key that any other account can access fails, so a key created by a less privileged account is refused when a more privileged service opens it.

## Operations

- Creating a key never replaces an existing one; if two callers create the same key at once, one of them fails, on every backend.
  With the Windows software provider, only the caller's account and SYSTEM can block the creation of a key.
- Opening a missing key reports that it is not there.
  Opening fails if the key breaks the access rule, is exportable, is a link, or uses an algorithm the crate does not support.
- Deleting is idempotent: deleting a key that is already gone succeeds.
- Listing under a prefix returns only well-formed names whose part before the first `_` equals that prefix, and never a link.
- No leftover copy of a private key survives a later operation in the same key store.
  Another process's work in progress is never taken for a leftover, and the crate removes only files whose names follow its scheme for keys and their temporary and deleted copies, never anything else in the key store; within the key store the caller chose, a name in that scheme counts as the crate's own, whatever its prefix.
- An unexpected entry in a key store never makes an operation panic, block, or read without bound: listing skips it, and any other operation skips it or fails promptly, because a key store can be shared with other software.
- Waiting for another process has a time limit; when it runs out, the operation fails.

## Signing

- Signing takes the message and, for P-256, returns the raw signature; producing DER is the caller's job.
- Signing can fail, and never panics.
- A backend may return different signatures for the same message.

## Backends

The backends are the Windows software provider, the file backend, and, later, TPM; adding a backend extends this list.
TPM-backed device keys are wanted later, and the code must stay easy to extend cleanly for them.
Later, once `picky-crypto` is published, device keys implement its private-key interface and the file backend uses it for cryptography.

A caller can name any backend on every platform, so it needs no platform-specific code.
A backend is built for every platform whose API supports it, whether or not the machine running it has the technology.
An unavailable backend returns an error that callers can tell apart from every other failure.
The crate never falls back to another backend, and never logs that error or raises a system event; reporting it is the caller's job.

### Windows software provider

"Machine key" is the Windows term for the mechanism behind this backend; it is allowed vocabulary and commits the backend to nothing.

### File backend

The file backend is a supported backend, not a test stand-in.
Its key files are PKCS#8.
On Unix, the directories it creates for keys are `0700`, so the access rule holds before the first key exists.
It needs only traverse permission on the ancestors of its key directory, not read permission, so a service can keep keys under a parent it cannot list.
Opening refuses a key file larger than 64 KiB without reading past that bound; a P-256 key file is about 140 bytes.
