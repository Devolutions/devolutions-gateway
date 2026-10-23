# Secret store

<a id="secrets"></a>
## Secrets

A secret is any data that could grant access to a third-party service, such as an API key and the URL it is used with.
A secret is never persisted.
A secret is not accessible through swap or a core dump: either it is never in swap or a core dump itself, or it is encrypted with a key that never is, as a chain of trust.
On a best-effort basis, a secret, in plain text or encrypted, is zeroed as soon as it is no longer used: when it is removed, or when it reaches its expiry, without waiting for a read.
All of this is best effort, as if someone has root access and we still try our best to keep the secret away from them; a secret is in plain text while it is used, such as when it is sent in an HTTP request.

<a id="replacement"></a>
## Replacement

Storing a secret under an ID that already has one replaces the old one.
