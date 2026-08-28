# Intent

## Senarios
1. NTLM
    a. Preflight send a NTLM credential injection request to the Gateway
    b. RDP client will send association token with matching JTI in the credential injection request to Gateway.
    c. Gateway will correctly recognize this connetion is intended for credential injection
    d. RDP client will proceed with TLS + CredSSP
    e. Gateway will intercept the CredSSP and also create CredSSP request as client to RDP server.
    f. We assert on that the RDP server receives the target credentials while the RDP client only sends the proxy credentials


2. Kerberos
    a. Preflight send a Kerberos credential injection request to the Gateway including the KDC information.
    b. RDP client will send association token with matching JTI in the credential injection request to Gateway.
    c. Gateway will correctly recognize this connetion is intended for credential injection
    d. RDP client will proceed with TLS + CredSSP, here it will also call KDC Proxy (which is also Gateway)
    e. Gateway will intercept the CredSSP and also create CredSSP request as client to RDP server.
    f. Gateway will forward the Kerberos request to the KDC with state driven by the target credentials, and we will assert on that the KDC receives the correct request.
    g. We assert on that the RDP server receives the target credentials while the RDP client only sends the proxy credentials

3. Reconnect stability, make sure we could reconnect with the same association token.

4. Failure behavior
    a. Missing or expired provisioning fails at 1.c or 2.c and uses ordinary forwarding.
    b. An incorrect target password or unavailable KDC fails at 2.e and must not fall back to ordinary forwarding.
    c. Missing KDC information fails before 2.e and must not connect to the RDP server.

