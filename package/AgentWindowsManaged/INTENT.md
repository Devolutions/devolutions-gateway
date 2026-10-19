## Agent Identity

- The token is passed as the `IDENTITY_ENROLLMENT_TOKEN` property, which is hidden so that it never appears in installer logs.
- The MSI hands the token to `identity enroll -` running as SYSTEM.
  It never writes the pending-enrollment file itself and never enrolls by itself.
- Uninstalling deletes the `identity` folder of the agent's data directory, rejection markers included, and every device key with the agent's prefix, without contacting any authority.
  A reinstall therefore behaves like a freshly imaged device: after a revocation, the same still-valid token enrolls a new identity and uses up a token use.
- A major upgrade keeps the identities and their keys.
