## Agent Identity

- The token is passed as the `IDENTITY_ENROLLMENT_TOKEN` property, which is hidden so that it never appears in installer logs.
- The MSI hands the token to `identity enroll -` running as SYSTEM.
  It never writes the pending-enrollment file itself and never enrolls by itself.
- Given a token, the MSI runs `identity enroll -` on a first install or a major upgrade, never on a repair, a maintenance change or an uninstall, and never without a token.
  If the command fails, for example on a malformed token, the install fails, so a deployment never reports success for a machine that cannot enroll; the install never waits for the authority, whose availability the service handles.
- Only a full uninstall deletes the `identity` folder of the agent's data directory, rejection markers included, and every device key with the agent's prefix, without contacting any authority.
  A reinstall therefore behaves like a freshly imaged device: after a revocation, the same still-valid token enrolls a new identity and uses up a token use.
  A failed cleanup never fails the uninstall, so a machine can always be uninstalled.
- A major upgrade keeps the identities and their keys.
