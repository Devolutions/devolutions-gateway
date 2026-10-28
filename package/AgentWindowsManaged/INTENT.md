## Data folder

- The installer gives `%ProgramData%\Devolutions\Agent` its owner and its permissions when it creates the folder, and resets both on every install, upgrade and repair, so that only SYSTEM and administrators can rename or replace what the agent stores there.
- An install, upgrade, repair or feature change fails before it changes anything, with an error in the installer's language naming the folder and the account at fault, when `%ProgramData%\Devolutions` or `%ProgramData%\Devolutions\Agent` is a link, can't be read, or has an owner other than SYSTEM, Administrators, TrustedInstaller or a member of Administrators, or when `%ProgramData%\Devolutions` lets another account rename or replace it or an entry of it.
  The installer refuses rather than repairs, because a folder another account controlled may hold entries that account left there, and it refuses the folders the agent refuses, so that a deployment never reports success for an agent that can't use its data folder.
  A full uninstall never refuses, so a machine can always be uninstalled.
- The installer never follows a link when it sets the security of a data folder, so that a link can't make it change the security of another folder.

## Agent Identity

- The token is passed as the `IDENTITY_ENROLLMENT_TOKEN` property, which is hidden so that it never appears in installer logs.
- The installer also reads the token from a file named by the `IDENTITY_ENROLLMENT_TOKEN_FILE` property, so that the token stays off msiexec's command line, which security tools and process auditing record and Intune shows in the app's install command.
  A relative path resolves against the installer's own folder, and the token is the file's first line.
  Setting both properties, or naming a missing file or one whose first line holds no token, fails the install, and the installer never deletes the file.
  Only a first install or a major upgrade reads the file.
- The MSI hands the token to `identity enroll -` running as SYSTEM.
  It never writes the pending-enrollment file itself and never enrolls by itself.
- Given a token, the MSI runs `identity enroll -` on a first install or a major upgrade, never on a repair, a maintenance change or an uninstall, and never without a token.
  If the command fails, for example on a malformed token, the install fails, so a deployment never reports success for a machine that cannot enroll; the install never waits for the authority, whose availability the service handles.
- Only a full uninstall deletes the `identity` folder of the agent's data directory, rejection markers included, and every device key with the agent's prefix, without contacting any authority.
  The uninstall never follows a link while it deletes that folder, so that a link can't make it delete files elsewhere.
  A reinstall therefore behaves like a freshly imaged device: after a revocation, the same still-valid token enrolls a new identity and uses up a token use.
  A failed cleanup never fails the uninstall, so a machine can always be uninstalled.
- A major upgrade keeps the identities and their keys.
