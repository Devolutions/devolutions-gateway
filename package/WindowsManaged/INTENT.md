## Data folder

- The installer gives `%ProgramData%\Devolutions\Gateway` its owner and its permissions when it creates the folder, and resets both on every install, upgrade and repair, so that only SYSTEM, administrators and the service account can change what the Gateway stores there, and only SYSTEM and administrators can rename or replace it.
- An install, upgrade, repair or feature change fails before it changes anything, with an error in the installer's language naming the folder and the account at fault, when `%ProgramData%\Devolutions` or `%ProgramData%\Devolutions\Gateway` is a link, can't be read, or has an owner other than SYSTEM, Administrators, TrustedInstaller or a member of Administrators, or when `%ProgramData%\Devolutions` lets another account rename or replace it or an entry of it.
  The installer refuses rather than repairs, because a folder another account controlled may hold a configuration or keys that account left there, and the Gateway trusts what it finds in its data folder.
  A full uninstall never refuses, so a machine can always be uninstalled.
- The installer never follows a link when it sets the security of the data folder or of an entry in it, so that a link can't make it change the security of anything else.
