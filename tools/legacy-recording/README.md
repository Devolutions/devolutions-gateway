# Devolutions Legacy Recording Server Migration Tool

This PowerShell script transforms session recording files from the legacy Devolutions recording server to the Devolutions Gateway session recording format, allowing you to migrate without losing previous recordings. Once the files are converted to Devolutions Gateway, they'll need to be re-indexed from Devolutions Server such that they can be found in their new location for playback from Devolutions Gateway.

From an elevated PowerShell terminal, run `MigrateRecordings.ps1` with the legacy recording output path as parameter:

```powershell
PS > .\MigrateRecordings.ps1 -LegacyPath "C:\inetpub\recording\output"
Migrating recordings to 'C:\ProgramData\Devolutions\Gateway\recordings'
Migrating 7e05bf2d-c97b-44eb-b256-351b3e2ef1f0 (075503d9-d016-496e-b0aa-cab8b020ce2d)
Migrating 2115ab16-308c-4eb4-a871-73bc8fd69022 (0f366b0e-e09d-4f57-b290-779f46fb68fd)
Migrating 479930c5-705a-4051-9edf-bdc2748452a4 (39a7d0ec-339e-4086-8d73-fbf455e1038a)
Migrating 2e3d219b-48a3-432a-b214-f11b8ddaa32e (b3409164-078b-4013-b4f6-9a4663d3df98)
```

The `-RecordingsPath` can be used to override the default destination path, if Devolutions Gateway is configured to use a non-default location. You can also perform the migration on one machine to manually copy the files over to the Devolutions Gateway recordings path on a different machine.

A sample 'legacy.zip' file containing legacy recordings is saved here for reference for testing this script.
