# Agent policy format migration

Upgrade with the Windows MSI to migrate an eligible legacy JSON policy from `%ProgramData%\Devolutions\Agent\package-broker-policy.json` to managed PackageBroker storage.
The installer retains the source through a no-follow handle, checks its owner and write permissions, and converts it before publication.
Unsafe paths, untrusted sources and YAML/YML files remain untouched and require administrator remediation.
An existing managed policy is never overwritten, including one that appears during migration.

Conversion accepts only the old committed-document shape: `$schema` must equal `https://devolutions.net/schemas/now-policy.schema.1.0.json`, and `PolicyVersion` must be a canonical, supported `1.minor.patch` version.
It removes `$schema` and renames `PolicyVersion` to `PolicyFormatVersion`, preserving the version rather than relabeling a compatible document as `1.0.0`.
All other JSON values retain their raw representation, including policy identity, publisher, revision, timestamps, validity, rules and order.
Mixed identities, duplicate or unknown fields, malformed JSON and unsupported versions fail conversion.
The official new-contract parser and the broker's committed-policy validator must both accept the result; failure aborts migration and preserves the source.
The ordinary broker reader does not accept either legacy identity field.

## Recovery and downgrade

For a converted policy, the installer keeps the legacy source and a protected `.legacy-policy-migration-<install-id>.marker.original` backup in `%ProgramData%\Devolutions\PackageBroker`.
Its protected marker records the source identity, SHA-256 digest and security descriptor, backup identity, converted-file identity and digest, and migration-owned managed-authority identity.
Neither commit nor rollback deletes the original backup.
The backup is recovery evidence, not an active policy.

Rollback removes only the unchanged migration-owned destination and authority marker, after verifying the retained legacy source and backup.
This restores legacy-path selection for an older Agent without leaving a new-format policy that it cannot parse.
Changed files, replacement authority markers and unverifiable evidence are preserved for manual recovery instead of being overwritten or deleted.
A repeated invocation leaves an existing destination alone; an interrupted invocation with the same install ID can undo its owned authority marker and retry.
An incomplete backup or marker, an unrelated managed-authority marker, or a different transaction's evidence requires manual recovery.
Do not remove the last verified original or a runtime authority marker merely to make installation succeed.

Before a later downgrade, stop the Agent and archive the active managed policy and recovery evidence.
The preserved legacy policy represents the state at migration, not subsequent policy edits.
Have an administrator verify that policy before restoring an old Agent, and resolve managed-path selection explicitly; retaining the backup does not automatically reverse later policy changes.

## Portable, manual and import installations

These entry points do not perform MSI migration.
A legacy document remains **Invalid**, not Missing and not a default policy; requests containing legacy identity fields are rejected.
An explicitly configured legacy `PackageBroker.PolicyPath` also remains Invalid until the administrator changes the configured document or selects the validated managed policy.

Preserve the original bytes and permissions before remediation.
On a trusted local copy, verify the canonical old schema and compatible version, remove `$schema`, and rename `PolicyVersion` without changing metadata or rules.
Use the official contract and broker validation to check the result before replacing an active policy through its supported administrative workflow.
Do not use a parser that discards duplicate keys, silently drops unknown fields or substitutes defaults.
The internal `installer-policy-convert` Agent command accepts JSON on stdin and emits validated JSON on stdout, but does not establish source trust or publish files; it is not a general import or automatic recovery API.
YAML/YML needs a separate administrator-reviewed conversion to strict JSON.
