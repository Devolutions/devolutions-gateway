## Overview

private-fs is a building block for files and directories that only the accounts a rule allows can access.
It exists so that the unsafe calls into the operating system's permission and ACL APIs live in one place, encapsulated, rather than being reimplemented by each crate that needs them.
It is meant for every crate in the workspace that keeps files from other accounts, such as the package broker, the agent's identity, the updater's files and the Gateway's secrets.
It covers files and directories only, not other objects the operating system secures, such as named pipes.

<a id="vocabulary"></a>
## Vocabulary

- **Rule**: what a caller asks for a file or directory: which accounts may own it, and which accounts may access it with which kind of access.
- **Check**: private-fs comparing an existing file or directory with a rule.
- **Repair**: bringing an existing file or directory into line with a rule.
- **Account**: a user, a group, or a built-in account such as root, SYSTEM or Administrators.
  *Avoid:* user, principal, trustee.
- **Owner**: the account that owns a file or directory, in the operating system's sense.
- **Access**: one kind of access: full, read and write, or add only.
  *Avoid:* permission, right, privilege and mode as general words; `mode` and DACL name only the platform mechanisms.
- **Supported**: whether a platform can enforce a kind of access.
- **Private**: a file or directory that satisfies its rule.
  *Avoid:* restricted, protected, secure, safe.
- **Handle**: an open, checked directory or file through which further operations on it happen.

*Avoid:* capability, which here could mean Linux capabilities, a handle, or what a platform supports; trusted account, which "an account the rule allows" says with the words above.

<a id="rules"></a>
## Rules

- Callers define the rules; private-fs checks, creates and repairs files and directories according to each caller's rule.
  private-fs knows the operating system's access control, and callers know their file formats, their locations and which accounts a rule allows.
- The checks live in private-fs rather than in each caller, because copies of one check drift.
- A rule names accounts, each with a kind of access.
  It names accounts rather than a kind of file, so that private-fs never knows its callers, and kinds of access rather than an exact mode or DACL, so that the knowledge of what each platform needs stays in private-fs.
- A caller writes one rule for every platform.
  Where a platform cannot enforce a kind of access, the rule says what to use instead, and private-fs never chooses a broader access on its own.
- Files and directories are created and opened through a handle checked against its rule, never by resolving a path again.

<a id="mechanisms"></a>
## Mechanisms

private-fs covers every mechanism through which another account can gain access to a file or directory, and a missing one is a defect:

- the owner and the permission bits;
- Linux ACLs and macOS ACLs;
- the Windows owner and DACL, inherited entries included;
- links and reparse points;
- volumes that ignore or fake ownership.

An administrator's override, such as root or the Windows backup and restore privileges, and security modules such as SELinux, which can only take access away, are outside it.

<a id="paths"></a>
## Creating, checking and repairing

- A new directory has exactly its caller's rule from the moment it exists.
- A directory that another process creates first counts as created only if it passes the rule.
- A directory whose files were reported written survives a power cut.
- private-fs refuses a link from the first existing directory of a path down, the part its caller controls.
- As OpenSSH's StrictModes does, private-fs checks the directories above that one on their resolved path, up to the root, and refuses the path when an account other than the system account, administrators and the accounts its rule allows can rename or replace one of them; being able to add an entry beside it does not count.
- A directory above whose permissions private-fs cannot read fails that check, because the account that owns it could otherwise hide it from the check.
- private-fs can bring an existing file or directory into line with a rule; each caller decides whether to repair or refuse.
