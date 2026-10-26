use std::{fmt, io};

use camino::{Utf8Path, Utf8PathBuf};

use crate::{Access, Account};

/// A failed operation, and the path it failed on.
#[derive(Debug)]
pub struct Error {
    path: Utf8PathBuf,
    kind: ErrorKind,
}

#[derive(Debug)]
pub enum ErrorKind {
    /// An I/O step failed.
    Io { step: &'static str, source: io::Error },
    /// The file or directory at the path, or the directory above it at the path, breaks its rule.
    Refused(Refusal),
    /// The rule gives `account` an `access` that this platform cannot enforce, and states no fallback.
    Unsupported { account: Account, access: Access },
}

/// Why a file or directory breaks its rule.
#[derive(Debug)]
pub enum Refusal {
    /// It is a symbolic link, a Windows reparse point whose tag is a name surrogate, such as a junction, or a file with
    /// more than one hard link.
    Link,
    /// It is not a directory.
    NotADirectory,
    /// It is not a regular file, or, on Windows, it is a reparse point whose tag is not a name surrogate, such as a cloud
    /// placeholder, whose content private-fs can't vouch for.
    NotAFile,
    /// An account that the rule doesn't allow owns it.
    Owner,
    /// It gives an account more access than the rule does, or, under an exact rule, less.
    Access,
    /// Its volume ignores or fakes ownership, or doesn't keep access control lists.
    Volume,
    /// It is the first existing directory of the path or a directory above it, and an account other than the system
    /// account, administrators and the accounts the rule allows can rename or replace it.
    Replaceable,
    /// It is the first existing directory of the path or a directory above it, and its owner or access can't be read.
    Unreadable(io::Error),
}

impl Error {
    pub(crate) fn io(path: &Utf8Path, step: &'static str, source: io::Error) -> Self {
        Self {
            path: path.to_owned(),
            kind: ErrorKind::Io { step, source },
        }
    }

    pub(crate) fn refused(path: &Utf8Path, refusal: Refusal) -> Self {
        Self {
            path: path.to_owned(),
            kind: ErrorKind::Refused(refusal),
        }
    }

    pub(crate) fn unsupported(path: &Utf8Path, account: Account, access: Access) -> Self {
        Self {
            path: path.to_owned(),
            kind: ErrorKind::Unsupported { account, access },
        }
    }

    pub fn path(&self) -> &Utf8Path {
        &self.path
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Reports whether a file or directory at the path, or above it, breaks its rule.
    pub fn is_refused(&self) -> bool {
        matches!(self.kind, ErrorKind::Refused(_))
    }

    /// Reports whether an I/O step failed because a path doesn't exist.
    pub fn is_not_found(&self) -> bool {
        matches!(&self.kind, ErrorKind::Io { source, .. } if source.kind() == io::ErrorKind::NotFound)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::Io { step, .. } => write!(formatter, "{step} {}", self.path),
            ErrorKind::Refused(refusal) => {
                let reason = match refusal {
                    Refusal::Link => "is a link",
                    Refusal::NotADirectory => "is not a directory",
                    Refusal::NotAFile => "is not a regular file",
                    Refusal::Owner => "is owned by an account the rule doesn't allow",
                    Refusal::Access => "gives access the rule doesn't",
                    Refusal::Volume => "is on a volume that doesn't enforce ownership and access",
                    Refusal::Replaceable => "can be renamed or replaced by an account the rule doesn't allow",
                    Refusal::Unreadable(_) => "has an owner or access that can't be read",
                };
                write!(formatter, "{} {reason}", self.path)
            }
            ErrorKind::Unsupported { account, access } => write!(
                formatter,
                "{access:?} access for {account:?} is not supported here and the rule for {} states no fallback",
                self.path
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Io { source, .. } | ErrorKind::Refused(Refusal::Unreadable(source)) => Some(source),
            ErrorKind::Refused(_) | ErrorKind::Unsupported { .. } => None,
        }
    }
}
