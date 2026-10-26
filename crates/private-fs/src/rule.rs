/// An account a rule names.
///
/// | Account | Linux and macOS | Windows |
/// |---|---|---|
/// | [`Account::CurrentUser`] | the effective user ID | the user of the process token |
/// | [`Account::System`] | root | LocalSystem |
/// | [`Account::Administrators`] | root | BUILTIN\Administrators; as an owner, also any member of it |
///
/// On Linux and macOS, root can access everything whatever the rule says, so a grant to [`Account::System`] or
/// [`Account::Administrators`] needs nothing on disk there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Account {
    CurrentUser,
    System,
    Administrators,
}

/// A kind of access.
///
/// | Access | Linux and macOS | Windows |
/// |---|---|---|
/// | [`Access::Full`] | supported | supported |
/// | [`Access::ReadWrite`] | supported for root only | supported |
/// | [`Access::AddOnly`] | supported for root only | supported on directories |
///
/// The owner of a file or directory on Linux and macOS can always change its mode, so it always has full access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Every operation, including changing the owner or who has access.
    Full,
    /// Reading, writing and deleting, but not changing the owner or who has access.
    ReadWrite,
    /// Adding entries to a directory, without listing, reading or removing them.
    AddOnly,
}

/// What a rule uses instead of an access that a platform cannot enforce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    Access(Access),
    NoAccess,
}

/// Which accounts may own a file or directory, and which accounts may access it with which kind of access.
///
/// A rule is written once for every platform.
/// Where a platform cannot enforce a grant, the grant's fallback applies; without one, every operation using the rule
/// fails with [`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported), because private-fs never chooses a broader
/// access on its own.
#[derive(Clone, Debug, Default)]
pub struct Rule {
    pub(crate) owners: Vec<Account>,
    pub(crate) grants: Vec<Grant>,
    pub(crate) owner_fallback: Option<Fallback>,
    pub(crate) exact: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Grant {
    pub(crate) account: Account,
    pub(crate) access: Access,
    pub(crate) fallback: Option<Fallback>,
}

impl Rule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allows `account` to own what the rule covers.
    ///
    /// private-fs creates files and directories owned by [`Account::CurrentUser`], so a rule used to create must allow it.
    #[must_use]
    pub fn owner(mut self, account: Account) -> Self {
        self.owners.push(account);
        self
    }

    /// Gives `account` `access`.
    #[must_use]
    pub fn grant(mut self, account: Account, access: Access) -> Self {
        self.grants.push(Grant {
            account,
            access,
            fallback: None,
        });
        self
    }

    /// Gives `account` `access`, or `fallback` where the platform does not support `access` for `account`.
    #[must_use]
    pub fn grant_or(mut self, account: Account, access: Access, fallback: Fallback) -> Self {
        self.grants.push(Grant {
            account,
            access,
            fallback: Some(fallback),
        });
        self
    }

    /// Sets what an owner that the rule gives less than full access keeps where the platform cannot take an owner's
    /// access away, as on Linux and macOS.
    #[must_use]
    pub fn owner_fallback(mut self, fallback: Fallback) -> Self {
        self.owner_fallback = Some(fallback);
        self
    }

    /// Makes a check also fail when a file or directory gives an account less than the rule does.
    ///
    /// By default a check fails only when a file or directory gives an account more than the rule does.
    /// On Linux and macOS an exact check also requires the mode the rule maps to, `0700` for a directory and `0600` for a
    /// file, ignoring the setuid, setgid and sticky bits, so a repair resets an owner's narrowed mode.
    #[must_use]
    pub fn exact(mut self) -> Self {
        self.exact = true;
        self
    }

    /// Returns every account the rule names, as an owner or in a grant.
    pub(crate) fn accounts(&self) -> impl Iterator<Item = Account> + '_ {
        self.owners
            .iter()
            .copied()
            .chain(self.grants.iter().map(|grant| grant.account))
    }
}
