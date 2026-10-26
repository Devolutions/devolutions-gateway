//! Accounts, the DACL a rule maps to, and the checks of owners and DACLs.

use std::io;
use std::mem::offset_of;
use std::os::windows::io::BorrowedHandle;

use camino::Utf8Path;
use win_api_wrappers::identity::sid::{Sid, StringSid};
use win_api_wrappers::security::descriptor::SecurityDescriptor;
use win_api_wrappers::token::Token;
use windows::Win32::Foundation::{GENERIC_ALL, LUID};
use windows::Win32::Security::Authorization::{
    AUTHZ_CLIENT_CONTEXT_HANDLE, AUTHZ_RESOURCE_MANAGER_HANDLE, AUTHZ_RM_FLAG_NO_AUDIT, AuthzContextInfoGroupsSids,
    AuthzFreeContext, AuthzFreeResourceManager, AuthzGetInformationFromContext, AuthzInitializeContextFromSid,
    AuthzInitializeResourceManager, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    self, ACCESS_ALLOWED_ACE, ACE_FLAGS, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
    GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, INHERIT_ONLY_ACE, InitializeAcl,
    InitializeSecurityDescriptor, NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    SetSecurityDescriptorOwner,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ALL_ACCESS, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
};
use windows::core::{BOOL, PCWSTR};

use super::nt::{raw, win32_error};
use crate::rule::Grant;
use crate::{Access, Account, Error, Fallback, Refusal, Result, Rule};

/// NT SERVICE\TrustedInstaller, which owns `C:\` and the system directories.
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// The SIDs the accounts of a rule, and the other accounts private-fs knows, map to.
pub(super) struct Accounts {
    /// The user of the process token, not its default owner, which is BUILTIN\Administrators for an elevated
    /// administrator.
    pub(super) user: Sid,
    system: Sid,
    administrators: Sid,
    owner_rights: Sid,
    trusted_installer: Sid,
}

impl Accounts {
    pub(super) fn current() -> io::Result<Self> {
        let well_known = |kind| Sid::from_well_known(kind, None).map_err(io::Error::other);
        let trusted_installer = StringSid::from_str(TRUSTED_INSTALLER)
            .map_err(io::Error::other)?
            .to_sid()
            .map_err(io::Error::other)?;
        Ok(Self {
            // The pseudo-handle of the process token, so that a thread impersonating, as under `BackupPrivilege`,
            // still maps CurrentUser to the process's user.
            user: Token::current_process_token()
                .sid_and_attributes()
                .map_err(io::Error::other)?
                .sid,
            system: well_known(Security::WinLocalSystemSid)?,
            administrators: well_known(Security::WinBuiltinAdministratorsSid)?,
            owner_rights: well_known(Security::WinCreatorOwnerRightsSid)?,
            trusted_installer,
        })
    }

    fn sid(&self, account: Account) -> &Sid {
        match account {
            Account::CurrentUser => &self.user,
            Account::System => &self.system,
            Account::Administrators => &self.administrators,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Directory,
    File,
}

/// One allow entry of a DACL: its SID, access mask and ACE flags.
pub(super) type Entry = (Sid, u32, u8);

/// A rule mapped to SIDs and access masks for one kind of item.
pub(super) struct Policy {
    pub(super) accounts: Accounts,
    kind: Kind,
    exact: bool,
    /// One grant per SID: several accounts can map to one SID, as CurrentUser and System do for LocalSystem.
    grants: Vec<(Sid, Access)>,
    owners: Vec<Sid>,
    /// Whether an owner that is a member of BUILTIN\Administrators is allowed.
    administrator_members_own: bool,
    /// The SIDs of every account the rule names, which the ancestor check allows besides the system accounts.
    rule_sids: Vec<Sid>,
}

impl Policy {
    /// Maps `rule` for an item of `kind`, applying the fallback of each grant this platform cannot enforce.
    pub(super) fn new(rule: &Rule, kind: Kind, path: &Utf8Path) -> Result<Self> {
        let accounts = Accounts::current().map_err(|error| Error::io(path, "read accounts", error))?;
        let mut grants: Vec<(Sid, Access)> = Vec::new();
        for grant in &rule.grants {
            let Some(access) = effective_access(grant, kind, path)? else {
                continue;
            };
            let sid = accounts.sid(grant.account);
            match grants.iter_mut().find(|(existing, _)| existing == sid) {
                Some((_, merged)) => *merged = union(*merged, access),
                None => grants.push((sid.clone(), access)),
            }
        }
        let mut owners: Vec<Sid> = Vec::new();
        for owner in &rule.owners {
            let sid = accounts.sid(*owner);
            if !owners.contains(sid) {
                owners.push(sid.clone());
            }
        }
        let rule_sids = rule.accounts().map(|account| accounts.sid(account).clone()).collect();
        Ok(Self {
            kind,
            exact: rule.exact,
            grants,
            owners,
            administrator_members_own: rule.owners.contains(&Account::Administrators),
            rule_sids,
            accounts,
        })
    }

    /// Returns this policy with an exact check.
    pub(super) fn exact(mut self) -> Self {
        self.exact = true;
        self
    }

    /// Reports whether the rule allows the current user to own what it covers, as creation requires.
    pub(super) fn allows_user_owner(&self) -> bool {
        self.owners.contains(&self.accounts.user)
    }

    fn access_of(&self, sid: &Sid) -> Option<Access> {
        self.grants
            .iter()
            .find(|(granted, _)| granted == sid)
            .map(|(_, access)| *access)
    }

    /// Returns the canonical entries of the rule: one per SID, with its mask and inheritance.
    fn entries(&self) -> Vec<Entry> {
        self.grants
            .iter()
            .map(|(sid, access)| (sid.clone(), mask(*access, self.kind), inheritance(*access, self.kind)))
            .collect()
    }

    /// Returns the mask of the OWNER RIGHTS entry for `owner`: exactly the access the rule gives the owner, so that the
    /// owner keeps no implicit access beyond it.
    fn owner_rights_mask(&self, owner: &Sid) -> u32 {
        self.access_of(owner).map_or(0, |access| mask(access, self.kind))
    }

    /// Returns the DACL entries that private-fs writes when `owner` owns the item: the canonical entries, and an OWNER
    /// RIGHTS entry when the rule gives the owner less than full access.
    pub(super) fn dacl(&self, owner: &Sid) -> Vec<Entry> {
        let mut entries = self.entries();
        if self.access_of(owner) != Some(Access::Full) {
            entries.push((self.accounts.owner_rights.clone(), self.owner_rights_mask(owner), 0));
        }
        entries
    }

    /// Reports whether the rule allows `owner` to own the item.
    pub(super) fn owner_allowed(&self, owner: &Sid, path: &Utf8Path, membership: &Membership<'_>) -> Result<bool> {
        if self.owners.contains(owner) {
            return Ok(true);
        }
        if !self.administrator_members_own {
            return Ok(false);
        }
        membership(owner).map_err(|error| Error::io(path, "check administrators membership", error))
    }

    /// Checks the owner and DACL of an item against the rule.
    pub(super) fn check(&self, security: &OwnerAndDacl, path: &Utf8Path, membership: &Membership<'_>) -> Result<()> {
        let refused = |refusal| Error::refused(path, refusal);
        let owner = security.owner.as_ref().ok_or_else(|| refused(Refusal::Owner))?;
        if !self.owner_allowed(owner, path, membership)? {
            return Err(refused(Refusal::Owner));
        }
        // A missing or NULL DACL grants everyone full access, and an unprotected one takes inherited entries.
        let Some(dacl) = security.dacl.as_ref().filter(|_| security.protected) else {
            return Err(refused(Refusal::Access));
        };
        let allowed_flags = match self.kind {
            Kind::Directory => {
                (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE).0
            }
            Kind::File => 0,
        };
        let owner_access = self.access_of(owner);
        let owner_rights_mask = self.owner_rights_mask(owner);
        let mut owner_rights = Vec::new();
        let mut others = Vec::new();
        for ace in dacl {
            let sid = match (&ace.sid, u32::from(ace.kind)) {
                (Some(sid), ACCESS_ALLOWED_ACE_TYPE) => sid,
                _ => return Err(refused(Refusal::Access)),
            };
            if u32::from(ace.flags) & !allowed_flags != 0 {
                return Err(refused(Refusal::Access));
            }
            let granted = if *sid == self.accounts.owner_rights {
                owner_rights.push((ace.mask, ace.flags));
                owner_rights_mask
            } else {
                others.push((sid.clone(), ace.mask, ace.flags));
                self.access_of(sid)
                    .map(|access| mask(access, self.kind))
                    .ok_or_else(|| refused(Refusal::Access))?
            };
            if ace.mask & !granted != 0 {
                return Err(refused(Refusal::Access));
            }
        }
        // Without an OWNER RIGHTS entry that applies to the item itself, the owner keeps READ_CONTROL and WRITE_DAC,
        // and through WRITE_DAC any access.
        let applies_to_item = |(_, flags): &(u32, u8)| u32::from(*flags) & INHERIT_ONLY_ACE.0 == 0;
        if owner_access != Some(Access::Full) && !owner_rights.iter().any(applies_to_item) {
            return Err(refused(Refusal::Access));
        }
        if self.exact {
            let mut expected = self.entries();
            expected.sort();
            others.sort();
            let owner_rights_exact = match owner_rights.as_slice() {
                [] => true,
                [(mask, flags)] => *mask == owner_rights_mask && *flags == 0,
                _ => false,
            };
            if others != expected || !owner_rights_exact {
                return Err(refused(Refusal::Access));
            }
        }
        Ok(())
    }

    /// Checks a directory above the item: its owner is the system account, administrators or an account of the rule,
    /// and no other account can rename or replace it or an entry of it.
    pub(super) fn check_ancestor(
        &self,
        security: &OwnerAndDacl,
        path: &Utf8Path,
        is_volume_root: bool,
        membership: &Membership<'_>,
    ) -> Result<()> {
        let accounts = &self.accounts;
        let allowed = |sid: &Sid| {
            [
                &accounts.system,
                &accounts.administrators,
                &accounts.trusted_installer,
                // OWNER RIGHTS applies to the owner, which this check requires to be allowed.
                &accounts.owner_rights,
            ]
            .contains(&sid)
                || self.rule_sids.contains(sid)
        };
        let Some(owner) = &security.owner else {
            return Err(Error::refused(
                path,
                Refusal::Unreadable(io::Error::new(io::ErrorKind::InvalidData, "the directory has no owner")),
            ));
        };
        if !allowed(owner)
            && !membership(owner).map_err(|error| Error::io(path, "check administrators membership", error))?
        {
            return Err(Error::refused(path, Refusal::Replaceable));
        }
        // A missing or NULL DACL grants everyone full access.
        let Some(dacl) = &security.dacl else {
            return Err(Error::refused(path, Refusal::Replaceable));
        };
        let mut replacing = WRITE_DAC.0 | WRITE_OWNER.0 | FILE_DELETE_CHILD.0 | GENERIC_ALL.0;
        // Nobody can delete or rename the root of a volume.
        if !is_volume_root {
            replacing |= DELETE.0;
        }
        for ace in dacl {
            match u32::from(ace.kind) {
                // Deny entries only take access away.
                ACCESS_DENIED_ACE_TYPE
                | ACCESS_DENIED_CALLBACK_ACE_TYPE
                | ACCESS_DENIED_OBJECT_ACE_TYPE
                | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => continue,
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {}
                _ => {
                    return Err(Error::refused(
                        path,
                        Refusal::Unreadable(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the directory has an access control entry of an unknown type",
                        )),
                    ));
                }
            }
            if u32::from(ace.flags) & INHERIT_ONLY_ACE.0 != 0 {
                continue;
            }
            let Some(sid) = &ace.sid else {
                return Err(Error::refused(path, Refusal::Replaceable));
            };
            if !allowed(sid) && !is_app_container(sid) && ace.mask & replacing != 0 {
                return Err(Error::refused(path, Refusal::Replaceable));
            }
        }
        Ok(())
    }
}

/// Reports whether `sid` is an AppContainer package SID (S-1-15-2-...) or capability SID (S-1-15-3-...).
///
/// An entry for one never grants access by itself: Windows grants an AppContainer process only the access that both
/// its user and groups, and its package and capabilities, are granted, and other processes don't hold these SIDs, as
/// Microsoft Learn "Launch an AppContainer" states in "AppContainer overview".
/// Windows puts such entries on user profile directories, such as `AppData\Local`.
fn is_app_container(sid: &Sid) -> bool {
    // SECURITY_APP_PACKAGE_AUTHORITY.
    const APP_PACKAGE_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 15];
    // SECURITY_APP_PACKAGE_BASE_RID and SECURITY_CAPABILITY_BASE_RID.
    const BASE_RIDS: [u32; 2] = [2, 3];
    sid.identifier_authority().Value == APP_PACKAGE_AUTHORITY
        && sid.sub_authorities().first().is_some_and(|rid| BASE_RIDS.contains(rid))
}

/// Reports whether an account is a member of BUILTIN\Administrators; injectable so that tests can decide it.
pub(super) type Membership<'a> = dyn Fn(&Sid) -> io::Result<bool> + 'a;

/// Returns the access a grant gives on an item of `kind` here, after its fallback, or `None` when it gives none.
fn effective_access(grant: &Grant, kind: Kind, path: &Utf8Path) -> Result<Option<Access>> {
    if supported(grant.access, kind) {
        return Ok(Some(grant.access));
    }
    match grant.fallback {
        None => Err(Error::unsupported(path, grant.account, grant.access)),
        Some(Fallback::NoAccess) => Ok(None),
        Some(Fallback::Access(access)) if supported(access, kind) => Ok(Some(access)),
        Some(Fallback::Access(access)) => Err(Error::unsupported(path, grant.account, access)),
    }
}

/// Reports whether Windows can enforce `access` on an item of `kind`: add-only access is a directory's.
fn supported(access: Access, kind: Kind) -> bool {
    !(access == Access::AddOnly && kind == Kind::File)
}

/// Returns the union of two kinds of access, whose masks nest: add-only within read and write within full.
fn union(left: Access, right: Access) -> Access {
    let rank = |access| match access {
        Access::AddOnly => 0,
        Access::ReadWrite => 1,
        Access::Full => 2,
    };
    if rank(left) < rank(right) { right } else { left }
}

pub(super) fn mask(access: Access, kind: Kind) -> u32 {
    match (access, kind) {
        (Access::Full, _) => FILE_ALL_ACCESS.0,
        (Access::ReadWrite, Kind::File) => (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE).0,
        (Access::ReadWrite, Kind::Directory) => {
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD).0
        }
        (Access::AddOnly, _) => (FILE_ADD_FILE | SYNCHRONIZE).0,
    }
}

/// Returns the ACE flags of a grant: full and read-write entries of a directory are inherited by what it holds.
fn inheritance(access: Access, kind: Kind) -> u8 {
    match (access, kind) {
        (Access::Full | Access::ReadWrite, Kind::Directory) => {
            u8::try_from((CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE).0).expect("ACE flags are one byte")
        }
        (Access::AddOnly, _) | (_, Kind::File) => 0,
    }
}

/// One entry of a DACL as read from a security descriptor.
#[derive(Debug)]
pub(super) struct Ace {
    kind: u8,
    flags: u8,
    mask: u32,
    /// The SID of an access-allowed or access-denied entry, `None` for an entry of another type.
    sid: Option<Sid>,
}

/// The owner and DACL of an item.
#[derive(Debug)]
pub(super) struct OwnerAndDacl {
    owner: Option<Sid>,
    protected: bool,
    /// `None` for a missing or NULL DACL.
    dacl: Option<Vec<Ace>>,
}

impl OwnerAndDacl {
    pub(super) fn owner(&self) -> Option<&Sid> {
        self.owner.as_ref()
    }

    /// Reads the owner and DACL of the item `handle` refers to, which needs `READ_CONTROL`.
    pub(super) fn of_handle(handle: BorrowedHandle<'_>) -> io::Result<Self> {
        let descriptor = SecurityDescriptor::of_handle(raw(handle), SE_FILE_OBJECT).map_err(win32_error)?;
        // SAFETY: The descriptor stays live through the call.
        unsafe { Self::parse(descriptor.as_raw()) }
    }

    /// # Safety
    ///
    /// `descriptor` points to a valid security descriptor that stays live through the call.
    pub(super) unsafe fn parse(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<Self> {
        // SAFETY: Per the function's contract, the descriptor is valid and live.
        let owner = unsafe { SecurityDescriptor::from_raw(descriptor) }
            .owner()
            .map_err(io::Error::other)?;
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: The descriptor is live and both outputs are writable.
        unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) }
            .map_err(win32_error)?;
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: The descriptor is live and every output is writable.
        unsafe { GetSecurityDescriptorDacl(descriptor, &raw mut present, &raw mut acl, &raw mut defaulted) }
            .map_err(win32_error)?;
        let dacl = if present.as_bool() && !acl.is_null() {
            // SAFETY: GetSecurityDescriptorDacl returned an ACL within the live descriptor.
            Some(unsafe { read_acl(acl) }?)
        } else {
            None
        };
        Ok(Self {
            owner,
            protected: control & SE_DACL_PROTECTED.0 != 0,
            dacl,
        })
    }
}

/// # Safety
///
/// `acl` points to a valid ACL that stays live through the call.
unsafe fn read_acl(acl: *mut ACL) -> io::Result<Vec<Ace>> {
    // SAFETY: Per the function's contract, the ACL is valid.
    let count = unsafe { (*acl).AceCount };
    let mut entries = Vec::with_capacity(usize::from(count));
    for index in 0..u32::from(count) {
        let mut pointer = std::ptr::null_mut();
        // SAFETY: The ACL is valid, the index is less than its entry count, and the output is writable.
        unsafe { GetAce(acl, index, &raw mut pointer) }.map_err(win32_error)?;
        if pointer.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid access control entry",
            ));
        }
        // SAFETY: GetAce returned an entry within the ACL, which starts with an ACE_HEADER.
        let header = unsafe { pointer.cast::<ACE_HEADER>().read_unaligned() };
        let has_sid = matches!(
            u32::from(header.AceType),
            ACCESS_ALLOWED_ACE_TYPE
                | ACCESS_DENIED_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | ACCESS_DENIED_CALLBACK_ACE_TYPE
        );
        let (mask, sid) = if has_sid {
            // These four types share the layout of ACCESS_ALLOWED_ACE: the header, the mask, then the SID.
            let too_short = || io::Error::new(io::ErrorKind::InvalidData, "access control entry too short");
            let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            let ace_size = usize::from(header.AceSize);
            let count_offset = sid_offset + 1 /* Revision */;
            if ace_size < count_offset + 1
            /* SubAuthorityCount */
            {
                return Err(too_short());
            }
            let count_pointer = pointer.cast::<u8>().wrapping_add(count_offset);
            // SAFETY: The entry is at least as long as the byte read, per its size checked above.
            let sub_authority_count = usize::from(unsafe { count_pointer.read() });
            if ace_size < sid_offset + sid_size(sub_authority_count) {
                return Err(too_short());
            }
            let mask_pointer = pointer.cast::<u8>().wrapping_add(offset_of!(ACCESS_ALLOWED_ACE, Mask));
            // SAFETY: The entry is at least as long as the fields read, per its sizes checked above.
            let mask = unsafe { mask_pointer.cast::<u32>().read_unaligned() };
            let sid_start = pointer
                .cast::<u8>()
                .wrapping_add(offset_of!(ACCESS_ALLOWED_ACE, SidStart));
            // SAFETY: The entry holds a whole SID starting at SidStart, per the size checked above.
            let sid = unsafe { Sid::from_psid(Security::PSID(sid_start.cast())) }.map_err(io::Error::other)?;
            (mask, Some(sid))
        } else {
            (0, None)
        };
        entries.push(Ace {
            kind: header.AceType,
            flags: header.AceFlags,
            mask,
            sid,
        });
    }
    Ok(entries)
}

/// Returns the size of a SID with `sub_authority_count` subauthorities, per [MS-DTYP] §2.4.2.2 SID.
fn sid_size(sub_authority_count: usize) -> usize {
    let header = 1 /* Revision */ + 1 /* SubAuthorityCount */ + 6 /* IdentifierAuthority */;
    header + 4 /* SubAuthority */ * sub_authority_count
}

/// An absolute security descriptor with an owner and a protected DACL, for creating an item or setting its
/// security.
pub(super) struct Descriptor {
    descriptor: Box<SECURITY_DESCRIPTOR>,
    // INVARIANT: The descriptor points into these buffers, so they live as long as it does and never move.
    _acl: Vec<u64>,
    _owner: Sid,
}

impl Descriptor {
    pub(super) fn new(owner: &Sid, entries: &[Entry]) -> io::Result<Self> {
        let too_large = || io::Error::new(io::ErrorKind::InvalidInput, "the access control list is too large");
        // An entry is its header and mask, then its SID.
        let size = entries.iter().try_fold(8 /* ACL header */, |size: usize, (sid, _, _)| {
            size.checked_add(offset_of!(ACCESS_ALLOWED_ACE, SidStart) + sid_size(sid.sub_authorities().len()))
        });
        // The ACL size is a 16-bit field.
        let size = size.and_then(|size| u16::try_from(size).ok()).ok_or_else(too_large)?;
        // A u64 buffer is aligned for an ACL, which needs 4-byte alignment.
        let mut acl = vec![0u64; usize::from(size).div_ceil(size_of::<u64>())];
        let acl_pointer = acl.as_mut_ptr().cast::<ACL>();
        // SAFETY: The buffer is aligned and writable for `size` bytes.
        unsafe { InitializeAcl(acl_pointer, u32::from(size), ACL_REVISION) }.map_err(win32_error)?;
        for (sid, mask, flags) in entries {
            // SAFETY: The ACL is initialized with room for every entry, and the SID is valid and live.
            unsafe {
                AddAccessAllowedAceEx(
                    acl_pointer,
                    ACL_REVISION,
                    ACE_FLAGS(u32::from(*flags)),
                    *mask,
                    sid.as_psid_const(),
                )
            }
            .map_err(win32_error)?;
        }
        let owner = owner.clone();
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let pointer = PSECURITY_DESCRIPTOR((&raw mut *descriptor).cast());
        // SAFETY: The descriptor is writable.
        unsafe { InitializeSecurityDescriptor(pointer, SECURITY_DESCRIPTOR_REVISION) }.map_err(win32_error)?;
        // SAFETY: The descriptor is initialized, and the owner SID is valid and lives as long as the descriptor.
        unsafe { SetSecurityDescriptorOwner(pointer, Some(owner.as_psid_const()), false) }.map_err(win32_error)?;
        // SAFETY: The descriptor is initialized, and the ACL is valid and lives as long as the descriptor.
        unsafe { SetSecurityDescriptorDacl(pointer, true, Some(acl_pointer.cast_const()), false) }
            .map_err(win32_error)?;
        // A protected DACL takes no entries from the parent directory.
        // SAFETY: The descriptor is initialized.
        unsafe { SetSecurityDescriptorControl(pointer, SE_DACL_PROTECTED, SE_DACL_PROTECTED) }.map_err(win32_error)?;
        Ok(Self {
            descriptor,
            _acl: acl,
            _owner: owner,
        })
    }

    pub(super) fn as_ref(&self) -> &SECURITY_DESCRIPTOR {
        &self.descriptor
    }

    pub(super) fn as_raw(&self) -> PSECURITY_DESCRIPTOR {
        PSECURITY_DESCRIPTOR(std::ptr::from_ref(&*self.descriptor).cast_mut().cast())
    }
}

/// Reports whether `account` is BUILTIN\Administrators or a member of it, through its Authz group expansion, falling
/// back to the members of the local Administrators group where Authz can't resolve the account.
pub(super) fn administrators_member(account: &Sid) -> io::Result<bool> {
    let administrators = Sid::from_well_known(Security::WinBuiltinAdministratorsSid, None).map_err(io::Error::other)?;
    if *account == administrators {
        return Ok(true);
    }
    match authz_member(account, &administrators) {
        Ok(is_member) => Ok(is_member),
        Err(error) => {
            // UNTESTED: an account that Authz can't resolve, such as a domain account while the domain controller
            // is unreachable, is a member when it is listed in the local Administrators group.
            // Every account a test can make is local, which Authz resolves; when changing this, keep the fallback to
            // a membership that exists only through the listing, and keep failing when neither source answers.
            let members = win_api_wrappers::netmgmt::get_local_admin_group_members().map_err(|_| error)?;
            Ok(members.contains(account))
        }
    }
}

struct AuthzResourceManager(AUTHZ_RESOURCE_MANAGER_HANDLE);

impl Drop for AuthzResourceManager {
    fn drop(&mut self) {
        // SAFETY: AuthzInitializeResourceManager returned this handle, which nothing else frees.
        let _ = unsafe { AuthzFreeResourceManager(self.0) };
    }
}

struct AuthzContext(AUTHZ_CLIENT_CONTEXT_HANDLE);

impl Drop for AuthzContext {
    fn drop(&mut self) {
        // SAFETY: AuthzInitializeContextFromSid returned this handle, which nothing else frees.
        let _ = unsafe { AuthzFreeContext(self.0) };
    }
}

fn authz_member(account: &Sid, group: &Sid) -> io::Result<bool> {
    let mut manager = AUTHZ_RESOURCE_MANAGER_HANDLE::default();
    // SAFETY: The output is writable, and the callbacks and the name are optional.
    unsafe {
        AuthzInitializeResourceManager(
            AUTHZ_RM_FLAG_NO_AUDIT.0,
            None,
            None,
            None,
            PCWSTR::null(),
            &raw mut manager,
        )
    }
    .map_err(win32_error)?;
    let manager = AuthzResourceManager(manager);
    let mut context = AUTHZ_CLIENT_CONTEXT_HANDLE::default();
    // SAFETY: The SID and the resource manager stay live until the context is freed, and the output is writable.
    unsafe {
        AuthzInitializeContextFromSid(
            0,
            account.as_psid_const(),
            manager.0,
            None,
            LUID::default(),
            None,
            &raw mut context,
        )
    }
    .map_err(win32_error)?;
    let context = AuthzContext(context);
    let mut required = 0;
    // SAFETY: A query with no buffer writes only the size it needs.
    let _ = unsafe {
        AuthzGetInformationFromContext(
            context.0,
            AuthzContextInfoGroupsSids,
            0,
            &raw mut required,
            std::ptr::null_mut(),
        )
    };
    let size = usize::try_from(required).map_err(io::Error::other)?;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid group list size");
    if size < size_of::<Security::TOKEN_GROUPS>() {
        return Err(invalid());
    }
    // A usize buffer is aligned for TOKEN_GROUPS, whose largest fields are pointers.
    let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
    // SAFETY: The buffer is aligned and writable for `required` bytes.
    unsafe {
        AuthzGetInformationFromContext(
            context.0,
            AuthzContextInfoGroupsSids,
            required,
            &raw mut required,
            buffer.as_mut_ptr().cast(),
        )
    }
    .map_err(win32_error)?;
    // SAFETY: AuthzGetInformationFromContext filled the aligned buffer, which starts with a TOKEN_GROUPS header.
    let groups = unsafe { &*buffer.as_ptr().cast::<Security::TOKEN_GROUPS>() };
    let count = usize::try_from(groups.GroupCount).map_err(io::Error::other)?;
    let bytes = count
        .checked_mul(size_of::<Security::SID_AND_ATTRIBUTES>())
        .and_then(|bytes| bytes.checked_add(offset_of!(Security::TOKEN_GROUPS, Groups)))
        .ok_or_else(invalid)?;
    if size < bytes {
        return Err(invalid());
    }
    // SAFETY: The buffer holds `count` entries, per the size checked above.
    let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) };
    for entry in entries {
        // SAFETY: AuthzGetInformationFromContext returned a valid SID in each entry, within the live buffer.
        if unsafe { Sid::from_psid(entry.Sid) }.map_err(io::Error::other)? == *group {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::core::HSTRING;

    use super::*;

    /// Parses an SDDL string, in which `{user}` stands for the current user's SID.
    fn security(sddl: &str) -> OwnerAndDacl {
        let user = Accounts::current().expect("read accounts").user;
        let sddl = HSTRING::from(sddl.replace("{user}", &user.to_string()));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: The string is NUL-terminated and the output is writable.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(&sddl, SDDL_REVISION_1, &raw mut descriptor, None)
        }
        .expect("parse SDDL");
        // SAFETY: The conversion returned a valid descriptor, freed below.
        let security = unsafe { OwnerAndDacl::parse(descriptor) }.expect("read descriptor");
        // SAFETY: The conversion allocated the descriptor with LocalAlloc, and nothing uses it any more.
        unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        security
    }

    fn policy(rule: &Rule, kind: Kind) -> Policy {
        Policy::new(rule, kind, Utf8Path::new("item")).expect("map rule")
    }

    fn no_member(_: &Sid) -> io::Result<bool> {
        Ok(false)
    }

    fn refusal(result: Result<()>) -> String {
        match result {
            Ok(()) => "accepted".to_owned(),
            Err(error) => match error.kind() {
                crate::ErrorKind::Refused(refusal) => format!("{refusal:?}"),
                kind => format!("{kind:?}"),
            },
        }
    }

    fn system_rule() -> Rule {
        Rule::new()
            .owner(Account::CurrentUser)
            .grant(Account::System, Access::Full)
    }

    // oracle: spec MS-DTYP §2.4.4.1 ACE_HEADER
    #[test]
    fn an_inherit_only_owner_rights_entry_leaves_the_owner_its_implicit_access() {
        // An inherit-only entry doesn't apply to the directory itself, so its owner keeps READ_CONTROL and WRITE_DAC.
        let security = security("O:{user}D:P(A;OICI;FA;;;SY)(A;OICIIO;;;;OW)");
        let checked = policy(&system_rule(), Kind::Directory).check(&security, Utf8Path::new("item"), &no_member);
        assert_eq!(refusal(checked), "Access");
    }

    // oracle: reference crates/private-fs/src/rule.rs Rule
    #[test]
    fn a_check_refuses_a_deny_entry() {
        // A rule names only accounts with access, so its DACL is allow entries only, and a deny entry is not one.
        // A check that skipped entries it can't compare would accept any other entry type.
        let security = security("O:{user}D:P(A;;FA;;;SY)(A;;;;;OW)(D;;FA;;;BU)");
        let checked = policy(&system_rule(), Kind::File).check(&security, Utf8Path::new("item"), &no_member);
        assert_eq!(refusal(checked), "Access");
    }

    // oracle: intent crates/private-fs/INTENT.md §mechanisms
    #[test]
    fn a_file_entry_with_inheritance_flags_is_refused() {
        let security = security("O:{user}D:P(A;OI;FA;;;SY)(A;;;;;OW)");
        let checked = policy(&system_rule(), Kind::File).check(&security, Utf8Path::new("item"), &no_member);
        assert_eq!(refusal(checked), "Access");
    }

    // oracle: intent crates/private-fs/INTENT.md §vocabulary
    #[test]
    fn an_exact_check_refuses_a_duplicate_entry() {
        let security = security("O:{user}D:P(A;;FA;;;SY)(A;;FA;;;SY)(A;;;;;OW)");
        let checked = policy(&system_rule().exact(), Kind::File).check(&security, Utf8Path::new("item"), &no_member);
        assert_eq!(refusal(checked), "Access");
    }

    // oracle: intent crates/private-fs/INTENT.md §vocabulary
    #[test]
    fn a_check_refuses_owner_rights_wider_than_the_owner_s_access() {
        // The rule gives the owner no access, so OWNER RIGHTS must grant nothing; a narrower check also refuses more.
        let security = security("O:{user}D:P(A;;FA;;;SY)(A;;FR;;;OW)");
        let checked = policy(&system_rule(), Kind::File).check(&security, Utf8Path::new("item"), &no_member);
        assert_eq!(refusal(checked), "Access");
    }

    // oracle: mutant grants to one account kept as two entries, which an exact check of what was created refuses
    #[test]
    fn grants_to_one_account_merge_into_one_entry() {
        let rule = system_rule()
            .grant(Account::System, Access::ReadWrite)
            .grant(Account::CurrentUser, Access::Full);
        let policy = policy(&rule, Kind::Directory);
        let system = &policy.accounts.system;
        let entries: Vec<_> = policy
            .dacl(&policy.accounts.user)
            .into_iter()
            .filter(|(sid, _, _)| sid == system)
            .collect();
        assert_eq!(entries, [(system.clone(), 0x001F_01FF, 0x3)]);
    }

    // oracle: spec MS-DTYP §2.4.4.1 ACE_HEADER
    #[test]
    fn an_ancestor_deny_or_inherit_only_entry_is_ignored() {
        // A deny entry only takes access away, and an inherit-only entry doesn't apply to the directory.
        let security = security("O:SYD:P(A;;FA;;;SY)(D;;FA;;;BU)(A;OICIIO;FA;;;BU)");
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), false, &no_member);
        assert_eq!(refusal(checked), "accepted");
    }

    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn delete_on_an_ancestor_is_refused_below_the_volume_root() {
        let security = security("O:SYD:P(A;;FA;;;SY)(A;;SD;;;BU)");
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), false, &no_member);
        assert_eq!(refusal(checked), "Replaceable");
    }

    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn delete_on_the_volume_root_is_ignored() {
        // Nobody can delete or rename the root of a volume.
        let security = security("O:SYD:P(A;;FA;;;SY)(A;;SD;;;BU)");
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), true, &no_member);
        assert_eq!(refusal(checked), "accepted");
    }

    // oracle: spec Microsoft Learn "Launch an AppContainer" §AppContainer overview
    #[test]
    fn an_ancestor_entry_for_an_app_container_capability_is_ignored() {
        // The capability SID that Windows puts on AppData\Local, with full access.
        let security = security(
            "O:SYD:P(A;;FA;;;SY)(A;;FA;;;S-1-15-3-3557520199-3666692283-3112367039-3524159787-2791857073-3163583606-3692855932)",
        );
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), false, &no_member);
        assert_eq!(refusal(checked), "accepted");
    }

    // oracle: spec MS-DTYP §2.4.4.6 ACCESS_ALLOWED_CALLBACK_ACE
    #[test]
    fn an_ancestor_callback_allow_entry_counts_as_an_allow_entry() {
        // A callback entry grants its access whenever its condition holds, which the check can't evaluate.
        let security = security("O:SYD:P(A;;FA;;;SY)(XA;;FA;;;BU;(Member_of {SID(BA)}))");
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), false, &no_member);
        assert_eq!(refusal(checked), "Replaceable");
    }

    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn an_ancestor_entry_of_an_unknown_type_is_unreadable() {
        // An object entry, which file systems don't use, has a layout the check doesn't read.
        let security = security("O:SYD:P(A;;FA;;;SY)(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)");
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), false, &no_member);
        assert!(refusal(checked).starts_with("Unreadable"));
    }

    // oracle: spec MS-DTYP §2.4.2.4 Well-Known SID Structures
    #[test]
    fn an_ancestor_owner_rights_entry_is_the_allowed_owner_s() {
        // OWNER RIGHTS stands for the owner, which the check has already allowed.
        let security = security("O:SYD:P(A;;FA;;;SY)(A;;FA;;;OW)");
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), false, &no_member);
        assert_eq!(refusal(checked), "accepted");
    }

    // oracle: spec Microsoft Learn "Launch an AppContainer" §AppContainer overview
    #[test]
    fn an_ancestor_entry_for_all_application_packages_is_ignored() {
        // ALL APPLICATION PACKAGES, S-1-15-2-1, a package SID.
        let security = security("O:SYD:P(A;;FA;;;SY)(A;;FA;;;AC)");
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), false, &no_member);
        assert_eq!(refusal(checked), "accepted");
    }

    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn an_ancestor_with_a_null_dacl_is_replaceable() {
        // A NULL DACL grants everyone full access.
        let security = security("O:SYD:NO_ACCESS_CONTROL");
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), false, &no_member);
        assert_eq!(refusal(checked), "Replaceable");
    }

    // oracle: intent crates/private-fs/INTENT.md §paths
    #[test]
    fn an_ancestor_owned_by_another_account_is_replaceable() {
        let security = security("O:BUD:P(A;;FA;;;SY)");
        let checked =
            policy(&system_rule(), Kind::Directory).check_ancestor(&security, Utf8Path::new("item"), false, &no_member);
        assert_eq!(refusal(checked), "Replaceable");
    }
}
