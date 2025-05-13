use core::{error, fmt};
use std::collections::{HashMap, HashSet};
use std::num::{ParseIntError, TryFromIntError};
use std::str::FromStr;
use std::string::FromUtf16Error;

/// A domain for accounts.
///
/// Since we are dealing with regular accounts and domain accounts, the identifier authority is `5 - NT AUTHORITY`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DomainId {
    /// The first subauthority.
    ///
    /// This is part of [well-known SID structures](https://learn.microsoft.com/en-ca/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab).
    ///
    /// For example, `21` is `SECURITY_NT_NON_UNIQUE`.
    pub(crate) subauth1: u8,
    /// The second subauthority, a 32-bit random number.
    pub(crate) subauth2: u32,
    /// The third subauthority, a 32-bit random number.
    pub(crate) subauth3: u32,
    /// The fourth subauthority, a 32-bit random number.
    pub(crate) subauth4: u32,
}

impl FromStr for DomainId {
    type Err = ParseDomainIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 4 {
            return Err(ParseDomainIdError::InvalidFormat);
        }

        let map_e = |e, field, value| ParseDomainIdError::ParseInt {
            source: e,
            field,
            value,
        };
        Ok(Self {
            subauth1: parts[0]
                .parse()
                .map_err(|e| map_e(e, "subauth1", parts[0].to_owned()))?,
            subauth2: parts[1]
                .parse()
                .map_err(|e| map_e(e, "subauth2", parts[1].to_owned()))?,
            subauth3: parts[2]
                .parse()
                .map_err(|e| map_e(e, "subauth3", parts[2].to_owned()))?,
            subauth4: parts[3]
                .parse()
                .map_err(|e| map_e(e, "subauth4", parts[3].to_owned()))?,
        })
    }
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}-{}-{}",
            self.subauth1, self.subauth2, self.subauth3, self.subauth4
        )
    }
}

#[derive(Debug)]
pub enum ParseDomainIdError {
    InvalidFormat,
    ParseInt {
        source: ParseIntError,
        field: &'static str,
        value: String,
    },
}

impl error::Error for ParseDomainIdError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::InvalidFormat => None,
            Self::ParseInt { source, .. } => Some(source),
        }
    }
}

impl fmt::Display for ParseDomainIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid format'"),
            Self::ParseInt { source, field, value } => {
                write!(f, "failed to parse field {} with value {}: {}", field, value, source)
            }
        }
    }
}

/// A security identifier.
///
/// The SID structure is described in the [Microsoft docs](https://learn.microsoft.com/en-ca/windows-server/identity/ad-ds/manage/understand-security-identifiers).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Sid {
    pub(crate) domain_id: DomainId,
    /// The relative ID, or RID, indicates a unique object ID within the domain.
    ///
    /// The max is 15000 according to the [Microsoft docs](https://learn.microsoft.com/en-ca/windows-server/identity/ad-ds/manage/managing-rid-issuance).
    pub(crate) relative_id: i16,
}

impl FromStr for Sid {
    type Err = ParseSidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(s) = s.strip_prefix("S-1-5-") else {
            return Err(ParseSidError::MissingPrefix);
        };
        let Some((domain_id, rid)) = s.rsplit_once('-') else {
            return Err(ParseSidError::InvalidFormat);
        };
        let domain_id = DomainId::from_str(domain_id)?;
        let rid = rid.parse().map_err(|e| ParseSidError::ParseInt {
            source: e,
            field: "relative_id",
            value: rid.to_owned(),
        })?;
        Ok(Self {
            domain_id,
            relative_id: rid,
        })
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-1-5-{}-{}", self.domain_id, self.relative_id)
    }
}

/// Error type for parsing a SID or domain ID.
#[derive(Debug)]
pub enum ParseSidError {
    InvalidFormat,
    MissingPrefix,
    ParseInt {
        source: ParseIntError,
        field: &'static str,
        value: String,
    },
    DomainId(ParseDomainIdError),
}

impl error::Error for ParseSidError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::InvalidFormat | Self::MissingPrefix => None,
            Self::ParseInt { source, .. } => Some(source),
            Self::DomainId(e) => Some(e),
        }
    }
}

impl fmt::Display for ParseSidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid format'"),
            Self::MissingPrefix => write!(f, "missing prefix"),
            Self::ParseInt { source, field, value } => {
                write!(f, "failed to parse field {} with value {}: {}", field, value, source)
            }
            Self::DomainId(e) => e.fmt(f),
        }
    }
}

impl From<ParseDomainIdError> for ParseSidError {
    fn from(e: ParseDomainIdError) -> Self {
        Self::DomainId(e)
    }
}

/// A user account.
///
/// This contains the information that is retrieved from WinAPI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Account {
    pub(crate) name: String,
    pub(crate) sid: Sid,
}

/// A user account with a unique ID.
///
/// This is the type to use when referring to accounts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountWithId {
    /// The numeric ID for the account ID that was generated by the database.
    pub(crate) id: i16,
    pub(crate) name: String,
    /// The numeric ID for the domain that was generated by the database.
    pub(crate) internal_domain_id: i16,
    pub(crate) sid: Sid,
}

impl PartialEq<Account> for AccountWithId {
    fn eq(&self, other: &Account) -> bool {
        self.name == other.name && self.sid == other.sid
    }
}

/// Get the list of usernames and corresponding SIDs.
///
/// `LookupAccountNameW` must be called to enable `ConvertSidToStringSidW` to work.
#[cfg(target_os = "windows")]
pub(crate) fn list_accounts() -> Result<Vec<Account>, ListAccountsError> {
    use windows::core::PWSTR;
    use windows::Win32::NetworkManagement::NetManagement::{
        NERR_Success, NetApiBufferFree, NetUserEnum, FILTER_NORMAL_ACCOUNT, MAX_PREFERRED_LENGTH, USER_INFO_0,
    };
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{LookupAccountNameW, PSID, SECURITY_MAX_SID_SIZE, SID_NAME_USE};

    // SAFETY: uses `NetUserEnum` and `LookupAccountNameW` from `windows`

    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut entries_read = 0;
    let mut total_entries = 0;

    // SAFETY: `buf` is a null-initialized out-pointer that NetUserEnum will allocate.
    // `entries_read` and `total_entries` are valid pointers to receive output counts.
    let status = unsafe {
        // Get the list of user accounts.
        NetUserEnum(
            None,
            0,
            FILTER_NORMAL_ACCOUNT,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            None,
        )
    };

    if status != NERR_Success {
        return Err(ListAccountsError::NetUserEnumFail(status));
    }

    #[expect(clippy::cast_ptr_alignment)]
    // SAFETY: `buf` is guaranteed by `NetUserEnum` to point to an array of `USER_INFO_0` structs.
    // We cast it and build a slice with `entries_read` elements, which was returned alongside `buf`.
    // We expect the alignment to be correct because `USER_INFO_0` is a `#[repr(C)]` struct with a single field, so it is identical to the alignment of PWSTR.
    let users = unsafe { std::slice::from_raw_parts(buf as *const USER_INFO_0, entries_read as usize) };

    let mut accounts = Vec::with_capacity(users.len());
    for user in users {
        // SAFETY: `user.usri0_name` is a valid string.
        let name = unsafe { user.usri0_name.display() }.to_string();
        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut sid_size = u32::try_from(sid.len())?;
        let mut domain_name = [0u16; 256];
        let mut domain_size = u32::try_from(domain_name.len())?;
        let domain_name = PWSTR(domain_name.as_mut_ptr());
        let mut sid_type = SID_NAME_USE(0);
        let sid = PSID(sid.as_mut_ptr().cast());

        // SAFETY: `user.usri0_name` is a valid string.
        // `sid` and `domain_name` buffers are correctly sized and initialized.
        // `sid_size` and `domain_size` are set to their respective buffer lengths.
        // All pointers are valid for writes.
        unsafe {
            LookupAccountNameW(
                None,
                user.usri0_name,
                Some(sid),
                &mut sid_size,
                Some(domain_name),
                &mut domain_size,
                &mut sid_type,
            )
        }?;

        let mut sid_str: PWSTR = PWSTR::null();
        // SAFETY: `sid` is a valid buffer previously populated by `LookupAccountNameW`.
        unsafe { ConvertSidToStringSidW(sid, &mut sid_str) }?;
        // SAFETY: `sid_str` is a valid string.
        let s = unsafe { sid_str.to_string() }?;
        let sid = Sid::from_str(&s)?;
        accounts.push(Account { name, sid })
    }

    // SAFETY: `buf` was allocated by `NetUserEnum` and must be freed.
    unsafe {
        NetApiBufferFree(Some(buf as *mut _));
    }
    Ok(accounts)
}

/// A diff of changes between two lists of accounts.
#[derive(Debug, PartialEq, Eq, Default)]
pub(crate) struct AccountsDiff {
    /// An account in this list has a new name and a new SID.
    pub(crate) added: Vec<Account>,
    /// A list of account IDs that have been removed.
    pub(crate) removed: Vec<i16>,
    /// A list of accounts with changed names.
    ///
    /// The elements are the account ID and the new name.
    pub(crate) changed_name: Vec<(i16, String)>,
    /// A list of accounts that are either new, or have new SIDs.
    ///
    /// These accounts have names that were previously known, but the SIDs have changed.
    /// The elements are the account ID of the previous account with that name and the new account details.
    ///
    /// We treat accounts with changed SID as a new account for the purposes of PEDM policy. The anomaly can be traced in the logs by querying the removal time of a previous account with the shared name and the add time of the new account. This maybe relevant for [Active Directory migration](https://learn.microsoft.com/en-ca/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc974384(v=ws.10)?redirectedfrom=MSDN).
    pub(crate) added_or_changed_sid: Vec<(i16, Account)>,
    /// Domain ID mappings that are known.
    ///
    /// This is taken from the list of accounts retrieved in the database.
    /// It is useful to determine if a domain ID needs to be added to the database when adding a new account.
    pub(crate) known_domain_ids: HashMap<DomainId, i16>,
}

impl AccountsDiff {
    pub(crate) fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.changed_name.is_empty()
            && self.added_or_changed_sid.is_empty()
    }

    /// Returns the combined list of added accounts and accounts that are either added or have changed SID.
    pub(crate) fn added_all(&self) -> Vec<&Account> {
        let mut v = self.added.iter().collect::<Vec<_>>();
        let added_or_changed = self.added_or_changed_sid.iter().map(|(_, a)| a).collect::<Vec<_>>();
        v.extend(added_or_changed.iter().copied());
        v
    }

    pub(crate) fn potentially_new_domains(&self) -> Vec<DomainId> {
        let mut ids = HashSet::new();
        for a in self.added_all() {
            if !self.known_domain_ids.contains_key(&a.sid.domain_id) {
                ids.insert(a.sid.domain_id.clone());
            }
        }
        ids.into_iter().collect()
    }
}

/// Compares two lists of accounts and returns the diff.
///
/// `old` and `new` are both is sorted by name.
/// `new` is sorted by name because it is how `NetUserEnum` returns the list.
/// We choose to sort `old` by name when retrieving from the database to match the order.
pub(crate) fn diff_accounts(old: &[AccountWithId], new: &[Account]) -> AccountsDiff {
    let mut added = Vec::new();
    let mut changed_name = Vec::new();
    let mut added_or_changed_sid = Vec::new();

    // Use SID as the key.
    let old_map = old.iter().map(|a| (&a.sid, a)).collect::<HashMap<_, _>>();

    let mut matched = HashSet::new();
    let old_names = old.iter().map(|a| (a.name.as_str(), a.id)).collect::<Vec<_>>();
    for i in new {
        // Check for a match by SID.
        if let Some(j) = old_map.get(&i.sid) {
            // Match found. Check for name change.
            if j.name != i.name {
                changed_name.push((j.id, i.name.clone()));
            }
            matched.insert(j.id);
        } else {
            // Check if the name is an old name.
            if let Ok(pos) = old_names.binary_search_by_key(&i.name.as_str(), |&(n, _)| n) {
                let old_id = old_names[pos].1;
                added_or_changed_sid.push((old_id, i.clone()));
                matched.insert(old_id);
            } else {
                added.push(i.clone());
            }
        }
    }

    // Unmatched accounts are removed.
    let mut removed = Vec::new();
    for i in old {
        if !matched.contains(&i.id) {
            removed.push(i.id);
        }
    }

    AccountsDiff {
        added,
        removed,
        changed_name,
        added_or_changed_sid,
        known_domain_ids: old.iter().fold(HashMap::new(), |mut acc, a| {
            acc.insert(a.sid.domain_id.clone(), a.internal_domain_id);
            acc
        }),
    }
}

#[derive(Debug)]
pub enum ListAccountsError {
    FromUtf16(FromUtf16Error),
    ParseSid(ParseSidError),
    TryFromInt(TryFromIntError),
    #[cfg(target_os = "windows")]
    Windows(windows_result::Error),
    /// Contains `nStatus`.
    NetUserEnumFail(u32),
}

impl error::Error for ListAccountsError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::FromUtf16(e) => Some(e),
            Self::ParseSid(e) => Some(e),
            Self::TryFromInt(e) => Some(e),
            #[cfg(target_os = "windows")]
            Self::Windows(e) => Some(e),
            Self::NetUserEnumFail(_) => None,
        }
    }
}

impl fmt::Display for ListAccountsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FromUtf16(e) => e.fmt(f),
            Self::ParseSid(e) => e.fmt(f),
            Self::TryFromInt(e) => e.fmt(f),
            #[cfg(target_os = "windows")]
            Self::Windows(e) => e.fmt(f),
            Self::NetUserEnumFail(n) => {
                write!(f, "NetUserEnum failed with nStatus: {n}")
            }
        }
    }
}

impl From<FromUtf16Error> for ListAccountsError {
    fn from(e: FromUtf16Error) -> Self {
        Self::FromUtf16(e)
    }
}
impl From<ParseSidError> for ListAccountsError {
    fn from(e: ParseSidError) -> Self {
        Self::ParseSid(e)
    }
}
impl From<TryFromIntError> for ListAccountsError {
    fn from(e: TryFromIntError) -> Self {
        Self::TryFromInt(e)
    }
}
#[cfg(target_os = "windows")]
impl From<windows_result::Error> for ListAccountsError {
    fn from(e: windows_result::Error) -> Self {
        Self::Windows(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain_id() {
        assert_eq!(
            DomainId::from_str("21-1-2-3").unwrap(),
            DomainId {
                subauth1: 21,
                subauth2: 1,
                subauth3: 2,
                subauth4: 3,
            }
        );
    }

    #[test]
    fn parse_sid() {
        assert_eq!(
            Sid::from_str("S-1-5-21-1-2-3-500").unwrap(),
            Sid {
                domain_id: DomainId {
                    subauth1: 21,
                    subauth2: 1,
                    subauth3: 2,
                    subauth4: 3,
                },
                relative_id: 500,
            }
        );
    }

    #[test]
    fn domain_id_to_string() {
        assert_eq!(
            DomainId {
                subauth1: 21,
                subauth2: 1,
                subauth3: 2,
                subauth4: 3,
            }
            .to_string(),
            "21-1-2-3".to_owned()
        );
    }

    #[test]
    fn sid_to_string() {
        assert_eq!(
            Sid {
                domain_id: DomainId {
                    subauth1: 21,
                    subauth2: 1,
                    subauth3: 2,
                    subauth4: 3,
                },
                relative_id: 500,
            }
            .to_string(),
            "S-1-5-21-1-2-3-500".to_owned()
        );
    }

    #[test]
    fn diff_accounts_no_change_one() {
        let diff = diff_accounts(
            &[AccountWithId {
                id: 1,
                name: "A".into(),
                internal_domain_id: 1,
                sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
            }],
            &[Account {
                name: "A".into(),
                sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
            }],
        );
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_accounts_no_change_two() {
        let diff = diff_accounts(
            &[
                AccountWithId {
                    id: 1,
                    name: "A".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                AccountWithId {
                    id: 2,
                    name: "B".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-2").unwrap(),
                },
            ],
            &[
                Account {
                    name: "A".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                Account {
                    name: "B".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-2").unwrap(),
                },
            ],
        );
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_accounts_add_one() {
        let diff = diff_accounts(
            &[],
            &[Account {
                name: "A".into(),
                sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
            }],
        );
        assert_eq!(
            diff.added,
            vec![Account {
                name: "A".into(),
                sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
            }]
        );
        assert!(diff.removed.is_empty());
        assert!(diff.changed_name.is_empty());
        assert!(diff.added_or_changed_sid.is_empty());
        assert!(diff.known_domain_ids.is_empty());
    }

    #[test]
    fn diff_accounts_add_two() {
        let diff = diff_accounts(
            &[],
            &[
                Account {
                    name: "A".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                Account {
                    name: "B".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-2").unwrap(),
                },
            ],
        );
        assert_eq!(
            diff.added,
            vec![
                Account {
                    name: "A".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                Account {
                    name: "B".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-2").unwrap(),
                },
            ]
        );
        assert!(diff.removed.is_empty());
        assert!(diff.changed_name.is_empty());
        assert!(diff.added_or_changed_sid.is_empty());
        assert!(diff.known_domain_ids.is_empty());
    }

    #[test]
    fn diff_accounts_remove_one() {
        let diff = diff_accounts(
            &[AccountWithId {
                id: 1,
                name: "Foo".into(),
                internal_domain_id: 1,
                sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
            }],
            &[],
        );
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec![1]);
        assert!(diff.changed_name.is_empty());
        assert!(diff.added_or_changed_sid.is_empty());
        assert_eq!(
            diff.known_domain_ids,
            HashMap::from([(
                DomainId {
                    subauth1: 21,
                    subauth2: 1,
                    subauth3: 2,
                    subauth4: 3,
                },
                1
            )])
        );
    }

    #[test]
    fn diff_accounts_remove_two() {
        let diff = diff_accounts(
            &[
                AccountWithId {
                    id: 1,
                    name: "A".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                AccountWithId {
                    id: 2,
                    name: "B".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-2").unwrap(),
                },
            ],
            &[],
        );
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec![1, 2]);
        assert!(diff.changed_name.is_empty());
        assert!(diff.added_or_changed_sid.is_empty());
        assert_eq!(
            diff.known_domain_ids,
            HashMap::from([(
                DomainId {
                    subauth1: 21,
                    subauth2: 1,
                    subauth3: 2,
                    subauth4: 3,
                },
                1
            )])
        );
    }

    #[test]
    fn diff_accounts_changed_name_one() {
        let diff = diff_accounts(
            &[AccountWithId {
                id: 1,
                name: "A".into(),
                internal_domain_id: 1,
                sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
            }],
            &[Account {
                name: "AA".into(),
                sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
            }],
        );

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.changed_name, vec![(1, "AA".into())]);
        assert!(diff.added_or_changed_sid.is_empty());
        assert_eq!(
            diff.known_domain_ids,
            HashMap::from([(
                DomainId {
                    subauth1: 21,
                    subauth2: 1,
                    subauth3: 2,
                    subauth4: 3,
                },
                1
            )])
        );
    }

    #[test]
    fn diff_accounts_changed_name_two() {
        let diff = diff_accounts(
            &[
                AccountWithId {
                    id: 1,
                    name: "A".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                AccountWithId {
                    id: 2,
                    name: "B".into(),
                    internal_domain_id: 2,
                    sid: Sid::from_str("S-1-5-21-7-8-9-2").unwrap(),
                },
            ],
            &[
                Account {
                    name: "AA".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                Account {
                    name: "BB".into(),
                    sid: Sid::from_str("S-1-5-21-7-8-9-2").unwrap(),
                },
            ],
        );

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.changed_name, vec![(1, "AA".into()), (2, "BB".into())]);
        assert!(diff.added_or_changed_sid.is_empty());
        assert_eq!(
            diff.known_domain_ids,
            HashMap::from([
                (
                    DomainId {
                        subauth1: 21,
                        subauth2: 1,
                        subauth3: 2,
                        subauth4: 3,
                    },
                    1
                ),
                (
                    DomainId {
                        subauth1: 21,
                        subauth2: 7,
                        subauth3: 8,
                        subauth4: 9,
                    },
                    2
                )
            ])
        );
    }

    #[test]
    fn test_added_or_changed_sid_one() {
        let diff = diff_accounts(
            &[AccountWithId {
                id: 1,
                name: "A".into(),
                internal_domain_id: 1,
                sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
            }],
            &[Account {
                name: "A".into(),
                sid: Sid::from_str("S-1-5-21-7-8-9-11").unwrap(),
            }],
        );

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed_name.is_empty());
        assert_eq!(
            diff.added_or_changed_sid,
            vec![(
                1,
                Account {
                    name: "A".into(),
                    sid: Sid::from_str("S-1-5-21-7-8-9-11").unwrap()
                }
            )]
        );
        assert_eq!(
            diff.known_domain_ids,
            HashMap::from([(
                DomainId {
                    subauth1: 21,
                    subauth2: 1,
                    subauth3: 2,
                    subauth4: 3,
                },
                1
            ),])
        );
    }

    #[test]
    fn diff_accounts_added_or_changed_sid_two() {
        let diff = diff_accounts(
            &[
                AccountWithId {
                    id: 1,
                    name: "A".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                AccountWithId {
                    id: 2,
                    name: "B".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-2").unwrap(),
                },
            ],
            &[
                Account {
                    name: "A".into(),
                    sid: Sid::from_str("S-1-5-21-7-8-9-11").unwrap(),
                },
                Account {
                    name: "B".into(),
                    sid: Sid::from_str("S-1-5-21-7-8-9-22").unwrap(),
                },
            ],
        );

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed_name.is_empty());
        assert_eq!(
            diff.added_or_changed_sid,
            vec![
                (
                    1,
                    Account {
                        name: "A".into(),
                        sid: Sid::from_str("S-1-5-21-7-8-9-11").unwrap()
                    }
                ),
                (
                    2,
                    Account {
                        name: "B".into(),
                        sid: Sid::from_str("S-1-5-21-7-8-9-22").unwrap()
                    }
                )
            ]
        );
        assert_eq!(
            diff.known_domain_ids,
            HashMap::from([(
                DomainId {
                    subauth1: 21,
                    subauth2: 1,
                    subauth3: 2,
                    subauth4: 3,
                },
                1
            )])
        );
    }

    #[test]
    fn diff_accounts_full() {
        let diff = diff_accounts(
            &[
                // A will not change.
                AccountWithId {
                    id: 1,
                    name: "A".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                // B will be removed.
                AccountWithId {
                    id: 2,
                    name: "B".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-2").unwrap(),
                },
                // C will have a name change.
                AccountWithId {
                    id: 3,
                    name: "C".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-3").unwrap(),
                },
                // E will have a new SID.
                AccountWithId {
                    id: 5,
                    name: "E".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-5").unwrap(),
                },
                // F is an account to be deleted, but the system will have a new one created with the same name.
                AccountWithId {
                    id: 6,
                    name: "F".into(),
                    internal_domain_id: 1,
                    sid: Sid::from_str("S-1-5-21-1-2-3-6").unwrap(),
                },
                // G is from a different domain. It will not change.
                AccountWithId {
                    id: 7,
                    name: "G".into(),
                    internal_domain_id: 2,
                    sid: Sid::from_str("S-1-5-21-7-8-9-7").unwrap(),
                },
            ],
            &[
                // A is unchanged.
                Account {
                    name: "A".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-1").unwrap(),
                },
                // C has a new name.
                Account {
                    name: "CC".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-3").unwrap(),
                },
                // D is a new account.
                Account {
                    name: "D".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-4").unwrap(),
                },
                // E has a new SID.
                Account {
                    name: "E".into(),
                    sid: Sid::from_str("S-1-5-21-7-8-9-55").unwrap(),
                },
                // F is a new account with the same name as a previous account.
                Account {
                    name: "F".into(),
                    sid: Sid::from_str("S-1-5-21-1-2-3-7").unwrap(),
                },
                Account {
                    name: "G".into(),
                    sid: Sid::from_str("S-1-5-21-7-8-9-7").unwrap(),
                },
            ],
        );

        assert_eq!(
            diff.added,
            vec![Account {
                name: "D".into(),
                sid: Sid::from_str("S-1-5-21-1-2-3-4").unwrap(),
            }]
        );
        assert_eq!(diff.removed, vec![2]);
        assert_eq!(diff.changed_name, vec![(3, "CC".into())]);
        assert_eq!(
            diff.added_or_changed_sid,
            vec![
                (
                    5,
                    Account {
                        name: "E".into(),
                        sid: Sid::from_str("S-1-5-21-7-8-9-55").unwrap()
                    }
                ),
                (
                    6,
                    Account {
                        name: "F".into(),
                        sid: Sid::from_str("S-1-5-21-1-2-3-7").unwrap()
                    }
                ),
            ]
        );
        assert_eq!(
            diff.known_domain_ids,
            HashMap::from([
                (
                    DomainId {
                        subauth1: 21,
                        subauth2: 1,
                        subauth3: 2,
                        subauth4: 3,
                    },
                    1
                ),
                (
                    DomainId {
                        subauth1: 21,
                        subauth2: 7,
                        subauth3: 8,
                        subauth4: 9,
                    },
                    2
                )
            ])
        );
    }
}
