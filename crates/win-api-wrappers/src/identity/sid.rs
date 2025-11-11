use std::{fmt, mem};

use thiserror::Error;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security;
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::core::{PCWSTR, PWSTR};

use crate::dst::{Win32Dst, Win32DstDef};
use crate::identity::account::{Account, AccountWithType};
use crate::raw_buffer::RawBuffer;
use crate::str::{U16CStr, U16CStrExt, U16CString, U16CStringExt};

pub use Security::WELL_KNOWN_SID_TYPE;

/// A string-format security identifier (SID), suitable for display, storage, or transmission
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StringSid {
    // INVARIANT: Must be a valid string-format SID.
    // SID strings use either the standard S-R-I-S-S… format,
    // or the SID string constant format such as "BA" for built-in administrators.
    inner: U16CString,
}

impl fmt::Display for StringSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let repr = self.inner.to_string_lossy();
        repr.fmt(f)
    }
}

impl StringSid {
    #[expect(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, widestring::error::ContainsNul<u16>> {
        U16CString::from_str(s).map(|s| StringSid { inner: s })
    }

    pub fn from_sid(sid: &Sid) -> anyhow::Result<Self> {
        sid.to_string_sid()
    }

    pub fn to_sid(&self) -> anyhow::Result<Sid> {
        Sid::from_string_sid(self)
    }

    pub fn as_u16cstr(&self) -> &U16CStr {
        self.inner.as_ucstr()
    }

    pub fn into_u16cstring(self) -> U16CString {
        self.inner
    }
}

pub struct SidAndAttributesRef<'sid> {
    pub sid: &'sid Sid,
    pub attributes: u32,
}

pub struct SidAndAttributes {
    pub sid: Sid,
    pub attributes: u32,
}

impl SidAndAttributes {
    /// Creates a [`SidAndAttributes`] from the given SID_AND_ATTRIBUTES.
    ///
    /// # Safety
    ///
    /// The Sid field of the provided SID_AND_ATTRIBUTES must be a valid SID.
    pub unsafe fn from_raw(sid_and_attributes: &Security::SID_AND_ATTRIBUTES) -> Result<Self, FromPsidErr> {
        // SAFETY:
        // - The Sid field is a valid SID as per safety preconditions of this function.
        // - A Rust-allocated copy of the SID is created, thus we don’t need to track ownership.
        let sid = unsafe { Sid::from_psid(sid_and_attributes.Sid)? };

        Ok(Self {
            sid,
            attributes: sid_and_attributes.Attributes,
        })
    }

    /// Returns a SID_AND_ATTRIBUTES structure whose Sid field may be mutated.
    pub fn as_mut_raw(&mut self) -> Security::SID_AND_ATTRIBUTES {
        Security::SID_AND_ATTRIBUTES {
            Sid: self.sid.as_psid(),
            Attributes: self.attributes,
        }
    }

    /// Returns a SID_AND_ATTRIBUTES structure whose Sid field must not be mutated.
    pub fn as_raw(&self) -> Security::SID_AND_ATTRIBUTES {
        Security::SID_AND_ATTRIBUTES {
            Sid: self.sid.as_psid_const(),
            Attributes: self.attributes,
        }
    }
}

pub type Sid = Win32Dst<SidDstDef>;

pub struct SidDstDef;

// SAFETY:
// - The offests are in bounds of the container (ensured via the offset_of! macro).
// - The container (SID) is not #[repr(packet)].
// - The container (SID) is #[repr(C)].
// - The array is defined last and its hardcoded size if of 1.
unsafe impl Win32DstDef for SidDstDef {
    type Container = Security::SID;

    type Item = u32;

    type ItemCount = u8;

    type Parameters = (u8, Security::SID_IDENTIFIER_AUTHORITY);

    const ITEM_COUNT_OFFSET: usize = mem::offset_of!(Security::SID, SubAuthorityCount);

    const ARRAY_OFFSET: usize = mem::offset_of!(Security::SID, SubAuthority);

    fn new_container((revision, identifier_authority): Self::Parameters, first_item: Self::Item) -> Self::Container {
        Security::SID {
            Revision: revision,
            SubAuthorityCount: 1,
            IdentifierAuthority: identifier_authority,
            SubAuthority: [first_item],
        }
    }

    fn increment_count(count: Self::ItemCount) -> Self::ItemCount {
        count + 1
    }
}

// SAFETY: Just a POD with no thread-unsafe interior mutabilty.
unsafe impl Send for Sid {}

// SAFETY: Just a POD with no thread-unsafe interior mutabilty.
unsafe impl Sync for Sid {}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut repr_ptr = PWSTR::null();

        // SAFETY:
        // - self a valid SID, well constructed.
        // - The mutability of the pointer is changed, but ConvertSidToStringSidW is not modifying the underlying data.
        unsafe { ConvertSidToStringSidW(self.as_psid_const(), &mut repr_ptr).map_err(|_| fmt::Error)? };

        // SAFETY: ConvertSidToStringSidW returns a null-terminated SID string.
        let repr = unsafe { U16CStr::from_pwstr(repr_ptr) };

        let res = f.write_str(&repr.to_string_lossy());

        // SAFETY: The pointer allocated by ConvertSidToStringSidW must be freed using `LocalFree`.
        unsafe { LocalFree(Some(HLOCAL(repr_ptr.0.cast()))) };

        res
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Clone for Sid {
    fn clone(&self) -> Self {
        let mut it = self.as_slice().iter();

        let first_item = it.next().expect("always at least one element is present");
        let mut sid = Sid::new((self.revision(), self.identifier_authority()), *first_item);

        for item in it {
            sid.push(*item);
        }

        sid
    }
}

impl Ord for Sid {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.revision()
            .cmp(&other.revision())
            .then_with(|| {
                self.identifier_authority()
                    .Value
                    .cmp(&other.identifier_authority().Value)
            })
            .then_with(|| self.sub_authorities().cmp(other.sub_authorities()))
    }
}

impl PartialOrd for Sid {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Sid {}

impl core::hash::Hash for Sid {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.revision().hash(state);
        self.identifier_authority().Value.hash(state);
        self.sub_authorities().hash(state);
    }
}

impl Sid {
    pub fn revision(&self) -> u8 {
        self.as_raw().as_ref().Revision
    }

    pub fn identifier_authority(&self) -> Security::SID_IDENTIFIER_AUTHORITY {
        self.as_raw().as_ref().IdentifierAuthority
    }

    pub fn sub_authorities(&self) -> &[u32] {
        self.as_slice()
    }

    /// Obtains a PSID pointing to this SID from an exclusive, mutable reference
    pub fn as_psid(&mut self) -> Security::PSID {
        Security::PSID(self.as_raw_mut().as_mut_ptr().cast())
    }

    /// Obtains a PSID pointing to this SID from a shared, non-mutable reference
    ///
    /// The SID must not be mutated through the returned PSID, that would be UB.
    pub fn as_psid_const(&self) -> Security::PSID {
        Security::PSID(self.as_raw().as_ptr().cast_mut().cast())
    }

    /// Obtains a SID using predefined aliases
    ///
    /// # Parameters
    ///
    /// - sid_type: Specifies what the SID will identify
    /// - domain_sid: SID identifying the domain to use when creating the SID.
    ///   Pass `None` to use local computer.
    pub fn from_well_known(sid_type: WELL_KNOWN_SID_TYPE, domain_sid: Option<&Sid>) -> anyhow::Result<Self> {
        use std::alloc::Layout;

        // The output has a variable size.
        // Therefore, we must call CreateWellKnownSid once with a zero-size, and check for the ERROR_INSUFFICIENT_BUFFER status.
        // At this point, we call CreateWellKnownSid again with a buffer of the correct size.

        let mut return_length = 0u32;

        let domain_sid = domain_sid.map(Sid::as_psid_const);

        // SAFETY: The domain SID is only used as an in parameter, and is actually never modified by CreateWellKnownSid.
        let res = unsafe { Security::CreateWellKnownSid(sid_type, domain_sid, None, &mut return_length) };

        let Err(err) = res else {
            anyhow::bail!("first call to CreateWellKnownSid did not fail")
        };

        // SAFETY: FFI call with no outstanding precondition.
        if unsafe { windows::Win32::Foundation::GetLastError() }
            != windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER
        {
            return Err(anyhow::Error::new(err)
                .context("first call to CreateWellKnownSid did not fail with ERROR_INSUFFICIENT_BUFFER"));
        }

        let allocated_length = return_length;
        let align = align_of::<Security::SID>();
        let layout = Layout::from_size_align(allocated_length as usize, align)?;

        // SAFETY: The layout initialization is checked using the Layout::from_size_align method.
        let mut sid = unsafe { RawBuffer::alloc_zeroed(layout).expect("oom") };

        // SAFETY: The domain SID is only used as an in parameter, and is actually never modified by CreateWellKnownSid.
        unsafe {
            Security::CreateWellKnownSid(
                sid_type,
                domain_sid,
                Some(Security::PSID(sid.as_mut_ptr().cast())),
                &mut return_length,
            )?
        };

        debug_assert_eq!(allocated_length, return_length);

        // SAFETY: CreateWellKnownSid returned with success, the SID struct is expected to be initialized.
        let sid = unsafe { sid.assume_init::<Security::SID>() };

        // SAFETY: Assuming CreateWellKnownSid returned a valid SID.
        let sid = unsafe { Sid::from_raw(sid) };

        Ok(sid)
    }

    /// Creates a copy of the pointed SID, allocated by Rust.
    ///
    /// # Safety
    ///
    /// The pointed SID must be a valid SID.
    pub unsafe fn from_psid(psid: Security::PSID) -> Result<Self, FromPsidErr> {
        use std::alloc::Layout;

        // SAFETY: FFI call with no outstanding precondition.
        let is_valid_sid = unsafe { Security::IsValidSid(psid) };

        if is_valid_sid.as_bool() {
            // SAFETY: The pointed SID is valid, checked above using IsValidSid.
            let sid_length = unsafe { Security::GetLengthSid(psid) };

            let align = align_of::<Security::SID>();
            let layout =
                Layout::from_size_align(sid_length as usize, align).expect("a SID layout should never be invalid");

            // SAFETY: The layout initialization is checked using the Layout::from_size_align method.
            let mut sid = unsafe { RawBuffer::alloc_zeroed(layout).expect("oom") };

            // SAFETY: FFI call with no outstanding precondition.
            unsafe {
                Security::CopySid(sid_length, Security::PSID(sid.as_mut_ptr().cast()), psid)
                    .map_err(|source| FromPsidErr::CopyFailed { source })?;
            }

            // SAFETY: On success, CopySid properly initialized the SID.
            let sid = unsafe { sid.assume_init() };

            // SAFETY: Caller must ensure that psid is a valid SID.
            let sid = unsafe { Self::from_raw(sid) };

            Ok(sid)
        } else {
            Err(FromPsidErr::InvalidSid)
        }
    }

    /// Converts a string-format SID into a valid, functional SID.
    pub fn from_string_sid(value: &StringSid) -> anyhow::Result<Self> {
        let mut psid = Security::PSID::default();

        // SAFETY: `value` is valid string-format SID.
        unsafe { ConvertStringSidToSidW(value.as_u16cstr().as_pcwstr(), &mut psid)? };

        // SAFETY: On success, psid points to a valid SID.
        let res = unsafe { Self::from_psid(psid) };

        // SAFETY: On success, psid is a valid pointer initialized by ConvertStringSidToSidW that must be freed using LocalFree.
        unsafe { LocalFree(Some(HLOCAL(psid.0))) };

        Ok(res?)
    }

    /// Converts a security identifier (SID) to a string-format SID
    pub fn to_string_sid(&self) -> anyhow::Result<StringSid> {
        let mut repr_ptr = PWSTR::null();

        // SAFETY:
        // - self a valid SID, well constructed.
        // - The mutability of the pointer is changed, but ConvertSidToStringSidW is not modifying the underlying data.
        unsafe { ConvertSidToStringSidW(self.as_psid_const(), &mut repr_ptr)? };

        // SAFETY: ConvertSidToStringSidW returns a null-terminated SID string.
        let repr = unsafe { U16CString::from_pwstr(repr_ptr) };

        // SAFETY: The pointer allocated by ConvertSidToStringSidW must be freed using `LocalFree`.
        unsafe { LocalFree(Some(HLOCAL(repr_ptr.0.cast()))) };

        Ok(StringSid { inner: repr })
    }

    /// Validates a security identifier (SID) by verifying that the revision
    /// number is within a known range, and that the number of subauthorities is less
    /// than the maximum.
    pub fn is_valid(&self) -> bool {
        // SAFETY: FFI call with no outstanding precondition.
        unsafe { Security::IsValidSid(self.as_psid_const()).as_bool() }
    }

    /// Retrieves the name of the account for this SID and the name of the first domain on which this SID is found.
    ///
    /// If the name cannot be resolved on the local system, this function will try to resolve the name using domain
    /// controllers trusted by the local system.
    ///
    /// # Parameters
    ///
    /// - system_name: Specifies the target computer. Can be the name of a remote computer.
    ///   If `None`, the account name translation begins on the local system.
    ///   Generally, specify a value only when the account is in an untrusted domain and the name of a computer in that
    ///   domain is known.
    pub fn lookup_account(&self, system_name: Option<&U16CStr>) -> anyhow::Result<AccountWithType> {
        let mut account_name_size = 0u32;
        let mut domain_name_size = 0u32;
        let mut sid_name_use = Security::SID_NAME_USE::default();

        // The output has a variable size.
        // Therefore, we must call LookupAccountSidW once with a zero-size, and check for the ERROR_INSUFFICIENT_BUFFER status.
        // At this point, we call LookupAccountSidW again with a buffer of the correct size.

        // SAFETY:
        // - Since cchName is 0, it receives the required buffer size, including the terminating null character.
        // - Same for cchReferencedDomainName.
        let res = unsafe {
            Security::LookupAccountSidW(
                system_name.map_or_else(PCWSTR::null, U16CStrExt::as_pcwstr),
                self.as_psid_const(),
                None,
                &mut account_name_size,
                None,
                &mut domain_name_size,
                &mut sid_name_use,
            )
        };

        let Err(err) = res else {
            anyhow::bail!("first call to LookupAccountSidW did not fail")
        };

        // SAFETY: FFI call with no outstanding precondition.
        if unsafe { windows::Win32::Foundation::GetLastError() }
            != windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER
        {
            return Err(anyhow::Error::new(err)
                .context("first call to LookupAccountSidW did not fail with ERROR_INSUFFICIENT_BUFFER"));
        }

        let mut account_name_buf = vec![0u16; account_name_size as usize];
        let mut domain_name_buf = vec![0u16; domain_name_size as usize];

        // SAFETY:
        // - account_name_buf is big enough to receive account_name_size bytes.
        // - domain_name buf is big enough to receive domain_name_size bytes.
        unsafe {
            Security::LookupAccountSidW(
                system_name.map_or_else(PCWSTR::null, U16CStrExt::as_pcwstr),
                self.as_psid_const(),
                Some(PWSTR::from_raw(account_name_buf.as_mut_ptr())),
                &mut account_name_size,
                Some(PWSTR::from_raw(domain_name_buf.as_mut_ptr())),
                &mut domain_name_size,
                &mut sid_name_use,
            )?
        };

        // FIXME? Original code was shrinking the number of sub authorities.
        // domain_sid.sub_authority.shrink_to(1);
        // If nothing wrong happens, it’s probably fine without shrinking?
        // Otherwise, we can perform a similar logic to the clone(), but only push the first value.

        let account = Account {
            sid: self.clone(),
            name: U16CString::from_vec_truncate(account_name_buf),
            domain_sid: self.clone(),
            domain_name: U16CString::from_vec_truncate(domain_name_buf),
        };

        Ok(AccountWithType::wrap(account, sid_name_use))
    }
}

#[derive(Debug, Clone, Error)]
pub enum FromPsidErr {
    #[error("invalid SID")]
    InvalidSid,
    #[error("failed to copy the provided SID")]
    CopyFailed { source: windows::core::Error },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::print_stdout)]

    use super::*;
    use crate::str::u16cstr;
    use rstest::rstest;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn create() {
        let mut sid = Sid::new((1, Security::SECURITY_AUTHENTICATION_AUTHORITY), 5);
        sid.push(10);
        sid.push(15);

        assert!(sid.is_valid());
        assert_eq!(sid.revision(), 1);
        assert_eq!(sid.identifier_authority(), Security::SECURITY_AUTHENTICATION_AUTHORITY);
        assert_eq!(sid.sub_authorities(), &[5, 10, 15]);
        assert_eq!(sid.to_string(), "S-1-18-5-10-15");
        assert_eq!(sid.to_string_sid().unwrap().as_u16cstr(), u16cstr!("S-1-18-5-10-15"));
    }

    #[rstest]
    #[case(Security::WinLocalSystemSid)]
    #[case(Security::WinBuiltinUsersSid)]
    #[case(Security::WinBuiltinAdministratorsSid)]
    #[case(Security::WinLocalSid)]
    #[case(Security::WinLocalAccountAndAdministratorSid)]
    #[case(Security::WinHighLabelSid)]
    #[cfg_attr(miri, ignore)]
    fn get_well_known_sid(#[case] input: WELL_KNOWN_SID_TYPE) {
        let sid = Sid::from_well_known(input, None).unwrap();
        assert!(sid.is_valid());
        println!("{sid}");
    }

    #[rstest]
    #[case("BA", "S-1-5-32-544")]
    #[case("AN", "S-1-5-7")]
    #[case("OW", "S-1-3-4")]
    #[case("S-1-5-32-544", "S-1-5-32-544")]
    #[cfg_attr(miri, ignore)]
    fn from_string_sid(#[case] input: &str, #[case] expected_output_string_sid: &str) {
        let input_string_sid = StringSid::from_str(input).unwrap();
        let sid = Sid::from_string_sid(&input_string_sid).unwrap();
        let output_string_sid = sid.to_string_sid().unwrap();
        assert_eq!(output_string_sid.to_string(), expected_output_string_sid);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn lookup_account() {
        let sid = Sid::from_well_known(Security::WinBuiltinUsersSid, None).unwrap();
        let account = sid.lookup_account(None).unwrap();
        assert_eq!(account.name, u16cstr!("Users"));
        assert_eq!(account.domain_name, u16cstr!("BUILTIN"));
    }
}
