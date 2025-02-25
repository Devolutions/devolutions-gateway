use std::mem;

use windows::Win32::Security;

use crate::dst::{Win32Dst, Win32DstDef};
use crate::identity::sid::{Sid, SidAndAttributes, SidAndAttributesRef};
use crate::raw_buffer::InitedBuffer;

pub struct TokenGroups {
    // Keeping the SIDs alive.
    sids: Vec<Sid>,
    // Pointing on the SIDs found in the sids Vec.
    raw: RawTokenGroups,
}

impl TokenGroups {
    pub fn new(first_group: SidAndAttributes) -> Self {
        let sid = first_group.sid;
        let psid = sid.as_psid_const();
        let attributes = first_group.attributes;

        Self {
            sids: vec![sid],
            raw: RawTokenGroups::new(
                (),
                Security::SID_AND_ATTRIBUTES {
                    Sid: psid,
                    Attributes: attributes,
                },
            ),
        }
    }

    /// Iterates over each group and creates a copy of the pointed SID, allocated by Rust.
    ///
    /// # Safety
    ///
    /// - The SIDs must all be valid.
    /// - The Groups array must hold exactly GroupCount elements.
    pub unsafe fn from_buffer(buffer: InitedBuffer<Security::TOKEN_GROUPS>) -> anyhow::Result<Self> {
        // SAFETY: Per method safety requirements, Groups holds exactly GroupCount elements.
        let raw_token_groups = unsafe { RawTokenGroups::from_raw(buffer) };

        let mut raw_items = raw_token_groups.as_slice().iter();

        let first_item = raw_items.next().expect("always at least one element is present");

        let mut token_groups = Self::new(SidAndAttributes {
            // SAFETY: Per method safety requirements, the SID is valid.
            sid: unsafe { Sid::from_psid(first_item.Sid)? },
            attributes: first_item.Attributes,
        });

        for item in raw_items {
            token_groups.push(SidAndAttributes {
                // SAFETY: Per method safety requirements, the SID is valid.
                sid: unsafe { Sid::from_psid(item.Sid)? },
                attributes: item.Attributes,
            })
        }

        Ok(token_groups)
    }

    pub fn push(&mut self, sid_and_attributes: SidAndAttributes) {
        self.raw.push(Security::SID_AND_ATTRIBUTES {
            Sid: sid_and_attributes.sid.as_psid_const(),
            Attributes: sid_and_attributes.attributes,
        });

        self.sids.push(sid_and_attributes.sid);
    }

    pub fn as_raw(&self) -> &Security::TOKEN_GROUPS {
        self.raw.as_raw().as_ref()
    }

    pub fn iter(&self) -> impl Iterator<Item = SidAndAttributesRef<'_>> {
        self.sids
            .iter()
            .zip(self.raw.as_slice())
            .map(|(sid, raw)| SidAndAttributesRef {
                sid,
                attributes: raw.Attributes,
            })
    }
}

type RawTokenGroups = Win32Dst<TokenGroupsDstDef>;

struct TokenGroupsDstDef;

// SAFETY:
// - The offests are in bounds of the container (ensured via the offset_of! macro).
// - The container (TOKEN_GROUPS) is not #[repr(packet)].
// - The container (TOKEN_GROUPS) is #[repr(C)].
// - The array is defined last and its hardcoded size if of 1.
unsafe impl Win32DstDef for TokenGroupsDstDef {
    type Container = Security::TOKEN_GROUPS;

    type Item = Security::SID_AND_ATTRIBUTES;

    type ItemCount = u32;

    type Parameters = ();

    const ITEM_COUNT_OFFSET: usize = mem::offset_of!(Security::TOKEN_GROUPS, GroupCount);

    const ARRAY_OFFSET: usize = mem::offset_of!(Security::TOKEN_GROUPS, Groups);

    fn new_container(_: Self::Parameters, first_item: Self::Item) -> Self::Container {
        Security::TOKEN_GROUPS {
            GroupCount: 1,
            Groups: [first_item],
        }
    }

    fn increment_count(count: Self::ItemCount) -> Self::ItemCount {
        count + 1
    }
}

// SAFETY: Just a POD with no thread-unsafe interior mutabilty.
unsafe impl Send for RawTokenGroups {}

// SAFETY: Just a POD with no thread-unsafe interior mutabilty.
unsafe impl Sync for RawTokenGroups {}
