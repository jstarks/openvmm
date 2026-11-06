// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Portable, pointer-free security descriptors with bounded structural decoding.
//!
//! ACE policy is provider-owned. Opaque ACE bodies survive decoding/encoding so
//! native providers are not restricted to the synthetic provider's access model.

use crate::spec::*;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

/// A malformed SID, ACL or self-relative security descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// Invalid SID revision, count or extent.
    #[error("invalid SID")]
    Sid,
    /// Invalid ACL revision or ACE extents.
    #[error("invalid ACL")]
    Acl,
    /// Invalid descriptor header, presence flags or offsets.
    #[error("invalid self-relative security descriptor")]
    Descriptor,
}

impl From<DecodeError> for Status {
    fn from(error: DecodeError) -> Self {
        match error {
            DecodeError::Sid => Self::INVALID_SID,
            DecodeError::Acl => Self::INVALID_ACL,
            DecodeError::Descriptor => Self::INVALID_SECURITY_DESCR,
        }
    }
}

/// A validated SID packet, independent of OS handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// Decode exactly one SID.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let sid = Self::prefix(bytes)?;
        if sid.len() != bytes.len() {
            return Err(DecodeError::Sid);
        }
        Ok(Self(sid.to_vec()))
    }

    fn prefix(bytes: &[u8]) -> Result<&[u8], DecodeError> {
        let (header, _) = SidHeader::read_from_prefix(bytes).map_err(|_| DecodeError::Sid)?;
        if header.revision != SID_REVISION
            || usize::from(header.sub_authority_count) > SID_MAX_SUB_AUTHORITIES
        {
            return Err(DecodeError::Sid);
        }
        let length =
            size_of::<SidHeader>() + usize::from(header.sub_authority_count) * size_of::<u32>();
        bytes.get(..length).ok_or(DecodeError::Sid)
    }

    /// Construct a SID from its authority and little-endian subauthorities.
    pub fn new(authority: [u8; 6], sub_authorities: &[u32]) -> Result<Self, DecodeError> {
        if sub_authorities.len() > SID_MAX_SUB_AUTHORITIES {
            return Err(DecodeError::Sid);
        }
        let mut bytes = SidHeader {
            revision: SID_REVISION,
            sub_authority_count: sub_authorities.len() as u8,
            identifier_authority: authority,
        }
        .as_bytes()
        .to_vec();
        for value in sub_authorities {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(Self(bytes))
    }

    /// Encoded SID packet.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// An allow/deny ACE, used when constructing an ordinary discretionary ACL.
#[derive(Debug, Clone)]
pub struct AccessAce {
    /// Deny rather than allow these rights.
    pub deny: bool,
    /// Inheritance flags.
    pub flags: AceFlags,
    /// Access mask, including optional generic rights.
    pub mask: u32,
    /// Principal or group.
    pub sid: Sid,
}

/// A structurally validated ACL, retaining opaque ACE kinds and unused ACL space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl(Vec<u8>);

/// One ACE within a validated ACL.
#[derive(Debug, Clone, Copy)]
pub struct Ace<'a> {
    /// ACE type.
    pub kind: AceType,
    /// Inheritance/audit flags.
    pub flags: AceFlags,
    bytes: &'a [u8],
}

impl Ace<'_> {
    /// Interpret a basic allow/deny ACE; other types remain opaque.
    pub fn access(&self) -> Option<AccessAce> {
        if !matches!(self.kind, AceType::ALLOWED | AceType::DENIED) {
            return None;
        }
        let (header, rest) =
            AccessAceHeader::read_from_prefix(self.bytes).expect("basic ACE prefix was validated");
        let sid = Sid::prefix(rest).expect("basic ACE SID was validated");
        Some(AccessAce {
            deny: self.kind == AceType::DENIED,
            flags: self.flags,
            mask: header.access_mask.into_bits(),
            sid: Sid(sid.to_vec()),
        })
    }

    /// Complete encoded ACE, including its header and opaque body.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
}

impl Acl {
    /// Decode exactly one ACL. Interpretation of non-basic ACE bodies is separate.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let acl = Self::prefix(bytes)?;
        if acl.len() != bytes.len() {
            return Err(DecodeError::Acl);
        }
        Ok(Self(acl.to_vec()))
    }

    fn prefix(bytes: &[u8]) -> Result<&[u8], DecodeError> {
        let (header, _) = AclHeader::read_from_prefix(bytes).map_err(|_| DecodeError::Acl)?;
        if !matches!(header.revision, ACL_REVISION | ACL_REVISION_DS) {
            return Err(DecodeError::Acl);
        }
        let acl = bytes
            .get(..usize::from(header.size.get()))
            .ok_or(DecodeError::Acl)?;
        let mut remaining = acl.get(size_of::<AclHeader>()..).ok_or(DecodeError::Acl)?;
        for _ in 0..header.ace_count.get() {
            let (ace, _) = AceHeader::read_from_prefix(remaining).map_err(|_| DecodeError::Acl)?;
            let length = usize::from(ace.size.get());
            if length < size_of::<AceHeader>() || !length.is_multiple_of(ACE_ALIGNMENT) {
                return Err(DecodeError::Acl);
            }
            let bytes = remaining.get(..length).ok_or(DecodeError::Acl)?;
            if matches!(ace.kind, AceType::ALLOWED | AceType::DENIED) {
                let (_, sid) =
                    AccessAceHeader::read_from_prefix(bytes).map_err(|_| DecodeError::Acl)?;
                Sid::prefix(sid).map_err(|_| DecodeError::Acl)?;
            }
            remaining = &remaining[length..];
        }
        Ok(acl)
    }

    /// Construct basic access ACEs in the supplied order, including an empty ACL.
    pub fn access(entries: &[AccessAce]) -> Result<Self, DecodeError> {
        let mut bytes = vec![0; size_of::<AclHeader>()];
        for entry in entries {
            let length = size_of::<AccessAceHeader>() + entry.sid.0.len();
            if bytes.len() + length > usize::from(u16::MAX) {
                return Err(DecodeError::Acl);
            }
            bytes.extend_from_slice(
                AccessAceHeader {
                    header: AceHeader {
                        kind: if entry.deny {
                            AceType::DENIED
                        } else {
                            AceType::ALLOWED
                        },
                        flags: entry.flags,
                        size: (length as u16).into(),
                    },
                    access_mask: AccessMask::from_bits(entry.mask),
                }
                .as_bytes(),
            );
            bytes.extend_from_slice(entry.sid.as_bytes());
        }
        let header = AclHeader {
            revision: ACL_REVISION,
            reserved0: 0,
            size: (bytes.len() as u16).into(),
            ace_count: u16::try_from(entries.len())
                .map_err(|_| DecodeError::Acl)?
                .into(),
            reserved1: 0.into(),
        };
        bytes[..size_of::<AclHeader>()].copy_from_slice(header.as_bytes());
        Ok(Self(bytes))
    }

    /// Iterate only within the validated ACE count, ignoring unused ACL space.
    pub fn entries(&self) -> impl Iterator<Item = Ace<'_>> {
        let (header, mut bytes) =
            AclHeader::read_from_prefix(&self.0).expect("validated ACL prefix");
        (0..header.ace_count.get()).map(move |_| {
            let (header, _) = AceHeader::read_from_prefix(bytes).expect("validated ACE header");
            let length = usize::from(header.size.get());
            let entry = Ace {
                kind: header.kind,
                flags: header.flags,
                bytes: &bytes[..length],
            };
            bytes = &bytes[length..];
            entry
        })
    }

    /// Complete ACL packet, including unused space.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ACL presence is distinct from the number of ACEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclState {
    /// ACL presence flag is clear.
    Absent,
    /// Presence flag is set but its offset is null.
    Null,
    /// A concrete ACL, possibly containing zero ACEs.
    Present(Acl),
}

/// Security descriptor components with no native pointers.
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    /// Owner SID.
    pub owner: Option<Sid>,
    /// Primary group SID.
    pub group: Option<Sid>,
    /// System ACL.
    pub sacl: AclState,
    /// Discretionary ACL.
    pub dacl: AclState,
    /// Control metadata; encode derives presence and self-relative bits from components.
    pub control: SecurityDescriptorControl,
    /// Resource manager byte, meaningful only with RM_CONTROL_VALID.
    pub resource_manager_control: u8,
}

impl SecurityDescriptor {
    /// A descriptor with no selected owner/group/ACL components.
    pub fn empty() -> Self {
        Self {
            owner: None,
            group: None,
            sacl: AclState::Absent,
            dacl: AclState::Absent,
            control: SecurityDescriptorControl::new().with_self_relative(true),
            resource_manager_control: 0,
        }
    }

    /// Decode bounded component offsets. Components may share storage or appear in any order.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (header, _) = SecurityDescriptorHeader::read_from_prefix(bytes)
            .map_err(|_| DecodeError::Descriptor)?;
        if header.revision != SECURITY_DESCRIPTOR_REVISION || !header.control.self_relative() {
            return Err(DecodeError::Descriptor);
        }
        let component = |offset: u32| {
            let offset = offset as usize;
            if offset < size_of::<SecurityDescriptorHeader>() {
                return Err(DecodeError::Descriptor);
            }
            bytes.get(offset..).ok_or(DecodeError::Descriptor)
        };
        let sid = |offset| {
            if offset == 0 {
                return Ok(None);
            }
            Ok(Some(Sid(Sid::prefix(component(offset)?)?.to_vec())))
        };
        let acl = |offset: u32, present: bool| {
            if !present {
                if offset != 0 {
                    return Err(DecodeError::Descriptor);
                }
                return Ok(AclState::Absent);
            }
            if offset == 0 {
                return Ok(AclState::Null);
            }
            Ok(AclState::Present(Acl(
                Acl::prefix(component(offset)?)?.to_vec()
            )))
        };
        Ok(Self {
            owner: sid(header.owner_offset.get())?,
            group: sid(header.group_offset.get())?,
            sacl: acl(header.sacl_offset.get(), header.control.sacl_present())?,
            dacl: acl(header.dacl_offset.get(), header.control.dacl_present())?,
            control: header.control,
            resource_manager_control: header.resource_manager_control,
        })
    }

    /// Encode contiguous self-relative components, preserving opaque ACEs.
    pub fn encode(&self) -> Vec<u8> {
        let mut header = SecurityDescriptorHeader {
            revision: SECURITY_DESCRIPTOR_REVISION,
            resource_manager_control: self.resource_manager_control,
            control: self
                .control
                .with_self_relative(true)
                .with_sacl_present(self.sacl != AclState::Absent)
                .with_dacl_present(self.dacl != AclState::Absent),
            owner_offset: 0.into(),
            group_offset: 0.into(),
            sacl_offset: 0.into(),
            dacl_offset: 0.into(),
        };
        let mut bytes = header.as_bytes().to_vec();
        // SID and ACL size limits bound this representation well below u32::MAX.
        let mut append = |component: &[u8]| {
            let offset = bytes.len() as u32;
            bytes.extend_from_slice(component);
            offset.into()
        };
        if let Some(owner) = &self.owner {
            header.owner_offset = append(owner.as_bytes());
        }
        if let Some(group) = &self.group {
            header.group_offset = append(group.as_bytes());
        }
        if let AclState::Present(acl) = &self.sacl {
            header.sacl_offset = append(acl.as_bytes());
        }
        if let AclState::Present(acl) = &self.dacl {
            header.dacl_offset = append(acl.as_bytes());
        }
        bytes[..size_of::<SecurityDescriptorHeader>()].copy_from_slice(header.as_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    fn literal_descriptor() -> Vec<u8> {
        vec![
            1, 0, 4, 128, 48, 0, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 28, 0, 1, 0, 0,
            0, 0, 0, 20, 0, 0x89, 0, 0x12, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0,
            0, 5, 18, 0, 0, 0,
        ]
    }

    #[test]
    fn descriptor_offsets_can_reorder_and_alias_components() {
        let bytes = literal_descriptor();
        let descriptor = SecurityDescriptor::decode(&bytes).unwrap();
        let system = Sid::new([0, 0, 0, 0, 0, 5], &[18]).unwrap();
        assert_eq!(descriptor.owner.as_ref(), Some(&system));
        assert_eq!(descriptor.group.as_ref(), Some(&system));
        let AclState::Present(acl) = &descriptor.dacl else {
            panic!("missing DACL");
        };
        let ace = acl.entries().next().unwrap().access().unwrap();
        assert!(!ace.deny);
        assert_eq!(ace.mask, 0x120089);
        assert_eq!(ace.sid, Sid::new([0, 0, 0, 0, 0, 1], &[0]).unwrap());
        assert_eq!(Acl::access(&[ace]).unwrap(), *acl);
        let encoded = descriptor.encode();
        assert_eq!(&encoded[..4], &[1, 0, 4, 128]);
        let decoded = SecurityDescriptor::decode(&encoded).unwrap();
        assert_eq!(decoded.owner, descriptor.owner);
        assert_eq!(decoded.group, descriptor.group);
        assert_eq!(decoded.dacl, descriptor.dacl);
    }

    #[test]
    fn absent_null_empty_and_opaque_acls_remain_distinct() {
        for state in [
            AclState::Absent,
            AclState::Null,
            AclState::Present(Acl::access(&[]).unwrap()),
        ] {
            let descriptor = SecurityDescriptor {
                dacl: state.clone(),
                ..SecurityDescriptor::empty()
            };
            assert_eq!(
                SecurityDescriptor::decode(&descriptor.encode())
                    .unwrap()
                    .dacl,
                state
            );
        }
        let mut bytes = literal_descriptor();
        bytes[28] = 0x42;
        let descriptor = SecurityDescriptor::decode(&bytes).unwrap();
        let AclState::Present(acl) = &descriptor.dacl else {
            panic!("missing DACL");
        };
        assert_eq!(acl.entries().next().unwrap().kind, AceType(0x42));
        assert!(acl.entries().next().unwrap().access().is_none());
        let encoded = descriptor.encode();
        assert_eq!(
            SecurityDescriptor::decode(&encoded).unwrap().dacl,
            descriptor.dacl
        );
        let acl = Acl::decode(&[2, 0, 12, 0, 0, 0, 0, 0, 1, 2, 3, 4]).unwrap();
        assert_eq!(acl.entries().count(), 0);
        assert_eq!(acl.as_bytes(), &[2, 0, 12, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
    }

    #[test]
    fn malformed_descriptor_sid_and_ace_extents_are_rejected() {
        let valid = literal_descriptor();
        for length in 0..valid.len() {
            assert!(
                SecurityDescriptor::decode(&valid[..length]).is_err(),
                "length {length}"
            );
        }
        for (offset, replacement) in [
            (0, vec![2]),
            (3, vec![0]),
            (4, vec![1, 0, 0, 0]),
            (8, u32::MAX.to_le_bytes().to_vec()),
            (2, vec![0]),
            (20, vec![3]),
            (22, vec![7, 0]),
            (24, vec![2, 0]),
            (30, vec![0, 0]),
            (30, vec![16, 0]),
            (30, vec![24, 0]),
            (37, vec![16]),
            (48, vec![0]),
            (49, vec![16]),
        ] {
            let mut bytes = valid.clone();
            bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
            assert!(
                SecurityDescriptor::decode(&bytes).is_err(),
                "offset {offset}"
            );
        }
        assert!(Sid::new([0; 6], &[0; 16]).is_err());
        assert!(Sid::decode(&[1, 15, 0, 0, 0, 0, 0, 5]).is_err());
        let world = Sid::new([0, 0, 0, 0, 0, 1], &[0]).unwrap();
        let mut extra = world.as_bytes().to_vec();
        extra.push(0);
        assert!(Sid::decode(&extra).is_err());
    }
}
