// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security layouts from [MS-DTYP] §§2.4.2, 2.4.4–2.4.6 and [MS-SMB2] §2.2.37.

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::little_endian::{U16, U32};

/// SID revision: [MS-DTYP] §2.4.2.2.
pub const SID_REVISION: u8 = 1;
/// Maximum SID subauthority count: [MS-DTYP] §2.4.2.2.
pub const SID_MAX_SUB_AUTHORITIES: usize = 15;
/// Basic ACL revision: [MS-DTYP] §2.4.5.
pub const ACL_REVISION: u8 = 2;
/// Directory-service ACL revision: [MS-DTYP] §2.4.5.
pub const ACL_REVISION_DS: u8 = 4;
/// Security descriptor revision: [MS-DTYP] §2.4.6.
pub const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
/// ACE sizes are multiples of four: [MS-DTYP] §2.4.4.1.
pub const ACE_ALIGNMENT: usize = 4;

/// Security information selectors: [MS-SMB2] §§2.2.37, 2.2.39.
#[bitfield(u32, repr = U32, from = U32::new, into = super::u32_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct SecurityInformation {
    pub owner: bool,
    pub group: bool,
    pub dacl: bool,
    pub sacl: bool,
    pub label: bool,
    pub attribute: bool,
    pub scope: bool,
    #[bits(9)]
    reserved0: u16,
    pub backup: bool,
    #[bits(15)]
    reserved1: u16,
}
le_bitfield_conversions!(SecurityInformation, u32, U32);

impl SecurityInformation {
    /// Flags defined by SMB; receivers ignore other bits.
    pub const VALID: u32 = 0x0001007f;
}

/// Self-relative descriptor control flags: [MS-DTYP] §2.4.6.
#[bitfield(u16, repr = U16, from = U16::new, into = super::u16_from_le, conversion = false)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct SecurityDescriptorControl {
    pub owner_defaulted: bool,
    pub group_defaulted: bool,
    pub dacl_present: bool,
    pub dacl_defaulted: bool,
    pub sacl_present: bool,
    pub sacl_defaulted: bool,
    pub dacl_trusted: bool,
    pub server_security: bool,
    pub dacl_auto_inherit_required: bool,
    pub sacl_auto_inherit_required: bool,
    pub dacl_auto_inherited: bool,
    pub sacl_auto_inherited: bool,
    pub dacl_protected: bool,
    pub sacl_protected: bool,
    pub rm_control_valid: bool,
    pub self_relative: bool,
}
le_bitfield_conversions!(SecurityDescriptorControl, u16, U16);

/// ACE inheritance and audit flags: [MS-DTYP] §2.4.4.1.
#[bitfield(u8)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
pub struct AceFlags {
    pub object_inherit: bool,
    pub container_inherit: bool,
    pub no_propagate_inherit: bool,
    pub inherit_only: bool,
    pub inherited: bool,
    #[bits(1)]
    reserved: u8,
    pub successful_access: bool,
    pub failed_access: bool,
}

open_enum! {
    /// ACE type tags: [MS-DTYP] §2.4.4.1.
    #[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
    pub enum AceType: u8 {
        #![expect(missing_docs, reason = "Names follow the cited ACE table.")]
        ALLOWED = 0x00,
        DENIED = 0x01,
        AUDIT = 0x02,
        ALARM = 0x03,
        ALLOWED_COMPOUND = 0x04,
        ALLOWED_OBJECT = 0x05,
        DENIED_OBJECT = 0x06,
        AUDIT_OBJECT = 0x07,
        ALARM_OBJECT = 0x08,
        ALLOWED_CALLBACK = 0x09,
        DENIED_CALLBACK = 0x0a,
        ALLOWED_CALLBACK_OBJECT = 0x0b,
        DENIED_CALLBACK_OBJECT = 0x0c,
        AUDIT_CALLBACK = 0x0d,
        ALARM_CALLBACK = 0x0e,
        AUDIT_CALLBACK_OBJECT = 0x0f,
        ALARM_CALLBACK_OBJECT = 0x10,
        MANDATORY_LABEL = 0x11,
        RESOURCE_ATTRIBUTE = 0x12,
        SCOPED_POLICY = 0x13,
    }
}

wire!(
    /// SID fixed prefix; little-endian subauthorities follow: [MS-DTYP] §2.4.2.2.
    SidHeader, 8 {
        revision: u8,
        sub_authority_count: u8,
        identifier_authority: [u8; 6],
    }
);
wire!(
    /// ACL fixed prefix: [MS-DTYP] §2.4.5.
    AclHeader, 8 {
        revision: u8,
        reserved0: u8,
        size: U16,
        ace_count: U16,
        reserved1: U16,
    }
);
wire!(
    /// ACE fixed prefix: [MS-DTYP] §2.4.4.1.
    AceHeader, 4 { kind: AceType, flags: AceFlags, size: U16 }
);
wire!(
    /// Basic allow/deny ACE prefix, followed by its SID: [MS-DTYP] §§2.4.4.2, 2.4.4.4.
    AccessAceHeader, 8 { header: AceHeader, access_mask: super::smb2::AccessMask }
);
wire!(
    /// Pointer-free SECURITY_DESCRIPTOR prefix: [MS-DTYP] §2.4.6.
    SecurityDescriptorHeader, 20 {
        revision: u8,
        resource_manager_control: u8,
        control: SecurityDescriptorControl,
        owner_offset: U32,
        group_offset: U32,
        sacl_offset: U32,
        dacl_offset: U32,
    }
);
