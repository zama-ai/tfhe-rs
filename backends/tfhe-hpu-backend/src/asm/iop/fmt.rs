//!
//! Define binary format encoding of IOp instructions
//! Rely on `bitfield_struct` crate to define bit-accurate insn format
//! and some manual From/To implementation to move to internal type
use crate::asm::dop::MAX_HPU_IN_CLUSTER;
use crate::asm::{CtId, IOpId, NodeId, PhysId, VirtId};
use bitfield_struct::bitfield;

use super::field::{OperandAddr, OperandProperties};
use super::*;

// Define type alias for underlying native type.
// NB: Currently bitfield don't support type alias and thus we use native type instead
pub type IOpWordRepr = u32;
pub type IOpRepr = Vec<u32>;

#[bitfield(u32)]
pub struct OperandPropertiesHex {
    #[bits(5)]
    _pad: u16,
    #[bits(8)]
    block: u8,
    #[bits(5)]
    vec_size: u8,
    #[bits(8)]
    iid: u8,
    #[bits(3)]
    pos: u8,
    #[bits(1)]
    is_last: bool,
    #[bits(2)]
    kind: u8,
}

impl From<&OperandPropertiesHex> for field::OperandProperties {
    fn from(value: &OperandPropertiesHex) -> Self {
        let kind = if value.kind() == OperandKind::Src as u8 {
            OperandKind::Src
        } else if value.kind() == OperandKind::Dst as u8 {
            OperandKind::Dst
        } else if value.kind() == OperandKind::Imm as u8 {
            OperandKind::Imm
        } else {
            OperandKind::Unknown
        };

        Self {
            block: field::OperandBlock(value.block()),
            vec_size: field::VectorSize(value.vec_size()),
            is_last: value.is_last(),
            iid: IOpId(value.iid()),
            pos: NodeId(value.pos()),
            kind,
        }
    }
}

impl From<&OperandProperties> for OperandPropertiesHex {
    fn from(value: &OperandProperties) -> Self {
        Self::new()
            .with_block(value.block.0)
            .with_vec_size(value.vec_size.0)
            .with_is_last(value.is_last)
            .with_iid(value.iid.0)
            .with_pos(value.pos.0)
            .with_kind(value.kind as u8)
    }
}

#[bitfield(u32)]
pub struct OperandAddrHex {
    #[bits(16)]
    base_cid: u16,
    #[bits(16)]
    _pad: u16,
}

impl From<&OperandAddrHex> for field::OperandAddr {
    fn from(value: &OperandAddrHex) -> Self {
        Self {
            base_cid: CtId(value.base_cid()),
        }
    }
}

impl From<&OperandAddr> for OperandAddrHex {
    fn from(value: &OperandAddr) -> Self {
        Self::new().with_base_cid(value.base_cid.0)
    }
}

#[bitfield(u32)]
pub struct ImmediateHeaderHex {
    #[bits(16)]
    lsb_msg: u16,
    #[bits(12)]
    block: u16,
    #[bits(1)]
    is_last: bool,
    #[bits(1)]
    _reserved: u8,
    #[bits(2)]
    kind: u8,
}

impl From<&ImmediateHeaderHex> for field::ImmediateHeader {
    fn from(value: &ImmediateHeaderHex) -> Self {
        let kind = if value.kind() == OperandKind::Src as u8 {
            OperandKind::Src
        } else if value.kind() == OperandKind::Dst as u8 {
            OperandKind::Dst
        } else if value.kind() == OperandKind::Imm as u8 {
            OperandKind::Imm
        } else {
            OperandKind::Unknown
        };

        Self {
            lsb_msg: value.lsb_msg(),
            block: field::ImmBlock(value.block()),
            is_last: value.is_last(),
            kind,
        }
    }
}

impl From<&field::ImmediateHeader> for ImmediateHeaderHex {
    fn from(value: &field::ImmediateHeader) -> Self {
        Self::new()
            .with_lsb_msg(value.lsb_msg)
            .with_block(value.block.0)
            .with_is_last(value.is_last)
            .with_kind(value.kind as u8)
    }
}

#[bitfield(u32)]
pub struct IOpHeaderHex {
    #[bits(8)]
    src_align: u8,
    #[bits(8)]
    dst_align: u8,
    #[bits(8)]
    opcode: u8,
    #[bits(1)]
    has_imm: bool,
    #[bits(1)]
    fw_mode: bool,
    #[bits(6)]
    _reserved: u8,
}

impl From<&IOpHeaderHex> for field::IOpHeader {
    fn from(value: &IOpHeaderHex) -> Self {
        let fw_mode = match value.fw_mode() {
            true => field::FwMode::Dynamic,
            false => field::FwMode::Static,
        };

        Self {
            src_align: field::OperandBlock(value.src_align()),
            dst_align: field::OperandBlock(value.dst_align()),
            opcode: field::IOpcode(value.opcode()),
            has_imm: value.has_imm(),
            fw_mode,
        }
    }
}

impl From<&field::IOpHeader> for IOpHeaderHex {
    fn from(value: &field::IOpHeader) -> Self {
        let fw_mode = match value.fw_mode {
            field::FwMode::Dynamic => true,
            field::FwMode::Static => false,
        };

        Self::new()
            .with_src_align(value.src_align.0)
            .with_dst_align(value.dst_align.0)
            .with_opcode(value.opcode.0)
            .with_has_imm(value.has_imm)
            .with_fw_mode(fw_mode)
    }
}

#[bitfield(u32)]
pub struct IOpMappingHex {
    #[bits(1)]
    used_0: bool,
    #[bits(3)]
    virt_0: u8,
    #[bits(1)]
    used_1: bool,
    #[bits(3)]
    virt_1: u8,
    #[bits(1)]
    used_2: bool,
    #[bits(3)]
    virt_2: u8,
    #[bits(1)]
    used_3: bool,
    #[bits(3)]
    virt_3: u8,
    #[bits(1)]
    used_4: bool,
    #[bits(3)]
    virt_4: u8,
    #[bits(1)]
    used_5: bool,
    #[bits(3)]
    virt_5: u8,
    #[bits(1)]
    used_6: bool,
    #[bits(3)]
    virt_6: u8,
    #[bits(1)]
    used_7: bool,
    #[bits(3)]
    virt_7: u8,
}

impl From<&IOpMappingHex> for field::IOpMapping {
    fn from(value: &IOpMappingHex) -> Self {
        let raw_value = u32::from(*value);
        let mut vid_pid_map = (0..MAX_HPU_IN_CLUSTER)
            .filter_map(|i| {
                let raw_pos = (raw_value >> (4 * i)) & 0xf;
                if (raw_pos & 0x1) == 0x1 {
                    Some((((raw_pos & 0xe) >> 1), i as u8))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Sort map by virtual_id
        vid_pid_map.sort_by_key(|x| x.0);

        // Extract ordered list and check for hole in the mapping
        let map = {
            let min = vid_pid_map.iter().map(|x| x.0).min().unwrap_or(0);
            let max = vid_pid_map.iter().map(|x| x.0).max().unwrap_or(0);
            if (vid_pid_map.len() != (max + 1) as usize) || (min != 0) {
                panic!("Invalid mapping: contain hole or duplicate values");
            }
            vid_pid_map.iter().map(|x| x.1).collect::<Vec<_>>()
        };
        Self::from(map)
    }
}

impl From<&field::IOpMapping> for IOpMappingHex {
    fn from(value: &field::IOpMapping) -> Self {
        Self::new()
            // Set used flags
            .with_used_0(value.virt_id(PhysId(0)).is_some())
            .with_used_1(value.virt_id(PhysId(1)).is_some())
            .with_used_2(value.virt_id(PhysId(2)).is_some())
            .with_used_3(value.virt_id(PhysId(3)).is_some())
            .with_used_4(value.virt_id(PhysId(4)).is_some())
            .with_used_5(value.virt_id(PhysId(5)).is_some())
            .with_used_6(value.virt_id(PhysId(6)).is_some())
            .with_used_7(value.virt_id(PhysId(7)).is_some())
            // Set value or 0
            .with_virt_0(value.virt_id(PhysId(0)).unwrap_or(VirtId(0)).0)
            .with_virt_1(value.virt_id(PhysId(1)).unwrap_or(VirtId(0)).0)
            .with_virt_2(value.virt_id(PhysId(2)).unwrap_or(VirtId(0)).0)
            .with_virt_3(value.virt_id(PhysId(3)).unwrap_or(VirtId(0)).0)
            .with_virt_4(value.virt_id(PhysId(4)).unwrap_or(VirtId(0)).0)
            .with_virt_5(value.virt_id(PhysId(5)).unwrap_or(VirtId(0)).0)
            .with_virt_6(value.virt_id(PhysId(6)).unwrap_or(VirtId(0)).0)
            .with_virt_7(value.virt_id(PhysId(7)).unwrap_or(VirtId(0)).0)
    }
}
