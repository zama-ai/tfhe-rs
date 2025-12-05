//!
//! Define binary format encoding of IOp instructions
//! Rely on `bitfield_struct` crate to define bit-accurate insn format
//! and some manual From/To implementation to move to internal type
use crate::asm::CtId;
use bitfield_struct::bitfield;

use super::*;

// Define type alias for underlying native type.
// NB: Currently bitfield don't support type alias and thus we use native type instead
pub type IOpWordRepr = u32;
pub type IOpRepr = Vec<u32>;

#[bitfield(u32)]
pub struct OperandHex {
    #[bits(16)]
    base_cid: u16,
    #[bits(8)]
    block: u8,
    #[bits(5)]
    vec_size: u8,
    #[bits(1)]
    is_last: bool,
    #[bits(2)]
    kind: u8,
}

impl From<&OperandHex> for field::Operand {
    fn from(value: &OperandHex) -> Self {
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
            base_cid: CtId(value.base_cid()),
            block: field::OperandBlock(value.block()),
            vec_size: field::VectorSize(value.vec_size()),
            is_last: value.is_last(),
            kind,
        }
    }
}

impl From<&Operand> for OperandHex {
    fn from(value: &Operand) -> Self {
        Self::new()
            .with_base_cid(value.base_cid.0)
            .with_block(value.block.0)
            .with_vec_size(value.vec_size.0)
            .with_is_last(value.is_last)
            .with_kind(value.kind as u8)
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
