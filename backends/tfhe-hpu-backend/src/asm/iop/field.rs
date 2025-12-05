//! List of IOp field
//! Mainly thin wrapper over basic type to enforce correct used of asm fields
use super::*;
use crate::asm::CtId;

use thiserror::Error;

/// Parsing error
#[derive(Error, Debug, Clone)]
pub enum HexParsingError {
    #[error("Invalid header")]
    Header,
    #[error("Invalid Operand Kind: {0}")]
    Kind(String),
    #[error("Invalid operand blocks")]
    Block,
    #[error("Incomplete stream")]
    EmptyStream,
}

// Vectorized ciphertext operands
// ------------------------------------------------------------------------------------------------
/// Type of the operands
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OperandKind {
    Src = 0x0,
    Dst = 0x1,
    Imm = 0x2,
    Unknown = 0x3,
}

/// VectorSize
/// => Number of operands defined in the operands block
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VectorSize(pub u8);
impl VectorSize {
    /// Create vector size with the correct encoding
    pub fn new(len: u8) -> Self {
        assert!(len != 0, "Empty vector couldn't be encoded");
        Self(len - 1)
    }
}

/// OperandSize
/// => Number of valid digit in oach operand block
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperandBlock(pub u8);
impl OperandBlock {
    /// Create vector size with the correct encoding
    pub fn new(width: u8) -> Self {
        assert!(width != 0, "Empty block couldn't be encoded");
        Self(width - 1)
    }
}

/// Ciphertext vectorized operands with extra parsing flags
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Operand {
    pub base_cid: CtId,
    pub block: OperandBlock,
    pub vec_size: VectorSize,
    pub is_last: bool,
    pub kind: OperandKind,
}

impl Operand {
    pub(crate) fn new(block: u8, base_cid: u16, vec_size: u8, kind: Option<OperandKind>) -> Self {
        Self {
            kind: kind.unwrap_or(OperandKind::Unknown),
            is_last: false,
            vec_size: VectorSize::new(vec_size),
            block: OperandBlock::new(block),
            base_cid: CtId(base_cid),
        }
    }
}

/// Create a dedicated type for a collection of Immediate
/// This is to enable trait implementation on it (c.f arg)
#[derive(Debug, Clone)]
pub struct OperandBundle(Vec<Operand>);

impl OperandBundle {
    pub(crate) fn set_kind(&mut self, kind: OperandKind) {
        assert!(
            kind != OperandKind::Imm,
            "OperandBundle couldn't be tagged as Imm"
        );
        self.0.iter_mut().for_each(|op| op.kind = kind);
    }
}

impl From<Vec<Operand>> for OperandBundle {
    fn from(inner: Vec<Operand>) -> Self {
        let mut inner = inner;
        // Enforce correct is_last handling
        inner.iter_mut().for_each(|op| op.is_last = false);
        if let Some(last) = inner.last_mut() {
            last.is_last = true;
        }
        Self(inner)
    }
}

impl std::ops::Deref for OperandBundle {
    type Target = Vec<Operand>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl OperandBundle {
    #[tracing::instrument(level = "trace", ret)]
    pub fn from_words(stream: &[IOpWordRepr]) -> Result<(Self, usize), HexParsingError> {
        // Keep track of the current peak index
        let mut peak_words = 0;

        let mut op_list = Vec::new();
        loop {
            let op = if let Some(op_word) = stream.get(peak_words) {
                peak_words += 1;
                Operand::from(&fmt::OperandHex::from_bits(*op_word))
            } else {
                return Err(HexParsingError::EmptyStream);
            };
            op_list.push(op);
            if op.is_last {
                break;
            }
        }
        Ok((Self(op_list), peak_words))
    }
    #[tracing::instrument(level = "trace", ret)]
    pub fn to_words(&self) -> Vec<IOpWordRepr> {
        self.0
            .iter()
            .map(|op| fmt::OperandHex::from(op).into_bits())
            .collect::<Vec<_>>()
    }
}

// Immediate operands
// ------------------------------------------------------------------------------------------------
/// Immediate Size
/// => Number of valid digit in following immediate
/// To obtain the number of valid bits, user should multiply by the msg_width
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImmBlock(pub u16);

/// Immediate header
/// Use to implement top-level parser manually
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImmediateHeader {
    pub(super) lsb_msg: u16,
    pub(super) block: ImmBlock,
    pub(super) is_last: bool,
    pub(super) kind: OperandKind,
}

/// Full Immediate representation (i.e. header + data)
#[derive(Debug, Clone, PartialEq)]
pub struct Immediate {
    pub(super) kind: OperandKind,
    pub(super) is_last: bool,
    pub(super) block: ImmBlock,
    pub(super) msg: Vec<u16>,
}

impl Immediate {
    /// Access imm msg for template patching
    /// Extract the correct block (i.e. MSG_WIDTH chunk)
    pub fn msg_block(&self, bid: u8) -> u16 {
        let word_id = bid as u32 / (u16::BITS / MSG_WIDTH as u32);
        let block_id = bid as u32 % (u16::BITS / MSG_WIDTH as u32);
        if let Some(word) = self.msg.get(word_id as usize) {
            (word >> (block_id * MSG_WIDTH as u32)) & ((1 << MSG_WIDTH) - 1)
        } else {
            0
        }
    }

    pub fn from_cst(cst: u128) -> Self {
        let mut u16_cst = cst
            .to_le_bytes()
            .chunks(2)
            .map(|x| u16::from_le_bytes(x.try_into().unwrap()))
            .collect::<Vec<_>>();

        let mut cst = cst;
        let block = {
            let mut block = 0;
            while cst != 0 {
                block += 1;
                cst >>= 2;
            }
            ImmBlock(block)
        };

        // Shrink to fit
        let msg_word = usize::div_ceil(block.0 as usize * MSG_WIDTH as usize, u16::BITS as usize);
        u16_cst.resize(msg_word, 0);

        Self {
            kind: OperandKind::Imm,
            is_last: false,
            block,
            msg: u16_cst,
        }
    }
    pub fn cst_value(&self) -> u128 {
        self.msg
            .iter()
            .enumerate()
            .map(|(pos, val)| (*val as u128) << (8 * std::mem::size_of::<u16>() * pos))
            .sum::<u128>()
    }
}

impl Immediate {
    #[tracing::instrument(level = "trace", ret)]
    pub fn from_words(stream: &[IOpWordRepr]) -> Result<(Self, usize), HexParsingError> {
        // Keep track of the current peak index
        let mut peak_words = 0;

        // 1. Parse header
        let header = if let Some(header_word) = stream.get(peak_words) {
            peak_words += 1;
            ImmediateHeader::from(&fmt::ImmediateHeaderHex::from_bits(*header_word))
        } else {
            return Err(HexParsingError::EmptyStream);
        };

        // Check flags
        if header.kind != OperandKind::Imm {
            return Err(HexParsingError::Kind(format!(
                "Get {:?} instead of {:?}",
                header.kind,
                OperandKind::Imm
            )));
        }

        // Get associated value:
        let mut le_msg = vec![header.lsb_msg];

        let data_word = usize::div_ceil(
            header.block.0 as usize * MSG_WIDTH as usize,
            8 * (std::mem::size_of::<IOpWordRepr>() / std::mem::size_of::<u16>()),
        );

        // NB: First imm word is encoded in the header
        for _w in 0..(data_word / 2) {
            if let Some(word) = stream.get(peak_words) {
                peak_words += 1;
                let u16_words = word
                    .to_le_bytes()
                    .chunks(2)
                    .map(|x| u16::from_le_bytes(x.try_into().unwrap()))
                    .collect::<Vec<_>>();
                le_msg.extend_from_slice(u16_words.as_slice());
            } else {
                return Err(HexParsingError::EmptyStream);
            }
        }

        Ok((
            Self {
                kind: header.kind,
                is_last: header.is_last,
                block: header.block,
                msg: le_msg,
            },
            peak_words,
        ))
    }

    pub fn to_words(&self) -> Vec<IOpWordRepr> {
        let mut words = Vec::new();
        let header = ImmediateHeader {
            lsb_msg: *self.msg.first().unwrap_or(&0),
            block: self.block,
            is_last: self.is_last,
            kind: self.kind,
        };
        words.push(fmt::ImmediateHeaderHex::from(&header).into_bits());

        if self.msg.len() > 1 {
            for imm in self.msg[1..]
                .chunks(std::mem::size_of::<IOpWordRepr>() / std::mem::size_of_val(&self.msg[0]))
            {
                let imm_word = match imm.len() {
                    1 => IOpWordRepr::from(imm[0]),
                    2 => IOpWordRepr::from(
                        imm[0] as IOpWordRepr + ((imm[1] as IOpWordRepr) << u16::BITS),
                    ),
                    _ => panic!("Unsupported chunks, IOpWordRepr has been changed"),
                };
                words.push(imm_word);
            }
        }
        words
    }
}

/// Create a dedicated type for a collection of Immediate
/// This is to enable trait implementation on it (c.f arg)
#[derive(Debug, Clone)]
pub struct ImmBundle(Vec<Immediate>);

impl ImmBundle {
    #[tracing::instrument(level = "trace", ret)]
    pub fn from_words(stream: &[IOpWordRepr]) -> Result<(Self, usize), HexParsingError> {
        // Keep track of the current peak index
        let mut peak_words = 0;

        let mut imm_list = Vec::new();
        loop {
            let (imm, peaked) = Immediate::from_words(&stream[peak_words..])?;
            peak_words += peaked;

            let is_last = imm.is_last;
            imm_list.push(imm);
            if is_last {
                break;
            }
        }
        Ok((Self(imm_list), peak_words))
    }
    #[tracing::instrument(level = "trace", ret)]
    pub fn to_words(&self) -> Vec<IOpWordRepr> {
        self.0
            .iter()
            .flat_map(|imm| imm.to_words())
            .collect::<Vec<_>>()
    }
}

impl From<Vec<Immediate>> for ImmBundle {
    #[tracing::instrument(level = "trace", ret)]
    fn from(inner: Vec<Immediate>) -> Self {
        let mut inner = inner;
        // Enforce correct is_last handling
        inner.iter_mut().for_each(|op| op.is_last = false);
        if let Some(last) = inner.last_mut() {
            last.is_last = true;
        }
        Self(inner)
    }
}

impl std::ops::Deref for ImmBundle {
    type Target = Vec<Immediate>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// IOp header
// ------------------------------------------------------------------------------------------------
/// Opcode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct IOpcode(pub u8);

/// Type of the operands
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FwMode {
    Static = 0x0,
    Dynamic = 0x1,
}

/// IOpHeader
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IOpHeader {
    pub(super) src_align: OperandBlock,
    pub(super) dst_align: OperandBlock,
    pub(super) opcode: IOpcode,
    pub(super) has_imm: bool,
    pub(super) fw_mode: FwMode,
}

/// Gather all subparts together
#[derive(Debug, Clone)]
pub struct IOp {
    pub(super) header: IOpHeader,
    pub(super) dst: OperandBundle,
    pub(super) src: OperandBundle,
    pub(super) imm: ImmBundle,
}
use std::collections::VecDeque;

/// Implement construction
/// Used to construct IOp from Backend HpuVar
impl IOp {
    pub fn new(opcode: IOpcode, dst: Vec<Operand>, src: Vec<Operand>, imm: Vec<Immediate>) -> Self {
        let dst_align = dst.iter().map(|x| x.block).max().unwrap();
        let src_align = src.iter().map(|x| x.block).max().unwrap();
        let has_imm = !imm.is_empty();

        let header = IOpHeader {
            src_align,
            dst_align,
            opcode,
            has_imm,
            fw_mode: FwMode::Static,
        };
        Self {
            header,
            dst: dst.into(),
            src: src.into(),
            imm: imm.into(),
        }
    }

    pub fn opcode(&self) -> IOpcode {
        self.header.opcode
    }
    pub fn asm_opcode(&self) -> AsmIOpcode {
        self.header.opcode.into()
    }

    // Compute associated fw block size
    // Used to compute fw_entry offset and fw translation validity
    pub fn fw_blk_width(&self) -> usize {
        std::cmp::max(self.header.dst_align.0, self.header.src_align.0) as usize
    }

    // Compute fw table entry
    pub fn fw_entry(&self) -> usize {
        self.fw_blk_width() * 0x100 + self.header.opcode.0 as usize
    }
    pub fn dst(&self) -> &OperandBundle {
        &self.dst
    }
    pub fn src(&self) -> &OperandBundle {
        &self.src
    }
    pub fn imm(&self) -> &ImmBundle {
        &self.imm
    }
}
/// Implement parsing logic from stream of word
/// Only consume the VecDeque on Success
impl IOp {
    #[tracing::instrument(level = "trace", ret)]
    pub fn from_words(stream: &mut VecDeque<IOpWordRepr>) -> Result<Self, HexParsingError> {
        // Keep track of the current peak index
        let mut peak_words = 0;

        // Enforce contiguous for ease of addressing in the queue
        stream.make_contiguous();

        // 1. Parse header
        let header = if let Some(header_word) = stream.get(peak_words) {
            peak_words += 1;
            IOpHeader::from(&fmt::IOpHeaderHex::from(*header_word))
        } else {
            return Err(HexParsingError::EmptyStream);
        };

        // 2. Parse Destination operands
        let dst = {
            let (dst, peaked) = OperandBundle::from_words(&stream.as_slices().0[peak_words..])?;
            for op in dst.iter() {
                // Check flags
                if op.kind != OperandKind::Dst {
                    return Err(HexParsingError::Kind(format!(
                        "Get {:?} instead of {:?}",
                        op.kind,
                        OperandKind::Dst
                    )));
                }
                if op.block > header.dst_align {
                    return Err(HexParsingError::Kind(format!(
                        "Get {:?} > {:?}",
                        op.block, header.dst_align
                    )));
                }
            }
            peak_words += peaked;
            dst
        };

        // 3. Parse Source operands
        let src = {
            let (src, peaked) = OperandBundle::from_words(&stream.as_slices().0[peak_words..])?;
            for op in src.iter() {
                // Check flags
                if op.kind != OperandKind::Src {
                    return Err(HexParsingError::Kind(format!(
                        "Get {:?} instead of {:?}",
                        op.kind,
                        OperandKind::Src
                    )));
                }
                if op.block > header.src_align {
                    return Err(HexParsingError::Kind(format!(
                        "Get {:?} > {:?}",
                        op.block, header.src_align
                    )));
                }
            }
            peak_words += peaked;
            src
        };

        // 4. Parse Immediate [Optional]
        let (imm, peaked) = if header.has_imm {
            ImmBundle::from_words(&stream.as_slices().0[peak_words..])?
        } else {
            (ImmBundle(Vec::new()), 0)
        };
        peak_words += peaked;

        // Successful extraction from the dequeue
        // Consume the associated words
        stream.drain(0..peak_words);

        Ok(Self {
            header,
            dst,
            src,
            imm,
        })
    }

    #[tracing::instrument(level = "trace", ret)]
    pub fn to_words(&self) -> Vec<IOpWordRepr> {
        let mut words = Vec::new();
        // 1. Header
        words.push(fmt::IOpHeaderHex::from(&self.header).into_bits());
        // 2. Destination
        words.extend(self.dst.to_words());
        // 3. Sources
        words.extend(self.src.to_words());
        // 4. Immediate
        words.extend(self.imm.to_words());
        words
    }
}
