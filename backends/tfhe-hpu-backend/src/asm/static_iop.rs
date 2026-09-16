//!
//! Static IOp catalog: name, legacy opcode byte, and the `zhc_builder`
//! function used to compile it into a circuit.
//!
//! Bridge legacy opcode with zhc_builder and define predefined name for asm mnemonics
//!
//! Current Opcode space could be viewed as follow:
//! | Range      | Categories                |
//! | ---------- | ------------------------- |
//! | 0x00.. 0x7f| User custom operations    |
//! | 0x80.. 0xff| Fw generated operations   |
//! | ---------- | ------------------------- |

use zhc::builder::{Builder, CiphertextSpec};
use zhc::config::hpu::HpuConfig;
use zhc::prelude::{Pipeline, PipelineExt};

use super::arg::Cursor;
use super::*;

/// Static IOp: fixed name, fixed legacy opcode byte, and a direct `zhc_builder` function.
///
/// Only ever covers parameter-free operations — `zhc_builder`'s parametrized ones (`cast`, `sum`)
/// don't fit a fixed-opcode-byte scheme (the same raw byte would have to mean every parameter
/// value at once), so they aren't represented here.
/// NB: Small tricks in [`get_opcode`](Iop::get_opcode) enable to unamed IOp and still coerce
///     to correct opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StaticIOp {
    // Uname section ----------------------------------------------------------
    IOp(u8) = 0x0,

    // Ct x Imm ---------------------------------------------------------------
    // Arith operations
    Adds = 0xA0,
    Subs = 0xA1,
    Ssub = 0xA2,
    Muls = 0xA3,
    Divs = 0xA4,
    Mods = 0xA5,
    // Overflowing Arith
    OvfAdds = 0xA8,
    OvfSubs = 0xA9,
    OvfSsub = 0xAA,
    OvfMuls = 0xAB,
    // Rotation and Shift
    RightShifts = 0xAC,
    LeftShifts = 0xAD,
    RightRots = 0xAE,
    LeftRots = 0xAF,

    // Ct x Ct ----------------------------------------------------------------
    // Arith operations
    Add = 0xE0,
    Sub = 0xE2,
    Mul = 0xE4,
    Div = 0xE5,
    Mod = 0xE6,
    // Overflowing Arith
    OvfAdd = 0xE8,
    OvfSub = 0xEA,
    OvfMul = 0xEC,
    // BW operations
    BwAnd = 0xD0,
    BwOr = 0xD1,
    BwXor = 0xD2,
    BwNot = 0xD3,
    // Rotation and shift
    RightShift = 0xDC,
    LeftShift = 0xDD,
    RightRot = 0xDE,
    LeftRot = 0xDF,
    // Cmp operations
    CmpGt = 0xC0,
    CmpGte = 0xC1,
    CmpLt = 0xC2,
    CmpLte = 0xC3,
    CmpEq = 0xC4,
    CmpNeq = 0xC5,
    // Ternary operations
    IfThenZero = 0xCA,
    IfThenElse = 0xCB,
    // Custom algorithm
    Erc7984 = 0x80,
    // Count bits
    CountZeros = 0x81,
    CountOnes = 0x82,
    Ilog2 = 0x83,
    LeadingZeros = 0x84,
    LeadingOnes = 0x85,
    TrailingZeros = 0x86,
    TrailingOnes = 0x87,
    // SIMD for maximum throughput
    AddSimd = 0xF0,
    Erc7984Simd = 0xF1,
    // Utility operations
    Flip = 0xFE,
    MemCpy = 0xFF,
}

impl StaticIOp {
    pub fn get_opcode(&self) -> u8 {
        // SAFETY: repr(u8) guarantees the discriminant is the first u8 in the layout
        // NB: Enum discriminant is used and opcode
        match self {
            // Explicit user encoded opcode
            Self::IOp(n) => *n,
            // Named opcode
            _ => unsafe { *(self as *const Self as *const u8) },
        }
    }

    /// Reverse of [`Self::get_opcode`]: looks up the named variant matching `opcode`, falling
    /// back to the raw unnamed `IOp(opcode)` form if none matches (e.g. a user/custom opcode).
    pub fn from_opcode(opcode: u8) -> Self {
        Self::ALL
            .iter()
            .find(|iop| iop.get_opcode() == opcode)
            .copied()
            .unwrap_or(Self::IOp(opcode))
    }

    /// Define starting boundary of User defined static IOp
    pub const USER_RANGE_LB: u8 = 0x0;
    /// Define ending boundary of User defined static IOp
    pub const USER_RANGE_UB: u8 = 0x7f;

    /// Every predefined IOp, in no particular order.
    pub const ALL: &'static [Self] = &[
        Self::Adds,
        Self::Subs,
        Self::Ssub,
        Self::Muls,
        Self::Divs,
        Self::Mods,
        Self::OvfAdds,
        Self::OvfSubs,
        Self::OvfSsub,
        Self::OvfMuls,
        Self::RightShifts,
        Self::LeftShifts,
        Self::RightRots,
        Self::LeftRots,
        Self::Add,
        Self::Sub,
        Self::Mul,
        Self::Div,
        Self::Mod,
        Self::OvfAdd,
        Self::OvfSub,
        Self::OvfMul,
        Self::BwAnd,
        Self::BwOr,
        Self::BwXor,
        Self::BwNot,
        Self::RightShift,
        Self::LeftShift,
        Self::RightRot,
        Self::LeftRot,
        Self::CmpGt,
        Self::CmpGte,
        Self::CmpLt,
        Self::CmpLte,
        Self::CmpEq,
        Self::CmpNeq,
        Self::IfThenZero,
        Self::IfThenElse,
        Self::Erc7984,
        Self::CountZeros,
        Self::CountOnes,
        Self::Ilog2,
        Self::LeadingZeros,
        Self::LeadingOnes,
        Self::TrailingZeros,
        Self::TrailingOnes,
        Self::AddSimd,
        Self::Erc7984Simd,
        Self::Flip,
        Self::MemCpy,
    ];

    /// The asm mnemonic this operation is parsed from / displayed as (inverse of `FromStr`).
    pub fn name(&self) -> &'static str {
        match self {
            Self::IOp(_) => "IOP[x]", // Fixme issue with static lifetime
            Self::Adds => "ADDS",
            Self::Subs => "SUBS",
            Self::Ssub => "SSUB",
            Self::Muls => "MULS",
            Self::Divs => "DIVS",
            Self::Mods => "MODS",
            Self::OvfAdds => "OVF_ADDS",
            Self::OvfSubs => "OVF_SUBS",
            Self::OvfSsub => "OVF_SSUB",
            Self::OvfMuls => "OVF_MULS",
            Self::RightShifts => "SHIFTS_R",
            Self::LeftShifts => "SHIFTS_L",
            Self::RightRots => "ROTS_R",
            Self::LeftRots => "ROTS_L",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::Mod => "MOD",
            Self::OvfAdd => "OVF_ADD",
            Self::OvfSub => "OVF_SUB",
            Self::OvfMul => "OVF_MUL",
            Self::BwAnd => "BW_AND",
            Self::BwOr => "BW_OR",
            Self::BwXor => "BW_XOR",
            Self::BwNot => "BW_NOT",
            Self::RightShift => "SHIFT_R",
            Self::LeftShift => "SHIFT_L",
            Self::RightRot => "ROT_R",
            Self::LeftRot => "ROT_L",
            Self::CmpGt => "CMP_GT",
            Self::CmpGte => "CMP_GTE",
            Self::CmpLt => "CMP_LT",
            Self::CmpLte => "CMP_LTE",
            Self::CmpEq => "CMP_EQ",
            Self::CmpNeq => "CMP_NEQ",
            Self::IfThenZero => "IF_THEN_ZERO",
            Self::IfThenElse => "IF_THEN_ELSE",
            Self::Erc7984 => "ERC_7984",
            Self::CountZeros => "COUNT0",
            Self::CountOnes => "COUNT1",
            Self::Ilog2 => "ILOG2",
            Self::LeadingZeros => "LEAD0",
            Self::LeadingOnes => "LEAD1",
            Self::TrailingZeros => "TRAIL0",
            Self::TrailingOnes => "TRAIL1",
            Self::AddSimd => "ADD_SIMD",
            Self::Erc7984Simd => "ERC_7984_SIMD",
            Self::Flip => "FLIP",
            Self::MemCpy => "MEMCPY",
        }
    }

    /// Bridges this IOp to the `zhc_builder` function that compiles it into a circuit.
    pub fn to_builder(&self, spec: CiphertextSpec) -> Builder {
        use zhc::builder::*;
        match self {
            Self::IOp(n) => panic!("IOp[{n}] format couldn't be used with builder."),
            Self::Adds => adds(spec),
            Self::Subs => subs(spec),
            Self::Ssub => ssub(spec),
            Self::Muls => muls(spec),
            Self::Divs => divs(spec),
            Self::Mods => mods(spec),
            Self::OvfAdds => overflow_adds(spec),
            Self::OvfSubs => overflow_subs(spec),
            Self::OvfSsub => overflow_ssub(spec),
            Self::OvfMuls => overflow_muls(spec),
            Self::RightShifts => shifts_right(spec),
            Self::LeftShifts => shifts_left(spec),
            Self::RightRots => rots_right(spec),
            Self::LeftRots => rots_left(spec),
            Self::Add => add(spec),
            Self::Sub => sub(spec),
            Self::Mul => mul(spec),
            Self::Div => div(spec),
            Self::Mod => rem(spec),
            Self::OvfAdd => overflow_add(spec),
            Self::OvfSub => overflow_sub(spec),
            Self::OvfMul => overflow_mul(spec),
            Self::BwAnd => bitwise_and(spec),
            Self::BwOr => bitwise_or(spec),
            Self::BwXor => bitwise_xor(spec),
            Self::BwNot => bitwise_inv(spec),
            Self::RightShift => shift_right(spec),
            Self::LeftShift => shift_left(spec),
            Self::RightRot => rotate_right(spec),
            Self::LeftRot => rotate_left(spec),
            Self::CmpGt => cmp_gt(spec),
            Self::CmpGte => cmp_gte(spec),
            Self::CmpLt => cmp_lt(spec),
            Self::CmpLte => cmp_lte(spec),
            Self::CmpEq => cmp_eq(spec),
            Self::CmpNeq => cmp_neq(spec),
            Self::IfThenZero => if_then_zero(spec),
            Self::IfThenElse => if_then_else(spec),
            Self::Erc7984 => erc7984(spec),
            Self::CountZeros => count_0(spec),
            Self::CountOnes => count_1(spec),
            Self::Ilog2 => ilog2(spec),
            Self::LeadingZeros => lead0(spec),
            Self::LeadingOnes => lead1(spec),
            Self::TrailingZeros => trail0(spec),
            Self::TrailingOnes => trail1(spec),
            Self::AddSimd => add_simd(spec),
            Self::Erc7984Simd => erc7984_simd(spec),
            Self::Flip => flip(spec),
            Self::MemCpy => memcpy(spec),
        }
    }

    /// Retrieved full HPU compilation pipeline for static IOp at a given spec
    /// NB: Some IOp still benefits from legacy hpu scheduler based on their kind and size.
    pub fn get_hpu_pipeline(&self, hpu_config: &HpuConfig, spec: CiphertextSpec) -> Pipeline {
        let pipeline = Pipeline::new()
            .with_builder(self.to_builder(spec))
            .with_hpu_config(hpu_config.clone());
        match (self, spec.int_size()) {
            (Self::Mul, _)
            | (Self::OvfMul, _)
            | (Self::RightRot | Self::LeftRot | Self::LeftShift | Self::RightShift, 128) => {
                pipeline.with_legacy_hpu_scheduler()
            }
            _ => pipeline,
        }
    }
}

/// Width asm mnemonics are padded to when rendered (c.f. `Display for StaticIOp`).
pub const ASM_OPCODE_WIDTH: usize = 8;

impl std::fmt::Display for StaticIOp {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match *self {
            Self::IOp(n) => format!("IOP[0x{n:x}]"),
            named => named.name().to_string(),
        };
        write!(f, "{name: <ASM_OPCODE_WIDTH$}")
    }
}

/// Extract StaticIOp from IOpcode
impl From<IOpcode> for StaticIOp {
    fn from(opcode: IOpcode) -> Self {
        Self::from_opcode(opcode.0)
    }
}

/// Extract StaticIOp from IOp
/// This is used from proper rendering in asm
impl From<&IOp> for StaticIOp {
    fn from(iop: &IOp) -> Self {
        Self::from(iop.header.opcode)
    }
}

impl From<StaticIOp> for IOpcode {
    fn from(iop: StaticIOp) -> Self {
        Self(iop.get_opcode())
    }
}

impl std::str::FromStr for StaticIOp {
    type Err = Box<ParsingError>;

    /// Parses either the raw form `IOP[0x..]`/`IOP[<dec>]`, or a bare mnemonic alias
    /// (`ADD`, `MUL`, ...).
    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut c = Cursor::new(s);
        if c.eat_str("IOP[") {
            let value: u8 = c.parse_uint(s, "opcode value")?;
            c.expect_char(']', s)?;
            c.expect_eof(s)?;
            if (Self::USER_RANGE_LB..=Self::USER_RANGE_UB).contains(&value) {
                Ok(Self::IOp(value))
            } else {
                Err(Box::new(ParsingError::Opcode(value)))
            }
        } else {
            let alias = c.rest();
            match alias {
                "ADDS" => Ok(Self::Adds),
                "SUBS" => Ok(Self::Subs),
                "SSUB" => Ok(Self::Ssub),
                "MULS" => Ok(Self::Muls),
                "DIVS" => Ok(Self::Divs),
                "MODS" => Ok(Self::Mods),
                "OVF_ADDS" => Ok(Self::OvfAdds),
                "OVF_SUBS" => Ok(Self::OvfSubs),
                "OVF_SSUB" => Ok(Self::OvfSsub),
                "OVF_MULS" => Ok(Self::OvfMuls),
                "SHIFTS_R" => Ok(Self::RightShifts),
                "SHIFTS_L" => Ok(Self::LeftShifts),
                "ROTS_R" => Ok(Self::RightRots),
                "ROTS_L" => Ok(Self::LeftRots),
                "ADD" => Ok(Self::Add),
                "SUB" => Ok(Self::Sub),
                "MUL" => Ok(Self::Mul),
                "DIV" => Ok(Self::Div),
                "MOD" => Ok(Self::Mod),
                "OVF_ADD" => Ok(Self::OvfAdd),
                "OVF_SUB" => Ok(Self::OvfSub),
                "OVF_MUL" => Ok(Self::OvfMul),
                "BW_AND" => Ok(Self::BwAnd),
                "BW_OR" => Ok(Self::BwOr),
                "BW_XOR" => Ok(Self::BwXor),
                "BW_NOT" => Ok(Self::BwNot),
                "SHIFT_R" => Ok(Self::RightShift),
                "SHIFT_L" => Ok(Self::LeftShift),
                "ROT_R" => Ok(Self::RightRot),
                "ROT_L" => Ok(Self::LeftRot),
                "CMP_GT" => Ok(Self::CmpGt),
                "CMP_GTE" => Ok(Self::CmpGte),
                "CMP_LT" => Ok(Self::CmpLt),
                "CMP_LTE" => Ok(Self::CmpLte),
                "CMP_EQ" => Ok(Self::CmpEq),
                "CMP_NEQ" => Ok(Self::CmpNeq),
                "IF_THEN_ZERO" => Ok(Self::IfThenZero),
                "IF_THEN_ELSE" => Ok(Self::IfThenElse),
                "ERC_7984" => Ok(Self::Erc7984),
                "COUNT0" => Ok(Self::CountZeros),
                "COUNT1" => Ok(Self::CountOnes),
                "ILOG2" => Ok(Self::Ilog2),
                "LEAD0" => Ok(Self::LeadingZeros),
                "LEAD1" => Ok(Self::LeadingOnes),
                "TRAIL0" => Ok(Self::TrailingZeros),
                "TRAIL1" => Ok(Self::TrailingOnes),
                "ADD_SIMD" => Ok(Self::AddSimd),
                "ERC_7984_SIMD" => Ok(Self::Erc7984Simd),
                "FLIP" => Ok(Self::Flip),
                "MEMCPY" => Ok(Self::MemCpy),
                _ => Err(Box::new(ParsingError::Opalias(alias.to_string()))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_round_trips_through_from_str() {
        for iop in StaticIOp::ALL {
            assert_eq!(
                iop.name().parse::<StaticIOp>().ok().as_ref(),
                Some(iop),
                "{}",
                iop.name()
            );
        }
    }

    #[test]
    fn get_opcode_round_trips_through_from_opcode() {
        for iop in StaticIOp::ALL {
            assert_eq!(StaticIOp::from_opcode(iop.get_opcode()), *iop);
        }
    }

    #[test]
    fn from_opcode_falls_back_to_unnamed_for_user_range() {
        assert_eq!(StaticIOp::from_opcode(0x12), StaticIOp::IOp(0x12));
    }
}
