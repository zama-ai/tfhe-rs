//!
//! Gather IOp argument in a common type
//! Provides a FromStr implementation for parsing

use crate::asm::{IOpId, PhysId};

use super::*;
use field::{
    FwMode, IOpHeader, IOpcode, ImmBundle, Immediate, Operand, OperandBlock, OperandBundle,
};
use static_iop::ASM_OPCODE_WIDTH;

/// A minimal recursive-descent cursor over an iop.asm token, supporting the small set of
/// productions (`str` literals, single-character delimiters, decimal/hex unsigned integers)
/// needed by this module's parsers. Mirrors `zhc_langs::doplang::parser::Cursor`.
///
/// `pub(crate)`: also used by [`StaticIOp`]'s `FromStr` in `static_iop.rs` to parse the raw
/// `IOP[..]` opcode form.
pub(crate) struct Cursor<'a> {
    rest: &'a str,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(s: &'a str) -> Self {
        Self { rest: s }
    }

    pub(crate) fn rest(&self) -> &'a str {
        self.rest
    }

    /// Consumes `lit` if `rest` starts with it.
    pub(crate) fn eat_str(&mut self, lit: &str) -> bool {
        if let Some(rest) = self.rest.strip_prefix(lit) {
            self.rest = rest;
            true
        } else {
            false
        }
    }

    /// Consumes any leading whitespace.
    fn skip_ws(&mut self) {
        self.rest = self.rest.trim_start();
    }

    /// Consumes a single expected character.
    pub(crate) fn expect_char(
        &mut self,
        expected: char,
        tok: &str,
    ) -> Result<(), Box<ParsingError>> {
        let mut chars = self.rest.chars();
        match chars.next() {
            Some(c) if c == expected => {
                self.rest = chars.as_str();
                Ok(())
            }
            _ => Err(Box::new(ParsingError::Unmatch(format!(
                "`{tok}`: expected `{expected}`"
            )))),
        }
    }

    /// Fails unless the whole token has been consumed.
    pub(crate) fn expect_eof(&self, tok: &str) -> Result<(), Box<ParsingError>> {
        if self.rest.trim().is_empty() {
            Ok(())
        } else {
            Err(Box::new(ParsingError::Unmatch(format!(
                "`{tok}`: unexpected trailing `{}`",
                self.rest
            ))))
        }
    }

    /// Parses an unsigned integer, accepting an optional `0x` hex prefix.
    pub(crate) fn parse_uint<T>(&mut self, tok: &str, what: &str) -> Result<T, Box<ParsingError>>
    where
        T: TryFrom<u128>,
    {
        let (digits, radix) = if let Some(hex) = self.rest.strip_prefix("0x") {
            let end = hex
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(hex.len());
            let (digits, rest) = hex.split_at(end);
            self.rest = rest;
            (digits, 16)
        } else {
            let end = self
                .rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(self.rest.len());
            let (digits, rest) = self.rest.split_at(end);
            self.rest = rest;
            (digits, 10)
        };
        if digits.is_empty() {
            return Err(Box::new(ParsingError::Unmatch(format!(
                "`{tok}`: expected a {what}"
            ))));
        }
        let val = u128::from_str_radix(digits, radix).map_err(|err| {
            Box::new(ParsingError::InvalidArg(format!(
                "`{tok}`: invalid {what}: {err}"
            )))
        })?;
        T::try_from(val).map_err(|_| {
            Box::new(ParsingError::InvalidArg(format!(
                "`{tok}`: {what} out of range"
            )))
        })
    }
}

/// Finds the next `<...>` group (angle brackets don't nest in iop.asm grammar), returning its
/// inner content and the remainder of `s` past the closing `>`.
fn take_group<'a>(s: &'a str, whole: &str) -> Result<(&'a str, &'a str), Box<ParsingError>> {
    let s = s.trim_start();
    let inner = s.strip_prefix('<').ok_or_else(|| {
        Box::new(ParsingError::Unmatch(format!(
            "{whole}: expected `<...>`, got `{s}`"
        )))
    })?;
    let end = inner.find('>').ok_or_else(|| {
        Box::new(ParsingError::Unmatch(format!(
            "{whole}: unterminated `<...>`"
        )))
    })?;
    let (inner, rest) = inner.split_at(end);
    Ok((inner, &rest[1..]))
}

/// Parsing error
#[derive(thiserror::Error, Debug, Clone)]
pub enum ParsingError {
    #[error("Opcode {0} is in in reserved range")]
    Opcode(u8),
    #[error("Unknown IOp alias {0}")]
    Opalias(String),
    #[error("Unmatch Asm Operation: {0}")]
    Unmatch(String),
    #[error("Invalid arguments number: expect {0}, get {1}")]
    ArgNumber(usize, usize),
    #[error("Invalid arguments type: expect {0}, get {1}")]
    ArgType(String, Arg),
    #[error("Invalid arguments: {0}")]
    InvalidArg(String),
    #[error("Empty line")]
    Empty,
}

// Asm arguments are slightly different that hex word
// Thus we can't directly mapped ASM arg to fmt structure
// Below, we define a set of arguments for parsing purpose

/// Properties asm parsing utility
#[derive(Debug, Clone)]
pub struct Properties {
    fw_mode: FwMode,
    align: OperandBlock,
}

impl std::fmt::Display for Properties {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mode = match self.fw_mode {
            FwMode::Static => "",
            FwMode::Dynamic => "dyn ",
        };
        write!(f, "{}I{}", mode, (self.align.0 + 1) * MSG_WIDTH)
    }
}

/// Extract properties from IOpHeader
impl From<&IOpHeader> for Properties {
    fn from(value: &IOpHeader) -> Self {
        Self {
            fw_mode: value.fw_mode,
            align: value.align,
        }
    }
}

impl std::str::FromStr for Properties {
    type Err = Box<ParsingError>;

    /// Parses `[dyn] I<width>`, the alignment shared by every destination and source operand.
    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut c = Cursor::new(s);
        c.skip_ws();
        let fw_mode = if c.eat_str("dyn") {
            FwMode::Dynamic
        } else {
            FwMode::Static
        };
        c.skip_ws();
        c.expect_char('I', s)?;
        let width: u16 = c.parse_uint(s, "operand width")?;
        c.expect_eof(s)?;
        Ok(Properties {
            fw_mode,
            align: OperandBlock::new((width / MSG_WIDTH as u16) as u8),
        })
    }
}

impl std::fmt::Display for IOpMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Display inner Vec as comma separated list of values
        write!(
            f,
            "{}",
            self.iter()
                .map(|pid| format!("{}", pid.0))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::str::FromStr for IOpMapping {
    type Err = Box<ParsingError>;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let specified_map = s
            .split(',')
            .map(|id| id.trim().parse::<u8>())
            .collect::<Result<Vec<_>, std::num::ParseIntError>>()
            .map_err(|x| Box::new(ParsingError::InvalidArg(format!("{x:?}"))))?;

        Ok(IOpMapping::from(specified_map))
    }
}

impl std::fmt::Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Block/vec_size are zeroed indexed value
        // -> Transform them in one indexed for human readability
        let block = self.props.block.0 + 1;
        let vec_size = self.props.vec_size.0 + 1;
        // A destination is produced by the IOp that carries it: its iid is the one already
        // rendered next to the opcode, so it's left implicit here.
        let iid = match self.props.kind {
            OperandKind::Dst => String::new(),
            _ => format!("@{}", self.props.iid.0),
        };
        if vec_size != 1 {
            write!(
                f,
                "I{}[{}]@0x{:0>2x}{{Hpu{}{iid}}}",
                block * MSG_WIDTH,
                vec_size,
                self.addr.base_cid.0,
                self.props.pos.0,
            )
        } else {
            write!(
                f,
                "I{}@0x{:0>2x}{{Hpu{}{iid}}}",
                block * MSG_WIDTH,
                self.addr.base_cid.0,
                self.props.pos.0,
            )
        }
    }
}

// OperandBundle
// Addr are packed in <> in the ASM format and thus we only parse them by bundle
impl std::fmt::Display for OperandBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.iter()
                .fold(" ".to_string(), |acc, x| format!("{acc}{x} "))
                .trim()
        )
    }
}

/// How the optional `@<iid>` suffix of an operand token is resolved.
#[derive(Debug, Clone, Copy)]
enum IidCtx {
    /// Destination operand: it is produced by the IOp being parsed, so its iid is implicit.
    /// An explicitly written one is only accepted when it matches.
    Dst(IOpId),
    /// Source operand: `@<iid>` names the IOp that produced it, and defaults to [`SW_IOP_ID`].
    Src,
}

/// Parses one operand token: `I<width>@<addr>{Hpu<pos>[@<iid>]}` (single) or
/// `I<width>[<len>]@<addr>{Hpu<pos>[@<iid>]}` (vector).
fn parse_operand(tok: &str, ctx: IidCtx) -> Result<Operand, Box<ParsingError>> {
    let mut c = Cursor::new(tok);
    c.expect_char('I', tok)?;
    let width: u16 = c.parse_uint(tok, "operand width")?;
    let block = (width / MSG_WIDTH as u16) as u8;

    let len: u8 = if c.eat_str("[") {
        let len = c.parse_uint(tok, "vector length")?;
        c.expect_char(']', tok)?;
        len
    } else {
        1
    };
    c.expect_char('@', tok)?;
    let base_cid: u16 = c.parse_uint(tok, "ct id")?;

    c.expect_char('{', tok)?;
    if !c.eat_str("Hpu") {
        return Err(Box::new(ParsingError::Unmatch(format!(
            "`{tok}`: expected `Hpu<pos>`"
        ))));
    }
    let pos: u8 = c.parse_uint(tok, "hpu position")?;
    let iid = if c.eat_str("@") {
        let iid = IOpId(c.parse_uint(tok, "iop id")?);
        if let IidCtx::Dst(own) = ctx {
            if iid != own {
                return Err(Box::new(ParsingError::InvalidArg(format!(
                    "`{tok}`: destination {iid} must match the IOp own {own}"
                ))));
            }
        }
        iid
    } else {
        match ctx {
            IidCtx::Dst(own) => own,
            IidCtx::Src => SW_IOP_ID,
        }
    };
    c.expect_char('}', tok)?;
    c.expect_eof(tok)?;

    Ok(Operand::new(block, base_cid, len, PhysId(pos), iid, None))
}

impl OperandBundle {
    /// Parses a whitespace separated list of operand tokens, `ctx` driving how each `@<iid>`
    /// suffix is resolved.
    #[tracing::instrument(level = "trace", ret)]
    fn parse(s: &str, ctx: IidCtx) -> Result<Self, Box<ParsingError>> {
        let mut operands = s
            .split_whitespace()
            .map(|tok| parse_operand(tok, ctx))
            .collect::<Result<Vec<_>, Box<ParsingError>>>()?;

        // Empty OperandBundle is considered as parsing error
        if operands.is_empty() {
            Err(Box::new(ParsingError::Unmatch(format!(
                "Invalid argument: Empty OperandBundle {s}"
            ))))
        } else {
            // Update is_last token
            operands.last_mut().unwrap().props.is_last = true;
            Ok(operands.into())
        }
    }
}

impl std::str::FromStr for OperandBundle {
    type Err = Box<ParsingError>;

    /// Parses a standalone bundle, i.e. without a surrounding IOp to bind destinations to: every
    /// `@<iid>` is read as-is (c.f. [`OperandBundle::parse`] for the IOp-aware entry point).
    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s, IidCtx::Src)
    }
}

// ImmBundle
// Imm are packed in <> in the ASM format and thus we only parse them by bundle
impl std::fmt::Display for ImmBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.iter()
                .fold(" ".to_string(), |acc, x| format!(
                    "{acc}0x{:x} ",
                    x.cst_value()
                ))
                .trim()
        )
    }
}

/// Parses one immediate token: a decimal or `0x`-prefixed hex constant.
fn parse_imm(tok: &str) -> Result<Immediate, Box<ParsingError>> {
    let mut c = Cursor::new(tok);
    let value: u128 = c.parse_uint(tok, "immediate")?;
    c.expect_eof(tok)?;
    Ok(Immediate::from_cst(value))
}

impl std::str::FromStr for ImmBundle {
    type Err = Box<ParsingError>;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut imms = s
            .split_whitespace()
            .map(parse_imm)
            .collect::<Result<Vec<_>, Box<ParsingError>>>()?;

        // Empty ImmBundle is considered as parsing error
        if imms.is_empty() {
            Err(Box::new(ParsingError::Unmatch(format!(
                "Invalid argument format {s}"
            ))))
        } else {
            // Update is_last token
            imms.last_mut().unwrap().is_last = true;
            Ok(imms.into())
        }
    }
}

/// Generic arguments
/// Used to pack argument under the same type
#[derive(Debug, Clone)]
pub enum Arg {
    Opcode(StaticIOp),
    Properties(Properties),
    Operand(OperandBundle),
    Imm(ImmBundle),
}

/// Use Display trait to convert into asm human readable file
/// Simply defer to inner type display impl while forcing the display width
impl std::fmt::Display for Arg {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Arg::Opcode(inner) => write!(f, "{inner}"),
            Arg::Properties(inner) => write!(f, "{inner}"),
            Arg::Operand(inner) => write!(f, "{inner}"),
            Arg::Imm(inner) => write!(f, "{inner}"),
        }
    }
}

/// Use FromStr trait to decode from asm file
impl std::str::FromStr for Arg {
    type Err = Box<ParsingError>;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match (
            OperandBundle::from_str(s),
            StaticIOp::from_str(s),
            Properties::from_str(s),
            ImmBundle::from_str(s),
        ) {
            (Ok(operand), ..) => Ok(Self::Operand(operand)),
            (Err(_), Ok(opcode), ..) => Ok(Self::Opcode(opcode)),
            (Err(_), Err(_), Ok(props), ..) => Ok(Self::Properties(props)),
            (Err(_), Err(_), Err(_), Ok(imm)) => Ok(Self::Imm(imm)),
            (Err(addr), Err(opcode), Err(props), Err(imm)) => {
                Err(Box::new(ParsingError::Unmatch(format!(
                    "{s}:
            Addr failed with{addr}
            Opcode failed with{opcode}
            Props failed with{props}
            Imm failed with{imm}
            "
                ))))
            }
        }
    }
}

impl std::fmt::Display for IOp {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Opcode and iid are rendered as one token, padded as a whole
        let opcode = StaticIOp::from(self).mnemonic();
        let iid = self.header.iid.0;
        write!(f, "{: <ASM_OPCODE_WIDTH$}", format!("{opcode}@{iid}"))?;

        let props = Properties::from(&self.header);
        write!(f, " <{props}>")?;
        // Mapping
        write!(f, " <{}>", self.map)?;

        // Destination operands list
        write!(f, " <{}>", self.dst)?;

        // Source operands list
        write!(f, " <{}>", self.src)?;

        // Immediate operands list [Optional]
        if self.header.has_imm {
            write!(f, " <{}>", self.imm)?;
        }

        Ok(())
    }
}

/// Use FromStr trait to decode from asm file
///
/// Grammar: `OPCODE@<iid> <PROPS> <MAP> <DST> <SRC> [<IMM>]` — the mnemonic/raw-opcode token
/// suffixed by the IOp own id, then each remaining section in its own `<...>` group (angle
/// brackets don't nest here, so each group is found by its next `<`/matching `>` via
/// [`take_group`], then delegated to that section's own parser).
impl std::str::FromStr for IOp {
    type Err = Box<ParsingError>;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let opcode_end = trimmed.find('<').ok_or_else(|| {
            Box::new(ParsingError::Unmatch(format!(
                "{s}: expected an opcode followed by `<...>` sections"
            )))
        })?;
        let (opcode_tok, rest) = trimmed.split_at(opcode_end);
        // `@<iid>` is optional, an omitted one defaults to the Sw reserved id
        let (opcode_tok, iid) = match opcode_tok.trim().split_once('@') {
            Some((opcode_tok, iid_tok)) => {
                let mut c = Cursor::new(iid_tok);
                let iid: u8 = c.parse_uint(s, "iop id")?;
                c.expect_eof(s)?;
                (opcode_tok, IOpId(iid))
            }
            None => (opcode_tok.trim(), SW_IOP_ID),
        };
        let opcode = StaticIOp::from_str(opcode_tok)?;

        let (props_tok, rest) = take_group(rest, s)?;
        let props = Properties::from_str(props_tok.trim())?;
        let (map_tok, rest) = take_group(rest, s)?;
        let map = IOpMapping::from_str(map_tok.trim())?;
        let (dst_tok, rest) = take_group(rest, s)?;
        let dst = {
            let mut bundle = OperandBundle::parse(dst_tok.trim(), IidCtx::Dst(iid))?;
            bundle.set_kind(OperandKind::Dst);
            bundle
        };
        let (src_tok, rest) = take_group(rest, s)?;
        let src = {
            let mut bundle = OperandBundle::parse(src_tok.trim(), IidCtx::Src)?;
            bundle.set_kind(OperandKind::Src);
            bundle
        };

        let rest = rest.trim();
        let (imm, has_imm) = if rest.is_empty() {
            (ImmBundle::from(vec![]), false)
        } else {
            let (imm_tok, rest) = take_group(rest, s)?;
            if !rest.trim().is_empty() {
                return Err(Box::new(ParsingError::Unmatch(format!(
                    "{s}: unexpected trailing `{}`",
                    rest.trim()
                ))));
            }
            (ImmBundle::from_str(imm_tok.trim())?, true)
        };

        // Aggregate some fields together to build real IOp
        let header = IOpHeader {
            iid,
            align: props.align,
            has_imm,
            fw_mode: props.fw_mode,
            opcode: IOpcode(opcode.get_opcode()),
        };

        Ok(IOp {
            header,
            map,
            dst,
            src,
            imm,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_raw_opcode_with_mapping_and_single_operands() {
        let iop: IOp = "IOP[0x35]@1 <I8> <2,0,1,3> <I8@0x08{Hpu2}> <I8@0x0{Hpu2@0} I8@0x4{Hpu2@7}>"
            .parse()
            .expect("valid line must parse");
        assert_eq!(iop.opcode(), IOpcode(0x35));
        assert_eq!(iop.fw_mode(), FwMode::Static);
        assert_eq!(iop.dst().len(), 1);
        assert_eq!(iop.src().len(), 2);
        assert_eq!(iop.iid(), IOpId(1));
        // Destinations inherit the IOp own iid, sources keep the one of their producer
        assert_eq!(iop.dst()[0].props.iid, IOpId(1));
        assert_eq!(iop.src()[1].props.iid, IOpId(7));
        assert!(iop.imm().is_empty());
    }

    #[test]
    fn parses_dyn_mnemonic_alias_vector_operand_and_immediate() {
        let iop: IOp = "MULS@3 <dyn I8> <0,1,2,3> <I8@0x8{Hpu0}> <I8[2]@0x0{Hpu2}> <0xaf>"
            .parse()
            .expect("valid line must parse");
        assert_eq!(iop.fw_mode(), FwMode::Dynamic);
        // A vector token is one logical Operand spanning several ciphertexts, not several
        // Operand entries.
        assert_eq!(iop.src().len(), 1);
        assert_eq!(iop.src()[0].props.vec_size.len(), 2);
        // An omitted source iid falls back on the Sw reserved one
        assert_eq!(iop.src()[0].props.iid, SW_IOP_ID);
        assert_eq!(iop.imm().len(), 1);
        assert_eq!(iop.imm()[0].cst_value(), 0xaf);
    }

    #[test]
    fn defaults_iid_when_opcode_is_unsuffixed() {
        let iop: IOp = "MUL <I64> <1> <I64@0x08{Hpu1}> <I64@0x0{Hpu1@2}>"
            .parse()
            .expect("valid line must parse");
        assert_eq!(iop.iid(), SW_IOP_ID);
    }

    #[test]
    fn rejects_destination_iid_mismatching_the_iop_one() {
        let err = "MUL@4 <I64> <1> <I64@0x08{Hpu1@2}> <I64@0x0{Hpu1@2}>"
            .parse::<IOp>()
            .unwrap_err();
        assert!(err.to_string().contains("must match"), "{err}");
    }

    #[test]
    fn round_trips_through_display() {
        let src = "MUL@2 <I64> <1, 2> <I64@0x08{Hpu1}> <I64@0x10{Hpu2@3}>";
        let iop: IOp = src.parse().expect("valid line must parse");
        let reparsed: IOp = format!("{iop}").parse().expect("emitted line must reparse");
        assert_eq!(format!("{iop}"), format!("{reparsed}"));
        assert_eq!(reparsed.iid(), IOpId(2));
        assert_eq!(reparsed.src()[0].props.iid, IOpId(3));
    }

    #[test]
    fn round_trips_operand_bundle_through_display() {
        // A standalone bundle has no IOp to bind destinations to, so every iid is explicit and
        // the grammar is symmetric.
        let src = "I64@0x08{Hpu1@0} I64@0x10{Hpu2@3}";
        let bundle: OperandBundle = src.parse().expect("valid bundle must parse");
        let reparsed: OperandBundle = format!("{bundle}")
            .parse()
            .expect("emitted bundle must reparse");
        assert_eq!(format!("{bundle}"), format!("{reparsed}"));
    }

    #[test]
    fn rejects_opcode_out_of_user_range() {
        let err = "IOP[0x80]@0 <I8> <0> <I8@0x0{Hpu0}> <I8@0x0{Hpu0}>"
            .parse::<IOp>()
            .unwrap_err();
        assert!(matches!(*err, ParsingError::Opcode(0x80)));
    }

    #[test]
    fn rejects_unknown_alias() {
        let err = "BOGUS@0 <I8> <0> <I8@0x0{Hpu0}> <I8@0x0{Hpu0}>"
            .parse::<IOp>()
            .unwrap_err();
        assert!(matches!(*err, ParsingError::Opalias(_)));
    }

    #[test]
    fn rejects_malformed_operand() {
        let err = "MUL@0 <I64> <1> <I64@0x08{Hpu1}> <I64@BOGUS{Hpu1}>"
            .parse::<IOp>()
            .unwrap_err();
        assert!(err.to_string().contains("ct id"), "{err}");
    }

    #[test]
    fn rejects_missing_section() {
        let err = "MUL@0 <I64> <1> <I64@0x08{Hpu1}>"
            .parse::<IOp>()
            .unwrap_err();
        assert!(err.to_string().contains("expected"), "{err}");
    }

    #[test]
    fn rejects_trailing_garbage_after_immediate() {
        let err = "MULS@0 <I8> <0> <I8@0x8{Hpu0}> <I8@0x0{Hpu0}> <0xaf> <extra>"
            .parse::<IOp>()
            .unwrap_err();
        assert!(err.to_string().contains("trailing"), "{err}");
    }
}
