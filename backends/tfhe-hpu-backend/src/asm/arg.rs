//!
//! Provide common Arg type
//!
//! This type is provided to circumvent limitation of enum_dispatch

use super::pbs::{Pbs, PbsLut};

use super::*;
use lazy_static::lazy_static;
use std::str::FromStr;

/// Minimum asm arg width to have aligned field
pub const ARG_MIN_WIDTH: usize = 16;

/// Memory is view as list of slot parked in multiple banks
/// However, they are handle differently based on their origin
///  * Heap slot is view as single Digit entity (and is return to HeapCache)
///  * UserX slot not view by heap and Used Template LD/ST operations inner usize is used to target
///    a digit within an integer
/// Furthermore, to enhance asm readability, UserX slot use another
/// syntax that cleary depict the Integer structure as pack of Digit
/// TODO rework this comment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemSlot {
    pub bid: usize,
    pub cid_ofst: usize,
    #[serde(skip)]
    pub(crate) mode: MemMode,
    #[serde(skip)]
    pub(crate) orig: Option<MemOrigin>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MemMode {
    #[default]
    Raw,
    Template,
    Int {
        width: usize,
        pos: Option<usize>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemOrigin {
    Dst,
    SrcA,
    SrcB,
    Heap,
}

impl std::fmt::Display for MemOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemOrigin::Dst => write!(f, "D"),
            MemOrigin::SrcA => write!(f, "A"),
            MemOrigin::SrcB => write!(f, "B"),
            MemOrigin::Heap => write!(f, "H"),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub enum MemSlotError {
    #[error("Integer: inner position greater or equal to integer width [{0} >= {1}]")]
    IntegerPosWidth(usize, usize),
    #[error("Integer: slot address not aligned with integer blk size [{0} % {1} != 0]")]
    IntegerAddrAlign(usize, usize),
    #[error("Integer: specified width mismtach with architecture properties [{0} =! {1}]")]
    IntegerWidth(usize, usize),
    #[error("Template without specified origin")]
    Template,
}

/// Some utilities to work with MemSlot
impl MemSlot {
    pub fn new(
        props: &ArchProperties,
        bid: usize,
        cid_ofst: usize,
        mode: MemMode,
        orig: Option<MemOrigin>,
    ) -> Result<Self, MemSlotError> {
        match mode {
            MemMode::Raw => {
                // Nothing enforced on bid/cid
            }
            MemMode::Template => {
                if orig.is_none() {
                    return Err(MemSlotError::Template);
                }
            }
            MemMode::Int { width, pos } => {
                // Check width match with arch properties
                if width != props.integer_w {
                    return Err(MemSlotError::IntegerWidth(width, props.integer_w));
                }

                // Check alignement
                if (cid_ofst % props.blk_w()) != 0 {
                    return Err(MemSlotError::IntegerAddrAlign(cid_ofst, width));
                }
                // Check inner pos if any
                if let Some(p) = pos {
                    if p >= width {
                        return Err(MemSlotError::IntegerPosWidth(p, width));
                    }
                }
            }
        }

        Ok(Self {
            bid,
            cid_ofst,
            mode,
            orig,
        })
    }

    pub fn new_uncheck(
        bid: usize,
        cid_ofst: usize,
        mode: MemMode,
        orig: Option<MemOrigin>,
    ) -> Self {
        Self {
            bid,
            cid_ofst,
            mode,
            orig,
        }
    }

    /// Bid getter
    pub fn bid(&self) -> usize {
        self.bid
    }

    /// Mode getter
    pub fn mode(&self) -> &MemMode {
        &self.mode
    }

    /// Orig getter
    pub fn orig(&self) -> &Option<MemOrigin> {
        &self.orig
    }

    /// Compute absolute cid based on cid_ofst and properties
    pub fn cid(&self) -> usize {
        match self.mode {
            MemMode::Raw => self.cid_ofst,
            MemMode::Int { pos, .. } => {
                if let Some(p) = pos {
                    self.cid_ofst + p
                } else {
                    self.cid_ofst
                }
            }
            MemMode::Template => self.cid_ofst,
        }
    }
}

impl Default for MemSlot {
    fn default() -> Self {
        Self {
            bid: 0,
            cid_ofst: 0,
            mode: MemMode::Raw,
            orig: None,
        }
    }
}

impl MemSlot {
    /// User Memslot are expected with a specified origin
    /// This is usefull for heap management (i.e. value with origin aren't handle as heap value
    pub fn default_user(orig: MemOrigin) -> Self {
        let mut dflt = Self::default();
        dflt.orig = Some(orig);
        dflt
    }
}

/// Generic arguments
/// Used to pack argument under the same type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arg {
    RegId(usize),
    MemId(MemSlot),
    Imm(usize),
    Pbs(Pbs),
}

/// Use Display trait to convert into asm human readable file
impl std::fmt::Display for Arg {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::RegId(id) => write!(f, "R{id}"),
            Self::MemId(slot) => match slot.mode {
                MemMode::Raw => write!(f, "@[{}]0x{:x}", slot.bid, slot.cid()),
                MemMode::Int { width, pos } => {
                    if let Some(p) = pos {
                        write!(f, "I{}@[{}]0x{:x}.{p}", width, slot.bid, slot.cid_ofst)
                    } else {
                        write!(f, "I{}@[{}]0x{:x}", width, slot.bid, slot.cid())
                    }
                }
                MemMode::Template => match slot.orig {
                    Some(orig) => write!(f, "T{}.{}", orig, slot.cid_ofst),
                    _ => panic!("Invalid orig for MemMode::Word"),
                },
            },
            Self::Imm(s) => write!(f, "{s}"),
            Self::Pbs(p) => write!(f, "Pbs{}", p.name()),
        }
    }
}

/// Use FromStr trait to decode from asm file
impl FromStr for Arg {
    type Err = ParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            // Register field parser
            static ref REG_RE: regex::Regex =
                regex::Regex::new(r"^R(?<rid>[0-9]+)").expect("Invalid regex");
            // Raw addr format
            static ref DADDR_RE: regex::Regex =
                regex::Regex::new(r"^@\[(?<bid>\d+)\]((?<cid>[0-9]{2,})|(?<hex_cid>0x[0-9a-fA-F]+))").expect("Invalid regex");
            // Integer addr format -> Iw@[bank]Addr
            static ref IADDR_RE: regex::Regex =
                regex::Regex::new(r"^I(?<width>[0-9]+)@\[(?<bid>\d+)\]((?<cid>[0-9]{2,})|(?<hex_cid>0x[0-9a-fA-F]+))(\.(?<inner>\d+))?").expect("Invalid regex");
            // Templated addr format -> Torig.ofst
            static ref TADDR_RE: regex::Regex =
                regex::Regex::new(r"^T(?<orig>[A,B,D,H])\.(?<ofst>\d+)").expect("Invalid regex");
            // Pbs field format
            static ref PBS_RE: regex::Regex = regex::Regex::new(r"^Pbs(?<name>[a-zA-Z]+)").unwrap();
        }

        match s.parse::<usize>() {
            Ok(val) => Ok(Self::Imm(val)),
            Err(_) => {
                if let Some(caps) = REG_RE.captures(s) {
                    let rid = caps["rid"]
                        .parse::<usize>()
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
                    Ok(Self::RegId(rid))
                } else if let Some(caps) = DADDR_RE.captures(s) {
                    let cid_ofst = if let Some(raw_cid) = caps.name("cid") {
                        raw_cid
                            .as_str()
                            .parse::<usize>()
                            .map_err(|err| ParsingError::InvalidArg(err.to_string()))?
                    } else {
                        // One of them must match, otherwise error will be arised before
                        let raw_hex_cid = caps.name("hex_cid").unwrap();
                        usize::from_str_radix(&raw_hex_cid.as_str()[2..], 16)
                            .map_err(|err| ParsingError::InvalidArg(err.to_string()))?
                    };
                    let bid = caps["bid"]
                        .parse::<usize>()
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;

                    let slot = MemSlot::new_uncheck(bid, cid_ofst, MemMode::Raw, None);
                    Ok(Self::MemId(slot))
                } else if let Some(caps) = IADDR_RE.captures(s) {
                    let width = caps["width"]
                        .parse::<usize>()
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;

                    let cid_ofst = if let Some(cid) = caps.name("cid") {
                        cid.as_str()
                            .parse::<usize>()
                            .map_err(|err| ParsingError::InvalidArg(err.to_string()))?
                    } else {
                        // One of them must match, otherwise error will be arised before
                        let hex_cid = caps.name("hex_cid").unwrap();
                        usize::from_str_radix(&hex_cid.as_str()[2..], 16)
                            .map_err(|err| ParsingError::InvalidArg(err.to_string()))?
                    };

                    let bid = caps["bid"]
                        .parse::<usize>()
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;

                    let inner = if let Some(raw_inner) = caps.name("inner") {
                        Some(
                            raw_inner
                                .as_str()
                                .parse::<usize>()
                                .map_err(|err| ParsingError::InvalidArg(err.to_string()))?,
                        )
                    } else {
                        None
                    };

                    let slot = MemSlot::new_uncheck(
                        bid,
                        cid_ofst,
                        MemMode::Int { width, pos: inner },
                        None,
                    );
                    Ok(Self::MemId(slot))
                } else if let Some(caps) = TADDR_RE.captures(s) {
                    let ofst = caps["ofst"]
                        .parse::<usize>()
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
                    let orig = match &caps["orig"] {
                        "A" => MemOrigin::SrcA,
                        "B" => MemOrigin::SrcB,
                        "D" => MemOrigin::Dst,
                        "H" => MemOrigin::Heap,
                        _ => panic!("Invalid origin match. Check TADDR_RE definition."),
                    };
                    let slot = MemSlot::new_uncheck(0, ofst, MemMode::Template, Some(orig));
                    Ok(Self::MemId(slot))
                } else if let Some(caps) = PBS_RE.captures(s) {
                    let pbs_name = PbsName::from_str(&caps["name"])
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
                    Ok(Self::Pbs(pbs_name.into()))
                } else {
                    Err(ParsingError::InvalidArg(s.to_string()))
                }
            }
        }
    }
}
