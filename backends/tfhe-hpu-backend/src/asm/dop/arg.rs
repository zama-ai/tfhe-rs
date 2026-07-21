//!
//! Gather DOp argument in a common type
//! Provides a FromStr implementation for parsing

use super::field::{ImmId, MemId, RegId, UserFlag};
use super::*;

/// Minimum asm arg width to have aligned field
pub const ARG_MIN_WIDTH: usize = 16;
pub const DOP_MIN_WIDTH: usize = 10;

/// Generic arguments
/// Used to pack argument under the same type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Reg(RegId),
    Mem(MemId),
    Imm(ImmId),
    Pbs(Pbs),
    IOpId(IOpId),
    HpuId(VirtId),
    UcoreFlag(UserFlag),
}

/// Use Display trait to convert into asm human readable file
/// Simply defer to inner type display impl while forcing the display width
impl std::fmt::Display for Arg {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Reg(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Self::Mem(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Self::Imm(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Self::Pbs(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Self::IOpId(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Self::HpuId(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
            Self::UcoreFlag(inner) => write!(f, "{inner: <ARG_MIN_WIDTH$}"),
        }
    }
}

/// Parsing error
#[derive(thiserror::Error, Debug, Clone)]
pub enum ParsingError {
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

/// Use FromStr trait to decode from asm file
impl std::str::FromStr for Arg {
    type Err = Box<ParsingError>;

    #[tracing::instrument(level = "trace", ret)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(reg) = RegId::from_str(s) {
            Ok(Self::Reg(reg))
        } else if let Ok(mem) = MemId::from_str(s) {
            Ok(Self::Mem(mem))
        } else if let Ok(imm) = ImmId::from_str(s) {
            Ok(Self::Imm(imm))
        } else if let Ok(pbs) = Pbs::from_str(s) {
            Ok(Self::Pbs(pbs))
        } else if let Ok(iid) = IOpId::from_str(s) {
            Ok(Self::IOpId(iid))
        } else if let Ok(hid) = VirtId::from_str(s) {
            Ok(Self::HpuId(VirtId(hid.0)))
        } else if let Ok(flag) = UserFlag::from_str(s) {
            Ok(Self::UcoreFlag(flag))
        } else {
            Err(Box::new(ParsingError::Unmatch(format!(
                "Invalid argument format {s}"
            ))))
        }
    }
}

pub trait FromAsm
where
    Self: Sized,
{
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, Box<ParsingError>>;
}

#[enum_dispatch]
pub trait ToAsm
where
    Self: Sized,
{
    fn name(&self) -> &'static str {
        std::any::type_name_of_val(self)
    }

    fn args(&self) -> Vec<arg::Arg> {
        let mut arg = self.dst();
        arg.extend_from_slice(self.src().as_slice());
        arg
    }
    fn dst(&self) -> Vec<arg::Arg>;
    fn src(&self) -> Vec<arg::Arg>;
    fn opcode(&self) -> Opcode;
}

#[enum_dispatch]
pub trait IsFlush
where
    Self: Sized,
{
    fn is_flush(&self) -> bool {
        false
    }
}

pub trait ToFlush
where
    Self: Sized + Clone,
{
    fn to_flush(&self) -> Self {
        self.clone()
    }
}

impl FromAsm for field::PeArithInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, Box<ParsingError>> {
        if (args.len() != 3) && (args.len() != 4) {
            return Err(Box::new(ParsingError::ArgNumber(3, args.len())));
        }

        let dst_rid = match args[0] {
            Arg::Reg(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[0].clone(),
                )))
            }
        };
        let src0_rid = match args[1] {
            Arg::Reg(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[1].clone(),
                )))
            }
        };
        let src1_rid = match args[2] {
            Arg::Reg(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[2].clone(),
                )))
            }
        };

        let mul_factor = if let Some(arg) = args.get(3) {
            match arg {
                Arg::Imm(ImmId::Cst(id)) => MulFactor(*id as u8),
                _ => {
                    return Err(Box::new(ParsingError::ArgType(
                        "Arg::Imm::Cst".to_string(),
                        args[3].clone(),
                    )))
                }
            }
        } else {
            MulFactor(0)
        };

        Ok(Self {
            opcode: Opcode::from(opcode),
            mul_factor,
            src1_rid,
            src0_rid,
            dst_rid,
        })
    }
}

impl ToAsm for PeArithInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        vec![arg::Arg::Reg(self.dst_rid)]
    }
    fn src(&self) -> Vec<arg::Arg> {
        let mut src = vec![arg::Arg::Reg(self.src0_rid), arg::Arg::Reg(self.src1_rid)];
        if self.mul_factor != MulFactor(0) {
            src.push(arg::Arg::Imm(ImmId::Cst(self.mul_factor.0 as u16)));
        }
        src
    }
    fn opcode(&self) -> Opcode {
        self.opcode
    }
}

impl FromAsm for field::PeArithMsgInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, Box<ParsingError>> {
        if args.len() != 3 {
            return Err(Box::new(ParsingError::ArgNumber(3, args.len())));
        }

        let dst_rid = match args[0] {
            Arg::Reg(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[0].clone(),
                )))
            }
        };
        let src_rid = match args[1] {
            Arg::Reg(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[1].clone(),
                )))
            }
        };
        let msg_cst = match args[2] {
            Arg::Imm(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::Imm".to_string(),
                    args[2].clone(),
                )))
            }
        };

        Ok(Self {
            opcode: Opcode::from(opcode),
            msg_cst,
            src_rid,
            dst_rid,
        })
    }
}

impl ToAsm for PeArithMsgInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        vec![arg::Arg::Reg(self.dst_rid)]
    }
    fn src(&self) -> Vec<arg::Arg> {
        vec![arg::Arg::Reg(self.src_rid), arg::Arg::Imm(self.msg_cst)]
    }
    fn opcode(&self) -> Opcode {
        self.opcode
    }
}

impl FromAsm for field::PeMemInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, Box<ParsingError>> {
        if args.len() != 2 {
            return Err(Box::new(ParsingError::ArgNumber(2, args.len())));
        }

        let parsed_opcode = Opcode::from(opcode);
        if parsed_opcode.is_ld_inst() {
            let rid = match args[0] {
                Arg::Reg(id) => id,
                _ => {
                    return Err(Box::new(ParsingError::ArgType(
                        "Arg::Reg".to_string(),
                        args[0].clone(),
                    )))
                }
            };
            let slot = match args[1] {
                Arg::Mem(id) => id,
                _ => {
                    return Err(Box::new(ParsingError::ArgType(
                        "Arg::Mem".to_string(),
                        args[1].clone(),
                    )))
                }
            };
            Ok(Self {
                rid,
                slot,
                opcode: parsed_opcode,
            })
        } else if parsed_opcode.is_st_inst() {
            let slot = match args[0] {
                Arg::Mem(id) => id,
                _ => {
                    return Err(Box::new(ParsingError::ArgType(
                        "Arg::Mem".to_string(),
                        args[0].clone(),
                    )))
                }
            };

            let rid = match args[1] {
                Arg::Reg(id) => id,
                _ => {
                    return Err(Box::new(ParsingError::ArgType(
                        "Arg::Reg".to_string(),
                        args[1].clone(),
                    )))
                }
            };
            Ok(Self {
                rid,
                slot,
                opcode: parsed_opcode,
            })
        } else {
            Err(Box::new(ParsingError::Unmatch(
                "PeMemInsn expect LD/ST opcode".to_string(),
            )))
        }
    }
}

impl ToAsm for PeMemInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        if self.opcode.is_ld_inst() {
            vec![Arg::Reg(self.rid)]
        } else if self.opcode.is_st_inst() {
            vec![Arg::Mem(self.slot)]
        } else {
            panic!("Unsupported opcode for PeMemInsn")
        }
    }
    fn src(&self) -> Vec<arg::Arg> {
        if self.opcode.is_ld_inst() {
            vec![Arg::Mem(self.slot)]
        } else if self.opcode.is_st_inst() {
            vec![Arg::Reg(self.rid)]
        } else {
            panic!("Unsupported opcode for PeMemInsn")
        }
    }
    fn opcode(&self) -> Opcode {
        self.opcode
    }
}

impl FromAsm for field::PeSyncInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, Box<ParsingError>> {
        if args.is_empty() {
            return Err(Box::new(ParsingError::ArgNumber(1, args.len())));
        }

        let iid = match args[0] {
            Arg::IOpId(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::IOpId".to_string(),
                    args[0].clone(),
                )))
            }
        };

        let (is_inner_sync, hid, flag) = if args.len() > 1 {
            let hid = match args[1] {
                Arg::HpuId(vid) => vid,
                _ => {
                    return Err(Box::new(ParsingError::ArgType(
                        "Arg::HpuId".to_string(),
                        args[1].clone(),
                    )))
                }
            };

            let flag = match args[2] {
                Arg::UcoreFlag(flag) => flag,
                _ => {
                    return Err(Box::new(ParsingError::ArgType(
                        "Arg::UcoreFlag".to_string(),
                        args[1].clone(),
                    )))
                }
            };
            (true, hid, flag)
        } else {
            (false, Default::default(), Default::default())
        };

        Ok(Self {
            opcode: Opcode::from(opcode),
            is_inner_sync,
            iid,
            hid,
            flag,
        })
    }
}

impl ToAsm for PeSyncInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        vec![]
    }
    fn src(&self) -> Vec<arg::Arg> {
        let mut src = Vec::with_capacity(2);
        src.push(Arg::IOpId(self.iid));
        if self.is_inner_sync {
            src.push(Arg::UcoreFlag(self.flag));
        }
        src
    }
    fn opcode(&self) -> Opcode {
        self.opcode
    }
}

impl FromAsm for field::PePbsInsn {
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, Box<ParsingError>> {
        if args.len() != 3 {
            return Err(Box::new(ParsingError::ArgNumber(3, args.len())));
        }

        let dst_rid = match args[0] {
            Arg::Reg(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[0].clone(),
                )))
            }
        };
        let src_rid = match args[1] {
            Arg::Reg(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::Reg".to_string(),
                    args[1].clone(),
                )))
            }
        };
        let pbs_lut = match &args[2] {
            Arg::Pbs(id) => id,
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::Pbs".to_string(),
                    args[2].clone(),
                )))
            }
        };

        Ok(Self {
            opcode: Opcode::from(opcode),
            gid: pbs_lut.gid(),
            src_rid,
            dst_rid,
        })
    }
}

impl ToAsm for PePbsInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        vec![Arg::Reg(self.dst_rid)]
    }
    fn src(&self) -> Vec<arg::Arg> {
        vec![
            Arg::Reg(self.src_rid),
            Arg::Pbs(Pbs::from_hex(self.gid).unwrap()),
        ]
    }
    fn opcode(&self) -> Opcode {
        self.opcode
    }
}

impl FromAsm for field::PeUcoreInsn {
    /// Parsing of PeUcoreInsn is a bit special
    /// Indeed, there is two mode:
    /// * Notify that start with VirtId and have Data optional
    /// * Wait/Ld_b2b that start with Flag and have Data optional
    fn from_args(opcode: u8, args: &[arg::Arg]) -> Result<Self, Box<ParsingError>> {
        fn get_flag(arg: &arg::Arg) -> Result<UserFlag, Box<ParsingError>> {
            match arg {
                Arg::UcoreFlag(flag) => Ok(*flag),
                _ => Err(Box::new(ParsingError::ArgType(
                    "Arg::UcoreFlag".to_string(),
                    arg.clone(),
                ))),
            }
        }

        fn get_slot(arg: Option<&arg::Arg>) -> Result<Option<MemId>, Box<ParsingError>> {
            if let Some(a) = arg {
                match a {
                    Arg::Mem(cid) => Ok(Some(*cid)),
                    _ => Err(Box::new(ParsingError::ArgType(
                        "Arg::Mem".to_string(),
                        a.clone(),
                    ))),
                }
            } else {
                Ok(None)
            }
        }

        if args.len() < 2 {
            return Err(Box::new(ParsingError::ArgNumber(2, args.len())));
        }

        let (hid, flag, slot) = match args[0] {
            Arg::HpuId(hid) => {
                // Only NOTIFY start with HpuId
                if opcode != u8::from(Opcode::NOTIFY()) {
                    return Err(Box::new(ParsingError::ArgType(
                        "Arg::UcoreFlag".to_string(),
                        args[0].clone(),
                    )));
                }
                let flag = get_flag(&args[1])?;
                let slot = get_slot(args.get(2))?.unwrap_or_default();
                (hid, flag, slot)
            }
            Arg::UcoreFlag(flag) => {
                // Notify must start with HpuId
                if opcode == u8::from(Opcode::NOTIFY()) {
                    return Err(Box::new(ParsingError::ArgType(
                        "Arg::HpuId".to_string(),
                        args[0].clone(),
                    )));
                }
                if let Some(slot) = get_slot(args.get(1))? {
                    (VirtId(1), flag, slot)
                } else {
                    (VirtId::default(), flag, MemId::default())
                }
            }
            _ => {
                return Err(Box::new(ParsingError::ArgType(
                    "Arg::HpuId|Arg::UcoreFlag".to_string(),
                    args[0].clone(),
                )))
            }
        };
        Ok(Self {
            opcode: Opcode::from(opcode),
            hid,
            flag,
            slot,
        })
    }
}

impl ToAsm for PeUcoreInsn {
    fn dst(&self) -> Vec<arg::Arg> {
        vec![]
    }
    fn src(&self) -> Vec<arg::Arg> {
        if self.opcode == Opcode::NOTIFY() {
            vec![
                Arg::HpuId(self.hid),
                Arg::UcoreFlag(self.flag),
                Arg::Mem(self.slot),
            ]
        } else {
            if self.hid == VirtId(0) {
                // No Data
                vec![Arg::UcoreFlag(self.flag)]
            } else {
                vec![Arg::UcoreFlag(self.flag), Arg::Mem(self.slot)]
            }
        }
    }
    fn opcode(&self) -> Opcode {
        self.opcode
    }
}

impl ToFlush for field::PePbsInsn {
    fn to_flush(&self) -> Self {
        PePbsInsn {
            opcode: self.opcode.to_flush(),
            ..*self
        }
    }
}
impl ToFlush for field::PeArithInsn {}
impl ToFlush for field::PeArithMsgInsn {}
impl ToFlush for field::PeMemInsn {}
impl ToFlush for field::PeSyncInsn {}
impl ToFlush for field::PeUcoreInsn {}
