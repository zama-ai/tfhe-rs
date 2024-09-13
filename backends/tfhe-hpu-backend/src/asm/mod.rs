//!
//! Set of trait used to described and handle an instruction set
//!
//! Provide two concrete implementation of those traits
//! * DigitOperations (DOp)
//! * IntegerOperarions (IOp)

pub mod arg;
pub mod dop;
pub mod iop;
pub mod pbs;

pub use strum;

use enum_dispatch::enum_dispatch;

pub use arg::{Arg, MemMode, MemOrigin, MemSlot, ARG_MIN_WIDTH};
pub use dop::*;
pub use iop::*;
pub use pbs::*;

use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

// #[cfg(test)]
// mod unit_tests;

// Parsing error
#[derive(Error, Debug, Clone)]
pub enum ArgError {
    #[error("Invalid arguments number: {self:?}[exp, get]")]
    InvalidNumber(usize, usize),
    #[error("Invalid arguments: {self:?}[exp, get]")]
    InvalidField(String, Arg),
}

// Parsing error
#[derive(Error, Debug, Clone)]
pub enum ParsingError {
    #[error("Unmatch Asm Operation")]
    Unmatch,
    #[error("Invalid arguments: {0}")]
    InvalidArg(String),
    #[error("Empty line")]
    Empty,
}

/// Describe Hw Properties
/// Use to generate valid Random values
#[derive(Debug, Clone)]
pub struct ArchProperties {
    pub regs: usize,
    pub mem: MemRegion,
    pub pbs_w: usize,

    pub msg_w: usize,
    pub carry_w: usize,
    pub nu: usize,
    pub integer_w: usize,
}

impl ArchProperties {
    pub fn blk_w(&self) -> usize {
        self.integer_w.div_ceil(self.msg_w)
    }
}

/// Memory region definition
/// Only used to define memory size and shape
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct MemRegion {
    pub bid: usize,
    pub size: usize,
}
impl FromStr for MemRegion {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (bid_str, size_str) = s
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .and_then(|s| s.split_once(':'))
            .ok_or(anyhow::Error::msg(
                "Parsing error: expect something like '{{bid: size}}'",
            ))?;

        // Convert str to usize
        let bid = bid_str.trim().parse::<usize>()?;
        let size = size_str.trim().parse::<usize>()?;
        Ok(Self { bid, size })
    }
}

/// Base trait to depict an ASM instruction
/// Provides a set of method to raison about intruction and access fields
#[enum_dispatch(DOp, IOp)]
pub trait Asm {
    fn name(&self) -> &'static str;
    fn has_imm(&self) -> bool;

    // Generic arguments handling
    fn args(&self) -> Vec<Arg>;
    fn dst(&self) -> Vec<Arg>;
    fn src(&self) -> Vec<Arg>;

    // Randomization
    fn randomize(&mut self, props: &ArchProperties, rng: &mut StdRng);

    // Serde as human readable ASM
    fn asm_encode(&self, width: usize) -> String;
    fn from_args(&mut self, args: Vec<Arg>) -> Result<(), anyhow::Error>;
}

#[enum_dispatch(DOp, IOp)]
// #[enum_dispatch(DOp)]
pub trait AsmBin {
    // Serde as binary values
    fn bin_encode_le(&self) -> Result<Vec<u8>, anyhow::Error>;
    fn from_deku(&mut self, any: &dyn Any) -> Result<(), ParsingError>;
}

/// Generic structure use to encode/decode ASM operation to/from a file
#[derive(Debug)]
pub struct Parser<Op> {
    op_list: Vec<Op>,
}

impl<Op> Parser<Op> {
    pub fn new(op_list: Vec<Op>) -> Self {
        Self { op_list }
    }
}

impl<Op> Parser<Op> {
    pub fn from_asm(&mut self, asm: &str) -> Result<Op, ParsingError>
    where
        Arg: std::str::FromStr,
        Op: Asm + Clone,
    {
        // Parse Args
        let arg_str = asm.split_whitespace().collect::<Vec<_>>();
        if !arg_str.is_empty() {
            let name = arg_str[0];
            let args = arg_str[1..]
                .iter()
                .map(|s| Arg::from_str(s))
                .collect::<Result<Vec<_>, _>>()?;

            // Template name patching if need
            let mut template_args = args
                .iter()
                .map(|arg| {
                    if let Arg::MemId(MemSlot {
                        mode: MemMode::Template,
                        orig,
                        ..
                    }) = arg
                    {
                        orig
                    } else {
                        &None
                    }
                })
                .filter(|orig| orig.is_some())
                .collect::<Vec<_>>();

            let name = if let Some(orig) = template_args.pop() {
                match orig.unwrap() {
                    MemOrigin::Dst => "TSTD".to_string(),
                    MemOrigin::SrcA => "TLDA".to_string(),
                    MemOrigin::SrcB => "TLDB".to_string(),
                    MemOrigin::Heap => {
                        format!("T{name}H")
                    }
                }
            } else {
                name.to_string()
            };

            // Try match against op
            for op in self.op_list.iter_mut() {
                if name == op.name() {
                    op.from_args(args)
                        .map_err(|err| ParsingError::InvalidArg(err.to_string()))?;
                    return Ok(op.clone());
                }
            }
            Err(ParsingError::Unmatch)
        } else {
            Err(ParsingError::Empty)
        }
    }

    pub fn read_asm<Arg>(&mut self, file: &str) -> Result<(String, Vec<Op>), anyhow::Error>
    where
        Arg: std::str::FromStr,
        Op: Asm + Clone,
    {
        // Open file
        let rd_f = BufReader::new(OpenOptions::new().create(false).read(true).open(file)?);

        let mut header = String::new();
        let mut ops = Vec::new();
        for (line, val) in rd_f.lines().flatten().enumerate() {
            if let Some(comment) = val.trim().strip_prefix('#') {
                header += comment.trim();
                header += "\n";
            } else {
                match self.from_asm(&val) {
                    Ok(op) => ops.push(op),
                    Err(ParsingError::Empty) => {}
                    Err(err) => {
                        anyhow::bail!(
                            "ReadAsm parser encounter error @{file}:{} ->{}",
                            line + 1,
                            err.to_string()
                        );
                    }
                }
            }
        }
        Ok((header, ops))
    }
}

impl<Op> Parser<Op> {
    pub fn from_be_bytes<Deku>(&mut self, bin: &[u8]) -> Result<Op, anyhow::Error>
    where
        Deku: for<'a> deku::DekuContainerRead<'a> + 'static,
        Op: AsmBin + Clone,
    {
        let (_, deku) = Deku::from_bytes((bin, 0))?;
        for op in self.op_list.iter_mut() {
            if op.from_deku(&deku).is_ok() {
                return Ok(op.clone());
            }
        }
        Err(ParsingError::Unmatch.into())
    }

    pub fn read_hex<Deku>(&mut self, file: &str) -> Result<(String, Vec<Op>), anyhow::Error>
    where
        Deku: for<'a> deku::DekuContainerRead<'a> + 'static,
        Op: AsmBin + Clone,
    {
        // Open file
        let rd_f = BufReader::new(OpenOptions::new().create(false).read(true).open(file)?);

        let mut header = String::new();
        let mut ops = Vec::new();

        for (line, val) in rd_f.lines().flatten().enumerate() {
            if let Some(comment) = val.trim().strip_prefix('#') {
                header += comment.trim();
                header += "\n";
            } else {
                // WARN: Deku expect BigEndian order (required to use Opcode as enum encoder)
                // File were written word by word (thus first byte read is the MSB one)
                let bytes = val
                    .as_bytes()
                    .chunks(2)
                    .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16))
                    .collect::<Result<Vec<u8>, _>>()?;

                match self.from_be_bytes::<Deku>(&bytes) {
                    Ok(op) => ops.push(op),
                    Err(err) => {
                        anyhow::bail!(
                            "ReadHex parser encounter error @{file}:{} ->{}",
                            line + 1,
                            err.to_string()
                        );
                    }
                }
            }
        }
        Ok((header, ops))
    }
}

pub fn write_asm<Op>(
    header: &str,
    ops: &[Op],
    file: &str,
    width: usize,
) -> Result<(), anyhow::Error>
where
    Op: Asm,
{
    // Create path
    let path = Path::new(file);
    if let Some(dir_p) = path.parent() {
        std::fs::create_dir_all(dir_p).unwrap();
    }

    // Open file
    let mut wr_f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    // TODO handle write error properly
    for l in header.lines() {
        writeln!(wr_f, "# {l}")?;
    }

    for op in ops.iter() {
        writeln!(wr_f, "{}", op.asm_encode(width))?;
    }
    Ok(())
}

pub fn write_hex<Op>(header: &str, ops: &[Op], file: &str) -> Result<(), anyhow::Error>
where
    Op: AsmBin + Clone,
{
    // Create path
    let path = Path::new(file);
    if let Some(dir_p) = path.parent() {
        std::fs::create_dir_all(dir_p).unwrap();
    }

    // Open file
    let mut wr_f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;

    // TODO handle write error properly
    for l in header.lines() {
        writeln!(wr_f, "# {l}")?;
    }

    // TODO handle write error properly
    for op in ops {
        let bytes = op.bin_encode_le()?;
        // Bytes are in little-endian but written from first to last line
        // To keep correct endianness -> reverse the chunked vector
        for bytes_chunks in bytes.chunks(std::mem::size_of::<u32>()).rev() {
            let word_b = bytes_chunks.try_into().expect("Invalid slice length");
            let word_u32 = u32::from_le_bytes(word_b);
            writeln!(wr_f, "{word_u32:08x}")?;
        }
    }
    Ok(())
}

/// Convert prog in translation table (word with 32)
/// First word is the table length
/// Other word are list of Op in hex format
pub fn tr_table<Op>(ops: &[Op]) -> Vec<u32>
where
    Op: AsmBin + Clone,
{
    let mut words_stream = Vec::with_capacity(ops.len() + 1);

    // First word of the stream is length in DOp
    words_stream.push(ops.len() as u32);
    ops.iter().for_each(|op| {
        let op_bytes = op.bin_encode_le().unwrap();
        let op_word = op_bytes.try_into().expect("Invalid slice length");
        words_stream.push(u32::from_le_bytes(op_word));
    });
    words_stream
}
