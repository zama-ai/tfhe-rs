pub mod dop;
pub use dop::arg::Arg as DOpArg;
pub use dop::{DOp, DigitParameters, ImmId, MemId, Pbs, PbsGid, PbsLut, RegId, ToHex};
pub mod iop;
pub use iop::{AsmIOpcode, IOp, IOpProto, IOpcode, OperandKind};

use std::collections::VecDeque;
use std::io::{BufRead, Write};

pub const ASM_COMMENT_PREFIX: [char; 2] = [';', '#'];

// Common type used in both DOp/IOp definition --------------------------------
/// Ciphertext Id
/// On-board memory is viewed as an array of ciphertext,
/// Thus, instead of using bytes address, ct id is used
/// => Id of the first ciphertext of the vector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CtId(pub u16);

// ---------------------------------------------------------------------------

/// Simple test for Asm parsing
#[cfg(test)]
mod tests;

/// Type to aggregate Op and header
/// Aim is to kept correct interleaving while parsing
#[derive(Debug, Clone)]
pub enum AsmOp<Op> {
    Comment(String),
    Stmt(Op),
}

impl<Op: dop::arg::ToFlush> AsmOp<Op> {
    pub fn to_flush(&mut self) {
        if let AsmOp::Stmt(op) = self {
            *op = op.to_flush();
        }
    }
}

impl<Op: std::fmt::Display> std::fmt::Display for AsmOp<Op> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Comment(c) => write!(f, "{}{c}", ASM_COMMENT_PREFIX[0]),
            Self::Stmt(op) => write!(f, "{op}"),
        }
    }
}

/// Generic struct to represent sequence of operations
/// Used to extract OP from ASM file
/// Work on any kind of Op that implement FromStr
#[derive(Debug, Clone)]
pub struct Program<Op>(Vec<AsmOp<Op>>);

impl<Op> Default for Program<Op> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<Op> Program<Op> {
    pub fn new(ops: Vec<AsmOp<Op>>) -> Self {
        Self(ops)
    }
    /// Push a new statement in the program
    pub fn push_stmt(&mut self, op: Op) {
        self.0.push(AsmOp::Stmt(op))
    }
    /// Push a new statement in the program
    /// Returns the position in which the statement was inserted
    pub fn push_stmt_pos(&mut self, op: Op) -> usize {
        let ret = self.0.len();
        self.0.push(AsmOp::Stmt(op));
        ret
    }
    /// Push a new comment in the program
    pub fn push_comment(&mut self, comment: String) {
        self.0.push(AsmOp::Comment(comment))
    }

    pub fn get_stmt_mut(&mut self, i: usize) -> &mut AsmOp<Op> {
        &mut self.0[i]
    }
}

impl<Op> std::ops::Deref for Program<Op> {
    type Target = Vec<AsmOp<Op>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Op: std::fmt::Display> std::fmt::Display for Program<Op> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for op in self.0.iter() {
            writeln!(f, "{op}")?;
        }
        Ok(())
    }
}

impl<Op, Err> Program<Op>
where
    Op: std::str::FromStr<Err = Err>,
    Err: std::error::Error,
{
    /// Generic function to extract OP from ASM file
    /// Work on any kind of Op that implement FromStr
    pub fn read_asm(file: &str) -> Result<Self, anyhow::Error> {
        // Open file
        let rd_f = std::io::BufReader::new(
            std::fs::OpenOptions::new()
                .create(false)
                .read(true)
                .open(file)?,
        );

        let mut asm_ops = Vec::new();
        for (line, val) in rd_f.lines().map_while(Result::ok).enumerate() {
            if let Some(comment) = val.trim().strip_prefix(ASM_COMMENT_PREFIX) {
                asm_ops.push(AsmOp::Comment(comment.to_string()))
            } else if !val.is_empty() {
                match Op::from_str(&val) {
                    Ok(op) => asm_ops.push(AsmOp::Stmt(op)),
                    Err(err) => {
                        tracing::warn!("ReadAsm failed @{file}:{}", line + 1);
                        anyhow::bail!("ReadAsm failed @{file}:{} with {}", line + 1, err);
                    }
                }
            }
        }
        Ok(Self(asm_ops))
    }
}

impl<Op> Program<Op>
where
    Op: std::fmt::Display,
{
    /// Generic function to write Op in ASM file
    /// Work on any kind of Op that implement Display
    pub fn write_asm(&self, file: &str) -> Result<(), anyhow::Error> {
        // Create path
        let path = std::path::Path::new(file);
        if let Some(dir_p) = path.parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }

        // Open file
        let mut wr_f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        writeln!(wr_f, "{self}").map_err(anyhow::Error::new)
    }
}

// Implement dedicated hex parser/dumper for DOp
impl Program<dop::DOp> {
    /// Generic function to extract OP from hex file
    /// Work on any kind of Op that implement FromStr
    pub fn read_hex(file: &str) -> Result<Self, anyhow::Error> {
        // Open file
        let rd_f = std::io::BufReader::new(
            std::fs::OpenOptions::new()
                .create(false)
                .read(true)
                .open(file)
                .unwrap_or_else(|_| panic!("Invalid HEX file {file}")),
        );

        let mut prog = Self::default();
        for (line, val) in rd_f.lines().map_while(Result::ok).enumerate() {
            if let Some(comment) = val.trim().strip_prefix(ASM_COMMENT_PREFIX) {
                prog.push_comment(comment.to_string());
            } else {
                let val_u32 =
                    dop::DOpRepr::from_str_radix(std::str::from_utf8(val.as_bytes()).unwrap(), 16)?;
                match dop::DOp::from_hex(val_u32) {
                    Ok(op) => prog.push_stmt(op),
                    Err(err) => {
                        tracing::warn!("DOp::ReadHex failed @{file}:{}", line + 1);
                        return Err(err.into());
                    }
                }
            }
        }
        Ok(prog)
    }

    /// Generic function to write Op in Hex file
    pub fn write_hex(&self, file: &str) -> Result<(), anyhow::Error> {
        // Create path
        let path = std::path::Path::new(file);
        if let Some(dir_p) = path.parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }

        // Open file
        let mut wr_f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        for op in self.0.iter() {
            match op {
                AsmOp::Comment(comment) => writeln!(wr_f, "{}{}", ASM_COMMENT_PREFIX[0], comment)?,
                AsmOp::Stmt(op) => writeln!(wr_f, "{:x}", op.to_hex())?,
            }
        }
        Ok(())
    }
}

impl Program<dop::DOp> {
    /// Convert a program of Dops in translation table
    pub fn tr_table(&self) -> Vec<dop::DOpRepr> {
        let ops_stream = self
            .iter()
            .filter_map(|op| match op {
                AsmOp::Comment(_) => None,
                AsmOp::Stmt(op) => Some(op),
            })
            .collect::<Vec<_>>();

        let mut words_stream = Vec::with_capacity(ops_stream.len() + 1);
        // First word of the stream is length in DOp
        words_stream.push(ops_stream.len() as u32);

        ops_stream.iter().for_each(|op| {
            words_stream.push(op.to_hex());
        });
        words_stream
    }
}

// Implement dedicated hex parser/dumper for IOp
impl Program<iop::IOp> {
    /// Generic function to extract OP from hex file
    pub fn read_hex(file: &str) -> Result<Self, anyhow::Error> {
        // Open file
        let rd_f = std::io::BufReader::new(
            std::fs::OpenOptions::new()
                .create(false)
                .read(true)
                .open(file)
                .unwrap_or_else(|_| panic!("Invalid HEX file {file}")),
        );

        let mut prog = Self::default();
        // Buffer word stream.
        // When comment token occurred, convert the word stream into IOp
        // -> No comment could be inserted in a middle of IOp word stream
        let mut word_stream = VecDeque::new();
        let mut file_len = 0;

        for val in rd_f.lines().map_while(Result::ok) {
            file_len += 1;
            if let Some(comment) = val.trim().strip_prefix(ASM_COMMENT_PREFIX) {
                while !word_stream.is_empty() {
                    match iop::IOp::from_words(&mut word_stream) {
                        Ok(op) => prog.push_stmt(op),
                        Err(err) => {
                            tracing::warn!(
                                "IOp::ReadHex failed @{file}:{}",
                                file_len - word_stream.len()
                            );
                            return Err(err.into());
                        }
                    }
                }
                prog.push_comment(comment.to_string());
            } else {
                let word = iop::IOpWordRepr::from_str_radix(
                    std::str::from_utf8(val.as_bytes()).unwrap(),
                    16,
                )?;
                word_stream.push_back(word);
            }
        }
        // Flush word stream
        while !word_stream.is_empty() {
            match iop::IOp::from_words(&mut word_stream) {
                Ok(op) => prog.push_stmt(op),
                Err(err) => {
                    tracing::warn!(
                        "IOp::ReadHex failed @{file}:{}",
                        file_len - word_stream.len()
                    );
                    return Err(err.into());
                }
            }
        }
        Ok(prog)
    }

    /// Generic function to write Op in Hex file
    pub fn write_hex(&self, file: &str) -> Result<(), anyhow::Error> {
        // Create path
        let path = std::path::Path::new(file);
        if let Some(dir_p) = path.parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }

        // Open file
        let mut wr_f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        for op in self.0.iter() {
            match op {
                AsmOp::Comment(comment) => writeln!(wr_f, "{}{}", ASM_COMMENT_PREFIX[0], comment)?,
                AsmOp::Stmt(op) => {
                    op.to_words()
                        .into_iter()
                        .try_for_each(|word| writeln!(wr_f, "{word:0>8x}"))?;
                }
            }
        }
        Ok(())
    }
}
