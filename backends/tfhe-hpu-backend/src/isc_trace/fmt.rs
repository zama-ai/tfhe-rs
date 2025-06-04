use super::packed_struct::{Len, NoMoreBits, PackedStructLsb};
use crate::asm::dop::DOp;
use bitvec::prelude::*;
use serde::Serialize;
use std::error::Error;
use std::fmt::Display;

// TODO: We need to have some kind of trace versioning system to be able to
// retroactively support traces coming from different hardware versions

pub static TRACE_W: usize = 16;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum IscQueryCmd {
    NONE,
    RDUNLOCK,
    RETIRE,
    REFILL,
    ISSUE,
}

#[derive(Debug)]
struct BadCmd;

impl Display for BadCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("No such command")
    }
}

impl Error for BadCmd {
    fn description(&self) -> &str {
        "No such command"
    }
}

impl Len for IscQueryCmd {
    fn len() -> usize {
        3
    }
}

impl<O> PackedStructLsb<O> for IscQueryCmd
where
    O: bitvec::store::BitStore,
{
    fn from_bit_slice_le(slice: &BitSlice<O, Lsb0>) -> Result<Self, Box<dyn Error>> {
        let bits = slice.get(0..3).ok_or(NoMoreBits)?.load::<u8>();
        match bits {
            0 => Ok(IscQueryCmd::NONE),
            1 => Ok(IscQueryCmd::RDUNLOCK),
            2 => Ok(IscQueryCmd::RETIRE),
            3 => Ok(IscQueryCmd::REFILL),
            4 => Ok(IscQueryCmd::ISSUE),
            _ => Err(BadCmd.into()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct IscPoolState {
    pub(super) pdg: bool,
    pub(super) rd_pdg: bool,
    pub(super) vld: bool,
    pub(super) wr_lock: u32,
    pub(super) rd_lock: u32,
    pub(super) issue_lock: u32,
    pub(super) sync_id: u32,
}

impl Len for IscPoolState {
    fn len() -> usize {
        28
    }
}

impl<O> PackedStructLsb<O> for IscPoolState
where
    O: bitvec::store::BitStore,
{
    fn from_bit_slice_le(slice: &BitSlice<O, Lsb0>) -> Result<Self, Box<dyn Error>> {
        Ok(IscPoolState {
            pdg: *(slice.get(0).ok_or(NoMoreBits)?),
            rd_pdg: *(slice.get(1).ok_or(NoMoreBits)?),
            vld: *(slice.get(2).ok_or(NoMoreBits)?),
            wr_lock: slice.get(3..10).ok_or(NoMoreBits)?.load::<u32>(),
            rd_lock: slice.get(10..17).ok_or(NoMoreBits)?.load::<u32>(),
            issue_lock: slice.get(17..24).ok_or(NoMoreBits)?.load::<u32>(),
            sync_id: slice.get(24..28).ok_or(NoMoreBits)?.load::<u32>(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct IscTrace {
    pub(super) state: IscPoolState,
    pub(super) cmd: IscQueryCmd,
    pub(super) insn: Option<DOp>,
    pub(super) insn_asm: Option<String>,
    pub(super) timestamp: u32,
}

impl<O> PackedStructLsb<O> for IscTrace
where
    O: bitvec::store::BitStore,
{
    fn from_bit_slice_le(slice: &BitSlice<O, Lsb0>) -> Result<Self, Box<dyn Error>> {
        let lwe_k_w = 10;
        let slice = slice.get(lwe_k_w..).ok_or(NoMoreBits)?;

        let state = IscPoolState::from_bit_slice_le(slice)?;
        let slice = slice.get(IscPoolState::len()..).ok_or(NoMoreBits)?;

        let cmd = IscQueryCmd::from_bit_slice_le(slice)?;
        let slice = slice.get(IscQueryCmd::len()..).ok_or(NoMoreBits)?;

        let insn = match cmd {
            IscQueryCmd::REFILL | IscQueryCmd::NONE => None,
            _ => {
                let insn = u32::from_bit_slice_le(slice)?;
                let dop = DOp::from_hex(insn)?;
                Some(dop)
            }
        };

        let slice = slice.get(u32::len()..).ok_or(NoMoreBits)?;
        let timestamp = u32::from_bit_slice_le(slice)?;
        let insn_asm = insn.as_ref().map(|dop| format!("{dop}"));

        Ok(IscTrace {
            state,
            cmd,
            insn,
            insn_asm,
            timestamp,
        })
    }
}

impl Len for IscTrace {
    fn len() -> usize {
        TRACE_W
    }
}

#[derive(Serialize, Debug)]
pub struct IscTraceStream(pub(super) Vec<IscTrace>);

impl IscTraceStream {
    pub fn sort(&mut self) {
        self.0.sort_by_key(|k| k.timestamp)
    }

    pub fn from_bytes(bytes: &[u8]) -> IscTraceStream {
        let view = bytes.view_bits::<Lsb0>();
        IscTraceStream(
            view.chunks(TRACE_W * 8)
                .filter_map(|c| IscTrace::from_bit_slice_le(c).ok())
                .collect(),
        )
    }
}

#[cfg(test)]
mod test;
