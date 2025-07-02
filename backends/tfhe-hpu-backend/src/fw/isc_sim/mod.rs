//! Model the instruction flom in HPU.
//!
//! Use a simple event based time simulation and simple PE modelisation

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

/// Implement a pool that mimics the RTL
mod pool;
use pool::Pool;

/// Implement simple model of Pe
mod pe;
pub(crate) use pe::{Flush as PeFlush, PeStore};
pub use pe::{PeConfig, PeConfigStore, PeCost};

/// Implement time simulation of Isc
mod scheduler;
pub use scheduler::Scheduler;

pub(crate) mod report;

use crate::asm;

/// Event used for modelisation of time advance
/// Contain the cycle in which the event must occurred and the associated event type
#[derive(Debug)]
pub struct Event {
    pub(crate) at_cycle: usize,
    pub(crate) event_type: EventType,
}

impl Event {
    pub(crate) fn new(event_type: EventType, at_cycle: usize) -> Self {
        Self {
            at_cycle,
            event_type,
        }
    }
}

/// Event are stored in a BinaryHeap and we want to pop the smallest one first
/// Thuse Ord trait is implemented in a "reverse".
impl Ord for Event {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.at_cycle.cmp(&other.at_cycle).reverse()
    }
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.at_cycle == other.at_cycle
    }
}
impl Eq for Event {}

/// Kind of the event
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EventType {
    RdUnlock(InstructionKind, usize),
    WrUnlock(InstructionKind, usize),
    ReqTimeout(InstructionKind, usize),
    DelTimeout(InstructionKind, usize),
    BatchStart { pe_id: usize, issued: usize },
    QuantumEnd,
    BpipTimeout,
    Query,
}

bitflags! {
/// Instruction are dispatch on Pe based on their kind
/// However, we also need to filter on a multi-kind fashion, thus we rely on bitflag instead of std
/// rust enum
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize, Hash)]
    pub struct InstructionKind: usize {
        const None = 0x00;
        const MemLd= 0x01;
        const MemSt= 0x02;
        const Arith= 0x04;
        const Pbs  = 0x08;
        const Sync = 0x10;
    }
}

impl std::fmt::Display for InstructionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match *self {
            Self::None => "None",
            Self::MemLd => "MemLd",
            Self::MemSt => "MemSt",
            Self::Arith => "Arith",
            Self::Pbs => "Pbs",
            Self::Sync => "Sync",
            _ => "MultiKind",
        };
        write!(f, "{kind}")
    }
}

impl From<&asm::DOp> for InstructionKind {
    fn from(value: &asm::DOp) -> Self {
        match value {
            asm::DOp::ADD(_)
            | asm::DOp::SUB(_)
            | asm::DOp::MAC(_)
            | asm::DOp::ADDS(_)
            | asm::DOp::SUBS(_)
            | asm::DOp::SSUB(_)
            | asm::DOp::MULS(_) => Self::Arith,
            asm::DOp::LD(_) => Self::MemLd,
            asm::DOp::ST(_) => Self::MemSt,
            asm::DOp::PBS(_)
            | asm::DOp::PBS_ML2(_)
            | asm::DOp::PBS_ML4(_)
            | asm::DOp::PBS_ML8(_) => Self::Pbs,
            asm::DOp::PBS_F(_)
            | asm::DOp::PBS_ML2_F(_)
            | asm::DOp::PBS_ML4_F(_)
            | asm::DOp::PBS_ML8_F(_) => Self::Pbs,
            asm::DOp::SYNC(_) => Self::Sync,
        }
    }
}

/// Use in the execution trace
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Query {
    Refill,
    Issue,
    RdUnlock,
    Retire,
}

#[derive(Debug, Serialize, Deserialize)]
enum TraceEvent {
    Query { cmd: Query, slot: pool::Slot },
    Timeout,
    ReqTimeout(usize),
    DelTimeout,
    BatchStart { pe_id: usize, issued: usize },
}

/// Generate a detailed execution trace that could be read afterward
#[derive(Debug, Serialize, Deserialize)]
pub struct Trace {
    timestamp: usize,
    event: TraceEvent,
}

impl std::fmt::Display for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{}::{:?}", self.timestamp, self.event)
    }
}
