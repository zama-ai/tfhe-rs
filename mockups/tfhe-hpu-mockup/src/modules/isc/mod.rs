//! Model the instruction flom in HPU.
//!
//! Use a simple event based time simulation and simple PE modelisation

use crate::mockup_params::IscSimParameters;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use tfhe::tfhe_hpu_backend::prelude::*;

/// Implement a pool that mimics the RTL
mod pool;
use pool::Pool;

/// Implement simple model of Pe
mod pe;
use pe::PeStore;
pub use pe::{PeConfig, PeConfigStore, PeCost};

/// Implement time simulation of Isc
mod scheduler;
pub use scheduler::Scheduler;

/// Event used for modelisation of time advance
/// Contain the cycle in which the event must occure and the associated event type
#[derive(Debug)]
struct Event {
    pub at_cycle: usize,
    pub event_type: EventType,
}

impl Event {
    pub fn new(event_type: EventType, at_cycle: usize) -> Self {
        Self {
            at_cycle,
            event_type,
        }
    }
}

/// Event are stored in a BinaryHeap and we want to pop the smallest one firs
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
#[derive(Debug, PartialEq, Eq)]
enum EventType {
    RdUnlock(InstructionKind, usize),
    WrUnlock(InstructionKind, usize),
    ReqTimeout(InstructionKind, usize),
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

impl From<&hpu_asm::DOp> for InstructionKind {
    fn from(value: &hpu_asm::DOp) -> Self {
        match value {
            hpu_asm::DOp::ADD(_)
            | hpu_asm::DOp::SUB(_)
            | hpu_asm::DOp::MAC(_)
            | hpu_asm::DOp::ADDS(_)
            | hpu_asm::DOp::SUBS(_)
            | hpu_asm::DOp::SSUB(_)
            | hpu_asm::DOp::MULS(_) => Self::Arith,
            hpu_asm::DOp::LD(_) => Self::MemLd,
            hpu_asm::DOp::ST(_) => Self::MemSt,
            hpu_asm::DOp::PBS(_)
            | hpu_asm::DOp::PBS_ML2(_)
            | hpu_asm::DOp::PBS_ML4(_)
            | hpu_asm::DOp::PBS_ML8(_) => Self::Pbs,
            hpu_asm::DOp::PBS_F(_)
            | hpu_asm::DOp::PBS_ML2_F(_)
            | hpu_asm::DOp::PBS_ML4_F(_)
            | hpu_asm::DOp::PBS_ML8_F(_) => Self::Pbs,
            hpu_asm::DOp::SYNC(_) => Self::Sync,
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

/// Generate a detailed execution trace that could be read afterward
#[derive(Debug, Serialize, Deserialize)]
pub struct Trace {
    timestamp: usize,
    cmd: Query,
    slot: pool::Slot,
}

impl std::fmt::Display for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{}::{:?} -> {:?}", self.timestamp, self.cmd, self.slot)
    }
}
