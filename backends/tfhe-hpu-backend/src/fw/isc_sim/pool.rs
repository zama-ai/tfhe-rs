use asm::dop::{
    DOpPbs, DOpPbsF, DOpPbsMl2, DOpPbsMl2F, DOpPbsMl4, DOpPbsMl4F, DOpPbsMl8, DOpPbsMl8F, IsFlush,
    ToAsm,
};
use asm::PbsLut;
use tracing::instrument;

use super::*;

#[derive(Debug)]
pub struct Pool {
    max_depth: usize,
    store: Vec<Slot>,
}

impl std::fmt::Display for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Pool content [{}]:", self.max_depth)?;
        for (i, slot) in self.store.iter().enumerate() {
            writeln!(f, "{i} -> {slot:?}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum IssueEvt {
    None,
    DOp {
        kind_1h: InstructionKind,
        flush: bool,
        slot: Slot,
    },
    Sync(Slot),
}

impl Pool {
    pub fn new(isc_depth: usize) -> Self {
        Self {
            max_depth: isc_depth,
            store: Vec::with_capacity(isc_depth),
        }
    }

    /// Check if the pool is full
    pub fn is_full(&self) -> bool {
        self.store.len() >= self.max_depth
    }

    /// This function find the first matching slot update it in place
    /// And also update lock counter of all matching slot
    /// kind_mh is an aggregtion of pending rd_unlock
    #[instrument(level = "trace", skip(self))]
    pub fn rd_unlock(&mut self, kind_mh: InstructionKind) -> (InstructionKind, &Slot) {
        // 1. find matching slot and update
        // -> Search for oldest issued instruction with matching kind
        let filter = Filter {
            vld: Some(true),
            rd_pdg: Some(true),
            pdg: Some(true),
            kind: Some(kind_mh),
            ..Default::default()
        };
        let mut slot = self.first_match(filter).expect("RdUnlock unmatched");
        slot.state.rd_pdg = false;

        // 2. Decrease matching rd_lock cnt
        let filter = Filter {
            vld: Some(true),
            pdg: Some(false),
            srcs_on_dst: Some((slot.inst.srca_id, slot.inst.srcb_id)),
            ..Default::default()
        };
        self.idx_matches(filter).into_iter().for_each(|idx| {
            tracing::trace!("RdLock decrement -> {:?}", self.store[idx]);
            // TODO dig in this condition
            // Find a case that required the underflow filtering
            if self.store[idx].state.rd_lock != 0 {
                self.store[idx].state.rd_lock -= 1;
            }
        });

        // 3. Insert modified slot back
        let kind_1h = slot.inst.kind;
        self.store.push(slot);
        // Use hand call to trace to prevent closure escape of ref with #[instrument(ret)]
        tracing::trace!("Return: {:?}", self.store.last().unwrap());
        (kind_1h, self.store.last().unwrap())
    }

    /// This function find the first matching slot update it in place
    /// And also update lock counter of all matching slot
    /// kind_mh is an aggregtion of pending wr_unlock
    #[instrument(level = "trace", skip(self), ret)]
    pub fn retire(&mut self, kind_mh: InstructionKind) -> Slot {
        // 1. find matching slot and update
        // -> Search for oldest issued instruction with matching kind
        let filter = Filter {
            vld: Some(true),
            rd_pdg: Some(false),
            pdg: Some(true),
            kind: Some(kind_mh),
            ..Default::default()
        };
        let slot = self.first_match(filter).expect("Retire unmatched");

        // 2. Decrease matching wr_lock cnt
        let filter = Filter {
            vld: Some(true),
            rd_pdg: Some(true),
            pdg: Some(false),
            dst_on_srcs: Some(slot.inst.dst_id),
            dst_on_dst: Some(slot.inst.dst_id),
            ..Default::default()
        };
        self.idx_matches(filter).into_iter().for_each(|idx| {
            tracing::trace!("WrLock decrement -> {:?}", self.store[idx]);
            if self.store[idx].state.wr_lock != 0 {
                self.store[idx].state.wr_lock -= 1;
            }
        });

        // 2. Decrease matching wr_lock cnt of Sync token
        let filter = Filter {
            vld: Some(true),
            kind: Some(InstructionKind::Sync),
            sync_id: Some(slot.state.sync_id),
            ..Default::default()
        };
        self.idx_matches(filter).into_iter().for_each(|idx| {
            tracing::trace!("SyncLock decrement -> {:?}", self.store[idx]);
            if self.store[idx].state.wr_lock != 0 {
                self.store[idx].state.wr_lock -= 1;
            }
        });

        slot
    }

    /// This function find the first empty slot, populated with DOp information and move it
    /// in front position
    #[instrument(level = "trace", skip(self), ret)]
    pub fn refill(&mut self, sync_id: usize, dop: asm::DOp) -> &Slot {
        assert!(
            self.store.len() < self.max_depth,
            "Refill in a already full pool"
        );

        let op_kind = InstructionKind::from(&dop);
        let dst_id = ArgId::from_dst(&dop);
        let srca_id = ArgId::from_srca(&dop);
        let srcb_id = ArgId::from_srcb(&dop);
        let flush = dop.is_flush();

        // 1. Compute (wr_lock, rd_lock)
        // RdLock -> #instruction before us that need to READ into our destination
        // WrLock -> #instruction before us that need to Write into one of our sources
        let (wr_lock, rd_lock, issue_lock) = if op_kind == InstructionKind::Sync {
            // Count vld instruction that match with sync_id
            let filter = Filter {
                vld: Some(true),
                sync_id: Some(sync_id),
                ..Default::default()
            };
            let sync_lock = self.idx_matches(filter).len();
            (sync_lock, 0, 0)
        } else {
            // Count vld instruction where our dst match on their srcs
            let filter = Filter {
                vld: Some(true),
                rd_pdg: Some(true),
                dst_on_srcs: Some(dst_id),
                ..Default::default()
            };
            let rd_lock = self.idx_matches(filter).len();

            // Count vld instruction where our src match on their dst
            let filter = Filter {
                vld: Some(true),
                srcs_on_dst: Some((srca_id, srcb_id)),
                dst_on_dst: Some(dst_id),
                ..Default::default()
            };
            let wr_lock = self.idx_matches(filter).len();

            // Count vld instruction that were not issued and are not flushes if
            // this is a flush and vice-versa. Only for PBSs.
            let issue_lock = if op_kind == InstructionKind::Pbs {
                let filter = Filter {
                    vld: Some(true),
                    rd_pdg: Some(true),
                    pdg: Some(false),
                    flush: Some(!flush),
                    kind: Some(InstructionKind::Pbs),
                    ..Default::default()
                };
                self.idx_matches(filter).len()
            } else {
                0
            };

            (wr_lock, rd_lock, issue_lock)
        };

        // 2. Create new slot and insert it in store
        let slot = Slot {
            inst: Instruction {
                kind: op_kind,
                dst_id,
                srca_id,
                srcb_id,
                flush,
                op: dop,
            },
            state: State {
                sync_id,
                rd_lock,
                wr_lock,
                issue_lock,
                vld: true,
                rd_pdg: true,
                pdg: false,
            },
        };
        tracing::debug!("Refill with {slot:?}");
        self.store.push(slot);
        self.store.last().unwrap()
    }

    /// This function find the first issuable slot if any, update it's information and move it
    /// in back position
    /// kind_mh is an aggregtion of available pe
    #[instrument(level = "trace", skip(self), ret)]
    pub fn issue(&mut self, kind_mh: InstructionKind) -> IssueEvt {
        // 1. find matching slot and update
        // -> Search for oldest unissued instruction with matching kind
        let filter = Filter {
            vld: Some(true),
            rd_pdg: Some(true),
            pdg: Some(false),
            lock_rdy: Some(true),
            kind: Some(kind_mh),
            ..Default::default()
        };
        if let Some(mut slot) = self.first_match(filter) {
            if slot.inst.kind == InstructionKind::Sync {
                // Sync are handle with custom logic -> Issue them, directly release the slot
                IssueEvt::Sync(slot)
            } else {
                if slot.inst.kind == InstructionKind::Pbs {
                    let filter = Filter {
                        vld: Some(true),
                        rd_pdg: Some(true),
                        pdg: Some(false),
                        flush: Some(!slot.inst.flush),
                        kind: Some(InstructionKind::Pbs),
                        ..Default::default()
                    };
                    self.idx_matches(filter).into_iter().for_each(|idx| {
                        tracing::trace!("Issue decrement -> {:?}", self.store[idx]);
                        self.store[idx].state.issue_lock =
                            self.store[idx].state.issue_lock.saturating_sub(1);
                    });
                }

                // Update slot and insert back
                slot.state.pdg = true;
                let kind_1h = slot.inst.kind;
                let flush = slot.inst.flush;
                let trace_slot = slot.clone();
                self.store.push(slot);
                IssueEvt::DOp {
                    kind_1h,
                    flush,
                    slot: trace_slot,
                }
            }
        } else {
            IssueEvt::None
        }
    }
}

impl Pool {
    /// Extract the first matching entry from the pool
    fn first_match(&mut self, filter: Filter) -> Option<Slot> {
        let match_idx = self.idx_matches(filter);
        if let Some(idx) = match_idx.first() {
            // extract value
            Some(self.store.remove(*idx))
        } else {
            None
        }
    }

    /// Return a vector of matching index
    fn idx_matches(&self, filter: Filter) -> Vec<usize> {
        self.store
            .iter()
            .enumerate()
            .filter(|(_, elem)| {
                if let Some(sync_id) = filter.sync_id {
                    elem.state.sync_id == sync_id
                } else {
                    true
                }
            })
            .filter(|(_, elem)| {
                if let Some(vld) = filter.vld {
                    elem.state.vld == vld
                } else {
                    true
                }
            })
            .filter(|(_, elem)| {
                if let Some(rd_pdg) = filter.rd_pdg {
                    elem.state.rd_pdg == rd_pdg
                } else {
                    true
                }
            })
            .filter(|(_, elem)| {
                if let Some(pdg) = filter.pdg {
                    elem.state.pdg == pdg
                } else {
                    true
                }
            })
            .filter(|(_, elem)| {
                if let Some(lock_rdy) = filter.lock_rdy {
                    elem.state.lock_rdy() == lock_rdy
                } else {
                    true
                }
            })
            .filter(|(_, elem)| {
                if let Some(kind) = filter.kind {
                    (elem.inst.kind & kind) != InstructionKind::None
                } else {
                    true
                }
            })
            .filter(|(_, elem)| {
                //TODO rework to enhance readability
                (if let Some(dst) = &filter.dst_on_srcs {
                    dst.mode != DOpMode::Unused
                        && ((elem.inst.srca_id == *dst) || (elem.inst.srcb_id == *dst))
                } else {
                    true
                } && if let Some((srca, srcb)) = &filter.srcs_on_dst {
                    ((srca.mode != DOpMode::Unused) && (elem.inst.dst_id == *srca))
                        || ((srcb.mode != DOpMode::Unused) && (elem.inst.dst_id == *srcb))
                } else {
                    true
                }) || filter
                    .dst_on_dst
                    .map(|dst| (dst.mode != DOpMode::Unused) && (elem.inst.dst_id == dst))
                    .unwrap_or(false)
            })
            .filter(|(_, elem)| filter.flush.map(|f| f == elem.inst.flush).unwrap_or(true))
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>()
    }
}

/// Instruction Mode -> Rid/Mid
/// Used as src/dst identifier
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
enum DOpMode {
    Unused,
    Memory,
    Register(usize),
}
/// Argument Id
/// Use for lock computation and match
#[derive(Debug, Eq, Clone, Copy, Serialize, Deserialize)]
struct ArgId {
    mode: DOpMode,
    id: usize,
}

impl PartialEq for ArgId {
    fn eq(&self, other: &Self) -> bool {
        match (self.mode, other.mode) {
            (DOpMode::Memory, DOpMode::Memory) | (DOpMode::Unused, DOpMode::Unused) => {
                self.id == other.id
            }
            (DOpMode::Register(self_msk), DOpMode::Register(other_msk)) => {
                // Does range overlaps ?! -> yes
                ((self.id ^ other.id) & (self_msk & other_msk)) == 0
            }
            _ => false,
        }
    }
}

impl Default for ArgId {
    fn default() -> Self {
        ArgId {
            mode: DOpMode::Unused,
            id: 0,
        }
    }
}

impl ArgId {
    fn from_arg(arg: asm::DOpArg) -> Self {
        match arg {
            asm::DOpArg::Reg(rid) => Self {
                mode: DOpMode::Register(usize::MAX),
                id: rid.0 as usize,
            },
            asm::DOpArg::Mem(ms) => {
                let id = match ms {
                    asm::MemId::Addr(ct_id) => ct_id.0 as usize,
                    _ => panic!("Template must have been resolved before execution"),
                };
                Self {
                    mode: DOpMode::Memory,
                    id,
                }
            }
            asm::DOpArg::Imm(_) | asm::DOpArg::Pbs(_) | asm::DOpArg::Sync(_) => Self {
                mode: DOpMode::Unused,
                id: 0,
            },
        }
    }

    fn from_dst(dop: &asm::DOp) -> Self {
        let dst = dop.dst();
        if dst.is_empty() {
            // No dest arg -> i.e Sync
            Self::default()
        } else {
            let mut arg = Self::from_arg(dst[0].clone());
            tracing::trace!(target = "pool", "Building dst for {:?}", dop);
            match dop {
                // Are we sure that this is better than what I had before?
                asm::DOp::PBS(DOpPbs(pbs))
                | asm::DOp::PBS_ML2(DOpPbsMl2(pbs))
                | asm::DOp::PBS_ML4(DOpPbsMl4(pbs))
                | asm::DOp::PBS_ML8(DOpPbsMl8(pbs))
                | asm::DOp::PBS_F(DOpPbsF(pbs))
                | asm::DOp::PBS_ML2_F(DOpPbsMl2F(pbs))
                | asm::DOp::PBS_ML4_F(DOpPbsMl4F(pbs))
                | asm::DOp::PBS_ML8_F(DOpPbsMl8F(pbs)) => {
                    // PBS used multiple contiguous register in case of many-lut
                    let lut = asm::Pbs::from_hex(pbs.gid).expect("Invalid PbsGid");
                    arg.mode = DOpMode::Register(lut.lut_msk());
                    tracing::trace!(
                        target = "pool",
                        "destination mask for {:?} = {:?}",
                        pbs,
                        arg.mode
                    );
                    arg
                }
                // Otherwise Standard ArgId handling
                _ => arg,
            }
        }
    }

    fn from_srca(dop: &asm::DOp) -> Self {
        let src = dop.src();
        if src.is_empty() {
            // No src arg -> i.e Sync
            Self::default()
        } else {
            Self::from_arg(src[0].clone())
        }
    }
    fn from_srcb(dop: &asm::DOp) -> Self {
        let src = dop.src();
        if src.len() < 2 {
            Self::default()
        } else {
            Self::from_arg(src[1].clone())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Instruction {
    pub(crate) op: asm::DOp,
    pub(crate) kind: InstructionKind,
    dst_id: ArgId,
    srca_id: ArgId,
    srcb_id: ArgId,
    flush: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct State {
    sync_id: usize,
    // RdLock -> #instruction before us that need to READ into our destination
    rd_lock: usize,
    // WrLock -> #instruction before us that need to Write into one of our sources
    wr_lock: usize,
    // IssueLock -> #instruction before us that need to be issued
    issue_lock: usize,
    vld: bool,
    rd_pdg: bool,
    pdg: bool,
}
impl State {
    fn lock_rdy(&self) -> bool {
        (self.rd_lock | self.wr_lock | self.issue_lock) == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Slot {
    pub(crate) inst: Instruction,
    pub(crate) state: State,
}

#[derive(Default, Debug)]
struct Filter {
    sync_id: Option<usize>,
    vld: Option<bool>,
    rd_pdg: Option<bool>,
    pdg: Option<bool>,
    lock_rdy: Option<bool>,
    kind: Option<InstructionKind>,
    dst_on_srcs: Option<ArgId>,
    srcs_on_dst: Option<(ArgId, ArgId)>,
    dst_on_dst: Option<ArgId>,
    flush: Option<bool>,
}
