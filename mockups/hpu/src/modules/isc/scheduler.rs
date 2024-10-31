use pe::PeConfigStore;

use super::*;
use std::collections::{BTreeMap, BinaryHeap, VecDeque};

// TODO put the real value
const QUERY_CYCLE: usize = 40;

#[derive(Debug)]
pub struct Scheduler {
    params: IscSimParameters,
    quantum_cycles: usize,
    sim_cycles: usize,
    pc: usize,
    sync_id: usize,

    dop_pdg: VecDeque<hpu_asm::DOp>,
    dop_exec: Vec<hpu_asm::DOp>,
    pool: Pool,
    evt_pdg: BinaryHeap<Event>,
    rd_unlock: VecDeque<InstructionKind>,
    wr_unlock: VecDeque<InstructionKind>,
    pe_store: PeStore,
}

impl Scheduler {
    pub fn new(params: IscSimParameters) -> Self {
        // NB: Scale match between freq and time (i.e. us vs MHz)
        let quantum_cycles = params.freq_MHz * params.quantum_us;
        let pool = Pool::new(&params);
        let pe_store = PeStore::from(PeConfigStore::from_ron(&params.pe_cfg));

        Self {
            params,
            dop_pdg: VecDeque::new(),
            dop_exec: Vec::new(),
            sim_cycles: 0,
            pc: 0,
            sync_id: 0,
            quantum_cycles,
            evt_pdg: BinaryHeap::new(),
            pool,
            rd_unlock: VecDeque::new(),
            wr_unlock: VecDeque::new(),
            pe_store,
        }
    }

    /// Insert the given list of DOp in the isc stream
    pub fn insert_dops(&mut self, dops: Vec<hpu_asm::DOp>) {
        self.dop_pdg.extend(dops);
    }

    /// Simulate execution for simulation quantum
    /// Return the list of retired Dops during the simulated windows
    pub fn schedule(&mut self, bpip_timeout: Option<u32>) -> Vec<hpu_asm::DOp> {
        tracing::debug!(
            "Start simulation @{} [{}]",
            self.sim_cycles,
            self.quantum_cycles
        );
        tracing::trace!("{self:?}");

        // Register end-of-quantum
        self.evt_pdg.push(Event::new(
            EventType::QuantumEnd,
            self.sim_cycles + self.quantum_cycles,
        ));

        // Register Bpip timeout
        // TODO only generated if pbs_fifo_in  isn't empty
        if let Some(timeout) = bpip_timeout {
            self.evt_pdg.push(Event::new(
                EventType::BpipTimeout,
                self.sim_cycles + timeout as usize,
            ));
        }

        // Register next query
        self.evt_pdg.push(Event::new(
            EventType::Query,
            self.sim_cycles + self.quantum_cycles,
        ));

        // Start simulation loop
        loop {
            let Event {
                at_cycle,
                event_type,
            } = self.evt_pdg.pop().expect("Event queue is empty");
            tracing::trace!("[@{at_cycle}] -> {event_type:?}");

            // Update cycle
            assert!(
                at_cycle >= self.sim_cycles,
                "Simulation error, next register event is in the past"
            );
            self.sim_cycles = at_cycle;

            match event_type {
                EventType::RdUnlock(kind, id) => {
                    // update associated pe state
                    self.pe_store.rd_unlock(id);
                    self.rd_unlock.push_back(kind);
                }
                EventType::WrUnlock(kind, id) => {
                    // update associated pe state
                    self.pe_store.wr_unlock(id);
                    self.wr_unlock.push_back(kind);
                }
                EventType::QuantumEnd => {
                    break;
                }
                EventType::BpipTimeout => {
                    // Trigger issue on pe store with batch_flush flag
                    let evts = self.pe_store.probe_for_exec(self.sim_cycles, true);
                    evts.into_iter().for_each(|evt| self.evt_pdg.push(evt));
                }
                EventType::Query => self.query(),
            }
        }

        // Replace content of dop_exec with empty vec and return it's previous content
        std::mem::replace(&mut self.dop_exec, Vec::new())
    }

    /// Acknowledge rd_unlock
    /// Remove first matching entry
    fn ack_rd_unlock(&mut self, kind_1h: InstructionKind) {
        let match_idx = self
            .rd_unlock
            .iter()
            .enumerate()
            .filter(|(_, kind)| InstructionKind::None != (**kind & kind_1h))
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();

        self.rd_unlock.remove(match_idx[0]);
    }

    fn ack_wr_unlock(&mut self, kind_1h: InstructionKind) {
        let match_idx = self
            .wr_unlock
            .iter()
            .enumerate()
            .filter(|(_, kind)| InstructionKind::None != (**kind & kind_1h))
            .map(|(idx, _)| idx)
            .collect::<Vec<_>>();

        self.wr_unlock.remove(match_idx[0]);
    }
}

impl Scheduler {
    /// Issue a query to the pool to update instruction state
    /// The generated query is arbiter as follow:
    /// * RdUnlock
    /// * Retire
    /// * Refill
    /// * Issue
    // NB: Aims is to remove finish instruction ASAP and to ensure that the pool is
    // filled as much as possible
    fn query(&mut self) {
        let query_issue = if !self.rd_unlock.is_empty() {
            let kind_mh = self.rd_unlock_kind();
            let kind_1h = self.pool.rd_unlock(kind_mh);
            self.ack_rd_unlock(kind_1h);
            true
        } else if !self.wr_unlock.is_empty() {
            let kind_mh = self.wr_unlock_kind();
            let (dop, kind_1h) = self.pool.retire(kind_mh);
            self.ack_wr_unlock(kind_1h);
            self.dop_exec.push(dop);
            true
        } else if !self.pool.is_full() && !self.dop_pdg.is_empty() {
            let dop = self.dop_pdg.pop_front().unwrap();
            let nxt_sync_id = match &dop {
                hpu_asm::DOp::SYNC(_) => self.sync_id + 1,
                _ => self.sync_id,
            };
            self.pool.refill(self.sync_id, dop);
            self.sync_id = nxt_sync_id;

            true
        } else {
            // By default try to issue
            let pe_avail = self.pe_store.avail_kind() | InstructionKind::Sync;
            match self.pool.issue(pe_avail) {
                pool::IssueEvt::None => false,
                pool::IssueEvt::DOp { kind_1h, flush } => {
                    // Push token in associated pe
                    self.pe_store.push(kind_1h);

                    // Probe for execution and registered generated events
                    let evts = self.pe_store.probe_for_exec(self.sim_cycles, flush);
                    evts.into_iter().for_each(|evt| self.evt_pdg.push(evt));
                    true
                }
                pool::IssueEvt::Sync(dop) => {
                    self.dop_exec.push(dop);
                    true
                }
            }
        };

        // Register next Query event
        // NB: Register new query event only if something usefull has append. Other-wise wait for
        // the next registered event
        if query_issue {
            self.evt_pdg
                .push(Event::new(EventType::Query, self.sim_cycles + QUERY_CYCLE));
        }
    }

    /// Aggregate all pending rd_unlock to obtain multibit filtering flag
    fn rd_unlock_kind(&self) -> InstructionKind {
        self.rd_unlock
            .iter()
            .fold(InstructionKind::None, |acc, kind| acc | *kind)
    }

    /// Aggregate all pending wr_unlock to obtain multibit filtering flag
    fn wr_unlock_kind(&self) -> InstructionKind {
        self.wr_unlock
            .iter()
            .fold(InstructionKind::None, |acc, kind| acc | *kind)
    }
}
