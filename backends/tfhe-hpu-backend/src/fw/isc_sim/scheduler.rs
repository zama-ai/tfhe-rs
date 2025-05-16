use crate::prelude::HpuIscParameters;

use super::*;
use std::collections::{BinaryHeap, HashMap, VecDeque};

use report::{DOpRpt, PeStoreRpt, TimeRpt};

// NB: Pool query take 4 cycles on avg there are 3 pool request in a query
const QUERY_CYCLE: usize = 12;

#[derive(Debug)]
pub struct Scheduler {
    freq_mhz: usize,
    quantum_cycles: usize,
    sim_cycles: usize,
    sync_id: usize,

    dop_pdg: VecDeque<asm::DOp>,
    dop_exec: Vec<asm::DOp>,
    pool: Pool,
    evt_pdg: BinaryHeap<Event>,
    rd_unlock: Vec<InstructionKind>,
    wr_unlock: Vec<InstructionKind>,
    pe_store: PeStore,
    trace: Vec<Trace>,
}

impl Scheduler {
    pub fn new(
        freq_mhz: usize,
        quantum_us: usize,
        isc_params: &HpuIscParameters,
        pe_config: PeConfigStore,
    ) -> Self {
        // NB: Scale match between freq and time (i.e. us vs MHz)
        let quantum_cycles = freq_mhz * quantum_us;
        let pool = Pool::new(isc_params.depth);
        let pe_store = PeStore::from(pe_config);

        Self {
            freq_mhz,
            dop_pdg: VecDeque::new(),
            dop_exec: Vec::new(),
            sim_cycles: 0,
            sync_id: 0,
            quantum_cycles,
            evt_pdg: BinaryHeap::new(),
            pool,
            rd_unlock: Vec::new(),
            wr_unlock: Vec::new(),
            pe_store,

            trace: Vec::new(),
        }
    }

    /// Insert the given list of DOp in the isc stream
    pub fn insert_dops(&mut self, dops: Vec<asm::DOp>) {
        self.dop_pdg.extend(dops);
    }

    /// Simulate execution for simulation quantum
    /// Return the list of retired Dops during the simulated windows
    pub fn schedule(&mut self, bpip_timeout: Option<u32>) -> Vec<asm::DOp> {
        tracing::trace!(
            "Start simulation @{} [{}]",
            self.sim_cycles,
            self.quantum_cycles
        );

        // Register end-of-quantum
        self.evt_pdg.push(Event::new(
            EventType::QuantumEnd,
            self.sim_cycles + self.quantum_cycles,
        ));

        // Register next query
        self.evt_pdg
            .push(Event::new(EventType::Query, self.sim_cycles));

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

            let trigger_query = match event_type {
                EventType::RdUnlock(kind, id) => {
                    // update associated pe state
                    self.pe_store.rd_unlock(id);
                    self.rd_unlock.push(kind);

                    // Update the pe
                    let evts = self.pe_store.probe_for_exec_id(id, self.sim_cycles, None);
                    evts.into_iter().for_each(|evt| self.evt_pdg.push(evt));

                    true
                }
                EventType::WrUnlock(kind, id) => {
                    // update associated pe state
                    self.pe_store.wr_unlock(id);
                    self.wr_unlock.push(kind);

                    // Update the pe
                    let evts = self.pe_store.probe_for_exec_id(id, self.sim_cycles, None);
                    evts.into_iter().for_each(|evt| self.evt_pdg.push(evt));

                    true
                }
                EventType::ReqTimeout(kind, _id) => {
                    match kind {
                        InstructionKind::Pbs => {
                            // Register Bpip timeout
                            if let Some(timeout) = bpip_timeout {
                                // delete the timeout timer
                                self.evt_pdg = std::mem::take(&mut self.evt_pdg)
                                    .into_iter()
                                    .filter(|ev| ev.event_type != EventType::BpipTimeout)
                                    .collect();

                                // And re-start it
                                let timeout_stamp = self.sim_cycles + timeout as usize;
                                self.evt_pdg
                                    .push(Event::new(EventType::BpipTimeout, timeout_stamp));

                                self.trace.push(Trace {
                                    timestamp: self.sim_cycles,
                                    event: TraceEvent::ReqTimeout(timeout_stamp),
                                });
                            }
                        }
                        _ => panic!("Unexpected unit required a timeout registration {kind:?}"),
                    };
                    false
                }
                EventType::BatchStart { pe_id, issued } => {
                    self.trace.push(Trace {
                        timestamp: self.sim_cycles,
                        event: TraceEvent::BatchStart { pe_id, issued },
                    });
                    false
                }
                EventType::QuantumEnd => {
                    break;
                }
                EventType::DelTimeout(kind, _) => {
                    assert!(
                        kind == InstructionKind::Pbs,
                        "Unexpected unit requiring a timeout deletion {kind:?}"
                    );

                    // delete the timeout timer
                    self.evt_pdg = std::mem::take(&mut self.evt_pdg)
                        .into_iter()
                        .filter(|ev| ev.event_type != EventType::BpipTimeout)
                        .collect();

                    self.trace.push(Trace {
                        timestamp: self.sim_cycles,
                        event: TraceEvent::DelTimeout,
                    });

                    false
                }
                EventType::BpipTimeout => {
                    // Trigger issue on pe store with batch_flush flag
                    let evts = self
                        .pe_store
                        .probe_for_exec(self.sim_cycles, Some(pe::Flush::Timeout));
                    evts.into_iter().for_each(|evt| self.evt_pdg.push(evt));

                    self.trace.push(Trace {
                        timestamp: self.sim_cycles,
                        event: TraceEvent::Timeout,
                    });
                    true
                }
                EventType::Query => self.query(),
            };

            // Register next Query event
            // NB: Register new query event only if something useful has append. Other-wise wait
            // for the next registered event
            if trigger_query
                && !self.evt_pdg.iter().any(
                    |Event {
                         at_cycle: _,
                         event_type,
                     }| *event_type == EventType::Query,
                )
            {
                // Queries should be issued periodically at every QUERY_CYCLE
                let next_query = ((self.sim_cycles + QUERY_CYCLE) / QUERY_CYCLE) * QUERY_CYCLE;
                self.evt_pdg.push(Event::new(EventType::Query, next_query));
            }
        }

        // Replace content of dop_exec with empty vec and return it's previous content
        std::mem::take(&mut self.dop_exec)
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
    fn query(&mut self) -> bool {
        if !self.rd_unlock.is_empty() {
            let kind_mh = self.rd_unlock_kind();
            let (kind_1h, slot) = self.pool.rd_unlock(kind_mh);
            //NB: Operation behavior is executed at the rd_unlock staage to prevent later operation
            // to clutter the source operands. The dst register is then available in
            // advance, but not used before it's real availability due to wr_lock.
            // -> Another option would have been to buffer the source operands. However, due to the
            // operands size, we had preferred to move the behavioral execution at the rd_unlock
            // stage
            self.dop_exec.push(slot.inst.op.clone());

            self.trace.push(Trace {
                timestamp: self.sim_cycles,
                event: TraceEvent::Query {
                    cmd: Query::RdUnlock,
                    slot: slot.clone(),
                },
            });

            self.ack_rd_unlock(kind_1h);

            true
        } else if !self.wr_unlock.is_empty() {
            let kind_mh = self.wr_unlock_kind();
            let slot = self.pool.retire(kind_mh);
            self.ack_wr_unlock(slot.inst.kind);

            self.trace.push(Trace {
                timestamp: self.sim_cycles,
                event: TraceEvent::Query {
                    cmd: Query::Retire,
                    slot,
                },
            });
            true
        } else if !self.pool.is_full() && !self.dop_pdg.is_empty() {
            let dop = self.dop_pdg.pop_front().unwrap();
            let nxt_sync_id = match &dop {
                asm::DOp::SYNC(_) => self.sync_id + 1,
                _ => self.sync_id,
            };
            let slot = self.pool.refill(self.sync_id, dop);
            self.sync_id = nxt_sync_id;

            tracing::trace!("Refill: {:?}", slot);

            self.trace.push(Trace {
                timestamp: self.sim_cycles,
                event: TraceEvent::Query {
                    cmd: Query::Refill,
                    slot: slot.clone(),
                },
            });
            true
        } else {
            // By default try to issue
            let pe_avail = self.pe_store.avail_kind() | InstructionKind::Sync;
            match self.pool.issue(pe_avail) {
                pool::IssueEvt::None => {
                    tracing::trace!("{}", self.pool);
                    tracing::trace!("{:?}", self.pe_store);

                    false
                }
                pool::IssueEvt::DOp {
                    kind_1h,
                    flush,
                    slot,
                } => {
                    tracing::trace!("Issue: {:?} flush: {:?}", slot, flush);

                    // Push token in associated pe
                    self.pe_store.push(kind_1h, flush);

                    // Flush the PE if this is a flush instruction
                    self.pe_store
                        .probe_for_exec(self.sim_cycles, None)
                        .into_iter()
                        .for_each(|evt| self.evt_pdg.push(evt));

                    self.trace.push(Trace {
                        timestamp: self.sim_cycles,
                        event: TraceEvent::Query {
                            cmd: Query::Issue,
                            slot,
                        },
                    });
                    true
                }
                pool::IssueEvt::Sync(slot) => {
                    self.dop_exec.push(slot.inst.op.clone());
                    self.trace.push(Trace {
                        timestamp: self.sim_cycles,
                        event: TraceEvent::Query {
                            cmd: Query::Issue,
                            slot,
                        },
                    });
                    true
                }
            }
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

impl Scheduler {
    pub fn dop_report(&self) -> DOpRpt {
        let mut map = HashMap::new();

        self.trace.iter().for_each(|pt| {
            if let Trace {
                timestamp: _,
                event:
                    TraceEvent::Query {
                        cmd: Query::Issue,
                        slot,
                    },
            } = pt
            {
                if let Some(entry) = map.get_mut(&slot.inst.kind) {
                    *entry += 1;
                } else {
                    map.insert(slot.inst.kind, 1);
                }
            }
        });
        DOpRpt(map)
    }

    pub fn time_report(&self) -> TimeRpt {
        let start = self.trace.first();
        let end = self.trace.last();

        match (start, end) {
            (Some(start), Some(end)) => {
                let cycle = end.timestamp - start.timestamp;
                let dur_us = cycle / self.freq_mhz;
                TimeRpt {
                    cycle,
                    duration: std::time::Duration::from_micros(dur_us as u64),
                }
            }
            (None, None) | (None, Some(_)) | (Some(_), None) => TimeRpt {
                cycle: 0,
                duration: std::time::Duration::from_secs(0),
            },
        }
    }

    pub fn pe_report(&mut self) -> PeStoreRpt {
        let rpt = PeStoreRpt::from(&self.pe_store);
        self.pe_store.reset_stats();
        rpt
    }

    pub fn reset_trace(&mut self) -> Vec<Trace> {
        std::mem::take(&mut self.trace)
    }
}
