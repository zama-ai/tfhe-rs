use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::prelude::{HpuConfig, HpuParameters};

use super::*;

use tracing::trace;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Flush {
    Timeout,
    Force,
    BatchFull,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum BatchCost {
    Fixed(usize),
    Linear {
        cnst: usize, // Fixed batch cost
        ppbs: usize, // Cost per PBS
        bmin: usize, // The minimum batch size
    },
}

impl Default for BatchCost {
    fn default() -> Self {
        BatchCost::Fixed(0)
    }
}

impl BatchCost {
    fn cost(&self, batch_size: usize) -> usize {
        match self {
            BatchCost::Fixed(cost) => *cost,
            BatchCost::Linear { cnst, ppbs, bmin } => *cnst + *ppbs * batch_size.max(*bmin),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PeCost {
    rd_lock: BatchCost,
    wr_lock: BatchCost,
}

#[derive(Clone, Debug, Default)]
pub struct PeStats {
    pub batches: usize,
    pub usage_sum: f64,
    pub issued: usize,
    pub by_timeout: usize,
    pub by_batchfull: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, Copy)]
pub struct BatchSize {
    pub min: usize,
    pub max: usize,
}

impl Default for BatchSize {
    fn default() -> Self {
        BatchSize { min: 1, max: 1 }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Pe {
    // PE Batch Configuration
    // The limits of the batch size for the PE
    batch_size: BatchSize,
    flush_opportunism: bool,
    // Runtime State
    // A limit to instructions in the PE
    pe_limit: usize,
    // The current FIFO limit
    fifo_limit: usize,
    // The current limit to start execution. Can be less than batch_size.max
    batch_limit: usize,
    // Flush state of the instructions currently in the PE+Queue
    in_fifo: VecDeque<bool>,
    // Instructions in the FIFO that are reading from the regfile
    reading: usize,
    // Instructions in the FIFO that have finished reading but not yet executing
    waiting: usize,
    // Instructions in the FIFO that are executing
    executing: usize,
    timeout_active: bool,
    cost: PeCost,
    kind: InstructionKind,
    stats: PeStats,
}

impl Pe {
    fn pending(&self) -> usize {
        self.in_fifo.len()
    }

    fn fifo_free(&self) -> usize {
        self.fifo_limit.saturating_sub(self.pending())
    }

    fn set_batch_limit(&mut self, limit: usize) {
        self.batch_limit = limit;
    }

    fn is_busy(&self) -> bool {
        self.executing != 0
    }

    fn is_full(&self) -> bool {
        self.fifo_free() == 0
    }

    fn avail_kind(&self) -> InstructionKind {
        if self.is_full() {
            InstructionKind::None
        } else {
            self.kind
        }
    }

    fn push(&mut self, flush: bool) {
        self.in_fifo.push_back(flush);
        assert!(
            self.in_fifo.len() <= self.fifo_limit,
            "Pushed above the PE fifo limit"
        )
    }

    fn rd_unlock(&mut self) {
        assert!(self.reading > 0, "RdUnlock request on already unlock pe");
        self.reading -= 1;
        self.waiting += 1;
    }

    fn wr_unlock(&mut self) {
        assert!(0 < self.executing, "WrUnlock request on a non-busy PE");
        self.executing -= 1;
        self.in_fifo.pop_front();
    }

    fn probe_for_exec(
        &mut self,
        pe_id: usize,
        at_cycle: usize,
        batch_flush: Option<Flush>,
    ) -> Vec<Event> {
        let mut evt = Vec::new();

        // Check if any instruction can be read
        let rd = self
            .pe_limit
            .min(self.pending())
            .saturating_sub(self.reading + self.waiting + self.executing);
        if rd > 0 {
            evt.extend((0..rd).map(|_| {
                Event::new(
                    EventType::RdUnlock(self.kind, pe_id),
                    at_cycle + self.cost.rd_lock.cost(rd),
                )
            }));
            self.reading += rd;
        }

        if !self.is_busy() {
            // Check if a batch can be issued
            let issued = (0..self.waiting)
                .map(|i| self.in_fifo[i])
                // Check if there's a forced flush queued
                .position(|c| c)
                .and_then(|p| {
                    if self.flush_opportunism {
                        // With flush_opportunism, we flush everything that is
                        // waiting
                        (self.waiting < self.batch_limit).then_some((Flush::Force, self.waiting))
                    } else {
                        // Else, flush exactly up to the first queued flush
                        (p < self.batch_limit).then(|| (Flush::Force, p + 1))
                    }
                })
                // If not, check if the batch is full
                .or_else(|| {
                    (self.waiting >= self.batch_limit)
                        .then_some((Flush::BatchFull, self.batch_limit))
                })
                // If not, check if there's a timeout or any other reason to
                // flush
                .or_else(|| {
                    batch_flush
                        .map(|b| (b, self.waiting))
                        .filter(|(_, pdg)| *pdg > 0)
                });

            if let Some((flush, issued)) = issued {
                // update state
                self.waiting -= issued;
                self.executing += issued;
                self.stats.issued += issued;
                self.stats.batches += 1;
                self.stats.by_timeout += (flush == Flush::Timeout) as usize;
                self.stats.by_batchfull += (flush == Flush::BatchFull) as usize;
                self.stats.usage_sum += (issued as f64 / self.batch_size.min as f64).min(1.0f64);

                evt.push(Event::new(
                    EventType::BatchStart { pe_id, issued },
                    at_cycle,
                ));

                if self.timeout_active && self.batch_limit > 1 {
                    evt.push(Event::new(
                        EventType::DelTimeout(self.kind, pe_id),
                        at_cycle,
                        // +1 To make sure the timer is deleted after being
                        // restarted
                    ));
                    self.timeout_active = false;
                }

                // Register unlock event
                evt.extend((0..issued).map(|_| {
                    Event::new(
                        EventType::WrUnlock(self.kind, pe_id),
                        at_cycle + self.cost.wr_lock.cost(issued),
                    )
                }));
            } else if !self.timeout_active && self.waiting > 0 && self.batch_limit > 1 {
                self.timeout_active = true;
                evt.push(Event::new(
                    EventType::ReqTimeout(self.kind, pe_id),
                    at_cycle,
                ));
            }
        }

        evt
    }

    pub fn reset_stats(&mut self) {
        self.stats = PeStats::default();
    }

    pub fn stats(&self) -> PeStats {
        self.stats.clone()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PeStore(pub(crate) Vec<(String, Pe)>);

impl PeStore {
    pub(crate) fn avail_kind(&self) -> InstructionKind {
        self.0
            .iter()
            .fold(InstructionKind::None, |acc, pe| acc | pe.1.avail_kind())
    }

    pub(crate) fn push(&mut self, kind_1h: InstructionKind, flush: bool) {
        // TODO check that kind is really one hot
        let mut capable_pe = self
            .0
            .iter_mut()
            .filter(|(_, pe)| InstructionKind::None != (pe.kind & kind_1h))
            .collect::<Vec<_>>();

        assert_eq!(
            capable_pe.len(),
            1,
            "Found {} capable pe for {:?}, unsupported",
            capable_pe.len(),
            kind_1h,
        );
        capable_pe[0].1.push(flush);
    }

    pub(crate) fn try_push(&mut self, kind_1h: InstructionKind, flush: bool) -> Option<usize> {
        let mut capable_pe = self
            .0
            .iter_mut()
            .enumerate()
            .filter(|(_, (_, pe))| (InstructionKind::None != (pe.kind & kind_1h)) && !pe.is_full())
            .collect::<Vec<_>>();

        capable_pe.first_mut().map(|(id, (_, pe))| {
            pe.push(flush);
            *id
        })
    }

    pub(crate) fn probe_for_exec_id(
        &mut self,
        id: usize,
        at_cycle: usize,
        batch_flush: Option<Flush>,
    ) -> Vec<Event> {
        self.0[id].1.probe_for_exec(id, at_cycle, batch_flush)
    }

    pub(crate) fn probe_for_exec(
        &mut self,
        at_cycle: usize,
        batch_flush: Option<Flush>,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        self.0.iter_mut().enumerate().for_each(|(id, pe)| {
            let evt = pe.1.probe_for_exec(id, at_cycle, batch_flush);
            events.extend(evt);
        });
        events
    }

    pub(crate) fn rd_unlock(&mut self, pe_id: usize) {
        self.0[pe_id].1.rd_unlock()
    }

    pub(crate) fn wr_unlock(&mut self, pe_id: usize) {
        self.0[pe_id].1.wr_unlock()
    }

    pub(crate) fn pending(&self) -> usize {
        self.0.iter().map(|(_, pe)| pe.pending()).sum::<usize>()
    }

    pub(crate) fn reset_stats(&mut self) {
        self.0.iter_mut().for_each(|(_, pe)| {
            pe.reset_stats();
        });
    }

    pub(crate) fn set_min_batch_limit(&mut self) {
        self.0.iter_mut().for_each(|(_, pe)| {
            pe.set_batch_limit(pe.batch_size.min);
        });
    }

    pub(crate) fn set_fifo_to_batch_limit(&mut self) {
        self.0.iter_mut().for_each(|(_, pe)| {
            pe.fifo_limit = pe.batch_limit;
        });
    }
}

/// Ligther view of Pe with only the parameters not the runtime state
/// Use for serde in config file
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeConfig {
    pub cost: PeCost,
    pub kind: InstructionKind,
    pub batch_size: BatchSize,   // The batch sizes
    pub pe_limit: Option<usize>, // The limit on the number of PBSs in the PE
    pub in_limit: Option<usize>, // The limit on the input fifo before the PE
    pub flush_opportunism: bool, /* Whether the PE is opportunistic when
                                  * scheduling */
}

impl PeConfig {
    pub fn new(
        cost: PeCost,
        kind: InstructionKind,
        batch_size: BatchSize,
        pe_limit: Option<usize>,
        in_limit: Option<usize>,
        flush_opportunism: bool,
    ) -> Self {
        Self {
            cost,
            kind,
            batch_size,
            pe_limit,
            in_limit,
            flush_opportunism,
        }
    }
}

impl From<PeConfig> for Pe {
    fn from(config: PeConfig) -> Self {
        let PeConfig {
            cost,
            kind,
            batch_size,
            pe_limit,
            in_limit,
            flush_opportunism,
        } = config;

        assert!(batch_size.max > 0, "Invalid batch_size value");
        Self {
            cost,
            kind,
            batch_size,
            flush_opportunism,
            pe_limit: pe_limit.unwrap_or(usize::MAX),
            fifo_limit: pe_limit
                .unwrap_or(usize::MAX)
                .saturating_add(in_limit.unwrap_or(usize::MAX)),
            batch_limit: batch_size.max,
            in_fifo: VecDeque::new(),
            ..Default::default()
        }
    }
}

impl From<&Pe> for PeConfig {
    fn from(pe: &Pe) -> Self {
        Self {
            cost: pe.cost.clone(),
            kind: pe.kind,
            batch_size: pe.batch_size,
            pe_limit: Some(pe.pe_limit),
            in_limit: Some(pe.fifo_limit - pe.pe_limit),
            flush_opportunism: pe.flush_opportunism,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeConfigStore(pub Vec<(String, PeConfig)>);

impl PeConfigStore {
    pub fn new(store: Vec<(String, PeConfig)>) -> Self {
        Self(store)
    }
}

/// Construct PeConfigStore directly from HpuParameters
/// Use RTL parameters to compute the expected performances
impl From<(&HpuParameters, &HpuConfig)> for PeConfigStore {
    fn from(tuple_config: (&HpuParameters, &HpuConfig)) -> Self {
        let (params, config) = tuple_config;
        // TODO: Add register to depicts the number of computation units (NB: Currently fixed to 1)
        let ldst_pe_nb = 1;
        let lin_pe_nb = 1;
        let pbs_pe_nb = 1;
        let total_pbs_nb = params.ntt_params.total_pbs_nb;
        let in_limit = Some(8); // TODO: Add registers with this information per PE

        // Extract used parameters for ease of access
        let batch_pbs = params.ntt_params.batch_pbs_nb;
        let lwe_k = params.pbs_params.lwe_dimension;
        let glwe_k = params.pbs_params.glwe_dimension;
        let poly_size = params.pbs_params.polynomial_size;
        let flush_opportunism = config.rtl.bpip_use_opportunism;
        let pem_axi_w = params.pc_params.pem_pc * params.pc_params.pem_bytes_w * 8;
        let ct_w = params.ntt_params.ct_width as usize;
        let lbx = params.ks_params.lbx;
        let min_batch_size = params.ntt_params.min_pbs_nb.unwrap();

        // Compute some intermediate values
        let blwe_coefs = (poly_size * glwe_k) + 1;
        let glwe_coefs = poly_size * (glwe_k + 1);
        let rpsi = params.ntt_params.radix * params.ntt_params.psi;

        // Cycles required to load a ciphertext in the computation pipe
        let ct_load_cycles = usize::div_ceil(glwe_coefs * params.pbs_params.pbs_level, rpsi);
        // Latency of a Cmux for a batch
        let cmux_lat = ct_load_cycles * batch_pbs;

        // NB: Keyswitch latency is dimension to match roughly the Cmux latency (with lbx coefs in
        // //) Keep this approximation here
        let ks_cycles = cmux_lat * lbx;

        let mut pe_config_store = Vec::with_capacity(ldst_pe_nb + lin_pe_nb + batch_pbs);

        // LoadStore
        // Load store performance is computed as access_cycle *2
        // Take 2 as really raw approximation
        // LoadStore operation don't support early rd_unlock -> assign same value as wr_unlock
        let ldst_raw_cycle = (blwe_coefs * ct_w).div_ceil(pem_axi_w);
        let ldst_cycle = ldst_raw_cycle * 2;
        for i in 0..ldst_pe_nb {
            let name = format!("LdSt_{i}");
            let cost = PeCost {
                rd_lock: BatchCost::Fixed(ldst_cycle),
                wr_lock: BatchCost::Fixed(1),
            };
            let kind = InstructionKind::MemLd | InstructionKind::MemSt;
            pe_config_store.push((
                name,
                PeConfig::new(cost, kind, BatchSize::default(), Some(1), in_limit, true),
            ));
        }

        // Linear operation
        // Linear operation performance is computed roughly as glwe_n*glwe_k
        // In practice this could be lower if multiple coefs are handle in //
        // Linear operation don't support early rd_unlock -> assign same value as wr_unlock
        let lin_cycle = blwe_coefs;
        for i in 0..lin_pe_nb {
            let name = format!("Lin_{i}");
            let cost = PeCost {
                rd_lock: BatchCost::Fixed(lin_cycle),
                wr_lock: BatchCost::Fixed(1),
            };
            let kind = InstructionKind::Arith;
            pe_config_store.push((
                name,
                PeConfig::new(cost, kind, BatchSize::default(), Some(1), in_limit, true),
            ));
        }

        // KsPbs operation
        // View as PeBatch unit
        // IPIP/BPIP Mode is handle by the scheduler module
        // Thus we view the KsPbs engine as a list of batch_pbs alu with full latency each
        let kspbs_rd_cycle = blwe_coefs.div_ceil(params.regf_params.coef_nb);
        let kspbs_cnst_cost = kspbs_rd_cycle; // write to regfile
        let kspbs_pbs_cost = (
            ks_cycles // latency of keyswitch
            + lwe_k * cmux_lat // Loop of cmux lat
            + batch_pbs * blwe_coefs.div_ceil(rpsi / 2 /* approx */)
            //Sample extract latency
        ) / batch_pbs;

        for i in 0..pbs_pe_nb {
            let name = format!("KsPbs_{i}");
            let cost = PeCost {
                rd_lock: BatchCost::Fixed(kspbs_rd_cycle),
                wr_lock: BatchCost::Linear {
                    cnst: kspbs_cnst_cost,
                    ppbs: kspbs_pbs_cost,
                    bmin: min_batch_size,
                },
            };
            let kind = InstructionKind::Pbs;
            pe_config_store.push((
                name,
                PeConfig::new(
                    cost,
                    kind,
                    BatchSize {
                        min: min_batch_size,
                        max: batch_pbs,
                    },
                    Some(total_pbs_nb),
                    in_limit,
                    flush_opportunism,
                ),
            ));
        }

        trace!("pe_config_store: {:?}", pe_config_store);

        Self::new(pe_config_store)
    }
}

impl From<PeConfigStore> for PeStore {
    fn from(config: PeConfigStore) -> Self {
        let store = config
            .0
            .into_iter()
            .map(|(name, pe)| (name, Pe::from(pe)))
            .collect::<Vec<_>>();

        Self(store)
    }
}
impl From<&PeStore> for PeConfigStore {
    fn from(store: &PeStore) -> Self {
        let config = store
            .0
            .iter()
            .map(|(name, pe)| (name.clone(), PeConfig::from(pe)))
            .collect::<Vec<_>>();

        Self(config)
    }
}
