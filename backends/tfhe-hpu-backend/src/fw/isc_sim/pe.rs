use ron::de::from_reader;
use ron::ser::to_writer_pretty;
use serde::{Deserialize, Serialize};

use super::*;
use std::fs::{File, OpenOptions};
use std::path::Path;

use enum_dispatch::enum_dispatch;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Flush {
    ByTimeout,
    ByFlush
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PeCost {
    rd_lock: usize,
    wr_lock: usize,
}
impl PeCost {
    pub fn new(rd_lock: usize, wr_lock: usize) -> Self {
        Self { rd_lock, wr_lock }
    }
}

#[derive(Clone, Debug)]
pub struct PeStats {
    pub batches: usize,
    pub issued: usize,
    pub by_timeout: usize,
}

impl Default for PeStats {
    fn default() -> Self {
        PeStats { batches: 0, issued: 0, by_timeout: 0 }
    }
}

#[enum_dispatch]
pub(crate) trait PeCommon {
    fn pending(&self) -> usize;
    fn stats(&self) -> PeStats;
    fn stats_mut(&mut self) -> &mut PeStats;
    fn batch_size(&self) -> usize;
    fn fifo_limit(&mut self) -> &mut Option<usize>;
}

#[derive(Clone, Debug)]
pub(crate) struct PeSingle {
    rd_lock: bool,
    wr_lock: bool,
    fifo_in: usize,
    fifo_limit: Option<usize>,
    cost: PeCost,
    kind: InstructionKind,
    stats: PeStats,
}

impl PeCommon for PeSingle {
    fn stats(&self) -> PeStats {
        self.stats.clone()
    }

    fn stats_mut(&mut self) -> &mut PeStats {
        &mut self.stats
    }

    fn pending(&self) -> usize {
        self.fifo_in
    }

    fn batch_size(&self) -> usize {
        1
    }

    fn fifo_limit(&mut self) -> &mut Option<usize> {
        &mut self.fifo_limit
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PeBatch {
    rd_lock: usize,
    wr_lock: usize,
    fifo_in: usize,
    fifo_limit: Option<usize>,
    batch_size: usize,
    cost: PeCost,
    kind: InstructionKind,
    stats: PeStats,
}

impl PeCommon for PeBatch {
    fn stats(&self) -> PeStats {
        self.stats.clone()
    }

    fn stats_mut(&mut self) -> &mut PeStats {
        &mut self.stats
    }

    fn pending(&self) -> usize {
        self.fifo_in
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    fn fifo_limit(&mut self) -> &mut Option<usize> {
        &mut self.fifo_limit
    }
}

#[derive(Clone, Debug)]
#[enum_dispatch(PeCommon)]
pub(crate) enum Pe {
    Single(PeSingle),
    Batch(PeBatch),
}

impl Pe {
    fn kind(&self) -> InstructionKind {
        match self {
            Pe::Single(pe) => pe.kind,
            Pe::Batch(pe) => pe.kind,
        }
    }
    fn is_busy(&self) -> bool {
        match self {
            Pe::Single(pe) => pe.rd_lock | pe.wr_lock,
            Pe::Batch(pe) => 0 != (pe.rd_lock + pe.wr_lock),
        }
    }
    fn fifo_free(&self) -> i32 {
        match self {
            Pe::Single(pe) => pe.fifo_limit
                .unwrap_or(usize::max_value()) as i32 - (pe.fifo_in as i32),
            Pe::Batch(pe) => pe.fifo_limit
                .unwrap_or(usize::max_value()) as i32 - (pe.fifo_in as i32)
        }
    }
    fn is_full(&self) -> bool {
        self.fifo_free() <= 0
    }
    fn avail_kind(&self) -> InstructionKind {
        if self.is_busy() {
            InstructionKind::None
        } else {
            self.kind()
        }
    }
    fn rd_unlock(&mut self) {
        match self {
            Pe::Single(pe) => {
                assert!(pe.rd_lock, "RdUnlock request on already unlock pe");
                assert!(pe.wr_lock, "RdUnlock request on pe without wr_lock set");
                pe.rd_lock = false
            }
            Pe::Batch(pe) => {
                assert!(0 < pe.rd_lock, "RdUnlock request on already unlock pe");
                assert!(0 < pe.wr_lock, "RdUnlock request on pe without wr_lock set");
                pe.rd_lock -= 1
            }
        }
    }
    fn wr_unlock(&mut self) {
        match self {
            Pe::Single(pe) => {
                assert!(pe.wr_lock, "WrUnlock request on already unlock pe");
                pe.wr_lock = false
            }
            Pe::Batch(pe) => {
                assert!(0 < pe.wr_lock, "WrUnlock request on already unlock pe");
                pe.wr_lock -= 1
            }
        }
    }

    fn push(&mut self) {
        match self {
            Pe::Single(pe) => pe.fifo_in += 1,
            Pe::Batch(pe) => pe.fifo_in += 1,
        }
    }

    fn probe_for_exec(&mut self, pe_id: usize, at_cycle: usize,
                      batch_flush: Option<Flush>) -> Vec<Event> {
        if !self.is_busy() {
            match self {
                Pe::Single(pe) => {
                    if 0 != pe.fifo_in {
                        // Update state
                        pe.fifo_in -= 1;
                        pe.rd_lock = true;
                        pe.wr_lock = true;
                        pe.stats.issued += 1;
                        pe.stats.batches += 1;

                        // Register unlock event
                        vec![
                            Event::new(
                                EventType::RdUnlock(pe.kind, pe_id),
                                at_cycle + pe.cost.rd_lock,
                            ),
                            Event::new(
                                EventType::WrUnlock(pe.kind, pe_id),
                                at_cycle + pe.cost.wr_lock,
                            ),
                        ]
                    } else {
                        Vec::new()
                    }
                }
                Pe::Batch(pe) => {
                    // Batch full or batch flush
                    if (pe.fifo_in >= pe.batch_size)
                        || (pe.fifo_in != 0 && batch_flush.is_some()) {
                        let issued = std::cmp::min(pe.batch_size, pe.fifo_in);

                        // update state
                        pe.fifo_in -= issued;
                        pe.rd_lock = issued;
                        pe.wr_lock = issued;
                        pe.stats.issued += issued;
                        pe.stats.batches += 1;
                        pe.stats.by_timeout += batch_flush
                            .is_some_and(|f| f == Flush::ByTimeout) as usize;

                        // Register unlock event
                        // First all rd_unlock then all wr_unlock
                        let mut evt = (0..issued)
                            .map(|_| {
                                Event::new(
                                    EventType::RdUnlock(pe.kind, pe_id),
                                    at_cycle + pe.cost.rd_lock,
                                )
                            })
                            .collect::<Vec<_>>();
                        evt.extend((0..issued).map(|_| {
                            Event::new(
                                EventType::WrUnlock(pe.kind, pe_id),
                                at_cycle + pe.cost.wr_lock,
                            )
                        }));
                        evt
                    } else if pe.fifo_in != 0 {
                        vec![Event::new(EventType::ReqTimeout(pe.kind, pe_id), at_cycle)]
                    } else {
                        Vec::new()
                    }
                }
            }
        } else {
            Vec::new()
        }
    }

    fn reset_stats(&mut self) {
        *self.stats_mut() = PeStats::default();
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

    pub(crate) fn push(&mut self, kind_1h: InstructionKind) {
        // TODO check that kind is really one hot
        let mut capable_pe = self
            .0
            .iter_mut()
            .filter(|(_, pe)| InstructionKind::None != (pe.kind() & kind_1h))
            .collect::<Vec<_>>();

        assert_eq!(
            capable_pe.len(),
            1,
            "Found {} capable pe for {:?}, unsupported",
            capable_pe.len(),
            kind_1h,
        );
        capable_pe[0].1.push();
    }

    pub(crate) fn try_push(&mut self, kind_1h: InstructionKind) -> Option<usize> {
        let mut capable_pe = self
            .0
            .iter_mut()
            .enumerate()
            .filter(|(_, (_, pe))|
                    (InstructionKind::None != (pe.kind() & kind_1h)) 
                    && !pe.is_busy() && !pe.is_full())
            .collect::<Vec<_>>();

        capable_pe
            .first_mut()
            .map(|(id, (_, pe))| {
                pe.push();
                *id
            })
    }

    pub(crate) fn probe_for_exec(&mut self, at_cycle: usize,
                                 batch_flush: Option<Flush>) -> Vec<Event> {
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

    pub(crate) fn is_busy(&self) -> bool {
        self.0.iter().fold(false, |acc, (_,next)| acc | next.is_busy())
    }

    pub(crate) fn pending(&self) -> usize {
        self.0.iter()
            .map(|(_,pe)| pe.pending())
            .sum::<usize>()
    }

    pub(crate) fn reset_stats(&mut self) {
        self.0
            .iter_mut()
            .for_each(|(_, pe)| {pe.reset_stats();});
    }

    pub(crate) fn set_batch_limit(&mut self) {
        self.0
            .iter_mut()
            .for_each(|(_, pe)| {
                *pe.fifo_limit() = Some(pe.batch_size());
            });
    }
}

/// Ligther view of Pe with only the parameters not the runtime state
/// Use for serde in config file
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeConfig {
    pub cost: PeCost,
    pub kind: InstructionKind,
    pub batch_size: usize,
}
impl PeConfig {
    pub fn new(cost: PeCost, kind: InstructionKind, batch_size: usize) -> Self {
        Self {
            cost,
            kind,
            batch_size,
        }
    }
}

impl From<PeConfig> for Pe {
    fn from(config: PeConfig) -> Self {
        let PeConfig {
            cost,
            kind,
            batch_size,
        } = config;

        assert!(batch_size > 0, "Invalid batch_size value");
        if batch_size == 1 {
            Self::Single(PeSingle {
                cost,
                kind,
                rd_lock: false,
                wr_lock: false,
                fifo_in: 0,
                fifo_limit: None,
                stats: PeStats::default()
            })
        } else {
            Self::Batch(PeBatch {
                cost,
                kind,
                batch_size,
                rd_lock: 0,
                wr_lock: 0,
                fifo_in: 0,
                fifo_limit: None,
                stats: PeStats::default()
            })
        }
    }
}

impl From<&Pe> for PeConfig {
    fn from(pe: &Pe) -> Self {
        let (cost, kind, batch_size) = match pe {
            Pe::Single(pe) => (pe.cost.clone(), pe.kind, 1),
            Pe::Batch(pe) => (pe.cost.clone(), pe.kind, pe.batch_size),
        };

        Self {
            cost,
            kind,
            batch_size,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeConfigStore(pub Vec<(String, PeConfig)>);

impl PeConfigStore {
    pub fn new(store: Vec<(String, PeConfig)>) -> Self {
        Self(store)
    }
    pub fn from_ron(config: &str) -> Self {
        let pe_f = File::open(config).expect("Failed opening file");
        match from_reader(pe_f) {
            Ok(data) => data,
            Err(err) => {
                panic!("Failed to load PeConfigStore from file {}", err);
            }
        }
    }

    pub fn to_ron(&self, config: &str) {
        let config = Path::new(config);
        if let Some(cfg_d) = config.parent() {
            std::fs::create_dir_all(cfg_d).unwrap();
        }

        let cfg_f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .append(false)
            .open(config)
            .unwrap();

        match to_writer_pretty(cfg_f, self, Default::default()) {
            Ok(_) => {}
            Err(err) => {
                panic!("Failed to write PeConfigStore to file {}", err);
            }
        }
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

impl Default for PeConfigStore {
    fn default() -> Self {
        PeConfigStore(vec![
            (String::from("LdSt_0"), PeConfig{
                cost: PeCost{
                    rd_lock: 354,
                    wr_lock: 355,
                },
                kind: InstructionKind::MemLd | InstructionKind::MemSt,
                batch_size: 1,
            }),
            (String::from("Lin_0"), PeConfig{
                cost: PeCost{
                    rd_lock: 2048,
                    wr_lock: 2049,
                },
                kind: InstructionKind::Arith,
                batch_size: 1,
            }),
            (String::from("KsPbs_0"), PeConfig{
                cost: PeCost{
                    rd_lock: 16384,
                    wr_lock: 556448,
                },
                kind: InstructionKind::Pbs,
                batch_size: 12,
            }),
        ])
    }
}

