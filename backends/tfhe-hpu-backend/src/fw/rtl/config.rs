use std::collections::HashMap;

#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize, Default)]
pub struct OpCfg {
    /// Whether to fill the batch fifo when scheduling or not
    pub fill_batch_fifo: bool,
    /// Uses the minimum batch size in the firmware generation
    pub min_batch_size: bool,
    /// The current flush behavior if flushing
    pub flush_behaviour: FlushBehaviour,
    /// Whether to emit flushes or not
    pub flush: bool,
    /// Whether to use latency tiers when scheduling
    pub use_tiers: bool,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RtlCfg {
    by_op: HashMap<String, OpCfg>,
    default: OpCfg,
}

#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize, Default)]
pub enum FlushBehaviour {
    #[default]
    Patient,
    NoPBS,
    Opportunist,
    Timeout(usize),
}

impl RtlCfg {
    pub fn new(default: OpCfg) -> Self {
        Self {
            by_op: HashMap::new(),
            default,
        }
    }

    pub fn insert(&mut self, key: &str, value: OpCfg) {
        self.by_op.insert(key.to_string(), value);
    }

    pub fn default(&self) -> OpCfg {
        self.default
    }
}

impl From<OpCfg> for RtlCfg {
    fn from(value: OpCfg) -> Self {
        Self::new(value)
    }
}

impl RtlCfg {
    pub fn get(&self, key: &str) -> OpCfg {
        *self.by_op.get(key).unwrap_or(&self.default)
    }
}
