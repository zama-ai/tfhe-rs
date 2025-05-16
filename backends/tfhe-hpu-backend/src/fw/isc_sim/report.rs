//! Report structure

use std::collections::HashMap;

use super::InstructionKind;

use super::pe::{Pe, PeStats, PeStore};

#[derive(Debug)]
pub struct TimeRpt {
    pub cycle: usize,
    pub duration: std::time::Duration,
}

#[derive(Debug)]
pub struct DOpRpt(pub HashMap<InstructionKind, usize>);

impl std::fmt::Display for DOpRpt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_val = {
            // Order alphabetically by key
            let mut keys = self.0.keys().collect::<Vec<_>>();
            keys.sort();

            keys.iter()
                .map(|k| {
                    format!(
                        "{k}: {}",
                        self.0
                            .get(k)
                            .unwrap_or_else(|| panic!("Error: Key {k} not available in DOpRpt"))
                    )
                })
                .collect::<Vec<_>>()
        };
        write!(f, "InstructionKind {{{}}}", key_val.join(", "))
    }
}

#[derive(Debug)]
pub struct PeRpt {
    pub stats: PeStats,
    pub usage: f64,
}
impl std::fmt::Display for PeRpt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "issued: {}, batches: {}, by_timeout: {}, usage: {}",
            self.stats.issued, self.stats.batches, self.stats.by_timeout, self.usage
        )?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct PeStoreRpt(HashMap<String, PeRpt>);
impl PeStoreRpt {
    pub fn new(map: HashMap<String, PeRpt>) -> PeStoreRpt {
        PeStoreRpt(map)
    }
}

impl From<&PeStore> for PeStoreRpt {
    fn from(value: &PeStore) -> Self {
        let report_collection: HashMap<String, PeRpt> = value
            .0
            .iter()
            .map(|(name, pe)| (name.clone(), PeRpt::from(pe)))
            .collect();
        PeStoreRpt::new(report_collection)
    }
}

impl From<&Pe> for PeRpt {
    fn from(value: &Pe) -> Self {
        let stats = value.stats();
        let usage = stats.usage_sum / (stats.batches as f64);
        PeRpt { stats, usage }
    }
}

impl std::fmt::Display for PeStoreRpt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Processing element statistics:")?;
        // Order alphabetically by key and print one by line
        let mut keys = self.0.keys().collect::<Vec<_>>();
        keys.sort();
        for k in keys {
            writeln!(f, "\t {k:?} => {}", self.0.get(k).unwrap())?;
        }
        Ok(())
    }
}
