//! Report structure

use std::collections::HashMap;

use crate::isc::InstructionKind;

#[derive(Debug)]
pub struct TimeRpt {
    pub cycle: usize,
    pub duration: std::time::Duration,
}

#[derive(Debug)]
pub struct DOpRpt(pub HashMap<InstructionKind, usize>);

impl std::fmt::Display for DOpRpt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Instructions execution report sorted by kind:")?;
        // Order alphabetically by key and print one by line
        let mut keys = self.0.keys().collect::<Vec<_>>();
        keys.sort();
        for k in keys {
            writeln!(f, "{k:?} => {}", self.0.get(k).unwrap())?;
        }
        Ok(())
    }
}
