//! Define instruction lifetime
//! Used to refine raw isc trace in something more readable

use crate::asm::dop;
use crate::isc_trace::{IscCommand, IscTrace, IscTraceStream};
use std::collections::LinkedList;

/// Contains time information related to instruction lifecycle
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct InsnLifetime {
    pub refill: u32,
    pub issue: u32,
    pub rd_unlock: u32,
    pub retire: u32,
}

impl InsnLifetime {
    /// Removed offset value from timestamp
    pub fn offset_ts(&mut self, offset: u32) {
        self.refill -= offset;
        self.issue -= offset;
        self.rd_unlock -= offset;
        self.retire -= offset;
    }

    /// Compute execution cycle
    pub fn exec_cycles(&self) -> u32 {
        self.retire - self.issue
    }
}
impl std::fmt::Display for InsnLifetime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refill: {: >10}, issue: {: >10}, rd_unlock: {: >10}, retire: {: >10}",
            self.refill, self.issue, self.rd_unlock, self.retire
        )
    }
}

// High-level view of the instruction trace
// Instead of discrete event, here we monitor instruction lifetime
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct InsnTrace {
    pub lifetime: InsnLifetime,
    pub insn: dop::DOp,
    pub insn_hex: u32,
    pub insn_asm: String,
}

impl std::fmt::Display for InsnTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{: >8}] {: <80} {{{:?}}}",
            self.lifetime.exec_cycles(),
            self.insn_asm,
            self.lifetime
        )
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct InsnTraceStream(Vec<InsnTrace>);

impl InsnTraceStream {
    /// Return a view on internal part
    pub fn as_view(&self) -> &[InsnTrace] {
        &self.0
    }

    /// Sort based on cmd
    pub fn sort_by(&mut self, cmd: IscCommand) {
        match cmd {
            IscCommand::None => {}

            IscCommand::RdUnlock => self.0.sort_by(|a, b| {
                let ts_a = a.lifetime.rd_unlock;
                let ts_b = b.lifetime.rd_unlock;
                ts_a.cmp(&ts_b)
            }),
            IscCommand::Retire => self.0.sort_by(|a, b| {
                let ts_a = a.lifetime.retire;
                let ts_b = b.lifetime.retire;
                ts_a.cmp(&ts_b)
            }),
            IscCommand::Refill => self.0.sort_by(|a, b| {
                let ts_a = a.lifetime.refill;
                let ts_b = b.lifetime.refill;
                ts_a.cmp(&ts_b)
            }),
            IscCommand::Issue => self.0.sort_by(|a, b| {
                let ts_a = a.lifetime.issue;
                let ts_b = b.lifetime.issue;
                ts_a.cmp(&ts_b)
            }),
        }
    }

    /// Align timestamp on first Op
    pub fn align_ts(&mut self) {
        // Sort on refill timestamp
        self.sort_by(IscCommand::Refill);

        // Get first op timestamp
        let ts_ofst = self.0[0].lifetime.refill;
        self.0
            .iter_mut()
            .for_each(|i| i.lifetime.offset_ts(ts_ofst));
    }
}

impl From<&IscTraceStream> for InsnTraceStream {
    fn from(value: &IscTraceStream) -> Self {
        // View stream as ll of ref
        let mut ll_view: LinkedList<&IscTrace> = value.as_view().iter().collect();

        let mut insn_stream = Vec::with_capacity(value.as_view().len().div_ceil(4));
        loop {
            // Get first refill
            if let Some(refill) = ll_view
                .extract_if(|e| matches!(e.state.cmd, IscCommand::Refill))
                .next()
            {
                // Found & remove other matching item
                let cmds = if dop::Opcode::from(dop::DOpRawHex::from_bits(refill.insn_hex).opcode())
                    .is_sync_inst()
                {
                    // Sync instruction as != lifecycle
                    vec![IscCommand::Issue]
                } else {
                    vec![IscCommand::Issue, IscCommand::RdUnlock, IscCommand::Retire]
                };
                let timestamp = cmds
                    .iter()
                    .filter_map(|cmd| {
                        if let Some(insn) = ll_view
                            .extract_if(|e| {
                                (e.insn_hex == refill.insn_hex) && (e.state.cmd == *cmd)
                            })
                            .next()
                        {
                            Some(insn.timestamp)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                if timestamp.len() != cmds.len() {
                    println!("{refill:?} has incomplete lifecycle");
                    break;
                } else {
                    let insn = dop::DOp::from_hex(refill.insn_hex).expect("Invalid Dop Hex code");
                    let insn_asm = insn.to_string();
                    let insn_trace = InsnTrace {
                        lifetime: InsnLifetime {
                            refill: refill.timestamp,
                            issue: timestamp[0],
                            rd_unlock: *timestamp.get(1).unwrap_or(&timestamp[0]),
                            retire: *timestamp.get(2).unwrap_or(&timestamp[0]),
                        },
                        insn_hex: refill.insn_hex,
                        insn,
                        insn_asm,
                    };
                    insn_stream.push(insn_trace);
                }
            } else {
                break;
            };
        }

        Self(insn_stream)
    }
}
