pub mod fmt;
pub mod packed_struct;

use crate::ffi;
pub use crate::isc_trace::fmt::{IscQueryCmd, IscTraceStream, TRACE_W};

pub struct TraceDump {
    trace: Vec<u8>,
}

use tracing::trace;

impl TraceDump {
    pub fn new_from(
        hpu_hw: &mut ffi::HpuHw,
        regmap: &hw_regmap::FlatRegmap,
        depth: usize,
    ) -> TraceDump {
        let size_b = ((depth * 1024 * 1024) / TRACE_W) * TRACE_W;

        let mut trace: Vec<u8> = vec![0; size_b];

        let offset_reg: Vec<usize> = ["trc_pc0_lsb", "trc_pc0_msb"]
            .into_iter()
            .map(|name| {
                let reg = regmap
                    .register()
                    .get(&format!("hbm_axi4_addr_1in3::{}", name))
                    .expect("Unknown register, check regmap definition");
                hpu_hw.read_reg(*reg.offset() as u64) as usize
            })
            .collect();
        let offset = offset_reg[0] + (offset_reg[1] << 32);

        trace!(
            target = "TraceDump",
            "Reading @0x{:x} size_b: {}",
            offset,
            size_b
        );

        let cut_props = ffi::MemZoneProperties {
            mem_kind: ffi::MemKind::Ddr { offset },
            size_b,
        };
        let mut mz = hpu_hw.alloc(cut_props);
        mz.sync(ffi::SyncMode::Device2Host);
        mz.read(0, trace.as_mut_slice());
        TraceDump { trace }
    }
}

impl From<TraceDump> for IscTraceStream {
    fn from(value: TraceDump) -> Self {
        IscTraceStream(
            IscTraceStream::from_bytes(value.trace.as_slice())
                .0
                .into_iter()
                .filter(|i| i.cmd != IscQueryCmd::NONE)
                .collect(),
        )
    }
}
