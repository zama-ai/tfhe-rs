//!
//! Utility application used to probe Hpu status
//! Enable manual step by step debug
use tfhe_hpu_backend::ffi;
use tfhe_hpu_backend::interface::rtl;
use tfhe_hpu_backend::interface::rtl::FromRtl;
use tfhe_hpu_backend::prelude::*;

use tfhe_hpu_backend::isc_trace::{IscTraceStream, TraceDump};

use clap::{Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;

use std::fs::File;

use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    #[command(about = "Read register")]
    Read {
        /// Register name
        #[arg(short, long)]
        name: String,
        #[arg(short, long, default_value_t = 1)]
        range: usize,
    },

    #[command(about = "Write register")]
    Write {
        /// Register name
        #[arg(short, long)]
        name: String,
        #[arg(short, long, value_parser=maybe_hex::<u32>)]
        value: u32,
    },

    #[command(about = "Dump given register section")]
    Dump {
        /// Section name
        #[arg(index = 1)]
        name: Vec<Section>,
    },

    #[command(about = "Reset given register section")]
    Reset {
        /// Section name
        #[arg(index = 1)]
        name: Vec<Section>,
    },
    #[command(about = "Flush ackq")]
    Flush,

    #[command(about = "Memory Zone read (Hbm)")]
    MzRead {
        /// Hbm pc
        #[arg(long, value_parser=maybe_hex::<usize>)]
        pc: usize,
        /// Hbm size
        #[arg(short, long, value_parser=maybe_hex::<usize>)]
        size: usize,
    },

    #[command(about = "Memory Zone write (Hbm)")]
    MzWrite {
        /// Hbm pc
        #[arg(long, value_parser=maybe_hex::<usize>)]
        pc: usize,
        /// Hbm size
        #[arg(short, long, value_parser=maybe_hex::<usize>)]
        size: usize,
        // Pattern to write in Mz
        #[arg(short, long, value_parser=maybe_hex::<u8>)]
        pattern: u8,
    },

    #[command(about = "Trace Dump")]
    TraceDump {
        #[arg(short, long, default_value_t = String::from("trace.json"))]
        file: String,
    },

    #[command(about = "Resets all HPU processing logic")]
    SoftReset {},
}

#[derive(Clone, Debug, ValueEnum)]
pub enum Section {
    PePbs,
    PeMem,
    PeAlu,
    Isc,
    Arch,
}

#[derive(Clone, Debug, Parser)]
struct CliArgs {
    // Fpga configuration -----------------------------------------------------
    #[arg(short, long, default_value_t = 0)]
    fpga_id: u32,
    #[arg(
        short,
        long,
        default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
    )]
    pub config: ShellString,

    #[command(subcommand)]
    cmd: Command,
}

fn main() {
    let args = CliArgs::parse();

    // Register tracing subscriber that use env-filter
    // Select verbosity with env_var: e.g. `RUST_LOG=Alu=trace`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        // Display source code file paths
        .with_file(false)
        // Display source code line numbers
        .with_line_number(false)
        .without_time()
        // Build & register the subscriber
        .init();

    // Load fpga configuration from file
    let config = HpuConfig::from_toml(&args.config.expand());

    // Instantiate bare-minimum abstraction around XRT -----------------------
    let mut hpu_hw = ffi::HpuHw::new_hpu_hw(
        &config.fpga.ffi,
        std::time::Duration::from_micros(config.fpga.polling_us),
    );
    let regmap = {
        let regmap_expanded = config
            .fpga
            .regmap
            .iter()
            .map(|f| f.expand())
            .collect::<Vec<_>>();
        let regmap_str = regmap_expanded
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>();
        hw_regmap::FlatRegmap::from_file(&regmap_str)
    };

    // Init the memory backend
    let params = HpuParameters::from_rtl(&mut hpu_hw, &regmap);
    hpu_hw.init_mem(&config, &params);

    // Handle user command --------------------------------------------------
    match args.cmd {
        Command::Read { name, range } => {
            let reg_start = regmap
                .register()
                .get(&name)
                .expect("Unknown register, check regmap definition");
            let addr_start = *reg_start.offset() as u64;

            println!("Start read register {name} @{addr_start:0>8x}");
            for idx in 0..range {
                let addr = addr_start + (idx * std::mem::size_of::<u32>()) as u64;
                let val = hpu_hw.read_reg(addr);
                println!("  @{addr:0>8x} -> {val:0>8x}");
            }
        }
        Command::Write { name, value } => {
            let reg = regmap
                .register()
                .get(&name)
                .expect("Unknown register, check regmap definition");
            let addr = *reg.offset() as u64;

            println!("Write {value:0>8x} in register {name} @{addr:0>8x}");
            hpu_hw.write_reg(addr, value);
        }
        Command::Dump { name } => {
            for sec in name {
                match sec {
                    Section::PePbs => println!(
                        "PePbs registers {:?}",
                        rtl::runtime::InfoPePbs::from_rtl(&mut hpu_hw, &regmap)
                    ),
                    Section::PeMem => println!(
                        "PeMem registers {:?}",
                        rtl::runtime::InfoPeMem::from_rtl(&mut hpu_hw, &regmap)
                    ),
                    Section::PeAlu => println!(
                        "PeAlu registers {:?}",
                        rtl::runtime::InfoPeAlu::from_rtl(&mut hpu_hw, &regmap)
                    ),
                    Section::Isc => println!(
                        "Isc registers {:?}",
                        rtl::runtime::InfoIsc::from_rtl(&mut hpu_hw, &regmap)
                    ),
                    Section::Arch => println!(
                        "Arch registers {:?}",
                        HpuParameters::from_rtl(&mut hpu_hw, &regmap)
                    ),
                }
            }
        }
        Command::Reset { name } => {
            for sec in name {
                match sec {
                    Section::PePbs => {
                        println!(" Reset PePbs registers");
                        let mut sec = rtl::runtime::InfoPePbs::from_rtl(&mut hpu_hw, &regmap);
                        sec.reset(&mut hpu_hw, &regmap);
                    }
                    Section::PeMem => {
                        println!(" Reset PeMem registers");
                        let mut sec = rtl::runtime::InfoPeMem::from_rtl(&mut hpu_hw, &regmap);
                        sec.reset(&mut hpu_hw, &regmap);
                    }
                    Section::PeAlu => {
                        println!(" Reset PeAlu registers");
                        let mut sec = rtl::runtime::InfoPeAlu::from_rtl(&mut hpu_hw, &regmap);
                        sec.reset(&mut hpu_hw, &regmap);
                    }
                    Section::Isc => {
                        println!(" Reset Isc registers");
                        let mut sec = rtl::runtime::InfoIsc::from_rtl(&mut hpu_hw, &regmap);
                        sec.reset(&mut hpu_hw, &regmap);
                    }
                    Section::Arch => {
                        println!(" Arch registers couldn't be reset");
                    }
                }
            }
        }
        Command::Flush => loop {
            #[cfg(feature = "hw-v80")]
            {
                // TODO add ack flush to prevent error with previous stall execution
            }
            #[cfg(not(feature = "hw-v80"))]
            {
                let ackq_addr = (*regmap
                    .register()
                    .get("WorkAck::ackq")
                    .expect("Unknown register, check regmap definition")
                    .offset()) as u64;
                let ack_code = hpu_hw.read_reg(ackq_addr);
                println!("Flush ackq -> {ack_code:0>8x}");
                if ack_code == ACKQ_EMPTY {
                    break;
                }
            }
        },
        Command::MzRead { pc, size } => {
            let mut bfr = vec![0xff_u8; size];

            let cut_props = ffi::MemZoneProperties {
                mem_kind: ffi::MemKind::Hbm { pc },
                size_b: size,
            };
            let mut mz = hpu_hw.alloc(cut_props);
            mz.sync(ffi::SyncMode::Device2Host);
            mz.read(0, bfr.as_mut_slice());
            if let Ok(bfr_u64) = bytemuck::try_cast_slice::<_, u64>(bfr.as_slice()) {
                println!("MemZone content [u64]: {bfr_u64:x?}");
            } else if let Ok(bfr_u32) = bytemuck::try_cast_slice::<_, u32>(bfr.as_slice()) {
                println!("MemZone content [u32]: {bfr_u32:x?}");
            } else if let Ok(bfr_u16) = bytemuck::try_cast_slice::<_, u16>(bfr.as_slice()) {
                println!("MemZone content [u16]: {bfr_u16:x?}");
            } else {
                println!("MemZone content [u8]: {bfr:x?}");
            }
        }
        Command::MzWrite { pc, size, pattern } => {
            let bfr = vec![pattern; size];
            let cut_props = ffi::MemZoneProperties {
                mem_kind: ffi::MemKind::Hbm { pc },
                size_b: size,
            };
            let mut mz = hpu_hw.alloc(cut_props);
            mz.write(0, bfr.as_slice());
            mz.sync(ffi::SyncMode::Host2Device);
        }
        Command::TraceDump { file: filename } => {
            let trace = TraceDump::new_from(&mut hpu_hw, &regmap, config.board.trace_depth);
            let parsed = IscTraceStream::from(trace);

            let file = File::create(filename).expect("Failed to create or open trace dump file");
            serde_json::to_writer_pretty(file.make_writer(), &parsed)
                .expect("Could not write trace dump");
        }
        Command::SoftReset {} => {
            let soft_reset = regmap
                .register()
                .get("hpu_reset::trigger")
                .expect("The current HPU does not support soft reset.");
            let soft_reset_addr = *soft_reset.offset() as u64;

            for reset in [true, false].into_iter() {
                hpu_hw.write_reg(soft_reset_addr, reset as u32);
                loop {
                    let done = {
                        let val = hpu_hw.read_reg(soft_reset_addr);
                        let fields = soft_reset.as_field(val);
                        *fields.get("done").expect("Unknown field") != 0
                    };
                    if done == reset {
                        break;
                    }
                }
            }
        }
    }
}
