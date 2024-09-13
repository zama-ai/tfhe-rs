//!
//! Utility application used to probe Hpu status
//! Enable manual step by step debug
use tfhe_hpu_backend::ffi;
use tfhe_hpu_backend::interface::rtl;
use tfhe_hpu_backend::interface::rtl::FromRtl;
use tfhe_hpu_backend::prelude::*;

use tfhe_hpu_backend::asm::{self, Asm, AsmBin, IOp};

use clap::{Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    #[clap(about = "Read register")]
    Read {
        /// Register name
        #[arg(short, long)]
        name: String,
        #[arg(short, long, default_value_t = 1)]
        range: usize,
    },

    #[clap(about = "Write register")]
    Write {
        /// Register name
        #[arg(short, long)]
        name: String,
        #[arg(short, long, value_parser=maybe_hex::<u32>)]
        value: u32,
    },

    #[clap(about = "Dump given register section")]
    Dump {
        /// Section name
        #[arg(index = 1)]
        name: Vec<Section>,
    },

    #[clap(about = "Reset given register section")]
    Reset {
        /// Section name
        #[arg(index = 1)]
        name: Vec<Section>,
    },
    #[clap(about = "Memory read (through ublaze)")]
    MemRead {
        /// Memory addr
        #[arg(short, long, value_parser=maybe_hex::<usize>)]
        addr: usize,
        #[arg(short, long, default_value_t = 1)]
        range: usize,
    },

    #[clap(about = "Memory write (through ublaze)")]
    MemWrite {
        /// Memory addr
        #[arg(short, long, value_parser=maybe_hex::<usize>)]
        addr: usize,
        #[arg(short, long, value_parser=maybe_hex::<u32>)]
        value: u32,
    },

    #[clap(about = "Flush ackq")]
    Flush,

    #[clap(about = "Memory Zone read (XRT)")]
    MzRead {
        /// Hbm pc
        #[arg(long, value_parser=maybe_hex::<usize>)]
        pc: usize,
        /// Hbm size
        #[arg(short, long, value_parser=maybe_hex::<usize>)]
        size: usize,
    },

    #[clap(about = "Memory Zone write (Xrt)")]
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
        default_value = "backends/tfhe-hpu-backend/config/hpu_config.toml"
    )]
    config: String,

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
    let config = HpuConfig::read_from(&args.config);

    // Instanciate bare-minimum abstraction around XRT -----------------------
    let mut hpu_hw = ffi::HpuHw::new_hpu_hw(&config.fpga.ffi);
    let regmap = hw_regmap::FlatRegmap::from_file(&config.fpga.regmap);

    // Handle user command --------------------------------------------------
    match args.cmd {
        Command::Read { name, range } => {
            let reg_start = regmap
                .register()
                .get(&name)
                .expect("Unknow register, check regmap definition");
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
                .expect("Unknow register, check regmap definition");
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
        Command::MemRead { addr, range } => {
            // Get work_q/ack_q addr
            let workq_addr = (*regmap
                .register()
                .get("WorkAck::workq")
                .expect("Unknow register, check regmap definition")
                .offset()) as u64;
            let ackq_addr = (*regmap
                .register()
                .get("WorkAck::ackq")
                .expect("Unknow register, check regmap definition")
                .offset()) as u64;

            for ofst in 0..range {
                let trgt_addr = addr + ofst * std::mem::size_of::<u32>();
                // Construct IOp
                let op = {
                    // NB: Only imm value is used
                    let mut rd = asm::IOpCtlRd::default();
                    rd.imm = trgt_addr;

                    IOp::CTL_RD(rd)
                };

                // Issue request
                tracing::debug!("Op Asm {}", op.asm_encode(8));
                let op_bytes = op.bin_encode_le().unwrap();
                let op_words = bytemuck::cast_slice::<_, u32>(op_bytes.as_slice());
                tracing::debug!("Op Words {:x?}", op_words);

                // NB: For parsing purpose, we must send the msb word (that contain opcode) first
                //   -> Thus we use a reversed version of the iterator
                for w in op_words.iter().rev() {
                    hpu_hw.write_reg(workq_addr, *w);
                }

                // Read value
                let val = loop {
                    let ack_code = hpu_hw.read_reg(ackq_addr);
                    if ack_code != ACKQ_EMPTY {
                        assert_eq!(ack_code, *op_words.last().unwrap(),
                            "Ack code mismatch, received an ack for another command [get: {ack_code:x}, exp: {:x}]", op_words.last().unwrap());
                        // Next word is the red value
                        let val = hpu_hw.read_reg(ackq_addr);

                        break val;
                    }
                };
                println!(
                    "  Ublaze read @{trgt_addr:0>8x}[{:0>8x}] -> {val:0>8x}",
                    trgt_addr / std::mem::size_of::<u32>()
                );
            }
        }
        Command::MemWrite { addr, value } => {
            // Get work_q/ack_q addr
            let workq_addr = (*regmap
                .register()
                .get("WorkAck::workq")
                .expect("Unknow register, check regmap definition")
                .offset()) as u64;
            let ackq_addr = (*regmap
                .register()
                .get("WorkAck::ackq")
                .expect("Unknow register, check regmap definition")
                .offset()) as u64;

            // Construct IOp
            let op = {
                // NB: Only imm value is used
                let mut wr = asm::IOpCtlWr::default();
                wr.imm = ((value as usize) << u32::BITS) as usize + addr;

                IOp::CTL_WR(wr)
            };
            // NB: Only imm value is used

            // Issue request
            tracing::debug!("Op Asm {}", op.asm_encode(8));
            let op_bytes = op.bin_encode_le().unwrap();
            let op_words = bytemuck::cast_slice::<_, u32>(op_bytes.as_slice());
            tracing::debug!("Op Words {:x?}", op_words);

            // NB: For parsing purpose, we must send the msb word (that contain opcode) first
            //   -> Thus we use a reversed version of the iterator
            for w in op_words.iter().rev() {
                hpu_hw.write_reg(workq_addr, *w);
            }

            // Read ack
            loop {
                let ack_code = hpu_hw.read_reg(ackq_addr);
                if ack_code != ACKQ_EMPTY {
                    assert_eq!(ack_code, *op_words.last().unwrap(),
                        "Ack code mismatch, received an ack for another command [get: {ack_code:x}, exp: {:x}]", op_words.last().unwrap());
                    break;
                }
            }
            println!("  Ublaze write @{addr:0>8x} -> {value:0>8x}");
        }
        Command::Flush => loop {
            let ackq_addr = (*regmap
                .register()
                .get("WorkAck::ackq")
                .expect("Unknow register, check regmap definition")
                .offset()) as u64;
            let ack_code = hpu_hw.read_reg(ackq_addr);
            println!("Flush ackq -> {ack_code:0>8x}");
            if ack_code == ACKQ_EMPTY {
                break;
            }
        },
        Command::MzRead { pc, size } => {
            let mut bfr = vec![0xff_u8; size];

            let cut_props = ffi::MemZoneProperties {
                hbm_pc: pc,
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
                hbm_pc: pc,
                size_b: size,
            };
            let mut mz = hpu_hw.alloc(cut_props);
            mz.write(0, bfr.as_slice());
            mz.sync(ffi::SyncMode::Host2Device);
        }
    }
}
