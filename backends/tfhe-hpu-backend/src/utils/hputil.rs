//!
//! Utility application used to probe Hpu status
//! Enable manual step by step debug
use hw_regmap::FlatRegmap;
use strum::{EnumIter, EnumString, IntoEnumIterator};
use tfhe_hpu_backend::ffi;
use tfhe_hpu_backend::interface::io_dump::HexMem;
use tfhe_hpu_backend::interface::rtl;
use tfhe_hpu_backend::interface::rtl::FromRtl;
use tfhe_hpu_backend::prelude::*;

use tfhe_hpu_backend::isc_trace::IscTraceStream;

use clap::{Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;

use std::fs::{File, OpenOptions};

#[derive(Clone, Debug, Parser)]
#[command(name = "hpu-mgmt-cli")]
#[command(about = "A CLI for Hpu management", long_about = None)]
struct CliArgs {
    // Fpga configuration -----------------------------------------------------
    #[arg(short, long, default_value_t = 0)]
    fpga_id: u8,
    #[arg(
        short,
        long,
        default_value = "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml"
    )]
    pub config: ShellString,

    #[command(subcommand)]
    command: Commands,
}

/// List of available commands
#[derive(Clone, Debug, Subcommand)]
pub enum Commands {
    /// Register operations
    #[command(about = "Registers related operations")]
    Register {
        #[command(subcommand)]
        action: RegisterAction,
    },
    /// Memory operations
    #[command(about = "Memory related operations")]
    Memory {
        /// Automatically add offset of associated Hbm pc to the following command
        #[arg(short, long)]
        pc: Option<usize>,
        #[command(subcommand)]
        action: MemoryAction,
    },
    /// Reset operations
    #[command(about = "Reset related operations")]
    Reset {
        #[command(subcommand)]
        action: ResetAction,
    },

    /// Hardware trace operation
    #[command(about = "Trace related operations")]
    TraceDump {
        /// Stop after a given size (Expressed in MiB)
        #[arg(long, short)]
        size_mib: Option<usize>,
        #[arg(default_value = "trace_dump.json")]
        file: String,
    },
    /// Ciphertext readback
    #[command(about = "")]
    Ciphertext {
        /// Tfhe Key seed
        #[arg(long, short, value_parser=maybe_hex::<u128>)]
        key_seed: u128,
        /// Ciphertext addr (Expressed in Slot#)
        #[arg(long, short, value_parser=maybe_hex::<usize>)]
        addr: usize,
        /// Ciphertext size (Expressend in Block)
        #[arg(long, short, value_parser=maybe_hex::<usize>)]
        size: usize,
    },
}

/// Action for the Register command
#[derive(Clone, Debug, Subcommand)]
pub enum RegisterAction {
    /// Read from a register address
    #[command(about = "Read register")]
    Read {
        /// Register name to read-from
        name: String,
        /// Number of contiguous register to read
        #[arg(short, long, default_value_t = 1)]
        range: usize,
    },
    /// Write to a register
    #[command(about = "Write register")]
    Write {
        /// Register name to write-from
        name: String,

        /// Values to write
        /// Each subsequent value will be written in the next contiguous register
        #[arg(short, long, value_parser=maybe_hex::<u32>)]
        value: Vec<u32>,
    },

    /// Dump given register section
    /// Empty vector => dump_all
    #[command(about = "Dump given register sections")]
    Dump {
        /// Section name
        section: Vec<Section>,
    },

    /// Dump given register section
    /// Empty vector => reset_all
    #[command(about = "Reset given register sections")]
    Reset {
        /// Section name
        section: Vec<Section>,
    },
}

/// Available Register section
#[derive(Clone, Debug, ValueEnum, EnumIter, EnumString, strum_macros::Display)]
pub enum Section {
    PePbs,
    PeMem,
    PeAlu,
    Isc,
    Arch,
}

/// Action for the Memory command
#[derive(Clone, Debug, Subcommand)]
pub enum MemoryAction {
    /// Read from memory address
    #[command(about = "Read memory")]
    Read {
        /// Address to read-from
        #[arg(long, short, value_parser=maybe_hex::<u64>)]
        addr: u64,
        /// Size to read in byte
        #[arg(long, short, value_parser=maybe_hex::<usize>)]
        size_b: usize,
    },
    /// Write to a register
    #[command(about = "Write memory")]
    Write {
        /// Address to write-to
        #[arg(long, short, value_parser=maybe_hex::<u64>)]
        addr: u64,
        /// Size to write in byte
        #[arg(long, short, value_parser=maybe_hex::<usize>)]
        size_b: usize,

        /// Pattern to write
        /// Nb: pattern is backed in a vector and used as ring-buffer.
        #[arg(short, long, value_parser=maybe_hex::<u64>)]
        value: Vec<u64>,
    },

    /// Dump given memory in a file
    #[command(about = "Dump given memory range")]
    Dump {
        /// Offset to dump-from
        #[arg(long, short, value_parser=maybe_hex::<u64>)]
        offset: u64,
        /// Size to dump in byte
        #[arg(long, short, value_parser=maybe_hex::<usize>)]
        size_b: usize,
        /// number of byte_per_line
        #[arg(long, short, value_parser=maybe_hex::<usize>)]
        line_b: usize,

        /// output file
        filename: String,
    },
}

/// Action for the Memory command
#[derive(Clone, Debug, Subcommand)]
pub enum ResetAction {
    Soft,
    Hard,
    Flush,
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

    // Instantiate bare-minimum abstraction around HpuHw -----------------------
    let mut hpu_hw = ffi::HpuHw::open_hpu_hw(
        args.fpga_id,
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

    // Handle user command -----------------------------------------------------
    match &args.command {
        Commands::Register { action } => match action {
            RegisterAction::Read { name, range } => {
                read_register_by_name(&mut hpu_hw, &regmap, name, *range)
            }
            RegisterAction::Write { name, value } => {
                write_register_by_name(&mut hpu_hw, &regmap, name, value)
            }
            RegisterAction::Dump { section } => {
                read_register_by_section(&mut hpu_hw, &regmap, section)
            }
            RegisterAction::Reset { section } => {
                reset_register_by_section(&mut hpu_hw, &regmap, section)
            }
        },
        Commands::Memory { action, pc } => {
            let pc_offset = if let Some(idx) = pc {
                ffi::MEM_BASE_ADDR + (idx * (ffi::MEM_BANK_SIZE_MB * 1024 * 1024)) as u64
            } else {
                0
            };

            match action {
                MemoryAction::Read { addr, size_b } => {
                    let data = read_mem(&mut hpu_hw, addr + pc_offset, *size_b);
                    println!("Read memory from @{:0>8x}[{size_b}]...", addr + pc_offset);
                    pretty_display(data, addr + pc_offset, 16);
                }
                MemoryAction::Write {
                    addr,
                    size_b,
                    value,
                } => {
                    println!(
                        "Write memory from @{:0>8x}[{size_b}] with pattern {value:x?}...",
                        addr + pc_offset
                    );
                    write_mem(&mut hpu_hw, addr + pc_offset, *size_b, value);
                }
                MemoryAction::Dump {
                    offset,
                    size_b,
                    line_b,
                    filename,
                } => {
                    let data = read_mem(&mut hpu_hw, offset + pc_offset, *size_b);
                    pretty_dump_in_file(filename, &data, *line_b);
                }
            }
        }
        Commands::Reset { action } => match action {
            ResetAction::Soft => soft_reset(&mut hpu_hw, &regmap),
            ResetAction::Hard => unimplemented!(),
            ResetAction::Flush => unimplemented!(),
        },
        Commands::TraceDump { file, size_mib } => {
            // trace depth is expressed in MiB
            let size_b = std::cmp::min(
                config.board.trace_depth,
                size_mib.unwrap_or(usize::max_value()),
            ) * 1024
                * 1024;

            trace_dump(&mut hpu_hw, &regmap, size_b, &file)
        }

        Commands::Ciphertext {
            key_seed,
            addr,
            size,
        } => read_and_dump_ct(&mut hpu_hw, &regmap, key_seed, addr, size),
    }
}

// Implement each action within a dedicated function
// Enhance command handling readability
fn read_register_by_name(hw: &mut ffi::HpuHw, regmap: &FlatRegmap, name: &str, range: usize) {
    let reg_start = regmap
        .register()
        .get(name)
        .unwrap_or_else(|| panic!("Unknown register name {name}, check regmap definition"));
    let addr_start = *reg_start.offset() as u64;

    println!("Start read register {name} @{addr_start:0>8x}");
    for idx in 0..range {
        let addr = addr_start + (idx * std::mem::size_of::<u32>()) as u64;
        let val = hw.read_reg(addr);
        println!("  @{addr:0>8x} -> {val:0>8x}");
    }
}
fn write_register_by_name(hw: &mut ffi::HpuHw, regmap: &FlatRegmap, name: &str, value: &[u32]) {
    let reg_start = regmap
        .register()
        .get(name)
        .unwrap_or_else(|| panic!("Unknown register name {name}, check regmap definition"));
    let addr_start = *reg_start.offset() as u64;

    println!("Start write register {name} @{addr_start:0>8x}");
    for (idx, v) in value.iter().enumerate() {
        let addr = addr_start + (idx * std::mem::size_of::<u32>()) as u64;
        println!("  @{addr:0>8x} <- {v:0>8x}");
        hw.write_reg(addr, *v);
    }
}

fn read_register_by_section(hw: &mut ffi::HpuHw, regmap: &FlatRegmap, section: &[Section]) {
    // Expand to all section if none
    let section = if section.is_empty() {
        &Section::iter().collect::<Vec<_>>()
    } else {
        section
    };

    for sec in section {
        match sec {
            Section::PePbs => println!(
                "{sec} registers {:?}",
                rtl::runtime::InfoPePbs::from_rtl(hw, &regmap)
            ),
            Section::PeMem => println!(
                "{sec} registers {:?}",
                rtl::runtime::InfoPeMem::from_rtl(hw, &regmap)
            ),
            Section::PeAlu => println!(
                "{sec} registers {:?}",
                rtl::runtime::InfoPeAlu::from_rtl(hw, &regmap)
            ),
            Section::Isc => println!(
                "{sec} registers {:?}",
                rtl::runtime::InfoIsc::from_rtl(hw, &regmap)
            ),
            Section::Arch => println!("{sec} registers {:?}", HpuParameters::from_rtl(hw, &regmap)),
        }
    }
}

fn reset_register_by_section(hw: &mut ffi::HpuHw, regmap: &FlatRegmap, section: &[Section]) {
    // Expand to all section if none
    let section = if section.is_empty() {
        &Section::iter().collect::<Vec<_>>()
    } else {
        section
    };

    for sec in section {
        match sec {
            Section::PePbs => {
                println!(" Reset {sec} registers ...");
                let mut sec_view = rtl::runtime::InfoPePbs::from_rtl(hw, regmap);
                sec_view.reset(hw, regmap);
            }
            Section::PeMem => {
                println!(" Reset {sec} registers ...");
                let mut sec_view = rtl::runtime::InfoPeMem::from_rtl(hw, regmap);
                sec_view.reset(hw, regmap);
            }
            Section::PeAlu => {
                println!(" Reset {sec} registers ...");
                let mut sec_view = rtl::runtime::InfoPeAlu::from_rtl(hw, regmap);
                sec_view.reset(hw, regmap);
            }
            Section::Isc => {
                println!(" Reset {sec} registers ...");
                let mut sec_view = rtl::runtime::InfoIsc::from_rtl(hw, regmap);
                sec_view.reset(hw, regmap);
            }
            _ => { /*Do Nothing*/ }
        }
    }
}

fn read_mem(hw: &mut ffi::HpuHw, addr: u64, size_b: usize) -> Vec<u8> {
    let mut data = vec![0; size_b];
    hw.read_abs(addr, &mut data);
    data
}

/// Display memory content in a pretty and understandable way
/// Data is passed as mutable vector to ease zero padding
fn pretty_display(data: Vec<u8>, addr: u64, byte_per_line: usize) {
    println!("@{: >8}::{: >16}_{: >16}", "address", "MSB", "LSB");
    for (idx, chunks) in data.chunks(byte_per_line).enumerate() {
        print!("@{:>8x} :: ", addr + (byte_per_line * idx) as u64);
        let residual = chunks.len() % byte_per_line;
        if residual != 0 {
            // Print some x_padding to keep alignment
            for i in 0..(byte_per_line - residual) {
                if (i != 0) && ((i % 8) == 0) {
                    print!("_");
                }
                print!("{:x>2}", "");
            }
        }
        for (i, b) in chunks.iter().rev().enumerate() {
            if (i != 0) && ((i % 8) == 0) {
                print!("_");
            }
            print!("{b:0>2x}");
        }
        println!("");
    }
}

fn write_mem(hw: &mut ffi::HpuHw, addr: u64, size_b: usize, value: &Vec<u64>) {
    // Construct full pattern
    let pattern = (0..((size_b / std::mem::size_of::<u64>()) + 1))
        .map(|i| value[i % value.len()])
        .collect::<Vec<_>>();
    // Cast it in byte-array and shrink it to correct size
    let pattern_b = bytemuck::cast_slice::<u64, u8>(pattern.as_slice());
    hw.write_abs(addr, &pattern_b[0..size_b]);
}

fn pretty_dump_in_file(file_path: &str, data: &[u8], line_bytes: usize) {
    // Open file
    let mut wr_f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(file_path)
        .unwrap();

    data.write_hex(&mut wr_f, line_bytes, Some("XX"));
}

fn soft_reset(hw: &mut ffi::HpuHw, regmap: &FlatRegmap) {
    let soft_reset = regmap
        .register()
        .get("hpu_reset::trigger")
        .expect("The current HPU does not support soft reset.");
    let soft_reset_addr = *soft_reset.offset() as u64;

    for reset in [true, false].into_iter() {
        hw.write_reg(soft_reset_addr, reset as u32);
        loop {
            let done = {
                let val = hw.read_reg(soft_reset_addr);
                let fields = soft_reset.as_field(val);
                *fields.get("done").expect("Unknown field") != 0
            };
            if done == reset {
                break;
            }
        }
    }
}

fn trace_dump(hw: &mut ffi::HpuHw, regmap: &FlatRegmap, size_b: usize, filename: &str) {
    let offset = {
        let offset_reg: Vec<usize> = ["trc_pc0_lsb", "trc_pc0_msb"]
            .into_iter()
            .map(|name| {
                let reg = regmap
                    .register()
                    .get(&format!("hbm_axi4_addr_1in3::{}", name))
                    .expect("Unknown register, check regmap definition");
                hw.read_reg(*reg.offset() as u64) as usize
            })
            .collect();
        offset_reg[0] as u64 + ((offset_reg[1] as u64) << 32)
    };

    println!("Dump {size_b} bytes of trace [@{offset:x}] inside {filename}");
    let raw_data = read_mem(hw, offset, size_b);
    let trace_stream =
        IscTraceStream::from_bytes(&raw_data).expect("Issue with during trace parsing");

    let file = File::create(filename).expect("Failed to create or open trace dump file");
    let buf_wr = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(buf_wr, &trace_stream).expect("Could not write trace dump");
}

fn read_and_dump_ct(
    hw: &mut ffi::HpuHw,
    regmap: &FlatRegmap,
    key_seed: u128,
    addr: u64,
    size: usize,
) {
    // Generate tfhe key
    // Force key seeder if seed specified by user
    if let Some(seed) = args.seed {
        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
        let shortint_engine = crate::shortint::engine::ShortintEngine::new_from_seeder(&mut seeder);
        crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
            std::mem::replace(engine, shortint_engine)
        });
    }

    // Extract pbs_configuration from Hpu and create Client/Server Key
    let params = HpuParameters::from_rtl(hw, regmap);
    let cks = ClientKey::new(KeySwitch32PBSParameters::from(&params));

    // Use Hpu memory view for ease
    let cut_size_b = memory::page_align(
        hpu_big_lwe_ciphertext_size(&params).div_ceil(params.pc_params.pem_pc)
            * std::mem::size_of::<u64>(),
    );
    let ct_props = memory::CiphertextMemoryProperties {
        mem_cut: config.board.ct_pc.clone(),
        // NB: Xrt only support page align memory allocation. Thus we round cut coefs to
        // match the next 4k page boundary
        cut_size_b,
        slot_nb: config.board.user_size,
        retry_rate_us: config.fpga.polling_us,
    };
    tracing::debug!("[N{hid}] Ct_mem properties -> {:?}", ct_props);

    // Convert addr and size in vec of slotId
    let slots = (0..size)
        .iter()
        .map(|b| SlotId(addr + b))
        .collect::<Vec<_>>();

    let hpu_ct = CiphertextSlot::raw_readback(hw, &slots, &ct_props, &params);
    let cpu_ct = RadixCiphertext {
        blocks: hpu_ct
            .into_iter()
            .map(|ct| {
                let pbs_p = KeySwitch32PBSParameters::from(ct.params());
                let cpu_ct = LweCiphertextOwned::from(ct.as_view());
                // Hpu output clean ciphertext without carry
                Ciphertext::new(
                    cpu_ct,
                    Degree::new(pbs_p.message_modulus.0 - 1),
                    NoiseLevel::NOMINAL,
                    pbs_p.message_modulus,
                    pbs_p.carry_modulus,
                    AtomicPatternKind::KeySwitch32,
                )
            })
            .collect::<Vec<_>>(),
    };
    let pt = cks.decrypt_radix(cpu_ct);
    println!(
        "Read {size} blocks from [@{addr:x}] and decrypt it's content => 0x{:x}",
        pt
    );
}
