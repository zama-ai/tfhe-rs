//! Implement V80 driver abstraction
//!
//! V80 relies on 2 drivers for communication
//! * Register access/Rpu interaction -> AMI
//! * Data xfer -> QDMA

use crate::ffi;
use crate::prelude::ShellString;

use std::error::Error;
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

mod ami;
use ami::AmiDriver;
mod pdi;
pub use pdi::{HpuV80Pdi, HpuV80Uuid};

use super::{MemAlloc, MemChunk};

mod qdma;
use qdma::QdmaDriver;
use rand::RngExt;

const DMA_XFER_ALIGN: usize = 4096_usize;

fn update_pcie_perms() {
    Command::new("sh")
        .arg(ShellString::new("${HPU_BACKEND_DIR}/scripts/v80-pcie-perms.sh".to_string()).expand())
        .status()
        .expect("Unable to update v80 pcie sysfs rights");
}

pub struct HpuHw {
    pub(super) ami: AmiDriver,
    pub(super) qdma: Arc<Mutex<QdmaDriver>>,
    allocator: Option<MemAlloc>,
}

impl HpuHw {
    /// Check current Hw state and lazily reload it if required
    /// NB: If ami driver doesn't respond, the board state couldn't be read, thus all boards are
    /// reloaded. Otherwise, only reload boards with invalid UUID.
    /// NB'': Checks on Qdma queue state are done at the end
    ///
    /// NB: This procedure requires unloading of Qdma/Ami driver and thus can't be directly
    /// implemented in the AMI
    pub fn lazy_load(
        board_props: Vec<ffi::BoardProperties>,
        hpu_path: &str,
        ami_path: &str,
        force_reload: bool,
    ) {
        // Open Pdi archive
        let hpu_pdi = HpuV80Pdi::from_bincode(hpu_path)
            .unwrap_or_else(|err| panic!("Invalid \'.hpu\' {hpu_path:?}: {err}"));
        let pdi_uuid = HpuV80Uuid::from_str(&hpu_pdi.metadata.bitstream.uuid)
            .expect("Invalid UUID format in pdi");

        // Extract the list of boards that need to be reprogrammed
        let trgt_boards = if force_reload {
            board_props.clone()
        } else {
            Self::check_invalid_state(&board_props, &hpu_pdi, &pdi_uuid)
        };

        if !trgt_boards.is_empty() {
            // Reload all stage_1 through JTAG
            Self::load_stage_1(&trgt_boards, &hpu_pdi, &pdi_uuid);

            // Write stage_2 through DMA
            Self::load_stage_2(&trgt_boards, &hpu_pdi);

            // Reload Ami driver
            tracing::info!("Load ami kernel module [{ami_path}]");
            Command::new("sudo")
                .arg("--stdin")
                .arg("/usr/sbin/insmod")
                .arg(ami_path)
                .status()
                .expect("Unable to load ami.ko");
        }

        // Check Qdma queue and recreate them if needed
        // NB: Check is done on all boards not only on the reprog one
        for b in board_props.iter() {
            Self::cfg_dma_queues(&b.pcie_id);
        }
    }

    fn check_invalid_state(
        board_props: &[ffi::BoardProperties],
        hpu_pdi: &HpuV80Pdi,
        hpu_uuid: &HpuV80Uuid,
    ) -> Vec<ffi::BoardProperties> {
        let trgt = board_props
            .iter()
            .filter_map(|board| {
                // Check state and version
                match AmiDriver::new(&board.pcie_id, &hpu_pdi.metadata.amc.his_version, None) {
                    Ok(ami) => {
                        if hpu_pdi.metadata.bitstream.uuid.to_lowercase()
                            == ami.uuid().to_lowercase()
                        {
                            tracing::info!("{board:?} -> [{hpu_uuid}]");
                            None
                        } else {
                            tracing::warn!(
                                "{board:?} -> UUID mismatch loaded {:?} expected {:?}",
                                ami.uuid().to_lowercase(),
                                hpu_pdi.metadata.bitstream.uuid.to_lowercase()
                            );
                            Some(board.clone())
                        }
                    }
                    Err(err) => {
                        tracing::warn!("[{board:?}] -> Ami loading error: {err:?}",);
                        Some(board.clone())
                    }
                }
            })
            .collect::<Vec<_>>();
        trgt
    }

    /// Program all boards in a single Vivado session (one hw_manager open)
    /// Streams lines prefixed with INFO/WARNING/ERROR via tracing while
    /// suppressing the verbose Vivado log.
    fn jtag_program_boards(serial_numbers: &[&str], pdi_path: &str) -> Result<(), String> {
        let mut cmd =
            Command::new(ShellString::new("${XILINX_VIVADO}/bin/vivado".to_string()).expand());
        cmd.arg("-mode")
            .arg("batch")
            .arg("-source")
            .arg(ShellString::new("${HPU_BACKEND_DIR}/scripts/pdi_jtag.tcl".to_string()).expand())
            .arg("-tclargs")
            .arg(pdi_path);
        for sn in serial_numbers {
            cmd.arg(sn);
        }
        cmd.stdout(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to launch vivado: {e}"))?;

        let stdout = child.stdout.take().expect("stdout was piped");
        for line in std::io::BufReader::new(stdout).lines().flatten() {
            if line.starts_with("INFO") {
                tracing::info!("{line}");
            } else if line.starts_with("WARNING") {
                tracing::warn!("{line}");
            } else if line.starts_with("ERROR") {
                tracing::error!("{line}");
            }
        }

        let status = child
            .wait()
            .map_err(|e| format!("Failed to wait for vivado: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("JTAG programming of stage 1 failed ({status})"))
        }
    }

    fn load_stage_1(
        board_props: &[ffi::BoardProperties],
        hpu_pdi: &HpuV80Pdi,
        hpu_uuid: &HpuV80Uuid,
    ) {
        tracing::info!("[{board_props:?}] will be loaded with pdi -> [{hpu_uuid}]");

        // Prerequisite. Enforce that ami/qdma driver are unloaded
        // Use two distinct commands to ease matching with sudoer rules
        // If either we fail to unload ami or qdma we must raise an error
        tracing::info!("Unload drivers ami/qdma_pf");
        let _ = Command::new("sudo")
            .arg("--stdin")
            .arg("/usr/sbin/rmmod")
            .arg("--syslog") // Output to syslog instead of stderr
            .arg("ami")
            .status();
        assert!(
            !std::path::Path::new("/sys/module/ami").exists(),
            "Failed to unload ami driver: module still loaded"
        );
        let _ = Command::new("sudo")
            .arg("--stdin")
            .arg("/usr/sbin/rmmod")
            .arg("--syslog") // Output to syslog instead of stderr
            .arg("qdma_pf")
            .status();
        assert!(
            !std::path::Path::new("/sys/module/qdma_pf").exists(),
            "Failed to unload qdma_pf driver: module still loaded"
        );

        // Load pdi stg1 content in filesystem to exchange with VivadoTool
        let pdi_stg1_tmp = format!(
            "hpu_stg1_{}.pdi",
            rand::rng()
                .sample_iter(rand::distr::Alphanumeric)
                .take(5)
                .map(char::from)
                .collect::<String>()
        );
        let tmp_dir = std::env::temp_dir();
        let tmp_dir_str = tmp_dir.to_str().expect("TEMP_DIR is not a valid UTF-8");
        // Write the binary data
        HpuV80Pdi::write_to_path(tmp_dir_str, &pdi_stg1_tmp, &hpu_pdi.pdi_stg1_bin)
            .expect("Error while expanding stg1 pdi on filesystem");

        // 1. Load PDI stage one through JTAG --------------------------------------
        // Open Vivado hw_manager once and program all boards in a single session
        let pdi_path = format!("{}/{}", tmp_dir_str, &pdi_stg1_tmp);
        let serial_numbers: Vec<&str> = board_props
            .iter()
            .map(|board| board.serial_number.as_str())
            .collect();
        tracing::info!(
            "Load stage1 through JTAG for {} board(s) in single Vivado session",
            serial_numbers.len()
        );
        Self::jtag_program_boards(&serial_numbers, &pdi_path)
            .unwrap_or_else(|e| panic!("Stage1 JTAG programming failed: {e}"));

        // 2. Rescan Pcie bus to detect new PF function ----------------------------
        // Update right on V80 pcie subsystem
        update_pcie_perms();

        for (i, board) in board_props.iter().enumerate() {
            tracing::info!(
                " Board[{}/{}][{board:?}] Updating Pcie physical functions status",
                i + 1,
                board_props.len()
            );
            let rm_pf0 = OpenOptions::new()
                .write(true)
                .open(format!(
                    "/sys/bus/pci/devices/0000:{:0>2}:00.0/remove",
                    board.pcie_id
                ))
                .ok();
            if let Some(mut pf0) = rm_pf0 {
                pf0.write_all(b"1\n")
                    .expect("Unable to trigger a remove of pci pf0");
            } else {
                tracing::debug!(
                    "Board[{}/{}][{board:?}] Pcie PF0 not present.",
                    i + 1,
                    board_props.len()
                );
            }

            OpenOptions::new()
                .write(true)
                .open(format!(
                    "/sys/bus/pci/devices/0000:{:0>2}:00.1/remove",
                    board.pcie_id
                ))
                .expect("Unable to open pci remove cmd file")
                .write_all(b"1\n")
                .expect("Unable to trigger a remove of pci pf1");
        }
        OpenOptions::new()
            .write(true)
            .open("/sys/bus/pci/rescan")
            .expect("Unable to open pci rescan cmd file")
            .write_all(b"1\n")
            .expect("Unable to trigger a pci rescan");

        // wait for QDMA to create its fs
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Update right on V80 pcie subsystem
        // NB: sysfs is recreated upon rescan
        update_pcie_perms();
    }

    fn dma_program_board(dev: &str, stg2_data: &[u8]) -> Result<(), String> {
        // Configure qmax
        OpenOptions::new()
            .write(true)
            .open(format!("/sys/bus/pci/devices/0000:{dev}:00.1/qdma/qmax"))
            .expect("Unable to open qdma qmax cmd file")
            .write_all(b"100\n")
            .unwrap_or_else(|_| tracing::debug!("Dma: Failed to configure qmax. Must have been already done after the last rescan"));

        // Create and start h2c queue at idx 0
        Command::new("dma-ctl")
            .arg(format!("qdma{dev}001"))
            .arg("q")
            .arg("add")
            .arg("idx")
            .arg("0")
            .arg("dir")
            .arg("h2c")
            .status()
            .expect("dma-ctl q add idx 0 h2c failed");
        Command::new("dma-ctl")
            .arg(format!("qdma{dev}001"))
            .arg("q")
            .arg("start")
            .arg("idx")
            .arg("0")
            .arg("dir")
            .arg("h2c")
            .arg("aperture_sz")
            .arg(DMA_XFER_ALIGN.to_string())
            .status()
            .expect("dma-ctl q start idx 0 h2c failed");

        // Write stage2 PDI through QDMA
        let qdma_h2c = OpenOptions::new()
            .read(false)
            .write(true)
            .create(false)
            .open(format!("/dev/qdma{dev}001-MM-0"))
            .map_err(|e| format!("Unable to open Qdma queue 0: {e}"))?;
        let ret = nix::sys::uio::pwrite(&qdma_h2c, stg2_data, 0x000102100000_i64)
            .map_err(|e| format!("pwrite failed: {e}"))?;
        if ret != stg2_data.len() {
            return Err(format!("Partial pwrite: {ret}/{} bytes", stg2_data.len()));
        }

        Ok(())
    }

    fn load_stage_2(board_props: &[ffi::BoardProperties], hpu_pdi: &HpuV80Pdi) {
        // NB: Dma requires same alignment aperture.
        let stg2_aligned = {
            let len = hpu_pdi.pdi_stg2_bin.len();
            let layout = std::alloc::Layout::from_size_align(len, DMA_XFER_ALIGN)
                .expect("Invalid layout definition for stg2 aligned buffer");
            let raw_ptr = unsafe { std::alloc::alloc(layout) };
            let data = unsafe { std::slice::from_raw_parts_mut(raw_ptr, len) };
            data.copy_from_slice(hpu_pdi.pdi_stg2_bin.as_slice());
            data
        };
        let stg2_data: &[u8] = stg2_aligned;

        // Program all boards in parallel — each has independent PCIe/QDMA paths
        // NB: use thread here instead of rayon, since dma_program_board is an IO heavy task
        std::thread::scope(|s| {
            for (i, board) in board_props.iter().enumerate() {
                s.spawn(move || {
                    tracing::info!(
                        "Board[{}/{}][{board:?}] Load stage2 through Qdma [{} bytes]",
                        i + 1,
                        board_props.len(),
                        stg2_data.len()
                    );
                    Self::dma_program_board(&board.pcie_id, stg2_data).unwrap_or_else(|e| {
                        panic!(
                            "Board[{}/{}][{board:?}] Stage2: {e}",
                            i + 1,
                            board_props.len()
                        )
                    });

                    tracing::debug!(
                        "Board[{}/{}][{board:?}] Removing Pcie PF0",
                        i + 1,
                        board_props.len()
                    );
                    OpenOptions::new()
                        .write(true)
                        .open(format!(
                            "/sys/bus/pci/devices/0000:{}:00.0/remove",
                            board.pcie_id
                        ))
                        .expect("Unable to open pci remove cmd file")
                        .write_all(b"1\n")
                        .expect("Unable to trigger a remove of pci pf0");
                });
            }
        });

        // Properly release custom allocated memory
        unsafe { nix::libc::free(stg2_aligned.as_mut_ptr() as *mut _) };

        tracing::info!("Rescan Pci bus for all");
        OpenOptions::new()
            .write(true)
            .open("/sys/bus/pci/rescan")
            .expect("Unable to open pci rescan cmd file")
            .write_all(b"1\n")
            .expect("Unable to trigger a pci rescan");
    }

    /// Create Dma queues
    /// Since all nodes rely on the same qdma driver, reloading a node breaks the dma interface
    /// Thus dma_queues must be recreated for each node when any of the cluster node is reloaded -_-
    pub fn cfg_dma_queues(dev: &str) {
        // Configure maximum Dma queues
        let qmax_path = format!("/sys/bus/pci/devices/0000:{dev}:00.1/qdma/qmax");

        match std::fs::read_to_string(&qmax_path) {
            Ok(current) if current.trim() == "100" => {
                tracing::debug!("Dma: qmax already set to 100, skipping");
            }
            Ok(_) => {
                if let Err(e) = OpenOptions::new()
                    .write(true)
                    .open(&qmax_path)
                    .and_then(|mut f| f.write_all(b"100\n"))
                {
                    tracing::debug!("Dma: Failed to configure qmax ({e}). Must have been already done after the last rescan");
                }
            }
            Err(e) => {
                tracing::debug!("Dma: Failed to read qmax ({e}), skipping configuration");
            }
        }

        if let Err(e) = OpenOptions::new()
            .write(true)
            .open(format!("/sys/bus/pci/devices/0000:{dev}:00.1/qdma/qmax"))
            .and_then(|mut f| f.write_all(b"100\n"))
        {
            tracing::debug!("Dma: Failed to configure qmax ({e}). Must have been already done after the last rescan");
        }

        // Create user queues ----------------------------------------------
        let h2c_path = format!("/dev/qdma{dev}001-MM-1");
        let c2h_path = format!("/dev/qdma{dev}001-MM-2");

        if !std::path::Path::new(&h2c_path).exists() {
            Command::new("dma-ctl")
                .arg(format!("qdma{dev}001"))
                .arg("q")
                .arg("add")
                .arg("idx")
                .arg("1")
                .arg("dir")
                .arg("h2c")
                .status()
                .expect("Unable to create Qdma queue1");
            Command::new("dma-ctl")
                .arg(format!("qdma{dev}001"))
                .arg("q")
                .arg("start")
                .arg("idx")
                .arg("1")
                .arg("dir")
                .arg("h2c")
                .status()
                .expect("Unable to start Qdma queue1");
        }

        if !std::path::Path::new(&c2h_path).exists() {
            Command::new("dma-ctl")
                .arg(format!("qdma{dev}001"))
                .arg("q")
                .arg("add")
                .arg("idx")
                .arg("2")
                .arg("dir")
                .arg("c2h")
                .status()
                .expect("Unable to create Qdma queue2");
            Command::new("dma-ctl")
                .arg(format!("qdma{dev}001"))
                .arg("q")
                .arg("start")
                .arg("idx")
                .arg("2")
                .arg("dir")
                .arg("c2h")
                .status()
                .expect("Unable to start Qdma queue2");
        }
    }

    /// Open ffi interface
    #[inline(always)]
    pub fn open_hpu_hw(
        pcie_id: &str,
        hpu_path: &str,
        ami_retry: std::time::Duration,
    ) -> Result<HpuHw, Box<dyn Error>> {
        // Load Pdi archive
        let hpu_pdi = HpuV80Pdi::from_bincode(hpu_path)
            .unwrap_or_else(|err| panic!("Invalid \'.hpu\' {hpu_path:?}: {err}"));

        // Construct qdma path
        let h2c_path = format!("/dev/qdma{pcie_id}001-MM-1");
        let c2h_path = format!("/dev/qdma{pcie_id}001-MM-2");

        // Open current Hw
        let ami = AmiDriver::new(pcie_id, &hpu_pdi.metadata.amc.his_version, Some(ami_retry))?;
        let qdma = QdmaDriver::new(&h2c_path, &c2h_path)?;

        Ok(Self {
            ami,
            qdma: Arc::new(Mutex::new(qdma)),
            allocator: None,
        })
    }

    pub fn init_mem(
        &mut self,
        config: &crate::interface::HpuConfig,
        params: &crate::entities::HpuParameters,
    ) {
        assert!(
            self.allocator.is_none(),
            "Error: Double request of HpuHw memory initialisation"
        );
        self.allocator = Some(MemAlloc::new(config, params));
    }

    pub fn read_abs_bytes(&self, addr: u64, bytes: &mut [u8]) {
        let qdma = self.qdma.lock().unwrap();
        qdma.read_bytes(addr as usize, bytes)
    }

    pub fn write_abs_bytes(&mut self, addr: u64, bytes: &[u8]) {
        let qdma = self.qdma.lock().unwrap();
        qdma.write_bytes(addr as usize, bytes)
    }

    /// Handle on-board memory allocation
    pub fn alloc(&mut self, props: ffi::MemZoneProperties) -> MemZone {
        let chunks = self
            .allocator
            .as_mut()
            .expect("Error: V80 backend memory must be explicitly init (c.f. init_mem)")
            .alloc(&props);
        MemZone::new(props.mem_kind, chunks[0].paddr, chunks, self.qdma.clone())
    }
    /// Handle on-board memory de-allocation
    pub fn release(&mut self, zone: &mut MemZone) {
        let MemZone { kind, chunks, .. } = zone;
        self.allocator
            .as_mut()
            .expect("Error: V80 backend memory must be explicitly init (c.f. init_mem)")
            .release(kind, chunks)
    }
}

pub struct MemZone {
    // Link properties
    kind: ffi::MemKind,
    addr: u64,
    chunks: Vec<MemChunk>,

    // Ref to Qdma driver
    qdma: Arc<Mutex<QdmaDriver>>,
}

impl MemZone {
    pub fn new(
        kind: ffi::MemKind,
        addr: u64,
        chunks: Vec<MemChunk>,
        qdma: Arc<Mutex<QdmaDriver>>,
    ) -> Self {
        Self {
            kind,
            addr,
            chunks,
            qdma,
        }
    }

    pub fn read_bytes(&self, ofst: usize, bytes: &mut [u8]) {
        let qdma = self.qdma.lock().unwrap();
        qdma.read_bytes(ofst + self.addr as usize, bytes)
    }

    pub fn paddr(&self) -> u64 {
        self.addr
    }

    pub fn size(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.size_b).sum()
    }

    pub fn write_bytes(&mut self, ofst: usize, bytes: &[u8]) {
        let qdma = self.qdma.lock().unwrap();
        qdma.write_bytes(ofst + self.addr as usize, bytes)
    }
}

/// Utility function to extract board device_id and serial_number from env
pub(super) fn get_board_properties() -> Result<Vec<ffi::BoardProperties>, String> {
    // Read rawmap from environ
    let v80_board_rawmap = std::env::var("V80_BOARDS_RAWMAP")
        .map_err(|_| "V80_BOARDS_RAWMAP environment variable not found.")?;

    // Extract list of tuple (pcie_id, serial_number, mac_addr)
    let mut board_props = Vec::new();
    for board in v80_board_rawmap.split('|') {
        let dev_sn_mac = board.split(':').collect::<Vec<_>>();
        if dev_sn_mac.len() != 3 {
            return Err(format!("Invalid format in V80_BOARDS_RAWMAP: {board}"));
        } else {
            // Read int from mac_addr string
            let mac_addr = if let Some(hex) = dev_sn_mac[2].strip_prefix("0x") {
                u32::from_str_radix(hex, 16)
            } else if let Some(oct) = dev_sn_mac[2].strip_prefix("0o") {
                u32::from_str_radix(oct, 8)
            } else if let Some(bin) = dev_sn_mac[2].strip_prefix("0b") {
                u32::from_str_radix(bin, 2)
            } else {
                dev_sn_mac[2].parse::<u32>()
            }
            .expect("Invalid mac addr format");
            board_props.push(ffi::BoardProperties {
                pcie_id: dev_sn_mac[0].to_string(),
                serial_number: dev_sn_mac[1].to_string(),
                mac_addr,
            });
        }
    }
    Ok(board_props)
}
