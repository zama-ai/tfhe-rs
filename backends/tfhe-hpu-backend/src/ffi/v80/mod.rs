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
pub use pdi::HpuV80Pdi;

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
        dev_sn: Vec<(String, String)>,
        hpu_path: &str,
        ami_path: &str,
        force_reload: bool,
    ) {
        // Open Pdi archive
        let hpu_pdi = HpuV80Pdi::from_bincode(hpu_path)
            .unwrap_or_else(|err| panic!("Invalid \'.hpu\' {hpu_path:?}: {err}"));
        let pdi_uuid = pdi::V80Uuid::from_str(&hpu_pdi.metadata.bitstream.uuid)
            .expect("Invalid UUID format in pdi");

        // Extract the list of boards that need to be reprogrammed
        let trgt_dev_sn = if force_reload {
            dev_sn.clone()
        } else {
            Self::check_invalid_state(&dev_sn, &hpu_pdi, &pdi_uuid)
        };

        if !trgt_dev_sn.is_empty() {
            // Reload all stage_1 through JTAG
            Self::load_stage_1(&trgt_dev_sn, &hpu_pdi, &pdi_uuid);

            // Write stage_2 through DMA
            Self::load_stage_2(&trgt_dev_sn, &hpu_pdi);

            // Reload Ami driver
            tracing::info!("Load ami kernel module [{ami_path}]");
            Command::new("sudo")
                .arg("/usr/sbin/insmod")
                .arg(ami_path)
                .status()
                .expect("Unable to load ami.ko");
        }

        // Check Qdma queue and recreate them if needed
        // NB: Check is done on all boards not only on the reprog one
        for (pcie_id, _sn) in dev_sn.iter() {
            Self::cfg_dma_queues(pcie_id);
        }
    }

    fn check_invalid_state(
        dev_sn: &[(String, String)],
        hpu_pdi: &pdi::HpuV80Pdi,
        hpu_uuid: &pdi::V80Uuid,
    ) -> Vec<(String, String)> {
        let trgt = dev_sn
            .iter()
            .filter_map(|(dev, sn)| {
                // Check state and version
                match AmiDriver::new(dev, &hpu_pdi.metadata.amc.his_version, None) {
                    Ok(ami) => {
                        if hpu_pdi.metadata.bitstream.uuid.to_lowercase()
                            == ami.uuid().to_lowercase()
                        {
                            tracing::info!("Board[{dev}::{sn}] -> [{hpu_uuid}]");
                            None
                        } else {
                            tracing::warn!(
                                "Board[{dev}::{sn}] -> UUID mismatch loaded {:?} expected {:?}",
                                ami.uuid().to_lowercase(),
                                hpu_pdi.metadata.bitstream.uuid.to_lowercase()
                            );
                            Some((dev.clone(), sn.clone()))
                        }
                    }
                    Err(err) => {
                        tracing::warn!("Board[{dev}::{sn}] -> Ami loading error: {err:?}",);
                        Some((dev.clone(), sn.clone()))
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
        dev_sn: &[(String, String)],
        hpu_pdi: &pdi::HpuV80Pdi,
        hpu_uuid: &pdi::V80Uuid,
    ) {
        tracing::info!("Boards [{dev_sn:?}] will be loaded with pdi -> [{hpu_uuid}]");

        // Prerequisite. Enforce that ami/qdma driver are unloaded
        // Use two distinct commands to ease matching with sudoer rules
        // If either we fail to unload ami or qdma we must raise an error
        tracing::info!("Unload drivers ami/qdma_pf");
        let _ = Command::new("sudo")
            .arg("/usr/sbin/rmmod")
            .arg("--syslog") // Output to syslog instead of stderr
            .arg("ami")
            .status();
        assert!(
            !std::path::Path::new("/sys/module/ami").exists(),
            "Failed to unload ami driver: module still loaded"
        );
        let _ = Command::new("sudo")
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
        let serial_numbers: Vec<&str> = dev_sn.iter().map(|(_, sn)| sn.as_str()).collect();
        tracing::info!(
            "Load stage1 through JTAG for {} board(s) in single Vivado session",
            serial_numbers.len()
        );
        Self::jtag_program_boards(&serial_numbers, &pdi_path)
            .unwrap_or_else(|e| panic!("Stage1 JTAG programming failed: {e}"));

        // 2. Rescan Pcie bus to detect new PF function ----------------------------
        // Update right on V80 pcie subsystem
        update_pcie_perms();

        for (i, (dev, sn)) in dev_sn.iter().enumerate() {
            tracing::info!(
                " Board[{}/{}][{dev}::{sn}] Updating Pcie physical functions status",
                i + 1,
                dev_sn.len()
            );
            let rm_pf0 = OpenOptions::new()
                .write(true)
                .open(format!("/sys/bus/pci/devices/0000:{dev:0>2}:00.0/remove"))
                .ok();
            if let Some(mut pf0) = rm_pf0 {
                pf0.write_all(b"1\n")
                    .expect("Unable to trigger a remove of pci pf0");
            } else {
                tracing::debug!(
                    "Board[{}/{}][{dev}::{sn}] Pcie PF0 not present.",
                    i + 1,
                    dev_sn.len()
                );
            }

            OpenOptions::new()
                .write(true)
                .open(format!("/sys/bus/pci/devices/0000:{dev:0>2}:00.1/remove"))
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

    fn load_stage_2(dev_sn: &[(String, String)], hpu_pdi: &HpuV80Pdi) {
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
        std::thread::scope(|s| {
            for (i, (dev, sn)) in dev_sn.iter().enumerate() {
                s.spawn(move || {
                    tracing::info!(
                        "Board[{}/{}][{dev}::{sn}] Load stage2 through Qdma [{} bytes]",
                        i + 1,
                        dev_sn.len(),
                        stg2_data.len()
                    );
                    Self::dma_program_board(dev, stg2_data).unwrap_or_else(|e| {
                        panic!("Board[{}/{}][{dev}::{sn}] Stage2: {e}", i + 1, dev_sn.len())
                    });

                    tracing::debug!(
                        "Board[{}/{}][{dev}::{sn}] Removing Pcie PF0",
                        i + 1,
                        dev_sn.len()
                    );
                    OpenOptions::new()
                        .write(true)
                        .open(format!("/sys/bus/pci/devices/0000:{dev}:00.0/remove"))
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
        OpenOptions::new()
            .write(true)
            .open(format!(
                "/sys/bus/pci/devices/0000:{dev}:00.1/qdma/qmax"
            ))
            .expect("Unable to open qdma qmax cmd file")
            .write_all(b"100\n")
        .unwrap_or_else(|_| tracing::debug!("Dma: Failed to configure qmax. Must have been already done after the last rescan"));

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
pub(super) fn get_board_dev_sn() -> Result<Vec<(String, String)>, String> {
    // Read rawmap from environ
    let v80_board_rawmap = std::env::var("V80_BOARDS_RAWMAP")
        .map_err(|_| "V80_BOARDS_RAWMAP environment variable not found.")?;

    // Extract list of tuple (pcie_id, serial_number)
    let mut board_dev_sn = Vec::new();
    for board in v80_board_rawmap.split('|') {
        let dev_sn = board.split(':').collect::<Vec<_>>();
        if dev_sn.len() != 2 {
            return Err(format!("Invalid format in V80_BOARDS_RAWMAP: {board}"));
        } else {
            board_dev_sn.push((dev_sn[0].to_string(), dev_sn[1].to_string()));
        }
    }
    Ok(board_dev_sn)
}

/// Utility function to extract board device_id and mac addresses from env
pub(super) fn get_boards_mac() -> Result<Vec<(String, String)>, String> {
    // Read rawmap from environ
    let v80_board_rawmap = std::env::var("V80_BOARDS_MAC")
        .map_err(|_| "V80_BOARDS_MAC environment variable not found.")?;

    // Extract list of tuple (pcie_id, serial_number)
    let mut boards_mac = Vec::new();
    for board in v80_board_rawmap.split('|') {
        let dev_mac = board.split(':').collect::<Vec<_>>();
        if dev_mac.len() != 2 {
            return Err(format!("Invalid format in V80_BOARDS_MAC: {board}"));
        } else {
            boards_mac.push((dev_mac[0].to_string(), dev_mac[1].to_string()));
        }
    }
    Ok(boards_mac)
}
