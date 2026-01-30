//! Implement V80 driver abstraction
//!
//! V80 rely on 2 driver for communication
//! * Register access/Rpu interaction -> AMI
//! * Data xfer -> QDMA

use crate::ffi;
use crate::prelude::ShellString;

use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

mod ami;
use ami::AmiDriver;
mod pdi;
pub use pdi::HpuV80Pdi;

mod mem_alloc;
use mem_alloc::{MemAlloc, MemChunk};

mod qdma;
use qdma::QdmaDriver;
use rand::Rng;

const DMA_XFER_ALIGN: usize = 4096_usize;

pub struct HpuHw {
    pub(super) ami: AmiDriver,
    pub(super) qdma: Arc<Mutex<QdmaDriver>>,
    allocator: Option<MemAlloc>,
}

#[derive(Debug)]
pub struct ForceError {}
impl Error for ForceError {}
impl std::fmt::Display for ForceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Reload Forced")
    }
}

impl HpuHw {
    /// Handle ffi instantiation
    /// Instantiate current HW and check uuid. If it match with targeted one continue,
    /// otherwise reload Pdi
    #[inline(always)]
    pub fn new_hpu_hw(
        id: &str,
        board_sn: &str,
        hpu_path: &str,
        ami_path: &str,
        ami_retry: std::time::Duration,
        h2c_path: &str,
        c2h_path: &str,
        force: &str,
    ) -> HpuHw {
        // Load Pdi archive
        let hpu_pdi = HpuV80Pdi::from_bincode(hpu_path)
            .unwrap_or_else(|err| panic!("Invalid \'.hpu\' {hpu_path:?}: {err}"));

        // Try current hw and fallback to a fresh reload
        let force: Result<Option<bool>, Box<dyn Error>> = match force {
            "true" => Err(Box::new(ForceError {})),
            _ => Ok(None),
        };
        force
            .and_then(|_| Self::try_current_hw(id, &hpu_pdi, ami_retry, h2c_path, c2h_path))
            .unwrap_or_else(|err| {
                tracing::warn!("Loading current HW failed with {err:?}. Will do a fresh reload");
                Self::reload_hw(
                    &id, &board_sn, &hpu_pdi, ami_path, ami_retry, h2c_path, c2h_path,
                )
            })
    }

    /// Load a Pdi in the FPGA
    /// NB: This procedure required unload of Qdma/Ami driver and thus couldn't be directly
    /// implemented     in the AMI
    fn try_current_hw(
        id: &str,
        pdi: &HpuV80Pdi,
        ami_retry: std::time::Duration,
        h2c_path: &str,
        c2h_path: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let ami = AmiDriver::new(id, &pdi.metadata.amc.his_version, ami_retry)?;
        let qdma = QdmaDriver::new(h2c_path, c2h_path)?;

        let hw = Self {
            ami,
            qdma: Arc::new(Mutex::new(qdma)),
            allocator: None,
        };

        let current_uuid = hw.ami.uuid().to_lowercase();
        if pdi.metadata.bitstream.uuid.to_lowercase() == current_uuid {
            let uuid = pdi::V80Uuid::from_str(&pdi.metadata.bitstream.uuid)
                .expect("Invalid UUID format in pdi");
            tracing::info!("Current pdi -> [\n{uuid}]");
            Ok(hw)
        } else {
            hw.ami.munmap_cnt().unwrap();
            Err(format!(
                "UUID mismatch loaded {:?} expected {:?}",
                current_uuid,
                pdi.metadata.bitstream.uuid.to_lowercase()
            )
            .into())
        }
    }

    /// Load a Pdi in the FPGA
    /// NB: This procedure required unload of Qdma/Ami driver and thus couldn't be directly
    /// implemented     in the AMI
    fn reload_hw(
        id: &str,
        board_sn: &str,
        pdi: &HpuV80Pdi,
        ami_path: &str,
        ami_retry: std::time::Duration,
        h2c_path: &str,
        c2h_path: &str,
    ) -> Self {
        tracing::warn!("FPGA reload procedure. Following step require sudo rights to handle modules loading and pcie subsystem configuration.");
        let uuid = pdi::V80Uuid::from_str(&pdi.metadata.bitstream.uuid)
            .expect("Invalid UUID format in pdi");
        tracing::info!("Load pdi -> [\n{uuid}]");
        tracing::debug!("Unload drivers ami/qdma_pf");
        //Prerequist. Enforce that ami/qdma driver are unloaded
        // NB: Separate the call to match sudoers rules
        let _ = Command::new("sudo")
            .arg("/usr/sbin/rmmod")
            .arg("--syslog") // Output to syslog instead of stderr
            .arg("ami")
            .status();
        let _ = Command::new("sudo")
            .arg("/usr/sbin/rmmod")
            .arg("--syslog") // Output to syslog instead of stderr
            .arg("qdma_pf")
            .status();

        // 1. Load PDI stage one through JTAG ----------------------------------
        // -> Use Xilinx hw_manager. Currently used through vivado for ease setup.
        // hw manager expect stage 1 in a file, thus start by expanding the stg1_pdi in a tmp file
        tracing::debug!("Load stage1 through JTAG");
        let pdi_stg1_tmp = format!(
            "hpu_stg1_{}.pdi",
            rand::thread_rng()
                .sample_iter(rand::distributions::Alphanumeric)
                .take(5)
                .map(char::from)
                .collect::<String>()
        );
        let tmp_dir = std::env::temp_dir();
        let tmp_dir_str = tmp_dir.to_str().expect("TEMP_DIR is not a valid UTF-8");

        // Write the binary data
        HpuV80Pdi::write_to_path(tmp_dir_str, &pdi_stg1_tmp, &pdi.pdi_stg1_bin)
            .expect("Error while expanding stg1 pdi on filesystem");

        let hw_monitor =
            Command::new(ShellString::new("${XILINX_VIVADO}/bin/vivado".to_string()).expand())
                .arg("-mode")
                .arg("batch")
                .arg("-source")
                .arg(
                    ShellString::new("${HPU_BACKEND_DIR}/scripts/pdi_jtag.tcl".to_string())
                        .expand(),
                )
                .arg("-tclargs")
                .arg(format!("{}/{}", tmp_dir_str, &pdi_stg1_tmp))
                .arg(format!("{}", &board_sn))
                .output()
                .expect("Stage1 loading encounters error");
        tracing::debug!("Stage1 loaded: {hw_monitor:?}");

        // Update right on V80 pcie subsystem
        Command::new("sudo")
            .arg(
                ShellString::new("${HPU_BACKEND_DIR}/scripts/v80-pcie-perms.sh".to_string())
                    .expand(),
            )
            .status()
            .expect("Unable to update v80 pcie sysfs right");

        tracing::debug!(" Updating Pcie physical functions status");
        let rm_pf0 = OpenOptions::new()
            .write(true)
            .open(
                ShellString::new(
                    "/sys/bus/pci/devices/0000:${V80_PCIE_DEV}:00.0/remove".to_string(),
                )
                .expand(),
            )
            .ok();
        if let Some(mut pf0) = rm_pf0 {
            pf0.write_all(b"1\n")
                .expect("Unable to triggered a remove of pci pf0");
        } else {
            tracing::debug!("Pcie PF0 not present.");
        }

        OpenOptions::new()
            .write(true)
            .open(
                ShellString::new(
                    "/sys/bus/pci/devices/0000:${V80_PCIE_DEV}:00.1/remove".to_string(),
                )
                .expand(),
            )
            .expect("Unable to open pci remove cmd file")
            .write_all(b"1\n")
            .expect("Unable to triggered a remove of pci pf1");
        OpenOptions::new()
            .write(true)
            .open("/sys/bus/pci/rescan")
            .expect("Unable to open pci rescan cmd file")
            .write_all(b"1\n")
            .expect("Unable to triggered a pci rescan");

        // wait for QDMA to create its fs
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Update right on V80 pcie subsystem
        // NB: sysfs is recreated upon rescan
        Command::new("sudo")
            .arg(
                ShellString::new("${HPU_BACKEND_DIR}/scripts/v80-pcie-perms.sh".to_string())
                    .expand(),
            )
            .status()
            .expect("Unable to update v80 pcie sysfs right");

        // 2. Load PDI stage two through QDMA ----------------------------------
        tracing::debug!("Load stage2 through Qdma");
        // Create h2c queue at idx 0

        tracing::debug!("Initializing queues");
        OpenOptions::new()
            .write(true)
            .open(
                ShellString::new(
                    "/sys/bus/pci/devices/0000:${V80_PCIE_DEV}:00.1/qdma/qmax".to_string(),
                )
                .expand(),
            )
            .expect("Unable to open qdma qmax cmd file")
            .write_all(b"100\n")
            .expect("Unable to configure Qdma max queues");
        Command::new("dma-ctl")
            .arg(ShellString::new("qdma${V80_PCIE_DEV}001".to_string()).expand())
            .arg("q")
            .arg("add")
            .arg("idx")
            .arg("0")
            .arg("dir")
            .arg("h2c")
            .status()
            .expect("Unable to create Qdma queue0");
        Command::new("dma-ctl")
            .arg(ShellString::new("qdma${V80_PCIE_DEV}001".to_string()).expand())
            .arg("q")
            .arg("start")
            .arg("idx")
            .arg("0")
            .arg("dir")
            .arg("h2c")
            .arg("aperture_sz")
            .arg(DMA_XFER_ALIGN.to_string())
            .status()
            .expect("Unable to start Qdma queue0");

        tracing::debug!("Uploading stage2: [{} bytes]", pdi.pdi_stg2_bin.len());
        // NB: Dma required same alignment as aperture.
        let stg2_aligned = {
            let len = pdi.pdi_stg2_bin.len();
            let layout = std::alloc::Layout::from_size_align(len, DMA_XFER_ALIGN)
                .expect("Invalid layout definition for stg2 aligned buffer");
            let raw_ptr = unsafe { std::alloc::alloc(layout) };
            let data = unsafe { std::slice::from_raw_parts_mut(raw_ptr, len) };
            data.copy_from_slice(pdi.pdi_stg2_bin.as_slice());
            data
        };

        let qdma_h2c = OpenOptions::new()
            .read(false)
            .write(true)
            .create(false)
            .open(ShellString::new("/dev/qdma${V80_PCIE_DEV}001-MM-0".to_string()).expand())
            .expect("Unable to open Qdma queue 0");
        let ret = nix::sys::uio::pwrite(&qdma_h2c, stg2_aligned, 0x000102100000_i64)
            .expect("Unable to write stage2 pdi");
        tracing::debug!("QDMA written {ret} bytes to device");
        // Properly release custom allocated memory
        unsafe { nix::libc::free(stg2_aligned.as_mut_ptr() as *mut _) };

        tracing::debug!(" Updating Pcie physical functions 0 status");
        OpenOptions::new()
            .write(true)
            .open(
                ShellString::new(
                    "/sys/bus/pci/devices/0000:${V80_PCIE_DEV}:00.0/remove".to_string(),
                )
                .expand(),
            )
            .expect("Unable to open pci remove cmd file")
            .write_all(b"1\n")
            .expect("Unable to triggered a remove of pci pf0");
        OpenOptions::new()
            .write(true)
            .open("/sys/bus/pci/rescan")
            .expect("Unable to open pci rescan cmd file")
            .write_all(b"1\n")
            .expect("Unable to triggered a pci rescan");

        // 3. Create user queues ----------------------------------------------
        Command::new("dma-ctl")
            .arg(ShellString::new("qdma${V80_PCIE_DEV}001".to_string()).expand())
            .arg("q")
            .arg("add")
            .arg("idx")
            .arg("1")
            .arg("dir")
            .arg("h2c")
            .status()
            .expect("Unable to create Qdma queue1");
        Command::new("dma-ctl")
            .arg(ShellString::new("qdma${V80_PCIE_DEV}001".to_string()).expand())
            .arg("q")
            .arg("start")
            .arg("idx")
            .arg("1")
            .arg("dir")
            .arg("h2c")
            .status()
            .expect("Unable to start Qdma queue1");

        Command::new("dma-ctl")
            .arg(ShellString::new("qdma${V80_PCIE_DEV}001".to_string()).expand())
            .arg("q")
            .arg("add")
            .arg("idx")
            .arg("2")
            .arg("dir")
            .arg("c2h")
            .status()
            .expect("Unable to create Qdma queue2");
        Command::new("dma-ctl")
            .arg(ShellString::new("qdma${V80_PCIE_DEV}001".to_string()).expand())
            .arg("q")
            .arg("start")
            .arg("idx")
            .arg("2")
            .arg("dir")
            .arg("c2h")
            .status()
            .expect("Unable to start Qdma queue2");

        // 4. load ami kernel module ------------------------------------------
        // Ami is to tight to amc version and thus bundle in .hpu_bin archive
        tracing::debug!("Load ami kernel module");
        Command::new("sudo")
            .arg("insmod")
            .arg(ami_path)
            .status()
            .expect("Unable to load ami.ko");

        Self {
            ami: AmiDriver::new(id, &pdi.metadata.amc.his_version, ami_retry)
                .expect("Unable to create AmiDriver after a fresh pdi load on device {id}"),
            qdma: Arc::new(Mutex::new(
                QdmaDriver::new(h2c_path, c2h_path)
                    .expect("Unable to create QdmaDriver after a fresh pdi load"),
            )),
            allocator: None,
        }
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
