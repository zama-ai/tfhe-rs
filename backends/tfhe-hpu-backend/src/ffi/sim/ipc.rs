//! IPC interface and associated Commands

use ipc_channel::ipc::{self, IpcOneShotServer, IpcReceiver, IpcSender};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::entities::HpuPBSParameters;
use crate::ffi::{self, SyncMode};

/// Register request
#[derive(Debug, Serialize, Deserialize)]
pub enum RegisterReq {
    Read { addr: u64 },
    Write { addr: u64, value: u32 },
    PbsParams,
}

/// Register acknowledgment
#[derive(Debug, Serialize, Deserialize)]
pub enum RegisterAck {
    Read(u32),
    Write,
    PbsParams(HpuPBSParameters),
}

/// FFI side of IPC channel used for Register xfer
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RegisterFfi {
    pub(crate) req: IpcSender<RegisterReq>,
    pub(crate) ack: IpcReceiver<RegisterAck>,
}
/// Sim side of IPC channel used for Register xfer
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterSim {
    pub req: IpcReceiver<RegisterReq>,
    pub ack: IpcSender<RegisterAck>,
}

pub(crate) fn register_channel() -> (RegisterFfi, RegisterSim) {
    let (req_tx, req_rx) = ipc::channel().unwrap();
    let (ack_tx, ack_rx) = ipc::channel().unwrap();

    (
        RegisterFfi {
            req: req_tx,
            ack: ack_rx,
        },
        RegisterSim {
            req: req_rx,
            ack: ack_tx,
        },
    )
}

/// Memory request
#[derive(Debug, Serialize, Deserialize)]
pub enum MemoryReq {
    Allocate {
        mem_kind: ffi::MemKind,
        size_b: usize,
    },
    Sync {
        mem_kind: ffi::MemKind,
        addr: u64,
        mode: SyncMode,
        data: Option<ipc::IpcSharedMemory>,
    },
    Release {
        mem_kind: ffi::MemKind,
        addr: u64,
    },
}

/// Memory acknowledgment
#[derive(Debug, Serialize, Deserialize)]
pub enum MemoryAck {
    Allocate { addr: u64 },
    Sync { data: Option<ipc::IpcSharedMemory> },
    Release,
}

/// FFI side of IPC channel used for Memory xfer
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MemoryFfi {
    pub(crate) req: IpcSender<MemoryReq>,
    pub(crate) ack: IpcReceiver<MemoryAck>,
}
/// FFI memory wrapped in an Arc<Mutex<_>>
/// Indeed, this object must be shared with all MemZone to enable proper sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MemoryFfiWrapped(pub(crate) Arc<Mutex<MemoryFfi>>);

impl From<MemoryFfi> for MemoryFfiWrapped {
    fn from(value: MemoryFfi) -> Self {
        Self(Arc::new(Mutex::new(value)))
    }
}

/// Sim side of IPC channel used for Memory xfer
#[derive(Debug, Serialize, Deserialize)]
pub struct MemorySim {
    pub req: IpcReceiver<MemoryReq>,
    pub ack: IpcSender<MemoryAck>,
}

pub(crate) fn memory_channel() -> (MemoryFfi, MemorySim) {
    let (req_tx, req_rx) = ipc::channel().unwrap();
    let (ack_tx, ack_rx) = ipc::channel().unwrap();

    (
        MemoryFfi {
            req: req_tx,
            ack: ack_rx,
        },
        MemorySim {
            req: req_rx,
            ack: ack_tx,
        },
    )
}

/// FFI side of IPC channel used for Memory xfer
/// Gather Register/Memory interface together to easily exchange them across OneShot server
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct IpcFfi {
    pub(crate) register: RegisterFfi,
    pub(crate) memory: MemoryFfiWrapped,
}

impl IpcFfi {
    /// Create IPC binding for Register and Memory interface
    /// Use a named file to retrieved the OneShot IPC channel that enable to exchange
    /// typed ipc_channels
    pub fn new_bind_on(ipc_name: &str) -> IpcFfi {
        // Open file
        let mut rd_f = BufReader::new(
            OpenOptions::new()
                .create(false)
                .read(true)
                .open(ipc_name)
                .unwrap(),
        );
        // Read name of the targeted oneshot channel
        let oneshot_name = {
            let mut name = String::new();
            rd_f.read_line(&mut name).unwrap();
            name
        };
        tracing::debug!("Will bind through {oneshot_name}");

        // Connect to the oneshot channel
        let bind_tx = IpcSender::connect(oneshot_name).unwrap();

        // Generate ipc channel and send Sim side through oneshot
        let (ffi, sim) = ipc_channel();
        bind_tx.send(sim).unwrap();

        ffi
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpcSim {
    pub register: RegisterSim,
    pub memory: MemorySim,
}
impl IpcSim {
    /// Create IPC Oneshot server and wait for endpoint
    pub fn new_bind_on(ipc_name: &str) -> IpcSim {
        // Create one shot channel
        let (oneshot_server, oneshot_name) = IpcOneShotServer::new().unwrap();
        // Register it into {ipc_name} file
        // Create folder if needed
        let path = Path::new(ipc_name);
        if let Some(dir_p) = path.parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }
        // Open file
        let mut wr_f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(ipc_name)
            .unwrap();
        write!(wr_f, "{oneshot_name}").unwrap();

        tracing::info!("Mockup waiting on IPC `{oneshot_name}`");
        let (_, ipc_sim): (_, IpcSim) = oneshot_server.accept().unwrap();

        ipc_sim
    }
}

pub(crate) fn ipc_channel() -> (IpcFfi, IpcSim) {
    let (register_ffi, register_sim) = register_channel();
    let (memory_ffi, memory_sim) = memory_channel();

    (
        IpcFfi {
            register: register_ffi,
            memory: MemoryFfiWrapped::from(memory_ffi),
        },
        IpcSim {
            register: register_sim,
            memory: memory_sim,
        },
    )
}
