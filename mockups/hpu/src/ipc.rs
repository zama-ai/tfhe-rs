//! Manage binding with tfhe-rs application
//!
//! Create a file with binding information and automatically refresh it
//! when connection close

use ipc_channel::ipc;
use tfhe::tfhe_hpu_backend::prelude::*;

pub struct Ipc {
    ipc_name: String,
    ipc: IpcSim,
}

impl Ipc {
    pub fn new(ipc_name: &str) -> Self {
        Self {
            ipc_name: ipc_name.to_string(),
            ipc: IpcSim::new_bind_on(ipc_name),
        }
    }

    fn ipc_reset(&mut self) {
        let new_ipc = IpcSim::new_bind_on(&self.ipc_name);
        self.ipc = new_ipc;
    }

    /// Recv next register request if any
    pub fn register_req(&mut self) -> Option<RegisterReq> {
        let req = {
            let IpcSim { register, .. } = &self.ipc;
            let RegisterSim { req, .. } = register;
            req
        };

        match req.try_recv() {
            Ok(cmd) => {
                tracing::trace!("RegisterReq Recv {cmd:x?}");
                Some(cmd)
            }
            Err(err) => match &err {
                ipc::TryRecvError::IpcError(kind) => match kind {
                    ipc::IpcError::Disconnected => {
                        self.ipc_reset();
                        None
                    }
                    _ => panic!("Encounter Ipc error {err:?}"),
                },
                ipc::TryRecvError::Empty => None,
            },
        }
    }

    /// Send register ack
    pub fn register_ack(&mut self, ack: RegisterAck) {
        let ack_tx = {
            let IpcSim { register, .. } = &self.ipc;
            let RegisterSim { ack, .. } = register;
            ack
        };

        // Silently drop error
        let _ = ack_tx.send(ack);
    }

    /// Recv next memory request if any
    pub fn memory_req(&mut self) -> Option<MemoryReq> {
        let req = {
            let IpcSim { memory, .. } = &self.ipc;
            let MemorySim { req, .. } = memory;
            req
        };

        match req.try_recv() {
            Ok(cmd) => {
                tracing::trace!("MemoryReq recv {cmd:x?}");
                Some(cmd)
            }
            Err(err) => match &err {
                ipc::TryRecvError::IpcError(kind) => match kind {
                    ipc::IpcError::Disconnected => {
                        self.ipc_reset();
                        None
                    }
                    _ => panic!("Encounter Ipc error {err:?}"),
                },
                ipc::TryRecvError::Empty => None,
            },
        }
    }

    /// Send memory ack
    pub fn memory_ack(&mut self, ack: MemoryAck) {
        let ack_tx = {
            let IpcSim { memory, .. } = &self.ipc;
            let MemorySim { ack, .. } = memory;
            ack
        };

        // Silently drop error
        let _ = ack_tx.send(ack);
    }
}
