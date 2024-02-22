use mpi::request::Request;
use mpi::topology::Process;
use mpi::traits::*;
use mpi::Tag;
use serde::{Deserialize, Serialize};
use std::mem::transmute;
use tfhe::shortint::Ciphertext;

const MAX_SIZE: usize = 100_000;

pub struct Receiving {
    buffer: Vec<u8>,
    future: Request<'static, [u8]>,
}

// impl Drop for Receiving {
//     fn drop(&mut self) {
//         panic!("Here")
//     }
// }

impl Receiving {
    pub fn new(process: &Process, tag: Tag) -> Self {
        let mut buffer = vec![0; MAX_SIZE];

        let future = process
            .immediate_receive_into_with_tag(unsafe { transmute(buffer.as_mut_slice()) }, tag);

        Self { buffer, future }
    }

    pub fn abort(self) {
        std::mem::forget(self.future);
    }
}

pub fn advance_receiving(
    receiving: &mut Option<Receiving>,
    process: &Process,
    tag: Tag,
) -> Option<Vec<u8>> {
    let mut opt_buffer = None;

    let receiver = receiving.take().unwrap();

    let new = match receiver.future.test() {
        Ok(_status) => {
            opt_buffer = Some(receiver.buffer);

            Receiving::new(process, tag)
        }
        Err(a) => Receiving {
            buffer: receiver.buffer,
            future: a,
        },
    };

    *receiving = Some(new);

    opt_buffer
}

pub struct Sending {
    pub buffer: Vec<u8>,
    pub a: Option<Request<'static, [u8]>>,
}

impl Sending {
    pub fn new(buffer: Vec<u8>, process: &Process, tag: Tag) -> Self {
        assert!(buffer.len() < MAX_SIZE);

        let a = Some(process.immediate_send_with_tag(unsafe { transmute(buffer.as_slice()) }, tag));

        Self { buffer, a }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IndexedCt {
    pub index: usize,
    pub ct: Ciphertext,
}
