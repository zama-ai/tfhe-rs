use mpi::point_to_point::ReceiveFuture;
use mpi::request::Request;
use mpi::topology::Process;
use mpi::traits::*;
use mpi::Tag;
use serde::{Deserialize, Serialize};
use std::mem::transmute;
use tfhe::shortint::Ciphertext;

pub enum Receiving {
    Start {
        size: ReceiveFuture<usize>,
    },
    Buffer {
        buffer: Vec<u8>,
        a: Request<'static, [u8]>,
    },
}

// impl Drop for Receiving {
//     fn drop(&mut self) {
//         panic!("Here")
//     }
// }

impl Receiving {
    pub fn new(process: &Process, tag: Tag) -> Self {
        Receiving::Start {
            size: process.immediate_receive_with_tag::<usize>(tag),
        }
    }

    pub fn abort(self) {
        match self {
            Receiving::Start { size } => {
                std::mem::forget(size);
            }
            Receiving::Buffer { .. } => panic!("Already received something"),
        }
    }
}

pub fn advance_receiving(
    receiving: &mut Option<Receiving>,
    process: &Process,
    tag: Tag,
) -> Option<Vec<u8>> {
    let mut opt_buffer = None;

    let a = receiving.take().unwrap();

    let new = match a {
        Receiving::Start { size } => match size.r#try() {
            Ok((size, _)) => {
                let mut buffer = vec![0; size];

                let a = process.immediate_receive_into(unsafe { transmute(buffer.as_mut_slice()) });

                Receiving::Buffer { buffer, a }
            }
            Err(size) => Receiving::Start { size },
        },
        Receiving::Buffer { buffer, a } => match a.test() {
            Ok(_status) => {
                opt_buffer = Some(buffer);

                Receiving::new(process, tag)
            }
            Err(a) => Receiving::Buffer { buffer, a },
        },
    };

    *receiving = Some(new);

    opt_buffer
}

pub struct Sending {
    pub len: Box<usize>,
    pub buffer: Vec<u8>,
    pub size: Option<Request<'static, usize>>,
    pub a: Option<Request<'static, [u8]>>,
}

impl Sending {
    pub fn new(buffer: Vec<u8>, process: &Process, tag: Tag) -> Self {
        let len = Box::new(buffer.len());
        let size = Some(process.immediate_send_with_tag(unsafe { transmute(len.as_ref()) }, tag));

        let a = Some(process.immediate_send_with_tag(unsafe { transmute(buffer.as_slice()) }, tag));

        Self {
            buffer,
            size,
            a,
            len,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IndexedCt {
    pub index: usize,
    pub ct: Ciphertext,
}
