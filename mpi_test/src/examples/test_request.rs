use crate::context::Context;
use crate::managers::{advance_receiving, Receiving, Sending};
use mpi::traits::*;

impl Context {
    pub fn test_request(&self) {
        let tag = 1;

        if self.is_root {
            let process = self.world.process_at_rank(1);

            for i in 0..3 {
                let Sending {
                    len: _,
                    buffer: _,
                    size,
                    a,
                } = Sending::new(vec![1, 2, i], &process, tag);
                size.unwrap().wait();
                a.unwrap().wait();
            }
        } else {
            let process = self.world.process_at_rank(0);

            let mut receive = Some(Receiving::new(&process, tag));

            for _ in 0..3 {
                let buffer = loop {
                    if let Some(buffer) = advance_receiving(&mut receive, &process, tag) {
                        break buffer;
                    }
                };

                dbg!(buffer);
            }
            receive.unwrap().abort();
        }
    }
}
