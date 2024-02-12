use crate::context::Context;
use crate::N;
use mpi::traits::*;
use std::time::Instant;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::{gen_keys, Ciphertext, ServerKey};

impl Context {
    pub fn async_pbs_batch(&self) {
        let root_process = self.world.process_at_rank(self.root_rank);

        let mut cks_opt = None;

        let mut sks_serialized = vec![];
        let mut sks_serialized_len = 0;

        if self.is_root {
            let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

            cks_opt = Some(cks);

            sks_serialized = bincode::serialize(&sks).unwrap();
            sks_serialized_len = sks_serialized.len();
        }

        root_process.broadcast_into(&mut sks_serialized_len);

        if sks_serialized.is_empty() {
            sks_serialized = vec![0; sks_serialized_len];
        }

        root_process.broadcast_into(&mut sks_serialized);

        let sks: ServerKey = bincode::deserialize(&sks_serialized).unwrap();

        let lookup_table = sks.generate_lookup_table(|x| (x + 1) % 16);

        if self.is_root {
            let cks = cks_opt.as_ref().unwrap();

            let mut inputs = vec![];

            for i in 0..N {
                let ct = cks.unchecked_encrypt(i % 16);

                inputs.push(ct);
            }

            let start = Instant::now();
            let elements_per_node = N as usize / self.size;

            let serialized: Vec<_> = (1..self.size)
                .map(|dest_rank| {
                    let inputs_chunk =
                        &inputs[elements_per_node * dest_rank..elements_per_node * (dest_rank + 1)];

                    bincode::serialize(inputs_chunk).unwrap()
                })
                .collect();

            let lens: Vec<_> = serialized.iter().map(|a| a.len()).collect();

            let sent_len: Vec<_> = lens
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    let dest_rank = i as i32 + 1;
                    let process = self.world.process_at_rank(dest_rank);

                    process.immediate_send(a)
                })
                .collect();

            let sent_vec: Vec<_> = serialized
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    let dest_rank = i as i32 + 1;
                    let process = self.world.process_at_rank(dest_rank);

                    process.immediate_send(a)
                })
                .collect();

            for i in sent_len {
                i.wait();
            }

            for i in sent_vec {
                i.wait();
            }

            let mut outputs: Vec<_> = inputs[0..elements_per_node]
                .iter()
                .map(|ct| sks.apply_lookup_table(ct, &lookup_table))
                .collect();

            let lens: Vec<_> = (1..self.size)
                .map(|dest_rank| {
                    let process = self.world.process_at_rank(dest_rank as i32);
                    process.immediate_receive()
                })
                .collect();

            let mut results: Vec<Vec<u8>> =
                lens.into_iter().map(|len| vec![0; len.get().0]).collect();

            let sent: Vec<_> = results
                .iter_mut()
                .enumerate()
                .map(|(i, a)| {
                    let dest_rank = i as i32 + 1;
                    let process = self.world.process_at_rank(dest_rank);

                    process.immediate_receive_into(a)
                })
                .collect();

            for i in sent {
                i.wait();
            }

            for result in results.iter() {
                let outputs_chunk: Vec<Ciphertext> = bincode::deserialize(result).unwrap();

                outputs.extend(outputs_chunk);
            }

            let duration = start.elapsed();

            let duration_sec = duration.as_secs_f32();

            println!("{N} PBS in {}s", duration_sec);
            println!("{} ms/PBS", duration_sec * 1000. / N as f32);

            for (i, ct) in outputs.iter().enumerate() {
                assert_eq!(cks.decrypt_message_and_carry(ct), (i as u64 + 1) % 16);
            }

            println!("All good 2");
        } else {
            let (len, _) = root_process.receive();

            let mut input = vec![0; len];

            // let mut status;

            root_process.receive_into(input.as_mut_slice());

            let input: Vec<Ciphertext> = bincode::deserialize(&input).unwrap();

            let output: Vec<_> = input
                .iter()
                .map(|ct| sks.apply_lookup_table(ct, &lookup_table))
                .collect();

            let output = bincode::serialize(&output).unwrap();

            root_process.send(&output.len());

            root_process.send(&output);
        }
    }

    pub fn test_mpi_immediate(&self) {
        let root_process = self.world.process_at_rank(self.root_rank);

        if self.is_root {
            let process = self.world.process_at_rank(1);

            let input = vec![1, 2, 3];

            let len = [input.len()];

            let a = process.immediate_send(&len);

            let b = process.immediate_send(input.as_slice());

            // drop(b);
            let b2 = process.immediate_send(input.as_slice());

            a.wait();
            b.wait();
            b2.wait();

            // let (outputs_chunks_serialized, _status) = process.receive_vec();
        } else if self.rank == 1 {
            let (len, _) = root_process.receive();

            let mut input = vec![0; len];

            // let mut status;

            let future = root_process.immediate_receive_into(input.as_mut_slice());

            future.wait();

            dbg!(input);
        }
    }
}
