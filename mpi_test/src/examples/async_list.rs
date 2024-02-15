use crate::async_::TaskGraph;
use crate::context::Context;
use crate::managers::IndexedCt;
use crate::N;
use mpi::traits::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::server_key::LookupTableOwned;
use tfhe::shortint::{gen_keys, Ciphertext, ServerKey};

struct ListOfPbs {
    pub inputs: Vec<Ciphertext>,
    pub outputs: HashMap<usize, Ciphertext>,
}

impl ListOfPbs {
    fn new(inputs: Vec<Ciphertext>) -> Self {
        Self {
            inputs,
            outputs: HashMap::new(),
        }
    }
}

impl TaskGraph for ListOfPbs {
    type Task = IndexedCt;

    type Result = IndexedCt;

    fn init(&mut self) -> Vec<IndexedCt> {
        self.inputs
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, ct)| IndexedCt { index: i, ct })
            .collect()
    }

    fn commit_result(&mut self, result: IndexedCt) -> Vec<IndexedCt> {
        self.outputs.insert(result.index, result.ct);

        vec![]
    }

    fn is_finished(&self) -> bool {
        self.outputs.len() == self.inputs.len()
    }
}

impl Context {
    pub fn async_pbs_list_queue(&self) {
        if self.is_root {
            let root_process = self.world.process_at_rank(self.root_rank);

            let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

            let mut sks_serialized = bincode::serialize(&sks).unwrap();
            let mut sks_serialized_len = sks_serialized.len();

            let sks = Arc::new(sks);

            root_process.broadcast_into(&mut sks_serialized_len);

            root_process.broadcast_into(&mut sks_serialized);

            let lookup_table = Arc::new(sks.generate_lookup_table(|x| (x + 1) % 16));

            let inputs: Vec<_> = (0..N).map(|i| cks.unchecked_encrypt(i % 16)).collect();

            let start = Instant::now();
            let mut a = ListOfPbs::new(inputs);
            self.async_pbs_graph_queue_master(
                &mut a,
                (sks, lookup_table),
                |(sks, lookup_table), input| run_pbs(input, sks, lookup_table),
            );

            let duration = start.elapsed();

            let duration_sec = duration.as_secs_f32();

            println!("{N} PBS in {}s", duration_sec);
            println!("{} ms/PBS", duration_sec * 1000. / N as f32);

            for (i, ct) in a.outputs.iter() {
                assert_eq!(cks.decrypt_message_and_carry(ct), (*i as u64 + 1) % 16);
            }

            println!("All good 3");
        } else {
            let root_process = self.world.process_at_rank(self.root_rank);

            let mut sks_serialized_len = 0;

            root_process.broadcast_into(&mut sks_serialized_len);

            let mut sks_serialized = vec![0; sks_serialized_len];

            root_process.broadcast_into(&mut sks_serialized);

            let sks: Arc<ServerKey> = Arc::new(bincode::deserialize(&sks_serialized).unwrap());

            let lookup_table = Arc::new(sks.generate_lookup_table(|x| (x + 1) % 16));

            self.async_pbs_graph_queue_worker((sks, lookup_table), |(sks, lookup_table), input| {
                run_pbs(input, sks, lookup_table)
            });
        }
    }
}

fn run_pbs(input: &IndexedCt, sks: &ServerKey, lookup_table: &LookupTableOwned) -> IndexedCt {
    IndexedCt {
        ct: sks.apply_lookup_table(&input.ct, lookup_table),
        index: input.index,
    }
}
