use crate::async_graph::Node;
use crate::context::Context;
use crate::N;
use petgraph::Graph;
use std::sync::Arc;
use tfhe::shortint::gen_keys;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

impl Context {
    pub fn async_flat_graph(&self) {
        if self.is_root {
            let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

            let mut graph = Graph::new();

            let mut expected_outputs = vec![];

            for i in 0..N {
                let plain = i % 16;

                let encrypted = cks.unchecked_encrypt(plain);

                let f = |x| x + 2;

                let lookup_table = sks.generate_lookup_table(f);

                // dbg!(cks.decrypt_message_and_carry(&sks.apply_lookup_table(&encrypted,
                // &lookup_table)));

                let input = graph.add_node(Node::Computed(encrypted));
                let output = graph.add_node(Node::ToCompute {
                    lookup_table: lookup_table.clone(),
                });

                graph.add_edge(input, output, 1);

                expected_outputs.push((output, f(plain)));
            }

            let sks = Arc::new(sks);

            let (graph, duration) = self.async_pbs_graph_queue_master1(sks, graph);

            let duration_sec = duration.as_secs_f32();

            println!("{N} PBS in {}s", duration_sec);
            println!("{} ms/PBS", duration_sec * 1000. / N as f32);

            for (node_index, expected_decryption) in expected_outputs {
                let node = graph.node_weight(node_index).unwrap();

                let ct = match node {
                    Node::Computed(ct) => ct,
                    _ => unreachable!(),
                };

                assert_eq!(cks.decrypt_message_and_carry(ct), expected_decryption);
            }

            println!("All good 4");
        } else {
            self.async_pbs_graph_queue_worker1();
        }
    }
}
