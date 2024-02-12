use crate::async_graph::Node;
use crate::context::Context;
use core::panic;
use petgraph::Graph;
use std::sync::Arc;
use tfhe::shortint::gen_keys;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

impl Context {
    pub fn async_small_mul(&self) {
        if self.is_root {
            let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

            let sks = Arc::new(sks);

            let bivar_mul_lut = sks.generate_lookup_table_bivariate(|a, b| (a * b) % 4).acc;

            let mut graph = Graph::new();
            let mut expected_outputs = vec![];

            for j in 0..16 {
                for i in 0..16 {
                    let in1_low = graph.add_node(Node::Computed(cks.unchecked_encrypt(j % 4)));
                    let in1_high = graph.add_node(Node::Computed(cks.unchecked_encrypt(j / 4)));

                    let in2_low = graph.add_node(Node::Computed(cks.unchecked_encrypt(i % 4)));
                    let in2_high = graph.add_node(Node::Computed(cks.unchecked_encrypt(i / 4)));

                    let out_low = graph.add_node(Node::ToCompute {
                        lookup_table: bivar_mul_lut.clone(),
                    });

                    graph.add_edge(in1_low, out_low, 1);
                    graph.add_edge(in2_low, out_low, 4);

                    let out_high_0 = graph.add_node(Node::ToCompute {
                        lookup_table: //sks.generate_lookup_table(|a| (((a / 4) * (a % 4)) / 4) % 4),
                         sks.generate_lookup_table_bivariate(|a, b| ((a * b) / 4)%4).acc

                    });

                    graph.add_edge(in1_low, out_high_0, 1);
                    graph.add_edge(in2_low, out_high_0, 4);

                    let out_high_1 = graph.add_node(Node::ToCompute {
                        lookup_table: bivar_mul_lut.clone(),
                    });

                    graph.add_edge(in1_low, out_high_1, 1);
                    graph.add_edge(in2_high, out_high_1, 4);

                    let out_high_2 = graph.add_node(Node::ToCompute {
                        lookup_table: bivar_mul_lut.clone(),
                    });

                    graph.add_edge(in1_high, out_high_2, 1);
                    graph.add_edge(in2_low, out_high_2, 4);

                    let out_high = graph.add_node(Node::ToCompute {
                        lookup_table: sks.generate_lookup_table(|a| a % 4),
                    });

                    graph.add_edge(out_high_1, out_high, 1);
                    graph.add_edge(out_high_2, out_high, 1);
                    graph.add_edge(out_high_0, out_high, 1);

                    expected_outputs.push((out_low, (i * j) % 4));
                    expected_outputs.push((out_high, ((i * j) / 4) % 4));
                }
            }

            let (graph, duration) = self.async_pbs_graph_queue_master1(sks.clone(), graph);

            let _duration_sec = duration.as_secs_f32();

            for (node_index, expected_decryption) in expected_outputs {
                let node = graph.node_weight(node_index).unwrap();

                let ct = match node {
                    Node::Computed(ct) => ct,
                    _ => unreachable!(),
                };

                assert_eq!(cks.decrypt_message_and_carry(ct), expected_decryption);
            }
            println!("All good 6");
            panic!();
        } else {
            self.async_pbs_graph_queue_worker1();
        }
    }
}
