use crate::async_graph::Node;
use crate::context::Context;
use petgraph::Graph;
use std::sync::Arc;
use tfhe::shortint::gen_keys;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

impl Context {
    pub fn async_small_graph(&self) {
        if self.is_root {
            let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

            let mut graph = Graph::new();

            let encrypted = cks.unchecked_encrypt(1);

            let f = |x| (x + 1) % 16;
            let g = |x| (x + 2) % 16;

            let node1 = graph.add_node(Node::Computed(encrypted));
            let node2 = graph.add_node(Node::ToCompute {
                lookup_table: sks.generate_lookup_table(f),
            });

            let node3 = graph.add_node(Node::ToCompute {
                lookup_table: sks.generate_lookup_table(g),
            });

            graph.add_edge(node1, node2, 1);

            graph.add_edge(node2, node3, 1);
            graph.add_edge(node1, node3, 2);

            let sks = Arc::new(sks);

            let (graph, duration) = self.async_pbs_graph_queue_master1(sks, graph);

            let _duration_sec = duration.as_secs_f32();

            // println!("{N} PBS in {}s", duration_sec);
            // println!("{} ms/PBS", duration_sec * 1000. / N as f32);

            let node = graph.node_weight(node3).unwrap();

            let ct = match node {
                Node::Computed(ct) => ct,
                _ => unreachable!(),
            };

            assert_eq!(cks.decrypt_message_and_carry(ct), g(2 + f(1)));

            println!("All good 5");
        } else {
            self.async_pbs_graph_queue_worker1();
        }
    }
}
