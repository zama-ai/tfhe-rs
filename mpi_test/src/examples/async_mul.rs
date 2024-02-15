use crate::async_graph::Node;
use crate::context::Context;
use core::panic;
use itertools::zip_eq;
// use petgraph::dot::{Config, Dot};
use petgraph::prelude::NodeIndex;
use petgraph::Graph;
use std::sync::Arc;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::{gen_keys, ServerKey};

impl Context {
    pub fn async_mul(&self, num_blocks: i32) {
        if self.is_root {
            let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

            let sks = Arc::new(sks);

            let mut graph = Graph::new();
            let mut expected_outputs = vec![];

            let cut_into_block = |number| {
                let mut number = number;
                (0..num_blocks)
                    .map(|_| {
                        let new = number % 4;
                        number /= 4;
                        new
                    })
                    .collect::<Vec<_>>()
            };

            let cut_into_nodes = |graph: &mut Graph<Node, u64>, number: u64| {
                cut_into_block(number)
                    .into_iter()
                    .map(|block| graph.add_node(Node::Computed(cks.unchecked_encrypt(block))))
                    .collect::<Vec<_>>()
            };

            let i = 24533;
            let j = 53864;

            let in1 = cut_into_nodes(&mut graph, i);
            let in2 = cut_into_nodes(&mut graph, j);

            let result = mul_graph(&mut graph, &sks, &in1, &in2);

            for (i, j) in zip_eq(&result, cut_into_block(i.wrapping_mul(j))) {
                expected_outputs.push((*i, j));
            }

            // println!("{:?}", Dot::with_config(&graph, &[Config::NodeNoLabel]));

            let (graph, duration) = self.async_pbs_graph_queue_master1(sks.clone(), graph);

            let duration_sec = duration.as_secs_f32();

            // for (i, node_index) in result.iter().enumerate() {
            //     let node = graph.node_weight(*node_index).unwrap();

            //     let ct = match node {
            //         Node::Computed(ct) => ct,
            //         _ => unreachable!(),
            //     };

            //     dbg!(i, cks.decrypt_message_and_carry(ct));
            // }

            for (node_index, expected_decryption) in expected_outputs {
                let node = graph.node_weight(node_index).unwrap();

                let ct = match node {
                    Node::Computed(ct) => ct,
                    _ => unreachable!(),
                };

                // dbg!(cks.decrypt_message_and_carry(ct), expected_decryption);
                assert_eq!(cks.decrypt_message_and_carry(ct), expected_decryption);
            }
            println!("All good 7");

            println!("MPI 64 block mul in {}s", duration_sec);

            panic!();
        } else {
            self.async_pbs_graph_queue_worker1();
        }
    }
}

pub fn mul_graph(
    graph: &mut Graph<Node, u64>,
    sks: &ServerKey,
    lhs: &[NodeIndex],
    rhs: &[NodeIndex],
) -> Vec<NodeIndex> {
    let mut terms_for_mul_low = compute_terms_for_mul_low(graph, sks, lhs, rhs);

    let mut result = vec![];

    for i in 0..(terms_for_mul_low.len() - 1) {
        let (low, high) = terms_for_mul_low.split_at_mut(i + 1);

        result.push(sum_blocks(graph, sks, &low[i], Some(&mut high[0])));
    }

    result.push(sum_blocks(
        graph,
        sks,
        terms_for_mul_low.last().unwrap(),
        None,
    ));

    result
}

fn compute_terms_for_mul_low(
    graph: &mut Graph<Node, u64>,
    sks: &ServerKey,
    lhs: &[NodeIndex],
    rhs: &[NodeIndex],
) -> Vec<Vec<NodeIndex>> {
    let message_modulus = sks.message_modulus.0 as u64;
    assert!(message_modulus <= sks.carry_modulus.0 as u64);

    let lsb_block_mul_lut = sks
        .generate_lookup_table_bivariate(|x, y| (x * y) % message_modulus)
        .acc;

    assert_eq!(rhs.len(), rhs.len());
    let len = rhs.len();

    let mut message_part_terms_generator = vec![vec![]; len];

    for (i, rhs_block) in rhs.iter().enumerate() {
        for (j, lhs_block) in lhs.iter().enumerate() {
            if (i + j) < len {
                let node = graph.add_node(Node::ToCompute {
                    lookup_table: lsb_block_mul_lut.clone(),
                });

                graph.add_edge(*lhs_block, node, 1);
                graph.add_edge(*rhs_block, node, message_modulus);

                message_part_terms_generator[i + j].push(node);
            } else {
                break;
            }
        }
    }

    if message_modulus > 2 {
        let msb_block_mul_lut = sks
            .generate_lookup_table_bivariate(|x, y| (x * y) / message_modulus)
            .acc;

        for (i, rhs_block) in rhs.iter().enumerate() {
            for (j, lhs_block) in lhs.iter().enumerate() {
                if (i + j + 1) < len {
                    let node = graph.add_node(Node::ToCompute {
                        lookup_table: msb_block_mul_lut.clone(),
                    });

                    graph.add_edge(*lhs_block, node, 1);
                    graph.add_edge(*rhs_block, node, message_modulus);

                    message_part_terms_generator[i + j + 1].push(node);
                } else {
                    break;
                }
            }
        }
    }

    message_part_terms_generator
}

fn sum_blocks(
    graph: &mut Graph<Node, u64>,
    sks: &ServerKey,
    blocks_ref: &[NodeIndex],
    mut carries: Option<&mut Vec<NodeIndex>>,
) -> NodeIndex {
    let mut blocks;

    let mut blocks_ref = blocks_ref;

    assert!(!blocks_ref.is_empty());

    let message_modulus = sks.message_modulus.0 as u64;

    // We don´t want a carry bigger than message_modulus
    let group_size = ((message_modulus * message_modulus - 1) / (message_modulus - 1)) as usize;

    loop {
        assert!(!blocks_ref.is_empty());
        if blocks_ref.len() == 1 {
            break blocks_ref[0];
        }

        if blocks_ref.len() <= group_size {
            break checked_add(graph, sks, blocks_ref, carries);
        }

        let number_groups = blocks_ref.len() / group_size;

        let mut sums: Vec<_> = (0..number_groups)
            .map(|i| {
                checked_add(
                    graph,
                    sks,
                    &blocks_ref[i * group_size..(i + 1) * group_size],
                    carries.as_deref_mut(),
                )
            })
            .collect();

        // May be better to do the way around?
        sums.extend_from_slice(&blocks_ref[number_groups * group_size..]);

        blocks = sums;

        blocks_ref = &blocks;
    }
}

fn checked_add(
    graph: &mut Graph<Node, u64>,
    sks: &ServerKey,
    blocks_ref: &[NodeIndex],
    mut carries: Option<&mut Vec<NodeIndex>>,
) -> NodeIndex {
    assert!(blocks_ref.len() > 1);

    let message_modulus = sks.message_modulus.0 as u64;

    let extract_message = sks.generate_lookup_table(|x| x % message_modulus);
    let extract_carry = sks.generate_lookup_table(|x| x / message_modulus);

    // We don´t want a carry bigger than message_modulus
    let group_size = (message_modulus * message_modulus - 1) / (message_modulus - 1);

    assert!(blocks_ref.len() <= group_size as usize);

    let sum = graph.add_node(Node::ToCompute {
        lookup_table: extract_message.clone(),
    });

    for i in blocks_ref {
        graph.add_edge(*i, sum, 1);
    }

    if let Some(carries) = carries.as_mut() {
        let new_carry = graph.add_node(Node::ToCompute {
            lookup_table: extract_carry.clone(),
        });

        for i in blocks_ref {
            graph.add_edge(*i, new_carry, 1);
        }

        carries.push(new_carry);
    }

    sum
}
