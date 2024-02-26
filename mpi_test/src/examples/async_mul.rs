use crate::async_pbs_graph::{Lut, Node};
use crate::context::Context;
use core::panic;
use itertools::{zip_eq, Itertools};
use petgraph::prelude::NodeIndex;
use petgraph::Graph;
use std::collections::BinaryHeap;
use std::sync::Arc;
use tfhe::core_crypto::commons::traits::UnsignedInteger;
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
                    .map(|block| {
                        graph.add_node(Node::Computed(Arc::new(cks.unchecked_encrypt(block))))
                    })
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

            println!("MPI {num_blocks} block mul in {}s", duration_sec);

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
    let len = lhs.len();

    assert_eq!(len, rhs.len());

    let mut terms_for_mul_low: Vec<BinaryHeap<NodeWithDepth>> =
        compute_terms_for_mul_low(graph, sks, lhs, rhs)
            .into_iter()
            .map(|a| {
                a.into_iter()
                    .map(|node| NodeWithDepth { node, depth: 0 })
                    .collect()
            })
            .collect();

    terms_for_mul_low.reverse();

    assert_eq!(len, terms_for_mul_low.len());

    let mut sum_messages = vec![];

    let mut sum_carries = vec![];

    let first_list = terms_for_mul_low.pop().unwrap();

    assert_eq!(first_list.len(), 1);
    let (first_message, first_carry) = sum_blocks(graph, sks, first_list, None);

    assert!(first_carry.is_none());

    for _ in 1..(len - 1) {
        let messages = terms_for_mul_low.pop().unwrap();

        let carries = terms_for_mul_low.last_mut();

        let (message, carry) = sum_blocks(graph, sks, messages, carries);

        sum_messages.push(message);
        sum_carries.push(carry.unwrap());
    }

    let (last_message, last_carry) = sum_blocks(graph, sks, terms_for_mul_low.pop().unwrap(), None);

    assert!(terms_for_mul_low.is_empty());

    sum_messages.push(last_message);

    assert!(last_carry.is_none());

    let mut result = vec![];

    result.push(first_message);

    result.push(sum_messages.remove(0));

    assert_eq!(sum_messages.len(), sum_carries.len());

    result.extend(&add_propagate_carry(
        graph,
        sks,
        &sum_messages,
        &sum_carries,
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

    assert_eq!(rhs.len(), rhs.len());
    let len = rhs.len();

    let mut message_part_terms_generator = vec![vec![]; len];

    for (i, rhs_block) in rhs.iter().enumerate() {
        for (j, lhs_block) in lhs.iter().enumerate() {
            if (i + j) < len {
                let node = graph.add_node(Node::ToCompute {
                    lookup_table: Lut::BivarMulLow,
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
        for (i, rhs_block) in rhs.iter().enumerate() {
            for (j, lhs_block) in lhs.iter().enumerate() {
                if (i + j + 1) < len {
                    let node = graph.add_node(Node::ToCompute {
                        lookup_table: Lut::BivarMulHigh,
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

struct NodeWithDepth {
    node: NodeIndex,
    depth: u32,
}

impl PartialEq for NodeWithDepth {
    fn eq(&self, other: &Self) -> bool {
        self.depth == other.depth
    }
}

impl Eq for NodeWithDepth {}

impl PartialOrd for NodeWithDepth {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeWithDepth {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.depth.cmp(&self.depth)
    }
}

fn sum_blocks(
    graph: &mut Graph<Node, u64>,
    sks: &ServerKey,
    mut messages: BinaryHeap<NodeWithDepth>,
    mut carries: Option<&mut BinaryHeap<NodeWithDepth>>,
) -> (NodeIndex, Option<NodeIndex>) {
    assert!(!messages.is_empty());

    let message_modulus = sks.message_modulus.0 as u64;

    // We don´t want a carry bigger than message_modulus
    let group_size = ((message_modulus * message_modulus - 1) / (message_modulus - 1)) as usize;

    if messages.len() == 1 {
        return (messages.pop().unwrap().node, None);
    }

    while messages.len() > group_size {
        let mut adding = vec![];

        let mut max_depth = 0;

        let len_next_iteration = messages.len() - group_size + 1;

        let to_add_now = if len_next_iteration < group_size {
            len_next_iteration
        } else {
            group_size
        };

        for _ in 0..to_add_now {
            let NodeWithDepth { node, depth } = messages.pop().unwrap();

            if depth > max_depth {
                max_depth = depth;
            }
            adding.push(node);
        }

        if let Some(carries) = &mut carries {
            let (sum, carry) = checked_add(graph, sks, &adding, true);

            messages.push(NodeWithDepth {
                node: sum,
                depth: max_depth,
            });

            carries.push(NodeWithDepth {
                node: carry.unwrap(),
                depth: max_depth,
            });
        } else {
            let (sum, carry) = checked_add(graph, sks, &adding, false);

            messages.push(NodeWithDepth {
                node: sum,
                depth: max_depth,
            });

            assert!(carry.is_none());
        }
    }

    assert!(messages.len() > 1);
    assert!(messages.len() <= group_size);

    let mut adding = vec![];

    while let Some(NodeWithDepth { node, .. }) = messages.pop() {
        adding.push(node);
    }

    if carries.is_some() {
        checked_add(graph, sks, &adding, true)
    } else {
        checked_add(graph, sks, &adding, false)
    }
}

fn checked_add(
    graph: &mut Graph<Node, u64>,
    sks: &ServerKey,
    blocks_ref: &[NodeIndex],
    build_carry: bool,
) -> (NodeIndex, Option<NodeIndex>) {
    assert!(blocks_ref.len() > 1);

    let message_modulus = sks.message_modulus.0 as u64;

    // We don´t want a carry bigger than message_modulus
    let group_size = (message_modulus * message_modulus - 1) / (message_modulus - 1);

    assert!(blocks_ref.len() <= group_size as usize);

    let sum = graph.add_node(Node::ToCompute {
        lookup_table: Lut::ExtractMessage,
    });

    for i in blocks_ref {
        graph.add_edge(*i, sum, 1);
    }

    let carry = if build_carry {
        let new_carry = graph.add_node(Node::ToCompute {
            lookup_table: Lut::ExtractCarry,
        });

        for i in blocks_ref {
            graph.add_edge(*i, new_carry, 1);
        }

        Some(new_carry)
    } else {
        None
    };

    (sum, carry)
}

fn add_propagate_carry(
    graph: &mut Graph<Node, u64>,
    sks: &ServerKey,
    ct1: &[NodeIndex],
    ct2: &[NodeIndex],
) -> Vec<NodeIndex> {
    let generates_or_propagates = generate_init_carry_array(graph, ct1, ct2);

    let (input_carries, _output_carry) =
        compute_carry_propagation_parallelized_low_latency(graph, sks, generates_or_propagates);

    (0..ct1.len())
        .map(|i| {
            let node = graph.add_node(Node::ToCompute {
                lookup_table: Lut::ExtractMessage,
            });

            graph.add_edge(ct1[i], node, 1);
            graph.add_edge(ct2[i], node, 1);
            if i > 0 {
                graph.add_edge(input_carries[i - 1], node, 1);
            }
            node
        })
        .collect()
}

fn compute_carry_propagation_parallelized_low_latency(
    graph: &mut Graph<Node, u64>,
    sks: &ServerKey,
    generates_or_propagates: Vec<NodeIndex>,
) -> (Vec<NodeIndex>, NodeIndex) {
    let modulus = sks.message_modulus.0 as u64;

    // Type annotations are required, otherwise we get confusing errors
    // "implementation of `FnOnce` is not general enough"
    let sum_function =
        |graph: &mut Graph<Node, u64>, block_carry: NodeIndex, previous_block_carry: NodeIndex| {
            let node = graph.add_node(Node::ToCompute {
                lookup_table: Lut::PrefixSumCarryPropagation,
            });

            graph.add_edge(block_carry, node, modulus);

            graph.add_edge(previous_block_carry, node, 1);

            node
        };

    let mut carries_out =
        compute_prefix_sum_hillis_steele(graph, sks, generates_or_propagates, sum_function);

    let last_block_out_carry = carries_out.pop().unwrap();
    (carries_out, last_block_out_carry)
}

fn generate_init_carry_array(
    graph: &mut Graph<Node, u64>,
    ct1: &[NodeIndex],
    ct2: &[NodeIndex],
) -> Vec<NodeIndex> {
    let generates_or_propagates: Vec<_> = ct1
        .iter()
        .zip_eq(ct2.iter())
        .enumerate()
        .map(|(i, (block1, block2))| {
            let lookup_table = if i == 0 {
                // The first block can only output a carry
                Lut::DoesBlockGenerateCarry
            } else {
                Lut::DoesBlockGenerateOrPropagate
            };

            let node = graph.add_node(Node::ToCompute { lookup_table });

            graph.add_edge(*block1, node, 1);
            graph.add_edge(*block2, node, 1);

            node
        })
        .collect();

    generates_or_propagates
}

pub(crate) fn compute_prefix_sum_hillis_steele<F>(
    graph: &mut Graph<Node, u64>,
    sks: &ServerKey,
    mut generates_or_propagates: Vec<NodeIndex>,
    sum_function: F,
) -> Vec<NodeIndex>
where
    F: for<'a> Fn(&'a mut Graph<Node, u64>, NodeIndex, NodeIndex) -> NodeIndex + Sync,
{
    debug_assert!(sks.message_modulus.0 * sks.carry_modulus.0 >= (1 << 4));

    let num_blocks = generates_or_propagates.len();
    let num_steps = generates_or_propagates.len().ceil_ilog2() as usize;

    let mut space = 1;
    let mut step_output = generates_or_propagates.clone();
    for _ in 0..num_steps {
        for (i, block) in step_output[space..num_blocks].iter_mut().enumerate() {
            let prev_block_carry = generates_or_propagates[i];
            *block = sum_function(graph, *block, prev_block_carry);
        }
        for i in space..num_blocks {
            generates_or_propagates[i].clone_from(&step_output[i]);
        }

        space *= 2;
    }

    generates_or_propagates
}

#[repr(u64)]
#[derive(PartialEq, Eq)]
pub enum OutputCarry {
    /// The block does not generate nor propagate a carry
    None = 0,
    /// The block generates a carry
    Generated = 1,
    /// The block will propagate a carry if it ever
    /// receives one
    Propagated = 2,
}

pub fn prefix_sum_carry_propagation(msb: u64, lsb: u64) -> u64 {
    if msb == OutputCarry::Propagated as u64 {
        lsb
    } else {
        msb
    }
}
