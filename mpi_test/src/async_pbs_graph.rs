use crate::async_task_graph::{Priority, TaskGraph};
use crate::context::Context;
use crate::examples::async_mul::{prefix_sum_carry_propagation, OutputCarry};
use logging_timer::time;
use mpi::traits::*;
use petgraph::algo::is_cyclic_directed;
use petgraph::stable_graph::NodeIndex;
use petgraph::Direction::{Incoming, Outgoing};
use petgraph::Graph;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tfhe::shortint::server_key::LookupTableOwned;
use tfhe::shortint::{self, Ciphertext, ServerKey};

#[derive(Clone, Serialize, Deserialize)]
pub struct IndexedCt {
    index: usize,
    ct: Ciphertext,
}

#[derive(Copy, Clone, Serialize, Deserialize)]

pub enum Lut {
    ExtractMessage,
    ExtractCarry,
    BivarMulLow,
    BivarMulHigh,
    PrefixSumCarryPropagation,
    DoesBlockGenerateCarry,
    DoesBlockGenerateOrPropagate,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IndexedCtAndLut {
    index: usize,
    ct: Ciphertext,
    lut: Lut,
}

#[derive(Clone)]

pub enum Node {
    Computed(shortint::Ciphertext),
    BootsrapQueued,
    ToCompute { lookup_table: Lut },
}

impl Node {
    fn ct(&self) -> Option<&shortint::Ciphertext> {
        match self {
            Node::Computed(ct) => Some(ct),
            _ => None,
        }
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Computed(_) => f.debug_tuple("Computed").finish(),
            Self::BootsrapQueued => write!(f, "BootsrapQueued"),
            Self::ToCompute { .. } => f.debug_struct("ToCompute").finish(),
        }
    }
}

pub struct FheGraph {
    graph: Graph<(Priority, Node), u64>,
    not_computed_nodes_count: usize,
    sks: Arc<ServerKey>,
}

fn insert_predecessors_recursively(
    graph: &Graph<Node, u64>,
    successors_max_depths: &mut HashMap<usize, i32>,
    node_index: NodeIndex,
) {
    if successors_max_depths.contains_key(&node_index.index()) {
        return;
    }

    if graph
        .neighbors_directed(node_index, Outgoing)
        .all(|successor| successors_max_depths.contains_key(&successor.index()))
    {
        let max_successors_depth = graph
            .neighbors_directed(node_index, Outgoing)
            .map(|successor| successors_max_depths[&successor.index()])
            .max();

        successors_max_depths.insert(node_index.index(), max_successors_depth.unwrap_or(0) + 1);

        for predecessor in graph.neighbors_directed(node_index, Incoming) {
            insert_predecessors_recursively(graph, successors_max_depths, predecessor);
        }
    }
}

impl FheGraph {
    pub fn new(graph: Graph<Node, u64>, sks: Arc<ServerKey>) -> Self {
        let not_computed_nodes_count = graph
            .node_weights()
            .filter(|node| !matches!(&node, Node::Computed(_)))
            .count();

        let mut successors_max_depth = HashMap::new();

        for node_index in graph.node_indices() {
            if graph.edges_directed(node_index, Outgoing).next().is_none() {
                insert_predecessors_recursively(&graph, &mut successors_max_depth, node_index);
            }
        }

        dbg!(&successors_max_depth.values().max());

        let graph = graph.map(
            |node_index, node| {
                (
                    Priority(successors_max_depth[&node_index.index()]),
                    node.clone(),
                )
            },
            |_, edge| *edge,
        );

        Self {
            graph,
            not_computed_nodes_count,
            sks,
        }
    }
    fn test_graph_init(&self) {
        assert!(!is_cyclic_directed(&self.graph));

        for i in self.graph.node_indices() {
            if self.graph.neighbors_directed(i, Incoming).next().is_none() {
                assert!(matches!(
                    &self.graph.node_weight(i),
                    Some((_, Node::Computed(_)))
                ))
            } else {
                assert!(matches!(
                    &self.graph.node_weight(i),
                    Some((_, Node::ToCompute { .. }))
                ))
            }
        }
    }

    fn assert_finishable(&self) {
        assert!(!is_cyclic_directed(&self.graph));

        for i in self.graph.node_indices() {
            if self.graph.neighbors_directed(i, Incoming).next().is_none() {
                assert!(matches!(
                    &self.graph.node_weight(i),
                    Some((_, Node::Computed(_)))
                ))
            }
        }
    }

    #[time]
    fn compute_multisum(&self, index: NodeIndex, sks: &ServerKey) -> Ciphertext {
        let mut iterator = self.graph.edges_directed(index, Incoming);

        let first_predecessor_edge = iterator.next().unwrap();
        let first_predecessor = self.graph[first_predecessor_edge.source()].1.ct().unwrap();

        let first_scalar = *first_predecessor_edge.weight();

        let mut multisum_result = sks.unchecked_scalar_mul(first_predecessor, first_scalar as u8);

        for edge in iterator {
            let scalar = *edge.weight();

            let ct = self.graph[edge.source()].1.ct().unwrap();

            sks.unchecked_add_scalar_mul_assign(&mut multisum_result, ct, scalar as u8);
        }
        multisum_result
    }

    #[time]
    fn multisum_and_build_task(&mut self, index: NodeIndex) -> (Priority, IndexedCtAndLut) {
        let multisum_result = self.compute_multisum(index, &self.sks);

        let lut = match self.graph.node_weight(index) {
            Some((_, Node::ToCompute { lookup_table })) => lookup_table.to_owned(),
            _ => unreachable!(),
        };

        self.graph.node_weight_mut(index).unwrap().1 = Node::BootsrapQueued;

        (
            Priority(0),
            IndexedCtAndLut {
                index: index.index(),
                ct: multisum_result,
                lut,
            },
        )
    }
}

impl TaskGraph for FheGraph {
    type Task = IndexedCtAndLut;

    type Result = IndexedCt;

    #[time]
    fn init(&mut self) -> Vec<(Priority, IndexedCtAndLut)> {
        self.test_graph_init();

        let nodes_to_compute: Vec<_> = self
            .graph
            .node_indices()
            .filter(|&i| {
                let to_compute =
                    matches!(self.graph.node_weight(i).unwrap().1, Node::ToCompute { .. });

                let all_predecessors_computed =
                    self.graph
                        .neighbors_directed(i, Incoming)
                        .all(|predecessor| {
                            matches!(
                                self.graph.node_weight(predecessor).unwrap().1,
                                Node::Computed(_)
                            )
                        });

                to_compute && all_predecessors_computed
            })
            .collect();

        nodes_to_compute
            .into_iter()
            .map(|index| self.multisum_and_build_task(index))
            .collect()
    }

    #[time]
    fn commit_result(&mut self, result: IndexedCt) -> Vec<(Priority, IndexedCtAndLut)> {
        self.not_computed_nodes_count -= 1;

        // dbg!(self.not_computed_nodes_count);

        let IndexedCt { index, ct } = result;

        let index = NodeIndex::new(index);

        let node_mut = self.graph.node_weight_mut(index).unwrap();

        assert!(matches!(node_mut.1, Node::BootsrapQueued));
        node_mut.1 = Node::Computed(ct);

        let nodes_to_compute: Vec<_> = self
            .graph
            .neighbors_directed(index, Outgoing)
            .filter(|&i| {
                assert!(matches!(
                    self.graph.node_weight(i).unwrap().1,
                    Node::ToCompute { .. }
                ));

                let all_predecessors_computed =
                    self.graph
                        .neighbors_directed(i, Incoming)
                        .all(|predecessor| {
                            matches!(
                                self.graph.node_weight(predecessor).unwrap().1,
                                Node::Computed(_)
                            )
                        });

                all_predecessors_computed
            })
            .collect();

        nodes_to_compute
            .into_iter()
            .map(|index| self.multisum_and_build_task(index))
            .collect()
    }

    fn is_finished(&self) -> bool {
        self.not_computed_nodes_count == 0
    }
}

impl Context {
    pub fn async_pbs_graph_queue_master1(
        &self,
        sks: Arc<ServerKey>,
        graph: Graph<Node, u64>,
    ) -> (Graph<Node, u64>, Duration) {
        let luts = Luts::new(&sks);

        let root_process = self.world.process_at_rank(self.root_rank);

        let mut sks_serialized = bincode::serialize(sks.as_ref()).unwrap();
        let mut sks_serialized_len = sks_serialized.len();

        let mut graph = FheGraph::new(graph, sks.clone());

        graph.assert_finishable();

        root_process.broadcast_into(&mut sks_serialized_len);

        root_process.broadcast_into(sks_serialized.as_mut_slice());

        let start = Instant::now();

        self.async_task_graph_queue_master(&mut graph, (sks, luts), move |sks, input| {
            run_pbs(input, &sks.0, &sks.1)
        });

        let duration = start.elapsed();

        (
            graph.graph.map(|_, node| node.1.clone(), |_, edge| *edge),
            duration,
        )
    }
    pub fn async_pbs_graph_queue_worker1(&self) {
        let root_process = self.world.process_at_rank(self.root_rank);

        let mut sks_serialized_len = 0;

        root_process.broadcast_into(&mut sks_serialized_len);

        let mut sks_serialized = vec![0; sks_serialized_len];

        root_process.broadcast_into(&mut sks_serialized);

        let sks: Arc<ServerKey> = Arc::new(bincode::deserialize(&sks_serialized).unwrap());

        let luts = Luts::new(&sks);

        self.async_task_graph_queue_worker((sks, luts), |(sks, luts), input| {
            run_pbs(input, sks, luts)
        });

        panic!()
    }
}

fn run_pbs(input: &IndexedCtAndLut, sks: &ServerKey, luts: &Luts) -> IndexedCt {
    IndexedCt {
        ct: sks.apply_lookup_table(&input.ct, luts.get(input.lut)),
        index: input.index,
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Luts {
    extract_message: LookupTableOwned,
    extract_carry: LookupTableOwned,
    bivar_mul_low: LookupTableOwned,
    bivar_mul_high: LookupTableOwned,
    prefix_sum_carry_propagation: LookupTableOwned,
    does_block_generate_carry: LookupTableOwned,
    does_block_generate_or_propagate: LookupTableOwned,
}

impl Luts {
    fn new(sks: &ServerKey) -> Self {
        let message_modulus = sks.message_modulus.0 as u64;

        Self {
            extract_message: sks.generate_lookup_table(|x| x % message_modulus),
            extract_carry: sks.generate_lookup_table(|x| x / message_modulus),
            bivar_mul_low: sks
                .generate_lookup_table_bivariate(|x, y| (x * y) % message_modulus)
                .acc,
            bivar_mul_high: sks
                .generate_lookup_table_bivariate(|x, y| (x * y) / message_modulus)
                .acc,
            prefix_sum_carry_propagation: sks
                .generate_lookup_table_bivariate(prefix_sum_carry_propagation)
                .acc,
            does_block_generate_carry: sks.generate_lookup_table(|x| {
                if x >= message_modulus {
                    OutputCarry::Generated as u64
                } else {
                    OutputCarry::None as u64
                }
            }),
            does_block_generate_or_propagate: sks.generate_lookup_table(|x| {
                if x >= message_modulus {
                    OutputCarry::Generated as u64
                } else if x == (message_modulus - 1) {
                    OutputCarry::Propagated as u64
                } else {
                    OutputCarry::None as u64
                }
            }),
        }
    }

    fn get(&self, lut: Lut) -> &LookupTableOwned {
        match lut {
            Lut::ExtractMessage => &self.extract_message,
            Lut::ExtractCarry => &self.extract_carry,
            Lut::BivarMulLow => &self.bivar_mul_low,
            Lut::BivarMulHigh => &self.bivar_mul_high,
            Lut::PrefixSumCarryPropagation => &self.prefix_sum_carry_propagation,
            Lut::DoesBlockGenerateCarry => &self.does_block_generate_carry,
            Lut::DoesBlockGenerateOrPropagate => &self.does_block_generate_or_propagate,
        }
    }
}
