use crate::async_::TaskGraph;
use crate::context::Context;
use mpi::traits::*;
use petgraph::algo::is_cyclic_directed;
use petgraph::stable_graph::NodeIndex;
use petgraph::Direction::{Incoming, Outgoing};
use petgraph::Graph;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tfhe::shortint::server_key::LookupTableOwned;
use tfhe::shortint::{self, Ciphertext, ServerKey};

#[derive(Clone, Serialize, Deserialize)]
pub struct IndexedCt {
    index: usize,
    ct: Ciphertext,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IndexedCtAndLut {
    index: usize,
    ct: Ciphertext,
    lut: LookupTableOwned,
}

pub enum Node {
    Computed(shortint::Ciphertext),
    BootsrapQueued,
    ToCompute { lookup_table: LookupTableOwned },
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
    graph: Graph<Node, u64>,
    not_computed_nodes_count: usize,
    sks: Arc<ServerKey>,
}

impl FheGraph {
    pub fn new(graph: Graph<Node, u64>, sks: Arc<ServerKey>) -> Self {
        let not_computed_nodes_count = graph
            .node_weights()
            .filter(|node| !matches!(&node, Node::Computed(_)))
            .count();

        dbg!(not_computed_nodes_count);

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
                    Some(Node::Computed(_))
                ))
            } else {
                assert!(matches!(
                    &self.graph.node_weight(i),
                    Some(Node::ToCompute { .. })
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
                    Some(Node::Computed(_))
                ))
            }
        }
    }

    fn compute_multisum(&self, index: NodeIndex, sks: &ServerKey) -> Ciphertext {
        let mut iterator = self.graph.neighbors_directed(index, Incoming);

        let first_predecessor_index = iterator.next().unwrap();
        let first_predecessor = self.graph[first_predecessor_index].ct().unwrap();

        let first_scalar = self.graph[self
            .graph
            .find_edge(first_predecessor_index, index)
            .unwrap()];

        let mut multisum_result = sks.unchecked_scalar_mul(first_predecessor, first_scalar as u8);

        for predecessor_index in iterator {
            let scalar = self.graph[self.graph.find_edge(predecessor_index, index).unwrap()];

            let ct = self.graph[predecessor_index].ct().unwrap();

            sks.unchecked_add_scalar_mul_assign(&mut multisum_result, ct, scalar as u8);
        }
        multisum_result
    }

    fn multisum_and_build_task(&mut self, index: NodeIndex) -> IndexedCtAndLut {
        let multisum_result = self.compute_multisum(index, &self.sks);

        let lut = match self.graph.node_weight(index) {
            Some(Node::ToCompute { lookup_table }) => lookup_table.to_owned(),
            _ => unreachable!(),
        };

        *self.graph.node_weight_mut(index).unwrap() = Node::BootsrapQueued;

        IndexedCtAndLut {
            index: index.index(),
            ct: multisum_result,
            lut,
        }
    }
}

impl TaskGraph for FheGraph {
    type Task = IndexedCtAndLut;

    type Result = IndexedCt;

    fn init(&mut self) -> Vec<IndexedCtAndLut> {
        self.test_graph_init();

        let nodes_to_compute: Vec<_> = self
            .graph
            .node_indices()
            .filter(|&i| {
                let to_compute =
                    matches!(self.graph.node_weight(i).unwrap(), Node::ToCompute { .. });

                let all_predecessors_computed =
                    self.graph
                        .neighbors_directed(i, Incoming)
                        .all(|predecessor| {
                            matches!(
                                self.graph.node_weight(predecessor).unwrap(),
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

    fn commit_result(&mut self, result: IndexedCt) -> Vec<IndexedCtAndLut> {
        self.not_computed_nodes_count -= 1;

        // dbg!(self.not_computed_nodes_count);

        let IndexedCt { index, ct } = result;

        let index = NodeIndex::new(index);

        let node_mut = self.graph.node_weight_mut(index).unwrap();

        assert!(matches!(node_mut, Node::BootsrapQueued));
        *node_mut = Node::Computed(ct);

        let nodes_to_compute: Vec<_> = self
            .graph
            .neighbors_directed(index, Outgoing)
            .filter(|&i| {
                assert!(matches!(
                    self.graph.node_weight(i).unwrap(),
                    Node::ToCompute { .. }
                ));

                let all_predecessors_computed =
                    self.graph
                        .neighbors_directed(i, Incoming)
                        .all(|predecessor| {
                            matches!(
                                self.graph.node_weight(predecessor).unwrap(),
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
        let root_process = self.world.process_at_rank(self.root_rank);

        let mut sks_serialized = bincode::serialize(sks.as_ref()).unwrap();
        let mut sks_serialized_len = sks_serialized.len();

        let mut graph = FheGraph::new(graph, sks.clone());

        graph.assert_finishable();

        root_process.broadcast_into(&mut sks_serialized_len);

        root_process.broadcast_into(sks_serialized.as_mut_slice());

        let start = Instant::now();

        self.async_pbs_graph_queue_master(&mut graph, sks, move |sks, input| run_pbs(input, sks));

        let duration = start.elapsed();

        (graph.graph, duration)
    }
    pub fn async_pbs_graph_queue_worker1(&self) {
        let root_process = self.world.process_at_rank(self.root_rank);

        let mut sks_serialized_len = 0;

        root_process.broadcast_into(&mut sks_serialized_len);

        let mut sks_serialized = vec![0; sks_serialized_len];

        root_process.broadcast_into(&mut sks_serialized);

        let sks: Arc<ServerKey> = Arc::new(bincode::deserialize(&sks_serialized).unwrap());

        self.async_pbs_graph_queue_worker(sks, |sks, input| run_pbs(input, sks));

        panic!()
    }
}

fn run_pbs(input: &IndexedCtAndLut, sks: &ServerKey) -> IndexedCt {
    IndexedCt {
        ct: sks.apply_lookup_table(&input.ct, &input.lut),
        index: input.index,
    }
}
