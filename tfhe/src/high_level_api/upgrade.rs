use crate::integer::compression_keys::DecompressionKey;
use crate::prelude::{CiphertextList, FheKeyswitch, Tagged};
use crate::shortint::parameters::CompressionParameters;
use crate::{
    ClientKey, CompressedCiphertextList, Device, HlExpandable, KeySwitchingKey, ServerKey, Tag,
};

/// Decompression key used to upgrade to some parameters while decompressing
pub struct DecompressionUpgradeKey {
    inner: DecompressionKey,
    tag_in: Tag,
    tag_out: Tag,
    out_device: Device,
}

impl DecompressionUpgradeKey {
    pub fn new(
        cks_in: &ClientKey,
        cks_out: &ClientKey,
        params: CompressionParameters,
        out_device: Device,
    ) -> crate::Result<Self> {
        let private_compression_key = cks_in
            .key
            .compression_key
            .as_ref()
            .ok_or_else(|| crate::error!("No compression key found"))?;

        let glwe_decompression_key = cks_out
            .key
            .key
            .key
            .new_decompression_key_with_params(&private_compression_key.key, params);

        Ok(Self {
            inner: DecompressionKey {
                key: glwe_decompression_key,
            },
            tag_in: cks_in.tag.clone(),
            tag_out: cks_out.tag.clone(),
            out_device,
        })
    }

    pub fn tag_in(&self) -> &Tag {
        &self.tag_in
    }

    pub fn tag_out(&self) -> &Tag {
        &self.tag_out
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CiphertextKind {
    Compressed,
    Compute,
}

/// Describes some keys
#[derive(Debug, PartialEq, Eq)]
pub struct KeyDescriptor {
    // The tag the key is associated with
    tag: Tag,
    // The kind of ciphertext the key is for
    kind: CiphertextKind,
    // The device meant for the key
    device: Device,
}

impl KeyDescriptor {
    pub fn new(tag: &Tag, kind: CiphertextKind, device: Device) -> Self {
        Self {
            tag: tag.clone(),
            kind,
            device,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Node(KeyDescriptor);

impl Node {
    fn new(tag: &Tag, kind: CiphertextKind, device: Device) -> Self {
        Self(KeyDescriptor {
            tag: tag.clone(),
            kind,
            device,
        })
    }
}

struct Edge {
    out_index: NodeId,
    data: usize,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct NodeId(usize);

#[derive(Default)]
struct UpgradeGraph {
    nodes: Vec<Node>,
    adjacency: Vec<Vec<Edge>>,
}

impl UpgradeGraph {
    fn index_of_node(&self, node: &Node) -> Option<NodeId> {
        self.nodes
            .iter()
            .position(|current_node| current_node == node)
            .map(NodeId)
    }

    fn get_or_insert_node(&mut self, node: Node) -> NodeId {
        self.index_of_node(&node)
            .unwrap_or_else(|| self.add_node(node))
    }

    fn add_node(&mut self, node: Node) -> NodeId {
        let node_id = self.nodes.len();
        self.nodes.push(node);
        self.adjacency.push(Vec::new());

        NodeId(node_id)
    }

    fn add_edge(&mut self, node_in: NodeId, node_out: NodeId, key_index: usize) {
        self.adjacency[node_in.0].push(Edge {
            out_index: node_out,
            data: key_index,
        });
    }

    fn find_upgrade_path(&self, source: NodeId, destination: NodeId) -> Option<Vec<usize>> {
        if source == destination {
            return Some(Vec::new());
        }

        if source.0 >= self.nodes.len() || destination.0 >= self.nodes.len() {
            return None;
        }

        let mut already_visited = vec![false; self.nodes.len()];
        already_visited[source.0] = true;

        let mut to_be_visited = vec![vec![source]];

        let mut path = Vec::new();
        'main: while !to_be_visited.is_empty() {
            if to_be_visited[to_be_visited.len() - 1].is_empty() {
                // We exhausted the search for this node
                to_be_visited.pop();

                if path.is_empty() {
                    return None;
                }
                path.pop().unwrap();
                continue;
            }

            path.push(to_be_visited.last_mut().unwrap().pop().unwrap());
            let current = path.last().unwrap();

            if self.adjacency[current.0].is_empty() {
                path.pop().unwrap();
            } else {
                let mut filtered_adjacency = Vec::with_capacity(self.adjacency[current.0].len());
                for vertex in self.adjacency[current.0].iter() {
                    if vertex.out_index == destination {
                        path.push(destination);
                        break 'main;
                    }

                    if !already_visited[vertex.out_index.0] {
                        already_visited[vertex.out_index.0] = true;
                        filtered_adjacency.push(vertex.out_index);
                    }
                }
                to_be_visited.push(filtered_adjacency)
            }
        }

        if path.last().unwrap() == &destination {
            let mut upgrade_path = Vec::with_capacity(path.len() - 1);
            let mut current_node = path[0];
            for next_node in path[1..].iter() {
                let vertex = self.adjacency[current_node.0]
                    .iter()
                    .find(|v| v.out_index == *next_node)
                    .unwrap();

                upgrade_path.push(vertex.data);
                current_node = vertex.out_index;
            }

            Some(upgrade_path)
        } else {
            None
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum UpgradeKey {
    Keyswitch(KeySwitchingKey),
    Decompress(DecompressionUpgradeKey),
}

impl UpgradeKey {
    fn input_cipher_kind(&self) -> CiphertextKind {
        match self {
            Self::Keyswitch(_) => CiphertextKind::Compute,
            Self::Decompress(_) => CiphertextKind::Compressed,
        }
    }

    fn tag_in(&self) -> &Tag {
        match self {
            Self::Keyswitch(k) => k.tag_in(),
            Self::Decompress(k) => k.tag_in(),
        }
    }

    fn tag_out(&self) -> &Tag {
        match self {
            Self::Keyswitch(k) => k.tag_out(),
            Self::Decompress(k) => k.tag_out(),
        }
    }

    fn out_device(&self) -> Device {
        match self {
            Self::Keyswitch(_) => Device::Cpu,
            Self::Decompress(k) => k.out_device,
        }
    }
}

impl From<KeySwitchingKey> for UpgradeKey {
    fn from(value: KeySwitchingKey) -> Self {
        Self::Keyswitch(value)
    }
}

impl From<DecompressionUpgradeKey> for UpgradeKey {
    fn from(value: DecompressionUpgradeKey) -> Self {
        Self::Decompress(value)
    }
}

/// This struct is meant to provide a mean to change
/// the parameters under which ciphertexts are encrypted in.
///
/// This is to help applications which will change parameters used
/// to keep good security or to be able to target new hardware and
/// still be able to easily load and update old ciphertexts (with old parameters).
/// Provided an upgrade path exists.
///
/// Parameters are identified by 3 components:
/// * The [Tag]
/// * The [Device]
/// * The [CiphertextKind]
///
/// To register parameters, add a key
/// * [Self::add_key_set]
/// * [Self::add_key_set_gpu]
///
/// Then upgrade keys that allow to go from one parameter set to another should
/// be added with [Self::add_upgrade_key]
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::shortint::parameters::{
///     COMP_PARAM_MESSAGE_2_CARRY_2, PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
///     PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
/// };
/// use tfhe::upgrade::UpgradeKeyChain;
/// use tfhe::{
///     set_server_key, ClientKey, ConfigBuilder, Device, FheUint32, KeySwitchingKey, ServerKey,
/// };
///
/// let compute_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
/// let compression_parameters = COMP_PARAM_MESSAGE_2_CARRY_2;
///
/// let config = ConfigBuilder::with_custom_parameters(compute_params)
///     .enable_compression(compression_parameters)
///     .build();
///
/// let mut ck1 = ClientKey::generate(config);
/// ck1.tag_mut().set_u64(1);
/// let sk1 = ServerKey::new(&ck1);
/// assert_eq!(sk1.tag().as_u64(), 1);
///
/// let mut ck2 = ClientKey::generate(config);
/// ck2.tag_mut().set_u64(2);
/// let sk2 = ServerKey::new(&ck2);
/// assert_eq!(sk2.tag().as_u64(), 2);
///
/// let ksk = KeySwitchingKey::with_parameters(
///     (&ck1, &sk1),
///     (&ck2, &sk2),
///     PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
/// );
///
/// let mut upgrader = UpgradeKeyChain::new();
/// upgrader.add_key_set(&sk1);
/// upgrader.add_key_set(&sk2);
/// upgrader.add_upgrade_key(ksk).unwrap();
///
/// let clear_a = 23428u32;
/// let clear_b = 985427u32;
///
/// let a = FheUint32::encrypt(clear_a, &ck1);
/// let b = FheUint32::encrypt(clear_b, &ck1);
///
/// let upgraded_a = upgrader.upgrade(&a, ck2.tag(), Device::Cpu).unwrap();
/// let upgraded_b = upgrader.upgrade(&b, ck2.tag(), Device::Cpu).unwrap();
///
/// set_server_key(sk2);
///
/// let c = upgraded_a + upgraded_b;
/// let dc: u32 = c.decrypt(&ck2);
/// assert_eq!(dc, clear_a.wrapping_add(clear_b));
/// ```
pub struct UpgradeKeyChain {
    graph: UpgradeGraph,
    upgrade_keys: Vec<UpgradeKey>,
}

impl Default for UpgradeKeyChain {
    fn default() -> Self {
        Self::new()
    }
}

impl UpgradeKeyChain {
    /// Creates a new and empty upgrader
    pub fn new() -> Self {
        Self {
            graph: UpgradeGraph::default(),
            upgrade_keys: Vec::default(),
        }
    }

    /// Adds the CPU server key into the upgrade system
    ///
    /// * It adds the compute parameters
    /// * It adds the compression parameters (if they exist)
    /// * It adds a path to go from compression parameters to compute parameters
    pub fn add_key_set(&mut self, sks: &ServerKey) {
        let node = Node::new(sks.tag(), CiphertextKind::Compute, Device::Cpu);
        let compute_node_id = self.graph.get_or_insert_node(node);

        if sks.key.compression_key.is_some() {
            let node = Node::new(sks.tag(), CiphertextKind::Compressed, Device::Cpu);
            let compressed_node_id = self.graph.get_or_insert_node(node);

            if let Some(decompression_key) = sks.key.decompression_key.as_ref() {
                self.graph
                    .add_edge(compressed_node_id, compute_node_id, self.upgrade_keys.len());
                self.upgrade_keys
                    .push(UpgradeKey::Decompress(DecompressionUpgradeKey {
                        inner: decompression_key.clone(),
                        tag_in: sks.tag.clone(),
                        tag_out: sks.tag.clone(),
                        out_device: Device::Cpu,
                    }))
            }
        }
    }

    /// Adds the GPU server key into the upgrade system
    ///
    /// * It adds the compute parameters
    /// * It adds the compression parameters (if they exist)
    #[cfg(feature = "gpu")]
    pub fn add_key_set_gpu(&mut self, sks: &crate::CudaServerKey) {
        let node = Node::new(sks.tag(), CiphertextKind::Compute, Device::CudaGpu);
        let _compute_node_id = self.graph.get_or_insert_node(node);

        if sks.key.compression_key.is_some() {
            let node = Node::new(sks.tag(), CiphertextKind::Compressed, Device::CudaGpu);
            let _compressed_node_id = self.graph.get_or_insert_node(node);
        }
    }

    /// Adds an upgrade key to the system
    ///
    /// There are 2 types of [UpgradeKey]
    ///
    /// * KeySwitchKey: to go from compute params to other compute params
    /// * Decompression: to go from compressed params to some compute params
    pub fn add_upgrade_key(&mut self, key: impl Into<UpgradeKey>) -> crate::Result<()> {
        let key = key.into();

        let node_in_idx = self
            .graph
            .index_of_node(&Node::new(
                key.tag_in(),
                key.input_cipher_kind(),
                Device::Cpu,
            ))
            .ok_or_else(|| {
                crate::error!("The input of this key does not match anything in the upgrade graph")
            })?;

        let node_out_idx = self
            .graph
            .index_of_node(&Node::new(
                key.tag_out(),
                CiphertextKind::Compute,
                key.out_device(),
            ))
            .ok_or_else(|| {
                crate::error!("The output of this key does not match anything in the upgrade graph")
            })?;

        self.graph
            .add_edge(node_in_idx, node_out_idx, self.upgrade_keys.len());
        self.upgrade_keys.push(key);

        Ok(())
    }

    /// Upgrades the input ciphertext to the compute params of the selected tag and device
    ///
    /// Returns an error if no upgrade path could be found
    pub fn upgrade<T>(&self, ct: &T, dest_tag: &Tag, dest_device: Device) -> crate::Result<T>
    where
        T: Tagged + Clone,
        KeySwitchingKey: FheKeyswitch<T>,
    {
        let input_node = Node::new(ct.tag(), CiphertextKind::Compute, Device::Cpu);
        let input_node_id = self
            .graph
            .index_of_node(&input_node)
            .ok_or_else(|| crate::error!("Input parameters have no matching point"))?;

        let output_node = Node::new(dest_tag, CiphertextKind::Compute, dest_device);
        let dest_node_id = self
            .graph
            .index_of_node(&output_node)
            .ok_or_else(|| crate::error!("Output parameters have no matching point"))?;

        let upgrade_path = self
            .graph
            .find_upgrade_path(input_node_id, dest_node_id)
            .ok_or_else(|| crate::error!("No upgrade path found"))?;

        Ok(self.apply_upgrade_path(ct, &upgrade_path))
    }

    /// Upgrades the input compressed ciphertext to the compute params of the selected tag and
    /// device
    ///
    /// Returns an error if no upgrade path could be found
    pub fn upgrade_from_compressed<T>(
        &self,
        input: &CompressedCiphertextList,
        index: usize,
        dest_tag: &Tag,
        dest_device: Device,
    ) -> crate::Result<T>
    where
        KeySwitchingKey: FheKeyswitch<T>,
        T: HlExpandable + Tagged + Clone,
    {
        let input_node = Node::new(&input.tag, CiphertextKind::Compressed, Device::Cpu);
        let input_node_id = self
            .graph
            .index_of_node(&input_node)
            .ok_or_else(|| crate::error!("Input parameters have no matching point"))?;

        let output_node = Node::new(dest_tag, CiphertextKind::Compute, dest_device);
        let dest_node_id = self
            .graph
            .index_of_node(&output_node)
            .ok_or_else(|| crate::error!("Output parameters have no matching point"))?;

        let upgrade_path = self
            .graph
            .find_upgrade_path(input_node_id, dest_node_id)
            .ok_or_else(|| crate::error!("No upgrade path found"))?;

        // The upgrade path cannot be empty
        let key_idx = upgrade_path.first().unwrap();
        let UpgradeKey::Decompress(key) = self.upgrade_keys.get(*key_idx).unwrap() else {
            panic!("Internal error, the first segment should be a decompression");
        };

        let ct = input
            .get_using_key(index, &key.inner, dest_tag)?
            .ok_or_else(|| {
                crate::error!(
                    "No ciphertext found at index: {index} (len {})",
                    input.len()
                )
            })?;

        if upgrade_path.len() == 1 {
            return Ok(ct);
        }

        let last = self.apply_upgrade_path(&ct, &upgrade_path[1..]);

        Ok(last)
    }

    // Follows the upgrade path
    //
    // NOTE: only keyswitch are allowed in the upgrade path
    fn apply_upgrade_path<T>(&self, ct: &T, upgrade_path: &[usize]) -> T
    where
        T: Tagged + Clone,
        KeySwitchingKey: FheKeyswitch<T>,
    {
        if upgrade_path.is_empty() {
            return ct.clone();
        }

        let mut intermediates = Vec::with_capacity(upgrade_path.len());
        let mut current = ct;
        for key_index in upgrade_path {
            let UpgradeKey::Keyswitch(key) =
                self.upgrade_keys.get(*key_index).expect("key not found")
            else {
                panic!("Only keyswitch are allowed")
            };
            intermediates.push(key.keyswitch(current));
            current = intermediates.last().unwrap();
        }
        intermediates.pop().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;
    #[cfg(feature = "gpu")]
    use crate::shortint::parameters::test_params::{
        TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::shortint::parameters::test_params::{
        TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use crate::upgrade::{DecompressionUpgradeKey, UpgradeKeyChain};
    use crate::*;

    #[test]
    fn test_graph() {
        let mut graph = UpgradeGraph::default();

        let node_1 = graph.add_node(Node::new(
            &Tag::from(1),
            CiphertextKind::Compute,
            Device::Cpu,
        ));

        let node_2_1 = graph.add_node(Node::new(
            &Tag::from(2),
            CiphertextKind::Compute,
            Device::Cpu,
        ));

        let node_3_1 = graph.add_node(Node::new(
            &Tag::from(3),
            CiphertextKind::Compute,
            Device::Cpu,
        ));

        // Finding a path from self to self returns an empty path
        // (as opposed to not finding a path which returns None)
        assert!(graph.find_upgrade_path(node_1, node_1).unwrap().is_empty());

        graph.add_edge(node_1, node_2_1, 0);
        graph.add_edge(node_2_1, node_3_1, 1);

        assert_eq!(graph.find_upgrade_path(node_1, node_2_1).unwrap(), vec![0]);
        assert_eq!(
            graph.find_upgrade_path(node_1, node_3_1).unwrap(),
            vec![0, 1]
        );
        assert!(graph.find_upgrade_path(node_2_1, node_1).is_none());
        assert!(graph.find_upgrade_path(node_3_1, node_1).is_none());

        let node_4_1 = graph.add_node(Node::new(
            &Tag::from(4),
            CiphertextKind::Compressed,
            Device::Cpu,
        ));
        let node_4_2 = graph.add_node(Node::new(
            &Tag::from(4),
            CiphertextKind::Compute,
            Device::Cpu,
        ));
        let node_5 = graph.add_node(Node::new(
            &Tag::from(5),
            CiphertextKind::Compute,
            Device::Cpu,
        ));

        graph.add_edge(node_4_1, node_5, 3);
        graph.add_edge(node_4_1, node_4_2, 4);
        graph.add_edge(node_4_2, node_5, 5);

        // There are two paths: 1 that is direct, the other that needs 2 switch
        // The direct path should be taken (this is a special case as the algorithm
        // used is not a shortest path)
        assert_eq!(graph.find_upgrade_path(node_4_1, node_5).unwrap(), vec![3]);

        assert!(graph.find_upgrade_path(node_1, node_5).is_none());
    }

    #[test]
    fn test_keychain_upgrade() {
        let compute_params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let compression_parameters = TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

        let config = ConfigBuilder::with_custom_parameters(compute_params)
            .enable_compression(compression_parameters)
            .build();

        // How many key-sets (ServerKey) we will create
        let num_key_sets = 10;
        assert!(num_key_sets >= 3);

        // In this test all key-sets use the same parameters,
        // we are mostly interested in testing the path-finding
        // than the actual keyswitch/decompression process
        //
        // But, for the sake of the test, we consider them as if they were different parameters
        // and that they represent an application that had to upgrade parameters x times
        let mut key_sets = vec![];
        for i in 0..num_key_sets {
            let mut ck = ClientKey::generate(config);
            ck.tag_mut().set_u64(i);

            let sk = ServerKey::new(&ck);
            assert_eq!(sk.tag().as_u64(), i);

            key_sets.push((ck, sk));
        }

        // Create the UpgradeKeyChain, and registers the CPU keys
        let mut upgrader = UpgradeKeyChain::default();
        for (_ck, sk) in &key_sets {
            upgrader.add_key_set(sk);
        }

        // We add an upgrade path to form a chain
        // param(0) -> param(1) -> ... -> param(n-1) -> param(n)
        //
        // This upgrade path moves from compute param to compute params
        for window in key_sets.windows(2) {
            let [(cks_i, sk_i), (cks_o, sk_o)] = window else {
                unreachable!();
            };
            let ksk = KeySwitchingKey::with_parameters(
                (cks_i, sk_i),
                (cks_o, sk_o),
                TEST_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            );
            assert_eq!(ksk.tag_in().as_u64(), sk_i.tag().as_u64());
            assert_eq!(ksk.tag_out().as_u64(), sk_o.tag().as_u64());

            upgrader.add_upgrade_key(ksk).unwrap();
        }

        // We create a decompression key that can be used to go from a compressed
        // ciphertext (part of a CompressedCiphertextList).
        //
        // This one is to go from the first key set, to the last
        let k = DecompressionUpgradeKey::new(
            &key_sets[0].0,
            &key_sets.last().unwrap().0,
            compression_parameters,
            Device::Cpu,
        )
        .unwrap();

        upgrader.add_upgrade_key(k).unwrap();

        let end_key_set = &key_sets[num_key_sets as usize - 1];

        // Test that given two ciphertexts encrypted under some 'old' key-set
        // we find a way to upgrade to the latest one
        //
        // This also tests that upgrading from latest to latest is ok
        for i in 0..num_key_sets {
            let start_key_set = &key_sets[i as usize];

            let clear_a = rand::random::<u32>();
            let clear_b = rand::random::<u32>();

            let a = FheUint32::encrypt(clear_a, &start_key_set.0);
            let b = FheUint32::encrypt(clear_b, &start_key_set.0);

            let upgraded_a = upgrader
                .upgrade(&a, &Tag::from(num_key_sets - 1), Device::Cpu)
                .unwrap();

            let upgraded_b = upgrader
                .upgrade(&b, &Tag::from(num_key_sets - 1), Device::Cpu)
                .unwrap();

            set_server_key(end_key_set.1.clone());

            let c = upgraded_a + upgraded_b;
            let dc: u32 = c.decrypt(&end_key_set.0);
            assert_eq!(dc, clear_a.wrapping_add(clear_b));
        }

        // We added a decomp key from ks0 to last ks
        // So we test that this path is taken
        {
            let clear_a = rand::random::<u32>();
            let clear_b = rand::random::<u32>();

            let a = FheUint32::encrypt(clear_a, &key_sets[0].0);
            let b = FheUint32::encrypt(clear_b, &key_sets[0].0);

            set_server_key(key_sets[0].1.clone());
            let list = CompressedCiphertextListBuilder::new()
                .push(a)
                .push(b)
                .build()
                .unwrap();

            let upgraded_a = upgrader
                .upgrade_from_compressed::<FheUint32>(
                    &list,
                    0,
                    key_sets.last().map(|x| x.1.tag()).unwrap(),
                    Device::Cpu,
                )
                .unwrap();
            let upgraded_b = upgrader
                .upgrade_from_compressed::<FheUint32>(
                    &list,
                    1,
                    key_sets.last().map(|x| x.1.tag()).unwrap(),
                    Device::Cpu,
                )
                .unwrap();
            set_server_key(end_key_set.1.clone());

            let c = upgraded_a * upgraded_b;
            let dc: u32 = c.decrypt(&end_key_set.0);
            assert_eq!(dc, clear_a.wrapping_mul(clear_b));
        }

        // For CPU server key, a path to go from compressed ciphertext to compute ciphertext
        // within the same keyset is automatically added.
        //
        // Test that it works, meaning we can upgrade_from_compressed
        for i in 1..num_key_sets as usize - 1 {
            println!("Upgrading from a compressed list of key-set {i}");
            // We DID NOT add a decomp key from ksi to last ks,
            // but we have series of ks from 1 to last, and we should know how to decompress within
            // same key set test that fall back path is found
            let clear_a = rand::random::<u32>();
            let clear_b = rand::random::<u32>();

            let a = FheUint32::encrypt(clear_a, &key_sets[i].0);
            let b = FheUint32::encrypt(clear_b, &key_sets[i].0);

            assert_eq!(a.tag().as_u64(), i as u64);
            assert_eq!(b.tag().as_u64(), i as u64);

            set_server_key(key_sets[i].1.clone());
            let list = CompressedCiphertextListBuilder::new()
                .push(a)
                .push(b)
                .build()
                .unwrap();

            assert_eq!(list.tag().as_u64(), i as u64);

            let upgraded_a = upgrader
                .upgrade_from_compressed::<FheUint32>(
                    &list,
                    0,
                    key_sets.last().map(|x| x.1.tag()).unwrap(),
                    Device::Cpu,
                )
                .unwrap();
            let upgraded_b = upgrader
                .upgrade_from_compressed::<FheUint32>(
                    &list,
                    1,
                    key_sets.last().map(|x| x.1.tag()).unwrap(),
                    Device::Cpu,
                )
                .unwrap();
            set_server_key(end_key_set.1.clone());

            let c = upgraded_a * upgraded_b;
            let dc: u32 = c.decrypt(&end_key_set.0);
            assert_eq!(dc, clear_a.wrapping_mul(clear_b));
        }

        #[cfg(feature = "gpu")]
        {
            // Create Compressed ServerKey that is special for GPU/CPU compression inter ops
            let gpu_compression_params =
                TEST_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
            let gpu_compute_params =
                TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

            let gpu_config = ConfigBuilder::with_custom_parameters(gpu_compute_params)
                .enable_compression(gpu_compression_params)
                .build();

            let gpu_key_set = {
                let mut ck = ClientKey::generate(gpu_config);
                ck.tag_mut().set_u64(0);

                let common_cck = end_key_set.0.clone().into_raw_parts().2;

                // We need the private compression key to be common between GPU and CPU
                // for the rest of the test to work. This is the only way to do it
                // until a more convenient API is added
                let (cks, pk, _, nsk, cnsk, cpkrndp, tag) = ck.into_raw_parts();
                let ck = ClientKey::from_raw_parts(cks, pk, common_cck, nsk, cnsk, cpkrndp, tag);

                let sk = CompressedServerKey::new(&ck);
                assert_eq!(sk.tag().as_u64(), 0);
                (ck, sk.decompress_to_gpu())
            };

            upgrader.add_key_set_gpu(&gpu_key_set.1);

            // Add an upgrade key that goes from compressed ciphertext
            // to GPU compute params
            let k = DecompressionUpgradeKey::new(
                &end_key_set.0,
                &gpu_key_set.0,
                gpu_compression_params,
                Device::CudaGpu,
            )
            .unwrap();

            upgrader.add_upgrade_key(k).unwrap();

            {
                let clear_a = rand::random::<u32>();
                let clear_b = rand::random::<u32>();

                let a = FheUint32::encrypt(clear_a, &end_key_set.0);
                let b = FheUint32::encrypt(clear_b, &end_key_set.0);

                assert_eq!(a.tag().as_u64(), num_key_sets - 1);
                assert_eq!(b.tag().as_u64(), num_key_sets - 1);

                set_server_key(end_key_set.1.clone());
                let list = CompressedCiphertextListBuilder::new()
                    .push(a)
                    .push(b)
                    .build()
                    .unwrap();

                assert_eq!(list.tag().as_u64(), num_key_sets - 1);

                let upgraded_a = upgrader
                    .upgrade_from_compressed::<FheUint32>(
                        &list,
                        0,
                        gpu_key_set.0.tag(),
                        Device::CudaGpu,
                    )
                    .unwrap();
                let upgraded_b = upgrader
                    .upgrade_from_compressed::<FheUint32>(
                        &list,
                        1,
                        gpu_key_set.0.tag(),
                        Device::CudaGpu,
                    )
                    .unwrap();
                set_server_key(gpu_key_set.1.clone());

                let c = upgraded_a * upgraded_b;
                let dc: u32 = c.decrypt(&gpu_key_set.0);
                assert_eq!(dc, clear_a.wrapping_mul(clear_b));
            }
        }
    }
}
