//! One copy of a value per NUMA node, the copy of the node of the calling thread picked at
//! each use.
//!
//! Prototype of the "one key copy per node" design: the keys are read whole by every
//! keyswitch and bootstrap, so on a machine with several NUMA nodes their placement bounds
//! the throughput. Each copy is made by a thread bound to the cores and the memory of its
//! node, and `local` returns the copy of the node the calling thread runs on (Linux only;
//! elsewhere, or without NUMA information, one copy).

/// A value copied once per NUMA node.
pub struct NumaReplicated<T> {
    replicas: Vec<T>,
    /// The index in `replicas` of the copy local to each CPU; CPUs out of it use copy 0.
    replica_of_cpu: Vec<usize>,
}

/// The address and the length in bytes of `slice`, a memory region to bind.
pub fn region<T>(slice: &[T]) -> (usize, usize) {
    (slice.as_ptr() as usize, std::mem::size_of_val(slice))
}

impl<T: Clone + Send + Sync> NumaReplicated<T> {
    /// One copy of `value` per NUMA node the process may run on.
    ///
    /// The copies are only allocated on their nodes: the automatic NUMA balancing of Linux
    /// may move their pages later, see [`Self::new_bound`].
    pub fn new(value: &T) -> Self {
        Self::new_bound(value, |_| Vec::new())
    }

    /// One copy of `value` per NUMA node the process may run on, the memory `regions` of
    /// each copy bound to its node.
    ///
    /// Without the binding, a thread that moves to another node during an operation reads
    /// the copy of its former node from afar, and the automatic NUMA balancing moves the
    /// pages of that copy toward it: over time, the copies get mixed over the nodes.
    pub fn new_bound(value: &T, regions: impl Fn(&T) -> Vec<(usize, usize)> + Sync) -> Self {
        let nodes = linux::nodes();
        if nodes.len() < 2 {
            return Self::single(value.clone());
        }
        Self::on_nodes(value, &nodes, &regions)
    }

    /// One copy of `value` per node of `nodes`.
    fn on_nodes(
        value: &T,
        nodes: &[linux::Node],
        regions: &(impl Fn(&T) -> Vec<(usize, usize)> + Sync),
    ) -> Self {
        let replicas = std::thread::scope(|scope| {
            let handles: Vec<_> = nodes
                .iter()
                .map(|node| {
                    scope.spawn(move || {
                        linux::bind_current_thread(node);
                        let replica = value.clone();
                        for (address, len) in regions(&replica) {
                            linux::bind_memory(address, len, node);
                        }
                        replica
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        let max_cpu = nodes.iter().flat_map(|node| &node.cpus).max().unwrap();
        let mut replica_of_cpu = vec![0; max_cpu + 1];
        for (replica, node) in nodes.iter().enumerate() {
            for &cpu in &node.cpus {
                replica_of_cpu[cpu] = replica;
            }
        }
        Self {
            replicas,
            replica_of_cpu,
        }
    }

    /// A single copy, without NUMA placement.
    pub fn single(value: T) -> Self {
        Self {
            replicas: vec![value],
            replica_of_cpu: Vec::new(),
        }
    }

    /// The copy of the node of the calling thread.
    pub fn local(&self) -> &T {
        let replica = linux::current_cpu()
            .and_then(|cpu| self.replica_of_cpu.get(cpu).copied())
            .unwrap_or(0);
        &self.replicas[replica]
    }

    /// The number of copies.
    pub fn len(&self) -> usize {
        self.replicas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.replicas.is_empty()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    /// A NUMA node and the CPUs of it the process may run on.
    pub struct Node {
        pub id: usize,
        pub cpus: Vec<usize>,
    }

    /// The NUMA nodes with CPUs the process may run on, from /sys.
    pub fn nodes() -> Vec<Node> {
        let allowed = allowed_cpus();
        let Ok(entries) = std::fs::read_dir("/sys/devices/system/node") else {
            return Vec::new();
        };
        let mut nodes: Vec<Node> = entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let id = entry
                    .file_name()
                    .to_str()?
                    .strip_prefix("node")?
                    .parse()
                    .ok()?;
                let list = std::fs::read_to_string(entry.path().join("cpulist")).ok()?;
                let cpus: Vec<usize> = parse_cpu_list(&list)
                    .into_iter()
                    .filter(|cpu| allowed.contains(cpu))
                    .collect();
                (!cpus.is_empty()).then_some(Node { id, cpus })
            })
            .collect();
        nodes.sort_by_key(|node| node.id);
        nodes
    }

    /// Parses a CPU list like "0-23,96-119".
    pub fn parse_cpu_list(list: &str) -> Vec<usize> {
        list.trim()
            .split(',')
            .filter(|range| !range.is_empty())
            .flat_map(|range| {
                let (first, last) = range.split_once('-').unwrap_or((range, range));
                first.parse::<usize>().unwrap()..=last.parse::<usize>().unwrap()
            })
            .collect()
    }

    /// The CPUs the calling thread may run on.
    fn allowed_cpus() -> Vec<usize> {
        // SAFETY: cpu_set_t is plain data, filled by sched_getaffinity.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
                return Vec::new();
            }
            (0..libc::CPU_SETSIZE as usize)
                .filter(|&cpu| libc::CPU_ISSET(cpu, &set))
                .collect()
        }
    }

    /// Binds the calling thread to the CPUs of `node` and its allocations to the memory of
    /// `node`, so what it writes first lands there.
    pub fn bind_current_thread(node: &Node) {
        const MPOL_BIND: libc::c_int = 2;
        // SAFETY: plain syscalls on the calling thread, with buffers that outlive them.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            for &cpu in &node.cpus {
                libc::CPU_SET(cpu, &mut set);
            }
            assert_eq!(
                libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set),
                0,
                "sched_setaffinity on node {}",
                node.id
            );
            let mut mask = vec![0u64; node.id / 64 + 1];
            mask[node.id / 64] |= 1 << (node.id % 64);
            assert_eq!(
                libc::syscall(
                    libc::SYS_set_mempolicy,
                    MPOL_BIND,
                    mask.as_ptr(),
                    mask.len() * 64 + 1,
                ),
                0,
                "set_mempolicy on node {}",
                node.id
            );
        }
    }

    /// Binds the whole pages of the `len` bytes at `address` to the memory of `node`, moving
    /// them there if needed. Pages with this policy are not moved by the NUMA balancing.
    pub fn bind_memory(address: usize, len: usize, node: &Node) {
        const MPOL_BIND: libc::c_ulong = 2;
        const MPOL_MF_MOVE: libc::c_ulong = 1 << 1;
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let start = address.next_multiple_of(page);
        let end = (address + len) / page * page;
        if end <= start {
            return;
        }
        let mut mask = vec![0u64; node.id / 64 + 1];
        mask[node.id / 64] |= 1 << (node.id % 64);
        // SAFETY: the range is mapped memory of the value, the mask outlives the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_mbind,
                start,
                end - start,
                MPOL_BIND,
                mask.as_ptr(),
                mask.len() * 64 + 1,
                MPOL_MF_MOVE,
            )
        };
        assert_eq!(
            result,
            0,
            "mbind on node {}: {}",
            node.id,
            std::io::Error::last_os_error()
        );
    }

    /// The CPU the calling thread runs on.
    pub fn current_cpu() -> Option<usize> {
        // SAFETY: no arguments, returns -1 on error.
        let cpu = unsafe { libc::sched_getcpu() };
        usize::try_from(cpu).ok()
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    pub struct Node {
        pub id: usize,
        pub cpus: Vec<usize>,
    }

    pub fn nodes() -> Vec<Node> {
        Vec::new()
    }

    pub fn bind_current_thread(_node: &Node) {}

    pub fn bind_memory(_address: usize, _len: usize, _node: &Node) {}

    pub fn current_cpu() -> Option<usize> {
        None
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_list() {
        assert_eq!(linux::parse_cpu_list("0-2,5,7-8\n"), [0, 1, 2, 5, 7, 8]);
    }

    #[test]
    fn one_copy_per_node() {
        let value = vec![1u64; 1 << 20];
        let replicated = NumaReplicated::new(&value);
        assert_eq!(replicated.len(), linux::nodes().len().max(1));
        assert_eq!(replicated.local(), &value);
    }

    /// Splits the CPUs of the first node in two fake nodes, to check that each thread gets
    /// the copy of its own CPUs on a machine with one node.
    #[test]
    fn local_copy_follows_the_cpu() {
        let node = linux::nodes().remove(0);
        if node.cpus.len() < 2 {
            return;
        }
        let half = node.cpus.len() / 2;
        let nodes = [
            linux::Node {
                id: node.id,
                cpus: node.cpus[..half].to_vec(),
            },
            linux::Node {
                id: node.id,
                cpus: node.cpus[half..].to_vec(),
            },
        ];
        let value = vec![7u8; 1 << 20];
        let replicated =
            NumaReplicated::on_nodes(&value, &nodes, &|replica: &Vec<u8>| vec![region(replica)]);
        assert_eq!(replicated.len(), 2);
        std::thread::scope(|scope| {
            for (replica, fake) in nodes.iter().enumerate() {
                let (replicated, value) = (&replicated, &value);
                scope.spawn(move || {
                    linux::bind_current_thread(fake);
                    let local = replicated.local();
                    assert!(std::ptr::eq(local, &replicated.replicas[replica]));
                    assert_eq!(local, value);
                });
            }
        });
    }
}
