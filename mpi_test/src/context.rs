use mpi::environment::Universe;
use mpi::topology::SimpleCommunicator;
use mpi::traits::*;

pub struct Context {
    pub universe: Universe,
    pub world: SimpleCommunicator,
    pub size: usize,
    pub rank: i32,
    pub root_rank: i32,
    pub is_root: bool,
}

#[allow(clippy::new_without_default)]
impl Context {
    pub fn new() -> Self {
        let universe = mpi::initialize().unwrap();
        let world = universe.world();

        let size = world.size() as usize;
        let rank = world.rank();
        let root_rank = 0;

        let is_root = rank == root_rank;

        Context {
            universe,
            world,
            size,
            rank,
            root_rank,
            is_root,
        }
    }
}
