use context::Context;

const N: u64 = 25;
fn main() {
    let context = Context::new();

    // context.run_local_on_root();

    // context.sync_pbs_batch();

    // context.async_pbs_batch();

    // context.test_request();

    // context.async_pbs_list_queue();

    // context.async_small_mul();

    // context.run_local_mul_on_root(64);

    context.async_mul(64);
}

pub mod async_;
pub mod async_graph;
pub mod context;
pub mod examples;
pub mod managers;
