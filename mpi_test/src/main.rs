use context::Context;

const N: u64 = 25;
fn main() {
    let context = Context::new();

    // simple_logger::init().unwrap();

    // context.run_local_on_root();

    // context.sync_pbs_batch();

    // context.async_pbs_batch();

    // context.test_request();

    // context.async_pbs_list_queue();

    // context.async_small_mul();

    context.run_local_mul_on_root(32);

    context.async_mul(32);
}

pub mod async_pbs_graph;
pub mod async_task_graph;
pub mod context;
pub mod examples;
pub mod managers;
