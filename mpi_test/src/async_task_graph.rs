use crate::context::Context;
use crate::managers::{advance_receiving, Receiving, Sending};
use async_priority_channel::{unbounded, Receiver, Sender};
use futures::executor::block_on;
use mpi::topology::Process;
use mpi::traits::*;
use mpi::Tag;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::VecDeque;
use std::mem::transmute;
use thread_priority::{set_current_thread_priority, ThreadPriority, ThreadPriorityValue};
use threadpool::ThreadPool;

const MASTER_TO_WORKER: Tag = 0;
const WORKER_TO_MASTER: Tag = 1;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(pub i32);

pub trait TaskGraph {
    type Task;
    type Result;

    fn init(&mut self) -> Vec<(Priority, Self::Task)>;
    fn commit_result(&mut self, result: Self::Result) -> Vec<(Priority, Self::Task)>;
    // fn no_work_in_queue(&self) -> bool;
    fn is_finished(&self) -> bool;
}

struct ClusterCharge {
    available_parallelism: usize,
    charge: Vec<usize>,
}

impl Context {
    pub fn async_task_graph_queue_master<
        T: Sync + Clone + Send + 'static,
        U: TaskGraph<Task = Task, Result = Result>,
        Task: Serialize + DeserializeOwned + Send + 'static,
        Result: Serialize + DeserializeOwned + Send + 'static,
    >(
        &self,
        task_graph: &mut U,
        state: T,
        f: impl Fn(&T, &Task) -> Result + Sync + Clone + Send + 'static,
    ) {
        let (send_task, receive_task) = unbounded::<Task, Priority>();
        let (send_result, receive_result) = crossbeam_channel::unbounded::<(Result, usize)>();

        // let mut sent_inputs = vec![];

        let mut charge = ClusterCharge {
            available_parallelism: std::thread::available_parallelism().unwrap().get(),
            charge: vec![0; self.size],
        };

        {
            let state = state.clone();
            let n_workers = (std::thread::available_parallelism().unwrap().get() - 1).max(1);
            let priority =
                ThreadPriority::Crossplatform(ThreadPriorityValue::try_from(32).unwrap());

            launch_threadpool(
                priority,
                n_workers,
                &receive_task,
                &send_result,
                move |receive_task, send_result, state| {
                    let f = f.clone();

                    handle_request(
                        receive_task,
                        send_result,
                        |state, task| (f(state, task), 0),
                        state,
                    )
                },
                state,
            );
        }

        let worker_senders: Vec<_> = (1..self.size)
            .map(|rank| {
                let (send_task, receive_task) = crossbeam_channel::unbounded::<Task>();
                let process_at_rank: Process<'static> =
                    unsafe { transmute(self.world.process_at_rank(rank as i32)) };

                std::thread::spawn(move || {
                    // set_current_thread_priority(priority).unwrap();

                    let mut sent_inputs = vec![];

                    while let Ok(task) = receive_task.recv() {
                        let buffer = bincode::serialize(&task).unwrap();
                        sent_inputs.push(Sending::new(buffer, &process_at_rank, MASTER_TO_WORKER))
                    }

                    for a in sent_inputs {
                        a.abort()
                    }
                });
                send_task
            })
            .collect();

        for rank in 1..self.size {
            let send_result = send_result.clone();

            let process_at_rank: Process<'static> =
                unsafe { transmute(self.world.process_at_rank(rank as i32)) };

            std::thread::spawn(move || {
                // set_current_thread_priority(priority).unwrap();
                let mut receives = VecDeque::new();

                for _ in 0..100 {
                    receives.push_back(Some(Receiving::new(&process_at_rank, WORKER_TO_MASTER)))
                }

                loop {
                    let Receiving { buffer, future } = receives.pop_front().unwrap().unwrap();

                    receives.push_back(Some(Receiving::new(&process_at_rank, WORKER_TO_MASTER)));

                    future.wait();

                    let result = bincode::deserialize(&buffer).unwrap();

                    send_result.send((result, rank)).unwrap();
                }
            });
        }

        for (priority, task) in task_graph.init() {
            self.enqueue_request(&mut charge, &send_task, priority, task, &worker_senders);
        }

        while !task_graph.is_finished() {
            let (result, rank) = receive_result.recv().unwrap();

            charge.charge[rank] -= 1;

            self.handle_new_result(task_graph, result, &mut charge, &send_task, &worker_senders);
        }

        for i in charge.charge {
            assert_eq!(i, 0);
        }

        std::mem::forget(send_task);
    }

    fn handle_new_result<U: TaskGraph>(
        &self,
        task_graph: &mut U,
        result: U::Result,
        charge: &mut ClusterCharge,
        send_task: &Sender<U::Task, Priority>,
        sent_inputs: &[crossbeam_channel::Sender<U::Task>],
    ) where
        U::Task: Serialize + DeserializeOwned,
    {
        let new_tasks = task_graph.commit_result(result);

        for (priority, task) in new_tasks {
            self.enqueue_request(charge, send_task, priority, task, sent_inputs);
        }
    }

    fn enqueue_request<Task: Serialize + DeserializeOwned>(
        &self,
        charge: &mut ClusterCharge,
        send_task: &Sender<Task, Priority>,
        priority: Priority,
        task: Task,
        sent_inputs: &[crossbeam_channel::Sender<Task>],
    ) {
        let rank = if charge.charge[self.root_rank as usize] < charge.available_parallelism {
            self.root_rank as usize
        } else {
            charge
                .charge
                .iter()
                .enumerate()
                .min_by_key(|(_index, charge)| *charge)
                .unwrap()
                .0
        };

        charge.charge[rank] += 1;

        if rank == self.root_rank as usize {
            block_on(send_task.send(task, priority)).unwrap();
        } else {
            sent_inputs[rank - 1].send(task).unwrap();
        }
    }

    pub fn async_task_graph_queue_worker<
        T: Sync + Clone + Send + 'static,
        Task: Serialize + DeserializeOwned + Send,
        Result: Serialize + DeserializeOwned + Send,
    >(
        &self,
        state: T,
        f: impl Fn(&T, &Task) -> Result + Sync + Clone + Send + 'static,
    ) {
        let f = move |state: &T, serialized_input: &Vec<u8>| {
            let input = bincode::deserialize(serialized_input).unwrap();

            let result = f(state, &input);

            bincode::serialize(&result).unwrap()
        };

        let (send_task, receive_task) = crossbeam_channel::unbounded::<Vec<u8>>();
        let (send_result, receive_result) = crossbeam_channel::unbounded::<Vec<u8>>();

        {
            let state = state.clone();
            let f = f.clone();
            let n_workers = (std::thread::available_parallelism().unwrap().get() - 1).max(1);
            let priority =
                ThreadPriority::Crossplatform(ThreadPriorityValue::try_from(32).unwrap());

            launch_threadpool2(
                priority,
                n_workers,
                &receive_task,
                &send_result,
                move |receive_task, send_result, state| {
                    let f = f.clone();

                    handle_request2(receive_task, send_result, f, state)
                },
                state,
            );
        }

        let root_process = self.world.process_at_rank(self.root_rank);

        let mut receives = VecDeque::new();

        for _ in 0..100 {
            receives.push_back(Some(Receiving::new(&root_process, MASTER_TO_WORKER)))
        }

        let mut send: VecDeque<Sending> = VecDeque::new();

        'outer: loop {
            if let Some(input) = advance_receiving(receives.front_mut().unwrap()) {
                assert!(receives.pop_front().unwrap().is_none());

                receives.push_back(Some(Receiving::new(&root_process, MASTER_TO_WORKER)));

                send_task.send(input).unwrap();

                // handle_request(&receive_task, &send_result, &f, state.clone());
            }

            while let Ok(output) = receive_result.try_recv() {
                send.push_back(Sending::new(output, &root_process, WORKER_TO_MASTER));
            }

            while let Some(front) = send.front_mut() {
                if let Some(a) = front.a.take() {
                    match a.test() {
                        Ok(_) => {
                            let b = send.pop_front();

                            assert!(b.unwrap().a.is_none());
                        }
                        Err(front_a) => {
                            front.a = Some(front_a);
                            continue 'outer;
                        }
                    }
                }
            }
        }
    }
}

fn launch_threadpool<
    T: Clone + Send + 'static,
    U: Send + 'static,
    V: Send + 'static,
    W: Send + Ord + 'static,
    // X: Send + Ord + 'static,
>(
    priority: ThreadPriority,
    n_workers: usize,
    receive_task: &Receiver<U, W>,
    send_result: &crossbeam_channel::Sender<V>,
    function: impl Fn(&Receiver<U, W>, &crossbeam_channel::Sender<V>, &T) + Send + Clone + 'static,
    state: T,
) {
    let pool = ThreadPool::new(n_workers);

    for _ in 0..n_workers {
        let receive_task = receive_task.clone();
        let send_result = send_result.clone();
        let function = function.clone();

        let state = state.clone();

        pool.execute(move || {
            set_current_thread_priority(priority).unwrap();

            loop {
                function(&receive_task, &send_result, &state);
            }
        });
    }
}

fn launch_threadpool2<T: Clone + Send + 'static, U: Send + 'static, V: Send + 'static>(
    priority: ThreadPriority,
    n_workers: usize,
    receive_task: &crossbeam_channel::Receiver<U>,
    send_result: &crossbeam_channel::Sender<V>,
    function: impl Fn(&crossbeam_channel::Receiver<U>, &crossbeam_channel::Sender<V>, &T)
        + Send
        + Clone
        + 'static,
    state: T,
) {
    let pool = ThreadPool::new(n_workers);

    for _ in 0..n_workers {
        let receive_task = receive_task.clone();
        let send_result = send_result.clone();
        let function = function.clone();

        let state = state.clone();

        pool.execute(move || {
            set_current_thread_priority(priority).unwrap();

            loop {
                function(&receive_task, &send_result, &state);
            }
        });
    }
}
fn handle_request<T, U, V, W: Ord>(
    receive_task: &Receiver<U, W>,
    send_result: &crossbeam_channel::Sender<(V, usize)>,
    f: impl Fn(&T, &U) -> (V, usize),
    state: &T,
) {
    let (input, _priority) = block_on(receive_task.recv()).unwrap();

    let result = f(state, &input);

    send_result.send(result).unwrap();
}

fn handle_request2<T, U, V>(
    receive_task: &crossbeam_channel::Receiver<U>,
    send_result: &crossbeam_channel::Sender<V>,
    f: impl Fn(&T, &U) -> V,
    state: &T,
) {
    let input = receive_task.recv().unwrap();

    let result = f(state, &input);

    send_result.send(result).unwrap();
}
