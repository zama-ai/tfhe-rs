use crate::context::Context;
use crate::managers::{advance_receiving, Receiving, Sending};
use async_priority_channel::{unbounded, Receiver, Sender};
use futures::executor::block_on;
use mpi::traits::*;
use mpi::Tag;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::VecDeque;
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
        let (send_result, receive_result) = unbounded::<Result, Priority>();

        let mut sent_inputs = vec![];

        let mut charge = ClusterCharge {
            available_parallelism: std::thread::available_parallelism().unwrap().get(),
            charge: vec![0; self.size],
        };

        for (priority, task) in task_graph.init() {
            self.enqueue_request(&mut charge, &send_task, priority, task, &mut sent_inputs);
        }

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

                    handle_request(receive_task, send_result, f, state)
                },
                state,
            );
        }
        let mut receiverss: Vec<_> = (1..self.size)
            .map(|rank| {
                let mut receives = VecDeque::new();

                let process = self.world.process_at_rank(rank as i32);
                for _ in 0..100 {
                    receives.push_back(Some(Receiving::new(&process, WORKER_TO_MASTER)))
                }
                receives
            })
            .collect();

        // let mut a = (1..self.size).map(|rank| {
        //     let (send_task, receive_task) = unbounded::<Task, Priority>();

        //     pool.execute(move || {
        //         let process = self.world.process_at_rank(rank as i32);
        //         let mut receiver = Some(Receiving::new(&process, WORKER_TO_MASTER));

        //         // set_current_thread_priority(priority).unwrap();

        //         let mut sent_inputs = vec![];

        //         loop {
        //             if let Ok((buffer, _)) = receive_result.recv() {
        //             } else {
        //                 break;
        //             }
        //         }
        //     });
        // });

        // let mut a = (1..self.size).map(|rank| {
        //     let (send_result, receive_result) = unbounded::<Result, Priority>();

        //     pool.execute(move || {
        //         let process = self.world.process_at_rank(rank as i32);
        //         let mut receiver = Some(Receiving::new(&process, WORKER_TO_MASTER));

        //         // set_current_thread_priority(priority).unwrap();

        //         let mut sent_inputs = vec![];

        //         loop {
        //             if let Ok((buffer, _)) = receive_result.try_recv() {}

        //             function(&receive_task, &send_result, &state);
        //         }
        //     });
        // });

        while !task_graph.is_finished() {
            for (i, receivers) in receiverss.iter_mut().enumerate() {
                let rank = i + 1;
                let process = self.world.process_at_rank(rank as i32);
                if let Some(buffer) = advance_receiving(receivers.front_mut().unwrap()) {
                    assert!(receivers.pop_front().unwrap().is_none());

                    receivers.push_back(Some(Receiving::new(&process, WORKER_TO_MASTER)));

                    let result = bincode::deserialize(&buffer).unwrap();

                    self.handle_new_result(
                        task_graph,
                        result,
                        &mut charge,
                        &send_task,
                        &mut sent_inputs,
                    );

                    charge.charge[rank] -= 1;

                    // if receiver.is_none() && !work_graph.no_work_in_queue() &&
                    // process.is_not_working() {     *receiver =
                    // Some(Receiving::new(&process, WORKER_TO_MASTER)); }
                }
            }
            if let Ok((buffer, _)) = receive_result.try_recv() {
                charge.charge[self.root_rank as usize] -= 1;

                self.handle_new_result(
                    task_graph,
                    buffer,
                    &mut charge,
                    &send_task,
                    &mut sent_inputs,
                );
            }
        }

        for i in charge.charge {
            assert_eq!(i, 0);
        }

        for receivers in receiverss {
            for receiver in receivers {
                std::mem::forget(receiver.unwrap()); //.abort()
            }
        }

        for a in sent_inputs {
            a.abort()
        }
        std::mem::forget(send_task);
    }

    fn handle_new_result<U: TaskGraph>(
        &self,
        task_graph: &mut U,
        result: U::Result,
        charge: &mut ClusterCharge,
        send_task: &Sender<U::Task, Priority>,
        sent_inputs: &mut Vec<Sending>,
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
        sent_inputs: &mut Vec<Sending>,
    ) {
        if charge.charge[self.root_rank as usize] < charge.available_parallelism {
            block_on(send_task.send(task, priority)).unwrap();
            charge.charge[self.root_rank as usize] += 1;
        } else {
            let rank = charge
                .charge
                .iter()
                .enumerate()
                .min_by_key(|(_index, charge)| *charge)
                .unwrap()
                .0;

            charge.charge[rank] += 1;

            if rank == self.root_rank as usize {
                block_on(send_task.send(task, priority)).unwrap();
            } else {
                let buffer = bincode::serialize(&task).unwrap();

                sent_inputs.push(Sending::new(
                    buffer,
                    &self.world.process_at_rank(rank as i32),
                    MASTER_TO_WORKER,
                ));
            }
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

        let (send_task, receive_task) = unbounded::<Vec<u8>, Priority>();
        let (send_result, receive_result) = unbounded::<Vec<u8>, Priority>();

        {
            let state = state.clone();
            let f = f.clone();
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

                    handle_request(receive_task, send_result, f, state)
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

                block_on(send_task.send(input, Priority(0))).unwrap();

                // handle_request(&receive_task, &send_result, &f, state.clone());
            }

            while let Ok((output, _)) = receive_result.try_recv() {
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
    X: Send + Ord + 'static,
>(
    priority: ThreadPriority,
    n_workers: usize,
    receive_task: &Receiver<U, W>,
    send_result: &Sender<V, X>,
    function: impl Fn(&Receiver<U, W>, &Sender<V, X>, &T) + Send + Clone + 'static,
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
    send_result: &Sender<V, W>,
    f: impl Fn(&T, &U) -> V,
    state: &T,
) {
    let (input, priority) = block_on(receive_task.recv()).unwrap();

    let result = f(state, &input);

    block_on(send_result.send(result, priority)).unwrap();
}
