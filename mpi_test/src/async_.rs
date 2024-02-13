use crate::context::Context;
use crate::managers::{advance_receiving, Receiving, Sending};
use crossbeam_channel::{unbounded, Receiver, Sender};
use mpi::traits::*;
use mpi::Tag;
use std::collections::VecDeque;
use thread_priority::{set_current_thread_priority, ThreadPriority, ThreadPriorityValue};
use threadpool::ThreadPool;

const MASTER_TO_WORKER: Tag = 0;
const WORKER_TO_MASTER: Tag = 1;

pub trait WorkGraph {
    fn init(&mut self) -> Vec<Vec<u8>>;
    fn commit_result(&mut self, result: Vec<u8>) -> Vec<Vec<u8>>;
    // fn no_work_in_queue(&self) -> bool;
    fn is_finished(&self) -> bool;
}

struct ClusterCharge {
    available_parallelism: usize,
    charge: Vec<usize>,
}

impl Context {
    pub fn async_pbs_graph_queue_master<T: Sync + Clone + Send + 'static, U: WorkGraph>(
        &self,
        work_graph: &mut U,
        state: T,
        f: impl Fn(&T, &[u8]) -> Vec<u8> + Sync + Clone + Send + 'static,
    ) {
        let (send_pbs, receive_pbs) = unbounded::<Vec<u8>>();
        let (send_result, receive_result) = unbounded::<Vec<u8>>();

        let mut sent_inputs = vec![];

        let mut charge = ClusterCharge {
            available_parallelism: std::thread::available_parallelism().unwrap().get(),
            charge: vec![0; self.size],
        };

        for buffer in work_graph.init() {
            self.enqueue_request(&mut charge, &send_pbs, buffer, &mut sent_inputs);
        }

        {
            let state = state.clone();
            let n_workers = (std::thread::available_parallelism().unwrap().get() - 1).max(1);
            let priority =
                ThreadPriority::Crossplatform(ThreadPriorityValue::try_from(32).unwrap());

            launch_threadpool(
                priority,
                n_workers,
                &receive_pbs,
                &send_result,
                move |receive_pbs, send_result, state| {
                    let f = f.clone();

                    handle_request(receive_pbs, send_result, f, state)
                },
                state,
            );
        }
        let mut receivers: Vec<_> = (1..self.size)
            .map(|rank| {
                let process = self.world.process_at_rank(rank as i32);
                Some(Receiving::new(&process, WORKER_TO_MASTER))
            })
            .collect();

        while !work_graph.is_finished() {
            for (i, receiver) in receivers.iter_mut().enumerate() {
                let rank = i + 1;
                let process = self.world.process_at_rank(rank as i32);
                if let Some(buffer) = advance_receiving(receiver, &process, WORKER_TO_MASTER) {
                    self.handle_new_result(
                        work_graph,
                        buffer,
                        &mut charge,
                        &send_pbs,
                        &mut sent_inputs,
                    );

                    charge.charge[rank] -= 1;

                    // if receiver.is_none() && !work_graph.no_work_in_queue() &&
                    // process.is_not_working() {     *receiver =
                    // Some(Receiving::new(&process, WORKER_TO_MASTER)); }
                }
            }
            if let Ok(buffer) = receive_result.try_recv() {
                charge.charge[self.root_rank as usize] -= 1;

                self.handle_new_result(
                    work_graph,
                    buffer,
                    &mut charge,
                    &send_pbs,
                    &mut sent_inputs,
                );
            }
        }

        for i in charge.charge {
            assert_eq!(i, 0);
        }

        for receiver in receivers {
            receiver.unwrap().abort();
        }

        for Sending {
            len,
            buffer,
            size,
            a,
        } in sent_inputs
        {
            size.unwrap().wait();
            a.unwrap().wait();
            drop(len);
            drop(buffer);
        }
        std::mem::forget(send_pbs);
    }

    fn handle_new_result<U: WorkGraph>(
        &self,
        work_graph: &mut U,
        buffer: Vec<u8>,
        charge: &mut ClusterCharge,
        send_pbs: &Sender<Vec<u8>>,
        sent_inputs: &mut Vec<Sending>,
    ) {
        let new_jobs = work_graph.commit_result(buffer);

        for buffer in new_jobs {
            self.enqueue_request(charge, send_pbs, buffer, sent_inputs);
        }
    }

    fn enqueue_request(
        &self,
        charge: &mut ClusterCharge,
        send_pbs: &Sender<Vec<u8>>,
        buffer: Vec<u8>,
        sent_inputs: &mut Vec<Sending>,
    ) {
        if charge.charge[self.root_rank as usize] < charge.available_parallelism {
            send_pbs.send(buffer).unwrap();
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
                send_pbs.send(buffer).unwrap();
            } else {
                sent_inputs.push(Sending::new(
                    buffer,
                    &self.world.process_at_rank(rank as i32),
                    MASTER_TO_WORKER,
                ));
            }
        }
    }

    pub fn async_pbs_graph_queue_worker<T: Sync + Clone + Send + 'static>(
        &self,
        state: T,
        f: impl Fn(&T, &[u8]) -> Vec<u8> + Sync + Clone + Send + 'static,
    ) {
        let (send_pbs, receive_pbs) = unbounded::<Vec<u8>>();
        let (send_result, receive_result) = unbounded::<Vec<u8>>();

        {
            let state = state.clone();
            let f = f.clone();
            let n_workers = (std::thread::available_parallelism().unwrap().get() - 1).max(1);
            let priority =
                ThreadPriority::Crossplatform(ThreadPriorityValue::try_from(32).unwrap());

            launch_threadpool(
                priority,
                n_workers,
                &receive_pbs,
                &send_result,
                move |receive_pbs, send_result, state| {
                    let f = f.clone();

                    handle_request(receive_pbs, send_result, f, state)
                },
                state,
            );
        }

        let root_process = self.world.process_at_rank(self.root_rank);

        let mut receive = Some(Receiving::new(&root_process, MASTER_TO_WORKER));

        let mut send: VecDeque<Sending> = VecDeque::new();

        'outer: loop {
            if let Some(input) = advance_receiving(&mut receive, &root_process, MASTER_TO_WORKER) {
                send_pbs.send(input).unwrap();

                // handle_request(&receive_pbs, &send_result, &f, state.clone());
            }

            while let Ok(output) = receive_result.try_recv() {
                send.push_back(Sending::new(output, &root_process, WORKER_TO_MASTER));
            }

            while let Some(front) = send.front_mut() {
                if let Some(len) = front.size.take() {
                    match len.test() {
                        Ok(_) => {}
                        Err(front_size) => {
                            front.size = Some(front_size);
                            continue 'outer;
                        }
                    }
                }
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

fn launch_threadpool<T: Clone + Send + 'static>(
    priority: ThreadPriority,
    n_workers: usize,
    receive_pbs: &Receiver<Vec<u8>>,
    send_result: &Sender<Vec<u8>>,
    function: impl Fn(&Receiver<Vec<u8>>, &Sender<Vec<u8>>, &T) + Send + Clone + 'static,
    state: T,
) {
    let pool = ThreadPool::new(n_workers);

    for _ in 0..n_workers {
        let receive_pbs = receive_pbs.clone();
        let send_result = send_result.clone();
        let function = function.clone();

        let state = state.clone();

        pool.execute(move || {
            set_current_thread_priority(priority).unwrap();

            loop {
                function(&receive_pbs, &send_result, &state);
            }
        });
    }
}

fn handle_request<T>(
    receive_pbs: &Receiver<Vec<u8>>,
    send_result: &Sender<Vec<u8>>,
    f: impl Fn(&T, &[u8]) -> Vec<u8>,
    state: &T,
) {
    let input = receive_pbs.recv().unwrap();

    let result = f(state, &input);

    send_result.send(result).unwrap();
}
