use crate::context::Context;
use crate::managers::{advance_receiving, Receiving, Sending};
use crossbeam_channel::{unbounded, Receiver, Sender};
use mpi::traits::*;
use mpi::Tag;
use std::collections::VecDeque;
use threadpool::ThreadPool;

const MASTER_TO_WORKER: Tag = 0;
const WORKER_TO_MASTER: Tag = 1;

pub trait WorkGraph {
    fn init(&mut self) -> Vec<Vec<u8>>;
    fn commit_result(&mut self, result: Vec<u8>) -> Vec<Vec<u8>>;
    // fn no_work_in_queue(&self) -> bool;
    fn is_finished(&self) -> bool;
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

        let mut rank_for_next_request = 0;

        let mut sent_inputs = vec![];

        for buffer in work_graph.init() {
            self.enqueue_request(
                &mut rank_for_next_request,
                &send_pbs,
                buffer,
                &mut sent_inputs,
            );
        }

        {
            let state = state.clone();
            let n_workers = 15;
            launch_threadpool(
                n_workers,
                &receive_pbs,
                &send_result,
                move |receive_pbs, send_result| {
                    let state = state.clone();

                    handle_request(receive_pbs, send_result, f.clone(), state)
                },
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
                let process = self.world.process_at_rank(i as i32 + 1);
                if let Some(buffer) = advance_receiving(receiver, &process, WORKER_TO_MASTER) {
                    self.handle_new_result(
                        work_graph,
                        buffer,
                        &mut rank_for_next_request,
                        &send_pbs,
                        &mut sent_inputs,
                    );
                    // if receiver.is_none() && !work_graph.no_work_in_queue() &&
                    // process.is_not_working() {     *receiver =
                    // Some(Receiving::new(&process, WORKER_TO_MASTER)); }
                }
            }
            if let Ok(buffer) = receive_result.try_recv() {
                self.handle_new_result(
                    work_graph,
                    buffer,
                    &mut rank_for_next_request,
                    &send_pbs,
                    &mut sent_inputs,
                );
            }
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
        rank_for_next_request: &mut i32,
        send_pbs: &Sender<Vec<u8>>,
        sent_inputs: &mut Vec<Sending>,
    ) {
        let new_jobs = work_graph.commit_result(buffer);

        for buffer in new_jobs {
            self.enqueue_request(rank_for_next_request, send_pbs, buffer, sent_inputs);
        }
    }

    fn enqueue_request(
        &self,
        rank_for_request: &mut i32,
        send_pbs: &Sender<Vec<u8>>,
        buffer: Vec<u8>,
        sent_inputs: &mut Vec<Sending>,
    ) {
        let rank = *rank_for_request % self.size as i32;

        //no work for master
        // let rank = *rank_for_request % (self.size as i32 - 1) + 1;

        *rank_for_request += 1;

        if rank == self.root_rank {
            send_pbs.send(buffer).unwrap();
        } else {
            sent_inputs.push(Sending::new(
                buffer,
                &self.world.process_at_rank(rank),
                MASTER_TO_WORKER,
            ));
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
            let n_workers = 1;
            launch_threadpool(
                n_workers,
                &receive_pbs,
                &send_result,
                move |receive_pbs, send_result| {
                    let f = f.clone();
                    let state = state.clone();

                    handle_request(receive_pbs, send_result, f, state)
                },
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

fn launch_threadpool(
    n_workers: usize,
    receive_pbs: &Receiver<Vec<u8>>,
    send_result: &Sender<Vec<u8>>,
    function: impl Fn(&Receiver<Vec<u8>>, &Sender<Vec<u8>>) + Send + Clone + 'static,
) {
    let pool = ThreadPool::new(n_workers);

    for _ in 0..n_workers {
        let receive_pbs = receive_pbs.clone();
        let send_result = send_result.clone();
        let function = function.clone();

        pool.execute(move || loop {
            function(&receive_pbs, &send_result);
        });
    }
}

fn handle_request<T>(
    receive_pbs: &Receiver<Vec<u8>>,
    send_result: &Sender<Vec<u8>>,
    f: impl Fn(&T, &[u8]) -> Vec<u8>,
    state: T,
) {
    let input = receive_pbs.recv().unwrap();

    let result = f(&state, &input);

    send_result.send(result).unwrap();
}
