//! A pool of writer threads, one pinned per core, each owning its own shard state.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use iris_core::CoreId;
use iris_core::multicore::{
    ChannelDispatcher, ChannelMode, DedicatedWorkerHandle, DedicatedWorkerThreadSpawner,
};

const CHANNEL_CAP: usize = 1 << 18;

/// Per-thread state of one stream: consumes its events, finalizes its files on close.
pub trait Shard: Send + 'static {
    type Event: Send + Serialize + 'static;
    fn handle(&mut self, ev: Self::Event);
    fn close(&mut self);
}

/// Type-erased view so `mod.rs` can shut down and report every pool uniformly.
pub trait AnyPool {
    fn shutdown(&self);
    fn report(&self, out: &mut String);
}

struct Worker<S: Shard> {
    tx: Arc<ChannelDispatcher<S::Event>>,
    shard: Arc<Mutex<S>>,
    handle: Mutex<Option<DedicatedWorkerHandle<S::Event>>>,
}

pub struct Pool<S: Shard> {
    name: &'static str,
    workers: Vec<Worker<S>>,
}

impl<S: Shard> Pool<S> {
    pub fn spawn(name: &'static str, cores: &[CoreId], mut make: impl FnMut(usize) -> S) -> Self {
        let workers = cores
            .iter()
            .enumerate()
            .map(|(i, core)| {
                let tx = Arc::new(ChannelDispatcher::new(
                    ChannelMode::Shared,
                    CHANNEL_CAP,
                    format!("{name}_{i}"),
                ));
                let shard = Arc::new(Mutex::new(make(i)));
                let s = shard.clone();
                let handle = DedicatedWorkerThreadSpawner::new()
                    .set_cores(vec![*core])
                    .set_dispatcher(tx.clone())
                    .set_handler(move |ev: S::Event| s.lock().unwrap().handle(ev))
                    .run();
                Worker {
                    tx,
                    shard,
                    handle: Mutex::new(Some(handle)),
                }
            })
            .collect();
        Self { name, workers }
    }

    /// Route to a writer by producer core; never blocks on I/O.
    pub fn dispatch(&self, ev: S::Event, core: &CoreId) {
        let w = &self.workers[core.raw() as usize % self.workers.len()];
        let _ = w.tx.dispatch(ev, None);
    }
}

impl<S: Shard> AnyPool for Pool<S> {
    /// Drain queues, join threads, then close shards (writes Parquet footers).
    fn shutdown(&self) {
        self.workers.iter().for_each(|w| w.tx.close_channels());
        for w in &self.workers {
            if let Some(h) = w.handle.lock().unwrap().take() {
                let _ = h.shutdown(None);
            }
        }
        self.workers
            .iter()
            .for_each(|w| w.shard.lock().unwrap().close());
    }

    fn report(&self, out: &mut String) {
        for (i, w) in self.workers.iter().enumerate() {
            let _ = writeln!(out, "[{} {i}]\n{}", self.name, w.tx.stats());
        }
    }
}
