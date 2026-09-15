//! The query, run off the UI thread.
//!
//! The credentials and the query builder are `tfhe-data-extractor`'s. What is
//! here is the plumbing between an async fetch and a synchronous window.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::Sender;

use benchmark_spec::{MeasuredId, Statistic};
use eframe::egui;
use tfhe_data_extractor::archive;
use tfhe_data_extractor::db::{self, FetchQuery, PbsKind, PgPool};

use crate::catalogue::Node;

use super::{Point, Store};

/// Not exposed in the interface yet: two knobs to argue about later, pinned
/// here so it is plain that they are pinned.
const DATABASE: &str = "tfhe_rs";
const BRANCH: &str = "main";

pub struct Db {
    runtime: tokio::runtime::Runtime,
    /// Opened on the first fetch, kept for the next one. A failed attempt
    /// leaves the cell empty, so the button can simply be pressed again.
    pool: Arc<tokio::sync::OnceCell<PgPool>>,
    config_file: Option<PathBuf>,
}

impl Db {
    pub fn new(config_file: Option<PathBuf>) -> anyhow::Result<Self> {
        Ok(Self {
            runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?,
            pool: Arc::new(tokio::sync::OnceCell::new()),
            config_file,
        })
    }

    pub fn fetch(&self, days: i32, tx: Sender<Result<Store, String>>, ctx: egui::Context) {
        let pool = self.pool.clone();
        let config_file = self.config_file.clone();

        self.runtime.spawn(async move {
            let outcome = fetch_all(&pool, config_file, days).await;
            let _ = tx.send(outcome.map_err(|err| format!("{err:#}")));
            // The UI thread sleeps until something asks it to wake up.
            ctx.request_repaint();
        });
    }
}

async fn fetch_all(
    pool: &tokio::sync::OnceCell<PgPool>,
    config_file: Option<PathBuf>,
    days: i32,
) -> anyhow::Result<Store> {
    let pool = pool
        .get_or_try_init(|| async {
            let config = db::DbConfig::load(config_file.as_deref())?;
            config.connect(DATABASE).await
        })
        .await?;

    let machines = archive::fleet();
    // Anchored on the crate prefixes, which is what leaves the pre-spec ids
    // out. Nothing narrower: the interface picks from what came back.
    let patterns = vec!["tfhe::%".to_string(), "zk::%".to_string()];

    let query = FetchQuery {
        machines: &machines,
        backend: None,
        branch: BRANCH,
        like_patterns: &patterns,
        exclude_non_default: true,
        param_pattern: None,
        metric: None,
        pbs_kind: PbsKind::Any,
        project_version: None,
        bench_date: None,
        time_span_days: days,
    };

    // The history, not the latest value: the X axis is time, so one row per
    // insertion is the point.
    let rows = db::fetch_bench_history(pool, &query).await?;
    Ok(Store::build(&rows, days))
}

impl Store {
    fn build(rows: &[db::HistoryRow], days: i32) -> Self {
        let mut store = Self {
            tree: Node::root(),
            points: HashMap::new(),
            fetched: rows.len(),
            unparsed: Vec::new(),
            unparsed_rows: 0,
            days,
        };
        let mut unparsed: HashMap<&str, String> = HashMap::new();

        for row in rows {
            let point = Point {
                at: row.inserted_at,
                value: row.value,
                bits: row.bit_size,
                machine: row.machine.clone(),
                params: row.params.clone(),
                variant: String::new(),
                backend: None,
                metric: None,
            };

            let id = match row.name.parse::<MeasuredId>() {
                Ok(id) => id,
                Err(err) => {
                    store.unparsed_rows += 1;
                    unparsed
                        .entry(row.name.as_str())
                        .or_insert_with(|| err.to_string());
                    // Keyed by the whole stored name, so a raw series can only
                    // ever hold one thing: no mean lands next to a std_dev.
                    store
                        .points
                        .entry(row.name.clone())
                        .or_default()
                        .push(point);
                    continue;
                }
            };
            if id.statistic != Statistic::Mean {
                continue;
            }

            store
                .points
                .entry(id.spec.bench_path().to_string())
                .or_default()
                .push(Point {
                    variant: id.variant.unwrap_or_default(),
                    // From the id, never from the `backend` column: the two
                    // have drifted apart (`db.rs:138`).
                    backend: Some(id.spec.backend()),
                    metric: Some(id.spec.metric()),
                    ..point
                });
        }

        store.unparsed = unparsed
            .into_iter()
            .map(|(name, reason)| (name.to_string(), reason))
            .collect();
        store.unparsed.sort();
        store.rebuild_tree();
        store
    }
}
