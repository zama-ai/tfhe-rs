//! PostgreSQL access layer (read-only) for the data extractor.
//!
//! Credentials come from a TOML config file (`--config-file`) and/or the
//! environment variables `DATA_EXTRACTOR_DATABASE_{HOST,USER,PASSWORD}`, the
//! latter taking precedence.

use std::path::Path;

use benchmark_spec::BenchmarkMetric;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Postgres, QueryBuilder};

/// Re-exported so a caller can hold a pool without taking its own `sqlx`
/// dependency, which would have to be kept on the same version as this one.
pub use sqlx::postgres::PgPool;

/// Database credentials. Every field is optional so the file and the
/// environment can each provide a subset.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct DbConfig {
    pub host: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ConfigFile {
    database: DbConfig,
}

impl DbConfig {
    /// Loads credentials from the optional TOML file, then overrides any value
    /// present in the environment, which wins.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut cfg = match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .map_err(|e| anyhow::anyhow!("cannot read config file {}: {e}", p.display()))?;
                toml::from_str::<ConfigFile>(&raw)?.database
            }
            None => DbConfig::default(),
        };

        if let Ok(v) = std::env::var("DATA_EXTRACTOR_DATABASE_HOST") {
            cfg.host = Some(v);
        }
        if let Ok(v) = std::env::var("DATA_EXTRACTOR_DATABASE_USER") {
            cfg.user = Some(v);
        }
        if let Ok(v) = std::env::var("DATA_EXTRACTOR_DATABASE_PASSWORD") {
            cfg.password = Some(v);
        }

        Ok(cfg)
    }

    fn connect_options(&self, dbname: &str) -> anyhow::Result<PgConnectOptions> {
        let host = self
            .host
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing database host"))?;
        let user = self
            .user
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing database user"))?;
        let password = self
            .password
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing database password"))?;

        Ok(PgConnectOptions::new()
            .host(host)
            .username(user)
            .password(password)
            .database(dbname)
            // RDS enforces TLS; `Require` encrypts without CA verification.
            .ssl_mode(PgSslMode::Require))
    }

    /// Opens a connection pool to the given database.
    pub async fn connect(&self, dbname: &str) -> anyhow::Result<PgPool> {
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(self.connect_options(dbname)?)
            .await?;
        Ok(pool)
    }
}

/// One benchmark result, as stored. `name` holds the whole rendered id, so
/// every structured part of a result has to be parsed back out of it:
///
/// ```text
/// name     = "<bench path>::<param set>::<type>_mean_avx512"
/// bit_size = 64
/// value    = 2310000.0     // nanoseconds, for a latency bench
/// machine  = "n3-H100-SXM5x8"
/// ```
#[derive(Debug, sqlx::FromRow)]
pub struct BenchRow {
    pub name: String,
    pub bit_size: i64,
    pub value: f64,
    /// As the runner registers it. Selected, not just filtered on: the archive
    /// elects a machine per operation rather than being told one.
    pub machine: String,
}

/// Escapes the `LIKE` metacharacters. Bench ids and parameter aliases are full
/// of `_`, which `LIKE` would otherwise read as "any single character", making
/// the pattern match more than was asked for.
///
/// ```text
/// add_parallelized  ->  add\_parallelized
/// ```
pub fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '_' | '%' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// PBS-kind filter, applied as a pattern on the parameter-set alias.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum PbsKind {
    Classical,
    #[value(name = "multi_bit")]
    MultiBit,
    /// Special variant used when the user doesn't care about the PBS kind.
    Any,
}

/// Dynamic filters for the benchmark fetch query.
pub struct FetchQuery<'a> {
    /// One for the tables, the whole fleet for the archive.
    pub machines: &'a [String],
    /// `None` = no backend filter. A spec id already carries the backend as one
    /// of its segments (`::cuda::`), so the column is redundant, and the two
    /// have drifted apart: the June 2026 runs read `cuda` in the id and `gpu`
    /// in the column. Of the two, the id is what the patterns match on.
    pub backend: Option<&'a str>,
    pub branch: &'a str,
    /// SQL `LIKE` patterns for the id; a row matching any of them is kept.
    /// Either one broad layer pattern, or one exact prefix per bench path when
    /// a regression profile drives the selection.
    pub like_patterns: &'a [String],
    /// Drop the `unchecked_` variants by name. Only needed for the broad
    /// pattern: a profile already spells out the operations it wants.
    pub exclude_non_default: bool,
    /// `None` = no metric filter (both latency and throughput).
    pub metric: Option<BenchmarkMetric>,
    pub pbs_kind: PbsKind,
    /// `LIKE` pattern on the parameter set alias, already wrapped in `%`.
    /// Matched as a substring, which matters: aliases carry a version prefix
    /// (`V1_6_PARAM_…`).
    pub param_pattern: Option<&'a str>,
    /// If set, pin to that exact commit; otherwise use the date window.
    pub project_version: Option<&'a str>,
    pub bench_date: Option<&'a str>,
    pub time_span_days: i32,
}

/// Tiny `WHERE` builder over `sqlx::QueryBuilder`.
///
/// [`BASE_QUERY`] ends with `WHERE true`, so every condition is a plain `AND`
/// and no method has to know whether it is the first one. Which one that would
/// be is not knowable anyway: most filters here are optional. It also keeps the
/// query valid when none of them applies.
///
/// ```sql
/// WHERE true AND h.name = $1 AND bk.name = $2 AND test.name LIKE ANY($3)
/// WHERE true                                    -- no filter active
/// ```
///
/// Column names are always hardcoded constants (safe to inline); only values go
/// through `push_bind`.
struct Filters<'a>(QueryBuilder<'a, Postgres>);

impl<'a> Filters<'a> {
    fn new(base: &str) -> Self {
        Filters(QueryBuilder::new(base))
    }

    fn eq<T>(&mut self, col: &str, val: T) -> &mut Self
    where
        T: 'a + sqlx::Encode<'a, Postgres> + sqlx::Type<Postgres> + Send,
    {
        self.0.push(" AND ").push(col).push(" = ").push_bind(val);
        self
    }

    /// `col = ANY($n)`: an allow-list, in one bind.
    fn eq_any(&mut self, col: &str, values: &'a [String]) -> &mut Self {
        self.0
            .push(" AND ")
            .push(col)
            .push(" = ANY(")
            .push_bind(values)
            .push(")");
        self
    }

    /// `col LIKE ANY($n)`: one round-trip whatever the number of patterns.
    fn like_any(&mut self, col: &str, patterns: &'a [String]) -> &mut Self {
        self.0
            .push(" AND ")
            .push(col)
            .push(" LIKE ANY(")
            .push_bind(patterns)
            .push(")");
        self
    }

    /// Appends a raw `AND <sql>`. Constant SQL only, never user input.
    fn raw(&mut self, sql: &str) -> &mut Self {
        self.0.push(" AND ").push(sql);
        self
    }
}

// `DISTINCT ON` keys on the machine as well as the id, because the two are
// independent: an id names its backend (`::cuda::`) but not the box, so two
// GPU machines running the same benchmark store the very same id. Keying on the
// id alone would keep whichever ran last and hide the other, which is fatal to
// a report electing a machine. For the reports pinned to one machine, the extra
// key changes nothing.
const BASE_QUERY: &str = "\
    SELECT DISTINCT ON (test.name, h.name) \
        test.name AS name, p.bit_size AS bit_size, m.value AS value, \
        h.name AS machine \
    FROM benchmark.metrics AS m \
    LEFT JOIN benchmark.hardware        AS h  ON m.hardware_id        = h.id \
    LEFT JOIN benchmark.backend         AS bk ON m.backend_id         = bk.id \
    LEFT JOIN benchmark.branch          AS b  ON m.branch_id          = b.id \
    LEFT JOIN benchmark.test            AS test ON m.test_id          = test.id \
    LEFT JOIN benchmark.parameters      AS p  ON m.parameters_id      = p.id \
    LEFT JOIN benchmark.project_version AS pv ON m.project_version_id = pv.id \
    WHERE true";

/// One stored result with the time it was inserted at.
///
/// The same row as [`BenchRow`] minus the "latest only" rule, plus what tells
/// two curves apart once several runs of one benchmark are on screen at the
/// same time.
#[derive(Debug, sqlx::FromRow)]
pub struct HistoryRow {
    pub name: String,
    pub bit_size: i64,
    pub value: f64,
    pub machine: String,
    /// The parameter set alias, `''` when the row has none.
    pub params: String,
    /// Seconds since the epoch. Extracted in SQL rather than decoded here: the
    /// column is `timestamp` on some deployments and `timestamptz` on others,
    /// and a typed decode would have to pick one.
    pub inserted_at: f64,
}

// No `DISTINCT ON`: every insertion is a point. `COALESCE` on the two columns
// reached through a `LEFT JOIN`, which the wider selections of a history do hit.
const HISTORY_QUERY: &str = "\
    SELECT test.name AS name, COALESCE(p.bit_size, 0) AS bit_size, m.value AS value, \
        h.name AS machine, COALESCE(p.crypto_parameters_alias, '') AS params, \
        EXTRACT(EPOCH FROM m.insert_time)::float8 AS inserted_at \
    FROM benchmark.metrics AS m \
    LEFT JOIN benchmark.hardware        AS h  ON m.hardware_id        = h.id \
    LEFT JOIN benchmark.backend         AS bk ON m.backend_id         = bk.id \
    LEFT JOIN benchmark.branch          AS b  ON m.branch_id          = b.id \
    LEFT JOIN benchmark.test            AS test ON m.test_id          = test.id \
    LEFT JOIN benchmark.parameters      AS p  ON m.parameters_id      = p.id \
    LEFT JOIN benchmark.project_version AS pv ON m.project_version_id = pv.id \
    WHERE true";

/// Every value each matching benchmark ever stored in the window, oldest first.
pub async fn fetch_bench_history(
    pool: &PgPool,
    q: &FetchQuery<'_>,
) -> anyhow::Result<Vec<HistoryRow>> {
    let mut f = Filters::new(HISTORY_QUERY);
    apply_filters(&mut f, q);
    f.0.push(" ORDER BY test.name, h.name, m.insert_time");

    let rows = f.0.build_query_as::<HistoryRow>().fetch_all(pool).await?;
    Ok(rows)
}

/// Latest value per `test.name` matching the filters.
pub async fn fetch_bench_rows(pool: &PgPool, q: &FetchQuery<'_>) -> anyhow::Result<Vec<BenchRow>> {
    let mut f = Filters::new(BASE_QUERY);
    apply_filters(&mut f, q);

    // Must open with the `DISTINCT ON` expressions; the trailing key is what
    // makes it "the most recent value of each id on each machine".
    f.0.push(" ORDER BY test.name, h.name, m.insert_time DESC");

    let rows = f.0.build_query_as::<BenchRow>().fetch_all(pool).await?;
    Ok(rows)
}

/// The `WHERE` clause both fetches share. Only the shape of the result and its
/// ordering differ between them.
fn apply_filters<'a>(f: &mut Filters<'a>, q: &'a FetchQuery<'a>) {
    f.eq("b.name", q.branch)
        .like_any("test.name", q.like_patterns)
        .eq_any("h.name", q.machines);

    if let Some(backend) = q.backend {
        f.eq("bk.name", backend);
    }

    if let Some(version) = q.project_version {
        f.eq("pv.name", version);
    }

    if let Some(pattern) = q.param_pattern {
        f.0.push(" AND p.crypto_parameters_alias LIKE ")
            .push_bind(pattern);
    }

    if q.exclude_non_default {
        // Default operations only. `smart_` was dropped from the benches in
        // a20ee6325; kept here for the historical rows.
        f.raw("test.name NOT SIMILAR TO '%(smart|unchecked)_%'");
    }

    match q.metric {
        Some(BenchmarkMetric::Latency) => {
            f.raw("test.name NOT LIKE '%::throughput::%'");
        }
        Some(BenchmarkMetric::Throughput) => {
            f.raw("test.name LIKE '%::throughput::%'");
        }
        _ => {}
    }

    match q.pbs_kind {
        PbsKind::Classical => {
            f.raw("p.crypto_parameters_alias NOT SIMILAR TO '%_MULTI_BIT_%'");
        }
        PbsKind::MultiBit => {
            f.raw("p.crypto_parameters_alias SIMILAR TO '%_MULTI_BIT_%'");
        }
        PbsKind::Any => {}
    }

    // Date window only when no exact commit was pinned. Anchored on the
    // requested date, which also closes the window, or on `now()`, in which case
    // there is nothing to close: no row can be inserted in the future.
    if q.project_version.is_none() {
        match q.bench_date {
            Some(date) => {
                f.0.push(" AND m.insert_time <= ")
                    .push_bind(date)
                    .push("::timestamp AND m.insert_time >= ")
                    .push_bind(date)
                    .push("::timestamp - make_interval(days => ")
                    .push_bind(q.time_span_days)
                    .push(")");
            }
            None => {
                f.0.push(" AND m.insert_time >= now() - make_interval(days => ")
                    .push_bind(q.time_span_days)
                    .push(")");
            }
        }
    }
}
