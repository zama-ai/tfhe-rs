use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use cargo_metadata::Message;
use forward_common::{ARTIFACTS, Cell, Matrix};

const ENTRIES: [(&str, &str); 2] = [("1.5.3", "compat_15"), ("1.6.1", "compat_16")];

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("orchestrator has a parent dir")
        .to_path_buf()
}

struct Version {
    label: String,
    manifest: PathBuf,
    data_dir: PathBuf,
}

fn build_and_locate(manifest: &Path) -> PathBuf {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--release")
        .arg("--message-format=json");
    cmd.arg("--manifest-path").arg(manifest);
    cmd.stderr(Stdio::inherit());
    let out = cmd.output().expect("failed to spawn cargo build");
    if !out.status.success() {
        eprintln!("build failed: {}", manifest.display());
        std::process::exit(1);
    }
    Message::parse_stream(out.stdout.as_slice())
        .filter_map(Result::ok)
        .find_map(|msg| match msg {
            Message::CompilerArtifact(artifact) => artifact.executable,
            _ => None,
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            eprintln!("no executable produced for {}", manifest.display());
            std::process::exit(1);
        })
}

fn run_bin(bin: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", bin.display()))
}

fn main() {
    let root = project_root();
    let workdir = root.join(".work");

    let versions: Vec<Version> = ENTRIES
        .iter()
        .map(|(label, dir)| {
            let safe = label.replace(['.', '/', ' '], "_");
            Version {
                manifest: root.join(dir).join("Cargo.toml"),
                data_dir: workdir.join(format!("data_{safe}")),
                label: label.to_string(),
            }
        })
        .collect();

    let bins: Vec<PathBuf> = versions
        .iter()
        .map(|v| {
            eprintln!(">> building {} ({})", v.label, v.manifest.display());
            build_and_locate(&v.manifest)
        })
        .collect();

    produce_all(&versions, &bins);

    let n = versions.len();
    let directions: Vec<(usize, usize)> =
        (0..n).flat_map(|p| (0..n).map(move |c| (p, c))).collect();

    let mut results = run_matrix(&directions, &versions, &bins);

    let rows: Vec<(String, Vec<Option<Cell>>)> = ARTIFACTS
        .iter()
        .map(|a| {
            let cells = (0..directions.len())
                .map(|di| results[di].remove(a.name))
                .collect();
            (a.name.to_string(), cells)
        })
        .collect();

    let matrix = Matrix {
        versions: versions.into_iter().map(|v| v.label).collect(),
        directions,
        rows,
    };

    let markdown = matrix.render_markdown();
    print!("{markdown}");
    std::fs::write(workdir.join("matrix.md"), &markdown).expect("failed to write matrix.md");
}

fn produce_all(versions: &[Version], bins: &[PathBuf]) {
    std::thread::scope(|s| {
        let handles: Vec<_> = versions
            .iter()
            .zip(bins)
            .map(|(v, bin)| {
                s.spawn(move || (v, run_bin(bin, &["produce", v.data_dir.to_str().unwrap()])))
            })
            .collect();
        for h in handles {
            let (v, out) = h.join().unwrap();
            eprint!("{}", String::from_utf8_lossy(&out.stderr));
            if !out.status.success() {
                eprintln!("produce failed for {}", v.label);
                std::process::exit(1);
            }
        }
    });
}

fn check_direction(producer: &Version, consumer_bin: &Path) -> HashMap<String, Cell> {
    let out = run_bin(
        consumer_bin,
        &["consume", producer.data_dir.to_str().unwrap()],
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(forward_common::parse_report)
        .map(|r| {
            (
                r.name,
                Cell {
                    ok: r.ok,
                    detail: r.detail,
                },
            )
        })
        .collect()
}

fn run_matrix(
    directions: &[(usize, usize)],
    versions: &[Version],
    bins: &[PathBuf],
) -> Vec<HashMap<String, Cell>> {
    std::thread::scope(|s| {
        directions
            .iter()
            .map(|&(p, c)| s.spawn(move || check_direction(&versions[p], &bins[c])))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    })
}
