use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use forward_common::{ARTIFACTS, Matrix, Outcome};

fn is_version_dir(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn retrieve_entries(root: &PathBuf) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = std::fs::read_dir(root)
        .expect("read project root")
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let dir = e.file_name().to_string_lossy().into_owned();
            let label = dir.strip_prefix("compat_")?.replace('_', ".");
            if is_version_dir(&label) || label == forward_common::NIGHTLY {
                Some((label, dir))
            } else {
                println!("skipping {} (not a version dir)", dir);
                None
            }
        })
        .collect();
    entries.sort();
    println!("Found {} entries: {:?}", entries.len(), entries);
    entries
}

/// Exit code telling the CI the matrix no longer matches the reviewed baseline,
/// as opposed to the tool itself having failed.
const BASELINE_MOVED: i32 = 2;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("orchestrator has a parent dir")
        .to_path_buf()
}

struct Version {
    version: String,
    manifest: PathBuf,
    data_dir: PathBuf,
}

fn spawn_version(manifest: &Path, args: &[&str]) -> Child {
    Command::new("cargo")
        .args(["run", "--release", "--quiet", "--manifest-path"])
        .arg(manifest)
        .arg("--")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn cargo")
}

fn main() {
    let root = project_root();
    let workdir = root.join(".work");
    let entries = retrieve_entries(&root);

    let versions: Vec<Version> = entries
        .iter()
        .map(|(label, dir)| {
            let safe = label.replace(['.', '/', ' '], "_");
            Version {
                manifest: root.join(dir).join("Cargo.toml"),
                data_dir: workdir.join(format!("data_{safe}")),
                version: label.to_string(),
            }
        })
        .collect();

    produce_all(&versions);

    let n = versions.len();
    let directions: Vec<(usize, usize)> = (0..n)
        .flat_map(|p| (0..n).map(move |c| (p, c)))
        .filter(|&(p, c)| p > c)
        .collect();

    let mut results = run_matrix(&directions, &versions);

    let rows: Vec<(String, Vec<Option<Outcome>>)> = ARTIFACTS
        .iter()
        .map(|a| {
            let cells = (0..directions.len())
                .map(|di| results[di].remove(a.name))
                .collect();
            (a.name.to_string(), cells)
        })
        .collect();

    let matrix = Matrix {
        versions: versions.into_iter().map(|v| v.version).collect(),
        directions,
        rows,
    };

    // Read the reviewed state before overwriting it, so the report can tell what
    // this branch moved. A missing file means everything is new.
    let baseline_path = root.join(forward_common::BASELINE_FILE);
    let reviewed = match std::fs::read_to_string(&baseline_path) {
        Ok(content) => forward_common::parse_baseline(&content),
        Err(err) => {
            eprintln!(
                "no baseline to compare against at {}: {err}",
                baseline_path.display()
            );
            forward_common::Baseline::new()
        }
    };
    let current = matrix.baseline();
    let diff = forward_common::diff_baseline(&reviewed, &current);
    std::fs::write(&baseline_path, forward_common::render_baseline(&current))
        .expect("failed to write baseline");

    let markdown = matrix.render_markdown(Some(&diff));
    print!("{markdown}");
    std::fs::write(root.join("matrix.md"), &markdown).expect("failed to write matrix.md");

    // A reason that moved on its own is not worth anyone's time: only a status
    // change, a new cell or a lost one means the baseline was not reviewed.
    if diff.has_status_changes() {
        eprintln!(
            "the matrix no longer matches {}, review it and commit the regenerated file",
            forward_common::BASELINE_FILE
        );
        std::process::exit(BASELINE_MOVED);
    }
}

fn produce_all(versions: &[Version]) {
    let handles: Vec<(_, _)> = versions
        .iter()
        .map(|v| {
            (
                spawn_version(&v.manifest, &["produce", v.data_dir.to_str().unwrap()]),
                &v.version,
            )
        })
        .collect();

    for (child, version) in handles {
        let out = child.wait_with_output().expect("failed to wait");
        if !out.status.success() {
            panic!(
                "version {version} failed to produce data: {}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
    }
}

fn parse_cells(out: &Output) -> HashMap<String, Outcome> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(forward_common::parse_report)
        .map(|r| {
            (
                r.name,
                Outcome {
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
) -> Vec<HashMap<String, Outcome>> {
    let children: Vec<Child> = directions
        .iter()
        .map(|&(p, c)| {
            spawn_version(
                &versions[c].manifest,
                &["consume", versions[p].data_dir.to_str().unwrap()],
            )
        })
        .collect();

    children
        .into_iter()
        .map(|child| {
            let out = child
                .wait_with_output()
                .expect("failed to wait for consume");
            parse_cells(&out)
        })
        .collect()
}
