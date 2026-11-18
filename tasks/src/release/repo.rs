//! The repository being released: its git history, its tags and its cargo workspace.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use cargo_metadata::{Metadata, MetadataCommand};

use super::{Failure, Result};
use crate::utils::project_root;

pub struct Repo {
    pub root: PathBuf,
}

impl Repo {
    /// The repository at `path`, the one holding this tool by default.
    pub fn new(path: Option<&Path>) -> Result<Self> {
        let root = path.map_or_else(project_root, Path::to_path_buf);
        // cargo reports the paths of the manifests from this one, which they are compared with.
        let root = root
            .canonicalize()
            .map_err(|error| Failure::new(format!("{}: {error}", root.display())))?;
        Ok(Self { root })
    }

    pub fn git(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .output()
            .map_err(|error| Failure::new(format!("could not run git: {error}")))?;
        if !output.status.success() {
            let reason = String::from_utf8_lossy(&output.stderr);
            return Err(Failure::new(format!(
                "git {} failed:\n{}",
                args.join(" "),
                reason.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// What cargo knows about the workspace: its packages and its directories.
    pub fn metadata(&self) -> Result<Metadata> {
        MetadataCommand::new()
            .manifest_path(self.root.join("Cargo.toml"))
            .current_dir(&self.root)
            .no_deps()
            // --locked keeps this read-only: without it a stale Cargo.lock would be rewritten
            // just by asking for the crate versions.
            .other_options(vec!["--locked".to_owned()])
            .exec()
            .map_err(|error| {
                Failure::new(format!(
                    "{error}\nIf Cargo.lock is out of date, run `make update_cargo_lock`."
                ))
            })
    }

    /// The commit being released.
    pub fn head(&self) -> Result<String> {
        Ok(self.git(&["rev-parse", "HEAD"])?.trim().to_owned())
    }

    /// Commit each tag of the repository points at.
    pub fn tag_commits(&self) -> Result<BTreeMap<String, String>> {
        // %(*objectname) is the commit of an annotated tag, empty for a lightweight one, whose
        // %(objectname) is the commit itself.
        let format = "--format=%(refname:short) %(*objectname) %(objectname)";
        let refs = self.git(&["for-each-ref", format, "refs/tags"])?;
        Ok(refs
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                Some((fields.next()?.to_owned(), fields.next()?.to_owned()))
            })
            .collect())
    }

    /// The manifest at `path`, as it is at `rev`.
    pub fn manifest_at(&self, rev: &str, path: &str) -> Result<toml::Table> {
        let content = self.git(&["show", &format!("{rev}:{path}")])?;
        toml::from_str(&content)
            .map_err(|error| Failure::new(format!("{path} at {rev} is not a manifest: {error}")))
    }

    /// Version declared by the manifest at `path`, as it is at `rev`.
    pub fn version_at(&self, rev: &str, path: &str) -> Result<String> {
        let manifest = self.manifest_at(rev, path)?;
        let version = manifest
            .get("package")
            .and_then(|package| package.get("version"));
        match version.and_then(toml::Value::as_str) {
            Some(version) => Ok(version.to_owned()),
            None => Err(Failure::new(format!(
                "{path} at {rev} does not declare a version"
            ))),
        }
    }
}
