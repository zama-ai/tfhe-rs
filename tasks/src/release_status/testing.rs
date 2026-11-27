//! Stand-ins for git and crates.io, and shorthands to describe a situation in a test.

use super::Error;
use super::crate_registry::CrateRegistry;
use super::git::Vcs;
use super::workspace::ReleaseCrate;
use cargo_metadata::semver::Version;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A repository that only knows what a test told it.
#[derive(Default)]
pub struct FakeRepo {
    tags: Vec<String>,
    fork_point: Option<String>,
    changes: HashMap<(String, String), Vec<String>>,
    files: HashMap<(String, String), String>,
}

impl FakeRepo {
    pub fn tags(mut self, tags: &[&str]) -> Self {
        self.tags = self::tags(tags);
        self
    }

    pub fn fork_point(mut self, fork_point: &str) -> Self {
        self.fork_point = Some(fork_point.to_owned());
        self
    }

    /// `paths` under `directory` differ between `base` and HEAD.
    pub fn change(mut self, base: &str, directory: &str, paths: &[&str]) -> Self {
        self.changes.insert(
            (base.to_owned(), directory.to_owned()),
            paths.iter().map(|path| path.to_string()).collect(),
        );
        self
    }

    /// `path` holds `content` at `rev`.
    pub fn file(mut self, rev: &str, path: &str, content: &str) -> Self {
        self.files
            .insert((rev.to_owned(), path.to_owned()), content.to_owned());
        self
    }
}

impl Vcs for FakeRepo {
    fn tags(&self) -> Result<Vec<String>, Error> {
        Ok(self.tags.clone())
    }

    fn fork_point(&self) -> Result<String, Error> {
        self.fork_point
            .clone()
            .ok_or_else(|| Error::Fatal("no fork point".to_owned()))
    }

    fn changed_files(&self, base: &str, directory: &str) -> Result<Vec<String>, Error> {
        let key = (base.to_owned(), directory.to_owned());
        Ok(self.changes.get(&key).cloned().unwrap_or_default())
    }

    fn file_at(&self, rev: &str, path: &str) -> Result<Option<String>, Error> {
        Ok(self.files.get(&(rev.to_owned(), path.to_owned())).cloned())
    }
}

/// A registry that only has what a test published, and is down for the crates of `unreachable`.
#[derive(Default)]
pub struct FakeRegistry {
    published: HashMap<String, Vec<Version>>,
    unreachable: Vec<String>,
}

impl FakeRegistry {
    pub fn publish(mut self, name: &str, versions: &[&str]) -> Self {
        self.published
            .insert(name.to_owned(), self::versions(versions));
        self
    }

    pub fn unreachable(mut self, name: &str) -> Self {
        self.unreachable.push(name.to_owned());
        self
    }
}

impl CrateRegistry for FakeRegistry {
    fn published_versions(&self, name: &str) -> Result<Vec<Version>, Error> {
        if self
            .unreachable
            .iter()
            .any(|unreachable| unreachable == name)
        {
            return Err(Error::Registry(format!("could not reach {name}")));
        }
        Ok(self.published.get(name).cloned().unwrap_or_default())
    }
}

/// A released crate living in a directory named after it at the root of the repository.
pub fn krate(name: &str, version: &str, dependencies: &[&str]) -> ReleaseCrate {
    let mut dependencies: Vec<String> = dependencies.iter().map(|d| d.to_string()).collect();
    dependencies.sort();
    ReleaseCrate {
        name: name.to_owned(),
        version: Version::parse(version).unwrap(),
        manifest: format!("{name}/Cargo.toml"),
        directory: name.to_owned(),
        dependencies,
    }
}

/// A manifest declaring `version`, followed by `rest`.
pub fn manifest(version: &str, rest: &str) -> String {
    format!(
        "[package]\n\
            name = \"a-crate\"\n\
            version = \"{version}\"\n\
            {rest}"
    )
}

pub fn tags(tags: &[&str]) -> Vec<String> {
    tags.iter().map(|tag| tag.to_string()).collect()
}

pub fn versions(versions: &[&str]) -> Vec<Version> {
    versions
        .iter()
        .map(|version| Version::parse(version).unwrap())
        .collect()
}

/// A scratch directory, removed when dropped.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "xtask-release-status-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write `content` to the file at `path`, creating its directory.
    pub fn write(&self, path: &str, content: &str) {
        let path = self.path.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
