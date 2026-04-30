use std::collections::{HashMap, HashSet};
use std::fmt::Display;

use cargo_metadata::MetadataCommand;
use cargo_metadata::semver::{Version, VersionReq};

#[derive(Debug, Clone)]
struct WorkspaceData {
    version: Version,
    is_publishable: bool,
}

impl WorkspaceData {
    fn from_package(pkg: &cargo_metadata::Package) -> Self {
        let is_publishable = match &pkg.publish {
            Some(publish) => !publish.is_empty(),
            None => true,
        };
        WorkspaceData {
            version: pkg.version.clone(),
            is_publishable,
        }
    }
}

struct LocalWorkspaceVersionChange {
    pkg_name: String,
    dep_name: String,
    dep_req: VersionReq,
    ws_version: Version,
}

impl Display for LocalWorkspaceVersionChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} depends on {} {} but workspace has {}",
            self.pkg_name, self.dep_name, self.dep_req, self.ws_version
        )
    }
}

struct CratePublishInformationMissing {
    pkg_name: String,
}

impl Display for CratePublishInformationMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Crate {}", self.pkg_name)
    }
}

fn req_exact_version(req: &VersionReq) -> Option<Version> {
    if req.comparators.len() == 1 {
        let c = &req.comparators[0];
        Some(Version::new(
            c.major,
            c.minor.unwrap_or(0),
            c.patch.unwrap_or(0),
        ))
    } else {
        None
    }
}

#[derive(Debug, PartialEq)]
enum DepStatus {
    /// Version requirement matches the workspace version.
    Ok,
    /// Version requirement doesn't match the workspace version.
    Outdated,
    /// Dep uses `*` — acceptable, but the parent crate must not be publishable.
    Star,
}

/// Check whether a local dependency requirement is acceptable.
/// Local deps must either use `*` or pin the exact workspace version.
fn check_dep_status(dep_req: &VersionReq, ws_version: &Version) -> DepStatus {
    if *dep_req == VersionReq::STAR {
        return DepStatus::Star;
    }
    match req_exact_version(dep_req) {
        Some(exact) if exact == *ws_version => DepStatus::Ok,
        _ => DepStatus::Outdated,
    }
}

pub fn check_local_workspace_version() {
    let metadata = MetadataCommand::new().exec().unwrap();

    let workspace_versions: HashMap<&str, WorkspaceData> = metadata
        .workspace_packages()
        .iter()
        .map(|p| (p.name.as_str(), WorkspaceData::from_package(p)))
        .collect();

    let mut publishable_with_star: HashSet<String> = HashSet::new();
    let mut outdateds: Vec<LocalWorkspaceVersionChange> = Vec::new();

    for pkg in metadata.workspace_packages() {
        let pkg_ws = workspace_versions.get(pkg.name.as_str());
        let pkg_is_publishable = pkg_ws.is_some_and(|ws| ws.is_publishable);

        for dep in &pkg.dependencies {
            if dep.source.is_none()
                && let Some(ws) = workspace_versions.get(dep.name.as_str())
            {
                match check_dep_status(&dep.req, &ws.version) {
                    DepStatus::Ok => {}
                    DepStatus::Outdated => {
                        outdateds.push(LocalWorkspaceVersionChange {
                            pkg_name: pkg.name.to_string(),
                            dep_name: dep.name.to_string(),
                            dep_req: dep.req.clone(),
                            ws_version: ws.version.clone(),
                        });
                    }
                    DepStatus::Star if pkg_is_publishable => {
                        publishable_with_star.insert(pkg.name.to_string());
                    }
                    DepStatus::Star => {}
                }
            }
        }
    }

    let missing_publish_info: Vec<_> = publishable_with_star
        .into_iter()
        .map(|pkg_name| CratePublishInformationMissing { pkg_name })
        .collect();

    print_results(&missing_publish_info, &outdateds);
}

fn print_results(
    missing_publish_info: &[CratePublishInformationMissing],
    outdateds: &[LocalWorkspaceVersionChange],
) {
    if !missing_publish_info.is_empty() {
        eprintln!("❌ Crates missing publish information:\n");
        eprintln!(
            "The following crate(s) have local dependencies with `*` version requirement, \
            but are publishable. Please either pin the dependency to the exact workspace \
            version or add `publish = false` to the crate's manifest."
        );
        for missing in missing_publish_info {
            eprintln!("\t{missing}");
        }
        eprintln!("\n{} issue(s) to fix.\n", missing_publish_info.len());
    }

    if outdateds.is_empty() {
        println!("✅ All local workspace dependencies are up to date.");
    } else {
        eprintln!("❌ Outdated local dependencies found:\n");
        for outdated in outdateds {
            eprintln!("\t{outdated}");
        }
        eprintln!("\n{} issue(s) to fix.", outdateds.len());
    }

    if !missing_publish_info.is_empty() || !outdateds.is_empty() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- req_exact_version ----

    #[test]
    fn req_exact_version_single_comparator() {
        let req: VersionReq = "^0.7.0".parse().unwrap();
        assert_eq!(req_exact_version(&req), Some(Version::new(0, 7, 0)));
    }

    #[test]
    fn req_exact_version_exact_syntax() {
        let req: VersionReq = "=1.2.3".parse().unwrap();
        assert_eq!(req_exact_version(&req), Some(Version::new(1, 2, 3)));
    }

    #[test]
    fn req_exact_version_only_major_minor() {
        let req: VersionReq = "^2.1".parse().unwrap();
        assert_eq!(req_exact_version(&req), Some(Version::new(2, 1, 0)));
    }

    #[test]
    fn req_exact_version_multiple_comparators_returns_none() {
        let req: VersionReq = ">=1.0.0, <2.0.0".parse().unwrap();
        assert_eq!(req_exact_version(&req), None);
    }

    #[test]
    fn req_exact_version_star_returns_none() {
        let req = VersionReq::STAR;
        assert_eq!(req_exact_version(&req), None);
    }

    // ---- check_dep_status ----

    #[test]
    fn matching_version_is_ok() {
        let req: VersionReq = "^0.7.0".parse().unwrap();
        assert_eq!(
            check_dep_status(&req, &Version::new(0, 7, 0)),
            DepStatus::Ok
        );
    }

    #[test]
    fn version_behind_workspace_is_outdated() {
        let req: VersionReq = "^0.6.0".parse().unwrap();
        assert_eq!(
            check_dep_status(&req, &Version::new(0, 7, 0)),
            DepStatus::Outdated
        );
    }

    #[test]
    fn version_ahead_of_workspace_is_outdated() {
        let req: VersionReq = "^0.8.0".parse().unwrap();
        assert_eq!(
            check_dep_status(&req, &Version::new(0, 7, 0)),
            DepStatus::Outdated
        );
    }

    #[test]
    fn patch_mismatch_is_outdated() {
        let req: VersionReq = "^1.2.3".parse().unwrap();
        assert_eq!(
            check_dep_status(&req, &Version::new(1, 2, 4)),
            DepStatus::Outdated
        );
    }

    #[test]
    fn range_requirement_is_always_outdated() {
        let req: VersionReq = ">=1.0.0, <2.0.0".parse().unwrap();
        assert_eq!(
            check_dep_status(&req, &Version::new(5, 0, 0)),
            DepStatus::Outdated
        );
        assert_eq!(
            check_dep_status(&req, &Version::new(1, 5, 0)),
            DepStatus::Outdated
        );
    }

    #[test]
    fn star_returns_star_status() {
        let req = VersionReq::STAR;
        assert_eq!(
            check_dep_status(&req, &Version::new(1, 0, 0)),
            DepStatus::Star
        );
    }
}
