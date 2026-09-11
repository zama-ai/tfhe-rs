#!/usr/bin/env python3
"""Report the release status of every crate published from this repository.

Answers the two questions asked before each release:
  - which crates changed since their last release and need a version bump?
  - which crates are bumped in Cargo.toml but not published on crates.io yet?

Everything is derived, nothing is hand-maintained: the crate list comes from the
`make_release_*.yml` workflows, versions and the dependency graph from `cargo
metadata`, releases from the git tags, published versions from the crates.io
sparse index.
"""

import argparse
import json
import re
import ssl
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO / ".github" / "workflows"
INDEX_URL = "https://index.crates.io"

# Release tags are named `<package name>-<version>`, except for the main crate.
TAG_PREFIXES = {"tfhe": "tfhe-rs"}

MERMAID_HEADER = """---
config:
  layout: elk
  elk:
    mergeEdges: true
    nodePlacementStrategy: NETWORK_SIMPLEX
---
flowchart TD"""

OK = "OK"
BUMP = "BUMP"
TAG = "TAG"
PUBLISH = "PUBLISH"
MISMATCH = "MISMATCH"


def git(*args):
    result = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"git {' '.join(args)} failed:\n{result.stderr.strip()}")
    return result.stdout


def version_key(version):
    """Sort key ordering versions as semver does, not as plain strings.

    1.0.0-alpha.9 < 1.0.0-alpha.10 < 1.0.0-beta.1 < 1.0.0

    Build metadata does not take part in precedence, and a numeric prerelease
    identifier ranks below an alphanumeric one, hence the (rank, value) pairs.
    """
    core, _, pre = version.partition("+")[0].partition("-")
    numbers = tuple(int(part) for part in core.split("."))
    labels = (
        tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split("."))
        if pre
        else ()
    )
    return numbers, not pre, labels


def release_line(version):
    """Major and minor of `version`, identifying the line it is released from.

    1.6.5 and 1.6.0-alpha.0 belong to the 1.6 line, 1.8.0 does not.
    """
    return version_key(version)[0][:2]


def release_crates():
    """Crates released from this repo, mapped to the workflow releasing them."""
    crates = {}
    for workflow in sorted(WORKFLOW_DIR.glob("make_release_*.yml")):
        for name in re.findall(
            r'^\s*package-name:\s*"(.+)"\s*$', workflow.read_text(), re.M
        ):
            crates[name] = workflow.name
    return crates


def workspace_packages():
    # --locked keeps this script read-only: without it a stale Cargo.lock would be
    # rewritten just by asking for the crate versions.
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--locked", "--format-version", "1"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit(
            f"{result.stderr.strip()}\n"
            "If Cargo.lock is out of date, run `make update_cargo_lock`."
        )
    metadata = json.loads(result.stdout)
    return {package["name"]: package for package in metadata["packages"]}


def published_versions(name, context):
    """Versions of `name` on crates.io, oldest first."""
    lowered = name.lower()
    if len(lowered) <= 2:
        path = f"{len(lowered)}/{lowered}"
    elif len(lowered) == 3:
        path = f"3/{lowered[0]}/{lowered}"
    else:
        path = f"{lowered[:2]}/{lowered[2:4]}/{lowered}"

    try:
        body = urllib.request.urlopen(
            f"{INDEX_URL}/{path}", context=context, timeout=30
        ).read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return []
        raise
    return [json.loads(line)["vers"] for line in body.decode().splitlines() if line]


def version_at(rev, manifest):
    """Version declared by `manifest` at `rev`."""
    return tomllib.loads(git("show", f"{rev}:{manifest}"))["package"]["version"]


def consumer_facing(manifest_text):
    """Manifest contents that a consumer of the published crate can observe.

    dev-dependencies only build this repo's own tests and benches, so changing
    them is not a reason to release a new version.
    """
    manifest = tomllib.loads(manifest_text)
    manifest.pop("dev-dependencies", None)
    for target in manifest.get("target", {}).values():
        target.pop("dev-dependencies", None)
    return manifest


def crate_status(name, package, tags, published):
    version = package["version"]
    manifest = str(Path(package["manifest_path"]).relative_to(REPO))
    directory = str(Path(manifest).parent)
    prefix = TAG_PREFIXES.get(name, name)

    pattern = re.compile(rf"{re.escape(prefix)}-(\d+\.\d+\.\d+.*)")
    own_tags = sorted(
        (match.group(1) for match in map(pattern.fullmatch, tags) if match),
        key=version_key,
    )
    # The baseline is the newest release that is not newer than the manifest, so
    # that a release branch compares against its own last dot release rather than
    # against a later release made on main. Tags are not filtered by reachability
    # because squash-merging leaves release tags off the branch they landed on.
    released = [v for v in own_tags if version_key(v) <= version_key(version)]
    baseline = f"{prefix}-{released[-1]}" if released else None
    tag = f"{prefix}-{version}" if version in own_tags else None

    changed = (
        git("diff", "--name-only", f"{baseline}..HEAD", "--", directory).splitlines()
        if baseline
        else []
    )
    if manifest in changed and consumer_facing(
        git("show", f"{baseline}:{manifest}")
    ) == consumer_facing(git("show", f"HEAD:{manifest}")):
        changed.remove(manifest)
    latest = max(published, key=version_key) if published else None
    # A release branch legitimately sits below the latest version published from
    # main, so only a release on the manifest's own line means it is stale.
    line = [v for v in published if release_line(v) == release_line(version)]
    line_latest = max(line, key=version_key) if line else None

    detail = ""
    if version in published:
        status = BUMP if changed else OK
    elif line_latest and version_key(version) < version_key(line_latest):
        status = MISMATCH
        detail = f"manifest version is behind crates.io ({line_latest})"
    elif tag:
        status = PUBLISH
        at_tag = version_at(tag, manifest)
        if at_tag != version:
            status = MISMATCH
            detail = f"tag {tag} points at a commit declaring version {at_tag}"
    else:
        status = TAG
        # The version is read from the working tree but the tag would land on
        # HEAD, so an uncommitted bump would tag the version it replaces.
        at_head = version_at("HEAD", manifest)
        if at_head != version:
            status = MISMATCH
            detail = f"HEAD declares version {at_head}, commit the bump before tagging"

    return {
        "crate": name,
        "version": version,
        "published": latest,
        "baseline_tag": baseline,
        "tag": tag or f"{prefix}-{version}",
        "tag_exists": tag is not None,
        "manifest": manifest,
        "changed_files": changed,
        "status": status,
        "detail": detail,
    }


def release_dependencies(package, names):
    """Crates of `names` that `package` depends on, dev-dependencies excluded."""
    return sorted(
        {
            dependency["name"]
            for dependency in package["dependencies"]
            if dependency["name"] in names and dependency["kind"] != "dev"
        }
    )


def publish_order(names, packages):
    """Crate names sorted so that a crate comes after the crates it depends on."""
    requirements = {
        name: set(release_dependencies(packages[name], names)) for name in names
    }
    ordered, done = [], set()
    while len(ordered) < len(names):
        ready = sorted(n for n in names if n not in done and requirements[n] <= done)
        if not ready:
            ready = sorted(set(names) - done)
        ordered.extend(ready)
        done.update(ready)
    return ordered


def print_table(reports):
    columns = [
        ("crate", lambda r: r["crate"]),
        ("manifest", lambda r: r["version"]),
        ("crates.io", lambda r: r["published"] or "-"),
        ("baseline tag", lambda r: r["baseline_tag"] or "-"),
        (
            "changes",
            lambda r: str(len(r["changed_files"])) if r["baseline_tag"] else "-",
        ),
        ("status", lambda r: r["status"]),
    ]
    rows = [[header for header, _ in columns]]
    rows += [[value(report) for _, value in columns] for report in reports]
    widths = [max(len(row[i]) for row in rows) for i in range(len(columns))]
    for row in rows:
        print("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip())


def print_actions(reports, workflows, show_files):
    by_status = {}
    for report in reports:
        by_status.setdefault(report["status"], []).append(report)
    pending = {r["crate"] for r in reports if r["status"] in (TAG, PUBLISH)}

    for report in by_status.get(MISMATCH, []):
        print(f"\n!! {report['crate']}: {report['detail']}")

    if BUMP in by_status:
        print("\nChanged since their last release, version bump needed:")
        for report in by_status[BUMP]:
            print(
                f"  {report['crate']}: {len(report['changed_files'])} changed file(s)"
                f" since {report['baseline_tag']}, bump {report['manifest']}"
            )
            if show_files:
                for path in report["changed_files"]:
                    print(f"      {path}")

    if TAG in by_status:
        print("\nBumped but not tagged, create the tags in this order:")
        for report in by_status[TAG]:
            tag = report["tag"]
            print(
                f"  git tag -s -a -m \"{report['crate']} {report['version']} release\""
                f" {tag} && git push origin tag {tag}"
            )
            print(f"      then run {workflows[report['crate']]} on tag {tag}")

    if PUBLISH in by_status:
        print("\nTagged but not on crates.io, run these workflows in this order:")
        for report in by_status[PUBLISH]:
            print(f"  {workflows[report['crate']]} on tag {report['tag']}")

    for report in by_status.get(TAG, []) + by_status.get(PUBLISH, []):
        blockers = sorted(pending & set(report["dependencies"]))
        if blockers:
            print(
                f"\nNote: publish {', '.join(blockers)} before {report['crate']};"
                " cargo publish fails on a dependency that is not on crates.io yet."
            )

    if set(by_status) <= {OK}:
        print("\nNothing to do: every released crate is up to date on crates.io.")


def pruned_dependencies(names, packages):
    """Dependency edges with the transitive ones removed, keeping the graph readable.

    An edge is kept only when the dependency cannot already be reached through
    another dependency, so `tfhe -> tfhe-versionable` is dropped in favour of
    `tfhe -> tfhe-zk-pok -> tfhe-safe-serialize -> tfhe-versionable`.
    """
    closure, kept = {}, {}
    # publish order guarantees that a crate is visited after its dependencies.
    for name in publish_order(names, packages):
        direct = release_dependencies(packages[name], names)
        indirect = set().union(set(), *(closure[dep] for dep in direct))
        kept[name] = [dep for dep in direct if dep not in indirect]
        closure[name] = set(direct) | indirect
    return kept


def print_mermaid(names, packages):
    print(MERMAID_HEADER)
    edges = pruned_dependencies(names, packages)
    for name in publish_order(names, packages):
        print(f'    {name.replace("-", "_")}["{name}"]')
    for name in sorted(names):
        for dependency in edges[name]:
            print(f'    {dependency.replace("-", "_")} --> {name.replace("-", "_")}')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--crate", action="append", help="only report this crate")
    parser.add_argument("--files", action="store_true", help="list the changed files")
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument(
        "--mermaid", action="store_true", help="print the release dependency graph"
    )
    parser.add_argument(
        "--check", action="store_true", help="exit with 1 if a crate needs attention"
    )
    args = parser.parse_args()

    workflows = release_crates()
    packages = workspace_packages()
    names = [name for name in workflows if not args.crate or name in args.crate]
    unknown = set(args.crate or []) - set(workflows)
    if unknown:
        parser.error(f"not released from this repo: {', '.join(sorted(unknown))}")

    if args.mermaid:
        print_mermaid(list(workflows), packages)
        return 0

    tags = git("tag").split()
    context = ssl.create_default_context()

    reports = []
    for name in publish_order(names, packages):
        try:
            published = published_versions(name, context)
        except (urllib.error.URLError, ssl.SSLError) as error:
            print(
                f"could not reach {INDEX_URL}: {error}\n"
                "Set SSL_CERT_FILE if you are behind a TLS-intercepting proxy.",
                file=sys.stderr,
            )
            return 2
        report = crate_status(name, packages[name], tags, published)
        report["dependencies"] = release_dependencies(packages[name], workflows)
        reports.append(report)

    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        print_table(reports)
        print_actions(reports, workflows, args.files)

    if args.check and any(report["status"] != OK for report in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
