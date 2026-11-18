#!/usr/bin/env python3
"""Report the release status of every crate published from this repository.

Answers the two questions asked before each release:
  - which crates changed since their last release and need a version bump?
  - which crates are bumped in Cargo.toml but not published on crates.io yet?

Everything is derived, nothing is hand-maintained: the crate list, versions and
the dependency graph come from `cargo metadata`, releases from the git tags,
published versions from the index of the registry, crates.io unless told
otherwise.

scripts/release_publish.py builds on this report to publish the crates.
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
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
from pathlib import Path

# The repository holding this script, see use_repo() to work on another one.
REPO = Path(__file__).resolve().parent.parent
# The name cargo gives to crates.io, and its index: the registry of a release
# unless --registry and --index name another one, as the release test run does.
CRATES_IO = "crates-io"
CRATES_IO_INDEX = "https://index.crates.io"
# crates.io asks its clients to identify themselves.
USER_AGENT = "tfhe-rs release_status (https://github.com/zama-ai/tfhe-rs)"

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


def use_repo(path):
    """Work on the repository at `path` rather than on the one holding this script."""
    global REPO
    REPO = Path(path).resolve()


class Registry:
    """The registry the crates are released to."""

    def __init__(self, name=CRATES_IO, index=None):
        if name != CRATES_IO and not index:
            sys.exit(f"--index is required to release to {name}")
        # What cargo calls it, as in `cargo publish --registry`.
        self.name = name
        # cargo configuration files write the same URL with a sparse+ prefix.
        self.index = (index or CRATES_IO_INDEX).removeprefix("sparse+").rstrip("/")
        # What to call it in a message.
        self.label = "crates.io" if name == CRATES_IO else name


def add_repo_arguments(parser):
    """Arguments choosing what is released and where to, see open_repo()."""
    parser.add_argument(
        "--repo",
        metavar="PATH",
        help="repository to work on, defaults to the one holding this script",
    )
    parser.add_argument(
        "--registry",
        default=CRATES_IO,
        metavar="NAME",
        help="registry the crates are released to, by the name cargo knows it by,"
        " defaults to crates.io",
    )
    parser.add_argument(
        "--index",
        metavar="URL",
        help="sparse index of --registry, required unless it is crates.io",
    )


def open_repo(args):
    """Apply the arguments of add_repo_arguments(), return the registry they name."""
    if args.repo:
        use_repo(args.repo)
    return Registry(args.registry, args.index)


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


def release_crates(packages, registry=CRATES_IO):
    """Crates this repo releases: every package cargo may publish to `registry`."""
    return sorted(
        name
        for name, p in packages.items()
        if p["publish"] is None or p["publish"] is True or registry in p["publish"]
    )


def cargo_metadata():
    """What cargo knows about the workspace: its packages and its directories."""
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
    return json.loads(result.stdout)


def workspace_packages(metadata=None):
    metadata = metadata or cargo_metadata()
    return {package["name"]: package for package in metadata["packages"]}


def index_path(name):
    """Path of the file listing the versions of crate `name` in a registry index."""
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def published_versions(name, index, context):
    """Versions of `name` in the registry, each with the checksum of its crate file.

    The index is what cargo itself reads, and all a registry is required to
    serve. A yanked version is listed like any other: it cannot be published again.
    """
    request = urllib.request.Request(
        f"{index}/{index_path(name)}", headers={"User-Agent": USER_AGENT}
    )
    try:
        body = urllib.request.urlopen(request, context=context, timeout=30).read()
    except urllib.error.HTTPError as error:
        if error.code in (404, 410):
            return {}
        raise
    entries = (json.loads(line) for line in body.splitlines() if line.strip())
    return {entry["vers"]: entry["cksum"] for entry in entries}


def fetch_published(names, index):
    """Published versions of each crate of `names`, see published_versions().

    Raises OSError when the registry cannot be reached.
    """
    context = ssl.create_default_context()
    # One connection per crate, so the fetches are worth overlapping.
    with ThreadPoolExecutor(max_workers=8) as pool:
        versions = pool.map(published_versions, names, repeat(index), repeat(context))
        return dict(zip(names, versions))


def tag_commits():
    """Commit each tag of the repository points at."""
    # %(*objectname) is the commit of an annotated tag, empty for a lightweight
    # one, whose %(objectname) is the commit itself.
    refs = git(
        "for-each-ref",
        "--format=%(refname:short) %(*objectname) %(objectname)",
        "refs/tags",
    )
    return {name: commits[0] for name, *commits in map(str.split, refs.splitlines())}


def version_at(rev, manifest):
    """Version declared by `manifest` at `rev`."""
    return tomllib.loads(git("show", f"{rev}:{manifest}"))["package"]["version"]


def strip_not_consumer_facing_keys(manifest_text):
    """Manifest contents that a consumer of the published crate can observe.

    dev-dependencies only build this repo's own tests and benches, so changing
    them is not a reason to release a new version.
    """
    manifest = tomllib.loads(manifest_text)
    manifest.pop("dev-dependencies", None)
    for target in manifest.get("target", {}).values():
        target.pop("dev-dependencies", None)
    return manifest


def fork_point():
    """Commit this branch was cut from, be it main or a release branch."""
    if len(git("rev-parse", "HEAD^@").split()) > 1:
        # A merge carries the merged branch's commits, which are not this branch's work.
        sys.exit("HEAD is a merge commit, pass a base: --pr-gate HEAD^1 in CI")
    own = git(
        "rev-list", "HEAD", "--not", "--glob=refs/remotes/origin/release/", "origin/main"
    ).splitlines()
    if not own:
        sys.exit("HEAD has no commits of its own, there is nothing to gate.")
    return f"{own[-1]}^"


def crate_status(name, package, tags, published, registry, base=None):
    """Where crate `name` stands, given the commit of each tag of the repository
    and the versions of the crate published to `registry`."""
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
    # `base` overrides all of this for the pull request gate.
    released = [v for v in own_tags if version_key(v) <= version_key(version)]
    baseline = base or (f"{prefix}-{released[-1]}" if released else None)
    tag = f"{prefix}-{version}" if version in own_tags else None

    changed = (
        git("diff", "--name-only", f"{baseline}..HEAD", "--", directory).splitlines()
        if baseline
        else []
    )
    if manifest in changed and strip_not_consumer_facing_keys(
        git("show", f"{baseline}:{manifest}")
    ) == strip_not_consumer_facing_keys(git("show", f"HEAD:{manifest}")):
        changed.remove(manifest)
    latest = max(published, key=version_key) if published else None
    # A release branch legitimately sits below the latest version published from
    # main, so only a release on the manifest's own line means it is stale.
    line = [v for v in published if release_line(v) == release_line(version)]
    line_latest = max(line, key=version_key) if line else None

    detail = ""
    if base and not changed:
        # A crate the pull request does not touch is never its problem.
        status = OK
    elif version in published:
        status = BUMP if changed else OK
    elif line_latest and version_key(version) < version_key(line_latest):
        status = MISMATCH
        detail = f"manifest version is behind {registry.label} ({line_latest})"
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
        "is_published": version in published,
        # Of the crate file the registry holds for this version, if any.
        "checksum": published.get(version),
        "baseline_tag": baseline,
        "tag": tag or f"{prefix}-{version}",
        "tag_exists": tag is not None,
        "tag_commit": tags[tag] if tag else None,
        "manifest": manifest,
        "changed_files": changed,
        "status": status,
        "detail": detail,
    }


def crate_reports(names, packages, release, registry, base=None):
    """Status of each crate of `names`, in the order they have to be published."""
    tags = tag_commits()
    try:
        published = fetch_published(names, registry.index)
    except OSError as error:
        print(f"could not reach {registry.index}: {error}", file=sys.stderr)
        sys.exit(2)
    reports = []
    for name in publish_order(names, packages):
        report = crate_status(
            name, packages[name], tags, published[name], registry, base
        )
        report["dependencies"] = release_dependencies(packages[name], release)
        reports.append(report)
    return reports


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


def print_table(reports, registry):
    columns = [
        ("crate", lambda r: r["crate"]),
        ("manifest", lambda r: r["version"]),
        (registry.label, lambda r: r["published"] or "-"),
        ("baseline", lambda r: r["baseline_tag"] or "-"),
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


def print_actions(reports, registry, show_files, brief=False):
    by_status = {}
    for report in reports:
        by_status.setdefault(report["status"], []).append(report)

    for report in by_status.get(MISMATCH, []):
        print(f"\n!! {report['crate']}: {report['detail']}")

    if BUMP in by_status:
        print("\nChanged without a version bump:")
        for report in by_status[BUMP]:
            print(
                f"  {report['crate']}: {len(report['changed_files'])} changed file(s)"
                f" since {report['baseline_tag']}, bump {report['manifest']}"
            )
            if show_files:
                for path in report["changed_files"]:
                    print(f"      {path}")

    if brief:
        return

    if TAG in by_status:
        print("\nBumped but not tagged, tag the commit they are released from:")
        for report in by_status[TAG]:
            tag = report["tag"]
            print(
                f"  git tag -s -a -m \"{report['crate']} {report['version']} release\""
                f" {tag} && git push origin tag {tag}"
            )

    if PUBLISH in by_status:
        print(f"\nTagged but not on {registry.label}:")
        for report in by_status[PUBLISH]:
            print(
                f"  {report['crate']} {report['version']},"
                f" tag {report['tag']} on commit {report['tag_commit'][:9]}"
            )
        # A single run publishes the crates tagged on a commit, in dependency
        # order: there is no order to follow by hand.
        print(
            "Run the make_release_tfhe workflow from one of the tags of a commit to"
            " release every crate tagged on it,\n`make release_plan TAG=<tag>` shows"
            " what that run would publish."
        )

    if set(by_status) <= {OK}:
        print(
            f"\nNothing to do: every released crate is up to date on {registry.label}."
        )


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
    parser.add_argument(
        "--crates", action="extend", nargs="+", help="only report these crates"
    )
    parser.add_argument("--files", action="store_true", help="list the changed files")
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument(
        "--mermaid", action="store_true", help="print the release dependency graph"
    )
    parser.add_argument(
        "--pr-gate",
        nargs="?",
        const="",
        metavar="REF",
        help="gate a pull request: judge only what changed since REF, defaulting to"
        " the branch's fork point, and exit with 1 on a missing bump",
    )
    add_repo_arguments(parser)
    args = parser.parse_args()
    registry = open_repo(args)

    packages = workspace_packages()
    release = release_crates(packages, registry.name)
    names = [name for name in release if not args.crates or name in args.crates]
    unknown = set(args.crates or []) - set(release)
    if unknown:
        parser.error(f"not released from this repo: {', '.join(sorted(unknown))}")

    if args.mermaid:
        print_mermaid(release, packages)
        return 0

    gate = args.pr_gate is not None
    base = (args.pr_gate or fork_point()) if gate else None
    reports = crate_reports(names, packages, release, registry, base)

    # TAG means the bump was made, which is what the gate asked for. Whether a
    # crate is ready to be released is for scripts/release_publish.py to tell.
    allowed = {OK, TAG, PUBLISH} if gate else None
    rejected = [r for r in reports if allowed and r["status"] not in allowed]

    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        print_table(reports, registry)
        print_actions(reports, registry, args.files, gate)

    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
