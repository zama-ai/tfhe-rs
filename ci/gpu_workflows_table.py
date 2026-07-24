#!/usr/bin/env python3
"""Generate a CSV table of GPU test workflows with their trigger and machine info."""

import csv
import re
import sys
import tomllib
from pathlib import Path

import yaml

WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"
SLAB_TOML = Path(__file__).parent / "slab.toml"

# Workflows to include (test workflows only, in display order)
WORKFLOWS = [
    "gpu_fast_tests",
    "gpu_signed_integer_tests",
    "gpu_unsigned_integer_tests",
    "gpu_signed_integer_classic_tests",
    "gpu_unsigned_integer_classic_tests",
    "gpu_integer_long_run_tests",
    "gpu_integer_multibit_tests_h100_2gpu_par",
    "gpu_integer_classic_tests_h100_2gpu_par",
    "gpu_core_hlapi_h100_2gpu_par",
    "gpu_hlapi_h100_tests",
    "gpu_core_h100_tests",
    "gpu_h100_long_run_tests",
    "gpu_full_multi_gpu_tests",
    "gpu_full_h100_tests",
    "gpu_signed_integer_h100_tests",
    "gpu_unsigned_integer_h100_tests",
    "gpu_code_validation_tests",
    "gpu_memory_sanitizer",
    "gpu_memory_sanitizer_h100",
    "gpu_noise_level_checks",
    "gpu_zk_tests",
    "gpu_zk_long_run_tests",
    "gpu_zk_code_validation_tests",
    "gpu_zk_memory_sanitizer",
]


def load_slab(path: Path) -> dict:
    """Load slab.toml and return a flat dict of profile_name -> {instance_type, fallbacks}."""
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    profiles = {}
    for backend_name, backend_profiles in raw.get("backend", {}).items():
        for profile_name, profile_data in backend_profiles.items():
            instance_type = profile_data.get("instance_type") or profile_data.get("flavor_name", "?")
            raw_fallbacks = profile_data.get("fallbacks", [])
            profiles[profile_name] = {
                "backend": backend_name,
                "instance_type": instance_type,
                "raw_fallbacks": raw_fallbacks,
            }

    # Resolve fallback instance types
    for profile_name, pdata in profiles.items():
        resolved = []
        for fb in pdata["raw_fallbacks"]:
            # fb is like "hyperstack.2-h100" or "terraform.scaleway-4-h100-sxm5"
            fb_profile = fb.split(".", 1)[1] if "." in fb else fb
            fb_instance = profiles.get(fb_profile, {}).get("instance_type", fb_profile)
            resolved.append(fb_instance)
        pdata["fallbacks"] = resolved

    return profiles


def parse_workflow(path: Path, slab: dict) -> dict:
    """Parse a workflow YAML file and extract trigger and machine info."""
    data = yaml.safe_load(path.read_text())

    on = data.get("on") or data.get(True) or {}  # 'on' parses as True in PyYAML
    # PyYAML parses the bare key `on:` as boolean True
    if True in data and "on" not in data:
        on = data[True]
    elif "on" in data:
        on = data["on"]
    else:
        on = {}

    # Normalize: 'on' can be a list (e.g. [push, pull_request]) or a dict
    if isinstance(on, list):
        on = {k: None for k in on}
    elif isinstance(on, str):
        on = {on: None}

    # --- Triggers ---
    has_dispatch = "workflow_dispatch" in on
    has_push = "push" in on

    pr = on.get("pull_request")
    has_pr = "pull_request" in on
    if isinstance(pr, dict):
        pr_types = pr.get("types", [])
    else:
        pr_types = []

    pr_regular = has_pr and (not pr_types or any(t in pr_types for t in ("opened", "synchronize", "reopened")))
    pr_labeled = has_pr and "labeled" in pr_types

    # Check setup-instance condition for 'approved' label (still use text search — it's in a string expression)
    text = path.read_text()
    pr_approved = pr_labeled and bool(re.search(r"label\.name == 'approved'", text))

    # Cron schedules
    schedule = on.get("schedule", [])
    crons = []
    if isinstance(schedule, list):
        for entry in schedule:
            if isinstance(entry, dict) and "cron" in entry:
                crons.append(str(entry["cron"]).strip())
    cron = "; ".join(crons)

    has_any_auto = pr_regular or pr_approved or cron or has_push
    manual_only = has_dispatch and not has_any_auto

    # --- Profile: walk jobs to find the slab-github-runner start step ---
    profile = None
    jobs = data.get("jobs", {})
    for job in jobs.values():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "") or ""
            if "slab-github-runner" not in uses:
                continue
            with_block = step.get("with", {}) or {}
            if str(with_block.get("mode", "")).strip() != "start":
                continue
            profile = str(with_block.get("profile", "")).strip() or None
            break
        if profile:
            break

    # Resolve profile info from slab
    if profile and profile in slab:
        instance_type = slab[profile]["instance_type"]
        fallbacks = slab[profile]["fallbacks"]
    else:
        instance_type = "?"
        fallbacks = []

    return {
        "Workflow": path.stem,
        "PR": "yes" if pr_regular else "",
        "PR on approved": "yes" if pr_approved else "",
        "Cron": cron,
        "Manual only": "yes" if manual_only else "",
        "Profile (instance)": f"{profile} ({instance_type})" if profile else "",
        "Fallbacks": " | ".join(fallbacks),
        "_test_targets": extract_test_targets(text),
    }


TEST_MARKERS = re.compile(r"cuda-tests-linux|make test_|cargo test|nextest run|nextest list")
MAKE_TEST_RE = re.compile(r"make\s+(test_\w+)")

# Known test targets — add new ones here when introduced
TEST_TARGETS = [
    "test_core_crypto_gpu",
    "test_cuda_backend",
    "test_high_level_api_gpu",
    "test_high_level_api_gpu_fast",
    "test_integer_compression_gpu",
    "test_integer_long_run_gpu",
    "test_integer_multi_bit_gpu_ci",
    "test_integer_short_run_gpu",
    "test_signed_integer_gpu_ci",
    "test_signed_integer_multi_bit_gpu_ci",
    "test_unsigned_integer_gpu_ci",
    "test_unsigned_integer_multi_bit_gpu_ci",
    "test_user_doc_gpu",
    "test_c_api_gpu",
    "test_integer_zk_experimental_gpu",
    "test_integer_zk_gpu",
    "test_zk_cuda_backend",
    "test_zk_cuda_backend_memcheck",
    "test_zk_cuda_backend_race_check",
    "test_zk_pok_experimental_gpu",
    "test_zk_pok_experimental_long_run_gpu",
    "test_zk_pok_experimental_short_run_gpu",
    "test_zk_pok_gpu_valgrind",
    "test_high_level_api_fake_multi_gpu",
    "test_signed_integer_fake_multi_gpu",
    "test_cuda_backend_race_check",
    "test_high_level_api_gpu_valgrind",
    "test_high_level_api_gpu_sanitizer",
]


def is_test_workflow(path: Path) -> bool:
    return bool(TEST_MARKERS.search(path.read_text()))


def extract_test_targets(text: str) -> set[str]:
    """Return whitelisted targets directly invoked via make in text."""
    return {t for t in TEST_TARGETS if re.search(rf"make\s+{t}\b", text)}


def find_unknown_test_targets(text: str) -> set[str]:
    """Return make test_* invocations not in TEST_TARGETS."""
    known = set(TEST_TARGETS)
    return {t for t in MAKE_TEST_RE.findall(text) if t not in known}


def main():
    slab = load_slab(SLAB_TOML)
    warnings: list[str] = []

    # Warn about gpu_* workflows not on the whitelist
    whitelist_set = set(WORKFLOWS)
    for path in sorted(WORKFLOWS_DIR.glob("gpu_*.yml")):
        name = path.stem
        if name not in whitelist_set:
            if is_test_workflow(path):
                kind = "test workflow — consider adding to whitelist"
            else:
                kind = "non-test workflow (build/helper) — intentionally excluded"
            warnings.append(f"WARNING: {name}.yml not in whitelist: {kind}")

    # First pass: parse and collect per-workflow warnings
    rows = []
    for name in WORKFLOWS:
        path = WORKFLOWS_DIR / f"{name}.yml"
        if not path.exists():
            warnings.append(f"WARNING: {name}.yml listed in whitelist but file not found")
            continue
        row = parse_workflow(path, slab)
        text = path.read_text()
        targets = row.pop("_test_targets")
        for unknown in sorted(find_unknown_test_targets(text)):
            warnings.append(f"WARNING: {name}.yml runs unknown test target '{unknown}' — add to TEST_TARGETS")
        for col in TEST_TARGETS:
            row[col] = "yes" if col in targets else ""
        rows.append(row)

    for w in warnings:
        print(w, file=sys.stderr)

    base_fields = ["Workflow", "PR", "PR on approved", "Cron", "Manual only", "Profile (instance)", "Fallbacks"]
    writer = csv.DictWriter(sys.stdout, fieldnames=base_fields + TEST_TARGETS)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)


if __name__ == "__main__":
    main()
