import argparse
import csv
import json
import math
import re
from pathlib import Path

MILLISECONDS_IN_NANO = 1e6

NOT_AVAILABLE = "N/A"

# (metric, param family, CSV header) for each value column, in output order.
COLUMNS = [
    ("latency", "classical", "Latency classical (ms)"),
    ("latency", "multi_bit", "Latency multi-bit (ms)"),
    ("throughput", "classical", "Throughput classical (ops/s)"),
    ("throughput", "multi_bit", "Throughput multi-bit (ops/s)"),
]


def _round_to_digits(value, max_digits):
    if value >= 100.0:
        rounding_digit = None
    elif value > 0:
        power_of_10 = math.floor(math.log10(value))
        rounding_digit = max_digits - (power_of_10 + 1)
    else:
        rounding_digit = None
    return f"{round(value, rounding_digit)}"


def _is_ct(point):
    return point["operand_type"] == "CipherText"


def _unsigned64_ct(point, op_token):
    return (
        op_token in point["id"]
        and point["bits"] == 64
        and _is_ct(point)
        and "::signed" not in point["id"]
    )


def _fhe_type_width(name):
    return name.replace("FheUint", "u").replace("FheInt", "i")


def _bitonic_shuffle_label(point):
    pid = point["id"]
    value_match = re.search(r"::(\d+)_bits", pid)
    key_match = re.search(r"::key_(\d+)_bits", pid)
    elems_match = re.search(r"::(\d+)_elements", pid)
    value_bits = value_match.group(1) if value_match else "?"
    key_bits = key_match.group(1) if key_match else "?"
    elems = elems_match.group(1) if elems_match else "?"
    return f"Bitonic Shuffle ({value_bits}b/{key_bits}b @ {elems})"


def _kv_store_label(op_name):
    def label(point):
        match = re.search(
            r"::key_([A-Za-z0-9]+)::value_([A-Za-z0-9]+)::(\d+)_elements",
            point["id"],
        )
        if not match:
            return f"KV Store - {op_name}"
        key = _fhe_type_width(match.group(1))
        value = _fhe_type_width(match.group(2))
        return f"KV Store - {op_name} ({key} key / {value} value @ {match.group(3)})"

    return label


RULES = [
    ("Add", lambda p: _unsigned64_ct(p, "::add")),
    ("Mul", lambda p: _unsigned64_ct(p, "::mul")),
    ("Div", lambda p: _unsigned64_ct(p, "::div_rem")),
    ("Comparison", lambda p: _unsigned64_ct(p, "::gt")),
    ("SNS", lambda p: "::noise_squash::" in p["id"]),
    (
        "SNS (decompress + squash + compress)",
        lambda p: "decomp_noise_squash_comp" in p["id"],
    ),
    (
        "Compress",
        lambda p: "packing_compression" in p["id"]
        and "pack_u64" in p["id"]
        and "unpack" not in p["id"],
    ),
    (
        "Decompress",
        lambda p: "packing_compression" in p["id"] and "unpack_u64" in p["id"],
    ),
    ("ZKPoK Proof (server)", lambda p: "pke_zk_proof" in p["id"]),
    (
        "ZKPoK Proof (verification)",
        lambda p: "pke_zk_verify_and_expand" in p["id"],
    ),
    *[
        (
            f"ERC7984 Transfer ({flavor})",
            lambda p, f=flavor: "erc7984" in p["id"]
            and f"::transfer::{f}::" in p["id"],
        )
        for flavor in ("whitepaper", "no_cmux", "overflow", "safe")
    ],
    (
        "Batch Swap Intents",
        lambda p: "swap_request" in p["id"] and "no_cmux" in p["id"],
    ),
    (
        "Redistribute Swap Tokens",
        lambda p: "swap_claim" in p["id"] and "no_cmux" in p["id"],
    ),
    (_bitonic_shuffle_label, lambda p: "bitonic_shuffle" in p["id"]),
    (_kv_store_label("get"), lambda p: "kv_store::get" in p["id"]),
    (_kv_store_label("update"), lambda p: "kv_store::update" in p["id"]),
    (_kv_store_label("map"), lambda p: "kv_store::map" in p["id"]),
    (
        "Vector find - contains (u64 @ 50)",
        lambda p: "::contains::FheUint64::50_elements" in p["id"]
        and "kv_store" not in p["id"],
    ),
    (
        "Vector find - match_value (u64 @ 50)",
        lambda p: "::match_value::FheUint64::50_elements" in p["id"],
    ),
]

ROW_ORDER = [label for label, _ in RULES if isinstance(label, str)]


def classify_pbs_kind(alias):
    alias = (alias or "").upper()
    if "GROUP" in alias or "MULTI_BIT" in alias:
        return "multi_bit"
    return "classical"


def normalize_point(raw):
    if raw.get("class") != "evaluate":
        return None

    test = raw.get("test", "")
    if "_std_dev" in test:
        return None

    metric = str(raw.get("type", "")).lower()
    if metric not in ("latency", "throughput"):
        return None

    params = raw.get("params") or {}
    alias = params.get("crypto_parameters_alias", "")

    return {
        "id": test,
        "value": float(raw["value"]),
        "metric": metric,
        "bits": params.get("bit_size"),
        "operand_type": params.get("operand_type"),
        "pbs": classify_pbs_kind(alias),
        "alias": alias,
        "backend": raw.get("backend"),
    }


def match_row(point):
    for label, predicate in RULES:
        try:
            if predicate(point):
                return label(point) if callable(label) else label
        except (KeyError, TypeError):
            continue
    return None


def load_points(input_files):
    points = []
    hardware_values = []
    for path in input_files:
        series = json.loads(Path(path).read_text())
        hardware = series.get("hardware")
        if hardware and hardware not in hardware_values:
            hardware_values.append(hardware)
        for raw in series.get("points", []):
            norm = normalize_point(raw)
            if norm is not None:
                points.append(norm)
    return points, hardware_values


def build_table(points):
    table = {}
    unmatched = []
    collisions = []

    for point in points:
        label = match_row(point)
        if label is None:
            unmatched.append(point["id"])
            continue

        cell = table.setdefault(label, {})
        key = (point["metric"], point["pbs"])
        if key not in cell:
            cell[key] = point["value"]
        elif cell[key] != point["value"]:
            collisions.append((label, point["metric"], point["pbs"], point["id"]))

    return table, {"unmatched": unmatched, "collisions": collisions}


def load_gpu_info(gpu_info_file):
    """Read the output of `nvidia-smi --query-gpu=name --format=csv,noheader`
    (one GPU name per line) and return (model, count), or None if empty.
    """
    names = [
        line.strip()
        for line in Path(gpu_info_file).read_text().splitlines()
        if line.strip()
    ]
    if not names:
        return None
    models = sorted(set(names))
    assert len(models) == 1, f"several GPU models found: {', '.join(models)}"
    return models[0], len(names)


def collect_param_sets(points):
    """Raw crypto parameter alias(es) seen across all points, per PBS kind."""
    param_sets = {}
    for family in ("classical", "multi_bit"):
        aliases = sorted(
            {p["alias"] for p in points if p["alias"] and p["pbs"] == family}
        )
        if aliases:
            param_sets[family] = ", ".join(aliases)
    return param_sets


def build_metadata_rows(hardware, gpu_info, param_sets):
    rows = []
    if gpu_info:
        model, count = gpu_info
        rows.append(["GPU model", model])
        rows.append(["GPU count", count])
        if hardware:
            rows.append(["Instance", hardware])
    elif hardware:
        rows.append(["Hardware", hardware])
    for family, label in [
        ("classical", "Parameter set classical"),
        ("multi_bit", "Parameter set multi-bit"),
    ]:
        if family in param_sets:
            rows.append([label, param_sets[family]])
    return rows


def _natural_key(label):
    return [
        int(token) if token.isdigit() else token
        for token in re.split(r"(\d+)", label)
    ]


def order_rows(table):
    known = [label for label in ROW_ORDER if label in table]
    extra = [label for label in table if label not in ROW_ORDER]
    return known + sorted(extra, key=_natural_key)


def write_csv(table, output_file, metadata_rows):
    header = ["Operation"] + [column_header for _, _, column_header in COLUMNS]
    lines = [list(row) for row in metadata_rows] + [header]
    for label in order_rows(table):
        cell = table[label]
        row = [label]
        for metric, family, _ in COLUMNS:
            value = cell.get((metric, family))
            if value is None:
                row.append(NOT_AVAILABLE)
            elif metric == "latency":
                row.append(_round_to_digits(value / MILLISECONDS_IN_NANO, 3))
            else:
                row.append(_round_to_digits(value, 3))
        lines.append(row)

    with open(output_file, "w", encoding="utf-8", newline="") as out:
        csv.writer(out).writerows(lines)


def main(args):
    points, hardware_values = load_points(args.input)
    if not points:
        print("No timing points found in the provided files; nothing written.")
        return

    table, diag = build_table(points)

    if not table:
        print("No summary operation matched the parsed points; nothing written.")
        return

    assert len(hardware_values) <= 1, (
        "several hardware names found across input files: "
        f"{', '.join(hardware_values)}"
    )
    hardware = hardware_values[0] if hardware_values else None
    gpu_info = load_gpu_info(args.gpu_info_file) if args.gpu_info_file else None
    param_sets = collect_param_sets(points)
    metadata_rows = build_metadata_rows(hardware, gpu_info, param_sets)

    write_csv(table, args.output_file, metadata_rows)

    print(f"Wrote {len(table)} operation(s) to {args.output_file}")
    for name, value in metadata_rows:
        print(f"{name}: {value}")
    if diag["collisions"]:
        print(f"WARNING: {len(diag['collisions'])} value collision(s) (kept first):")
        for label, metric, family, test in diag["collisions"][:10]:
            print(f"  - {label} [{metric}/{family}]: {test}")
    if diag["unmatched"]:
        unique_unmatched = sorted(set(diag["unmatched"]))
        print(f"Note: {len(unique_unmatched)} benchmark id(s) did not map to a row:")
        for test in unique_unmatched[:15]:
            print(f"  - {test}")
        if len(unique_unmatched) > 15:
            print(f"  ... and {len(unique_unmatched) - 15} more")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "Extract a benchmark summary CSV from tfhe-benchmark-parser JSON output"
    )
    parser.add_argument(
        "-i",
        "--input",
        action="append",
        required=True,
        help="A parsed_benchmark_results_*.json file. Repeat to merge several.",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        default="summary_benchmarks.csv",
        help="Path of the output CSV file",
    )
    parser.add_argument(
        "--gpu-info-file",
        help="File holding the output of "
        "`nvidia-smi --query-gpu=name --format=csv,noheader`, "
        "used to report the GPU model and count",
    )

    main(parser.parse_args())
