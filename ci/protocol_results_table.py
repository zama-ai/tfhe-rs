#!/usr/bin/env python3
"""Render the protocol benchmark results as a table, for the job log and for download."""

import argparse
import csv
import json
import sys
from pathlib import Path

NANOSECONDS_IN_MILLISECOND = 1e6

MISSING = "—"

NOT_AVAILABLE = "N/A"

CSV_HEADER = ["Protocol component", "Latency (ms)", "Throughput (tx/s)"]

# Spans in protocol order, with the name each one carries in the transaction.
SPANS = [
    ("decomp_transfer_comp", "TFHEw: decomp_transfer_comp"),
    ("decomp_transfer_comp_no_rerand", "TFHEw: decomp_transfer_comp (no rerand)"),
    ("decomp_noise_squash_comp", "SNSw: decomp_noise_squash_comp"),
    ("full_transaction", "TFHEw+SNSw: full_transaction"),
    ("full_transaction_no_rerand", "TFHEw+SNSw: full_transaction (no rerand)"),
]

PROTOCOL_MARKER = "::protocol::"


def span_of(test):
    """The protocol kind a bench id names, or None when the id is not a protocol one."""
    if PROTOCOL_MARKER not in test:
        return None
    segments = test.split("::")
    index = segments.index("protocol")
    return segments[index + 1] if index + 1 < len(segments) else None


def read_points(paths):
    """Protocol means as {span: {metric: value}}, and the parameter aliases they were measured on."""
    measured = {}
    aliases = set()

    for path in paths:
        series = json.loads(Path(path).read_text())
        for point in series.get("points", []):
            test = point["test"]
            if "_std_dev" in test:
                continue
            span = span_of(test)
            if span is None:
                continue
            measured.setdefault(span, {})[point["type"].lower()] = float(point["value"])
            alias = point.get("params", {}).get("crypto_parameters_alias")
            if alias:
                aliases.add(alias)

    return measured, sorted(aliases)


def measurements(values, gpus_used):
    """Latency in milliseconds and per-GPU throughput, either one None when not measured."""
    latency = values.get("latency")
    throughput = values.get("throughput")

    return (
        latency / NANOSECONDS_IN_MILLISECOND if latency else None,
        throughput / gpus_used if throughput else None,
    )


def format_row(values, gpus_used):
    latency, throughput = measurements(values, gpus_used)

    return [
        f"{latency:.2f} ms" if latency is not None else MISSING,
        f"{throughput:.2f} tx/s" if throughput is not None else MISSING,
    ]


def csv_row(values, gpus_used):
    latency, throughput = measurements(values, gpus_used)

    return [
        f"{latency:.2f}" if latency is not None else NOT_AVAILABLE,
        f"{throughput:.2f}" if throughput is not None else NOT_AVAILABLE,
    ]


def render(rows, headers):
    """A box table, sized on its widest cell, one space of padding each side."""
    widths = [
        max(len(row[column]) for row in [headers] + rows) + 2
        for column in range(len(headers))
    ]

    def rule(left, middle, right):
        return left + middle.join("─" * width for width in widths) + right

    def line(cells, centered=False):
        padded = [
            f" {cell:<{width - 1}}" if not centered else f"{cell:^{width}}"
            for cell, width in zip(cells, widths)
        ]
        return "│" + "│".join(padded) + "│"

    out = [rule("┌", "┬", "┐"), line(headers, centered=True)]
    for row in rows:
        out.append(rule("├", "┼", "┤"))
        out.append(line(row))
    out.append(rule("└", "┴", "┘"))

    return "\n".join(out)


def gpu_lines(gpu_info):
    """The GPU names nvidia-smi wrote, one per GPU, or an empty list without the file."""
    if not gpu_info:
        return []
    path = Path(gpu_info)
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def metadata_rows(gpus, hardware, gpus_used, aliases):
    """Key/value rows that open the CSV, as the summary CSV writes them."""
    rows = []

    if gpus:
        rows.append(["GPU model", gpus[0]])
        rows.append(["GPU count", len(gpus)])
        rows.append(["GPUs used", gpus_used])
    if hardware:
        rows.append(["Hardware", hardware])
    if aliases:
        rows.append(["Parameter set", ", ".join(aliases)])

    return rows


def write_csv(rows, metadata, path):
    with open(path, "w", encoding="utf-8", newline="") as out:
        csv.writer(out).writerows([list(row) for row in metadata] + [CSV_HEADER] + rows)


def header_lines(gpus, hardware, gpus_used):
    lines = []

    if gpus:
        model = gpus[0]
        lines.append(f"GPUs detected: {len(gpus)} x {model}")
        if len(set(gpus)) > 1:
            lines.append(f"  mixed models: {', '.join(gpus)}")
        lines.append(f"GPUs used by this run: {gpus_used}")
        lines.append(f"Results on 1x {model}")
    else:
        lines.append(f"Results on {hardware or 'the benchmark machine'}")

    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="+", help="parsed benchmark results, JSON")
    parser.add_argument("--gpu-info", help="gpu_info.txt, one GPU name per line")
    parser.add_argument("--hardware", help="hardware name, used when there is no GPU list")
    parser.add_argument(
        "--gpus-used",
        type=int,
        default=1,
        help="GPUs the run spread over, throughput is divided by it (default: 1)",
    )
    parser.add_argument("--output", help="also write the table here")
    parser.add_argument("--csv", help="write the same figures as CSV, for the artifact")
    args = parser.parse_args()

    if args.gpus_used < 1:
        parser.error("--gpus-used must be at least 1")

    measured, aliases = read_points(args.results)
    if not measured:
        print("No protocol results found, nothing to tabulate.", file=sys.stderr)
        return 0

    known = [span for span, _ in SPANS]
    spans = [(span, label) for span, label in SPANS if span in measured]
    spans += [(span, span) for span in sorted(measured) if span not in known]

    gpus = gpu_lines(args.gpu_info)
    rows = [[label] + format_row(measured[span], args.gpus_used) for span, label in spans]

    table = render(rows, ["Protocol component", "Latency", "Throughput"])
    text = "\n".join(header_lines(gpus, args.hardware, args.gpus_used))
    text += "\n\n" + table + "\n"

    print(text)
    if args.output:
        Path(args.output).write_text(text)
    if args.csv:
        write_csv(
            [[label] + csv_row(measured[span], args.gpus_used) for span, label in spans],
            metadata_rows(gpus, args.hardware, args.gpus_used, aliases),
            args.csv,
        )
        print(f"CSV written to {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
