import argparse
from pathlib import Path
import json


def main(args):
    criterion_dir = Path(args.criterion_dir)
    output_file = Path(args.output_file)

    data = []
    for json_file in sorted(criterion_dir.glob("**/*.json")):
        # print(json_file)
        if json_file.parent.name == "base" or json_file.name != "benchmark.json":
            continue

        try:
            bench_data = json.loads(json_file.read_text())
            estimate_file = json_file.with_name("estimates.json")
            estimate_data = json.loads(estimate_file.read_text())
            parameter_set = json_file.parent.parent.name

            # bench_function_id = bench_data["function_id"]

            # split = bench_function_id.split("::")
            # if split.len() == 5:  # Signed integers
            #     (_, _, function_name, parameter_set, bits) = split
            # else:  # Unsigned integers
            #     (_, function_name, parameter_set, bits) = split

            # if "_scalar_" in bits:
            #     (bits, scalar) = bits.split("_bits_scalar_")
            #     bits = int(bits)
            #     scalar = int(scalar)
            # else:
            #     (bits, _) = bits.split("_")
            #     bits = int(bits)
            #     scalar = None

            estimate_mean_ms = estimate_data["mean"]["point_estimate"] / 1000000
            estimate_lower_bound_ms = (
                estimate_data["mean"]["confidence_interval"]["lower_bound"] / 1000000
            )
            estimate_upper_bound_ms = (
                estimate_data["mean"]["confidence_interval"]["upper_bound"] / 1000000
            )

            data.append(
                (
                    # bench_function_id,
                    parameter_set,
                    # bits,
                    # scalar,
                    estimate_mean_ms,
                    estimate_lower_bound_ms,
                    estimate_upper_bound_ms,
                )
            )
        except:
            pass

    if len(data) == 0:
        print("No integer bench found, skipping writing output file")
        return

    with open(output_file, "w", encoding="utf-8") as output:
        output.write(
            "parameter_set,mean_ms,"
            "confidence_interval_lower_bound_ms,confidence_interval_upper_bound_ms\n"
        )
        # Sort by func_name, bit width and then parameters
        data.sort(key=lambda x: (x[0], x[2], x[1]))

        for dat in data:
            (
                parameter_set,
                # bits,
                # scalar,
                estimate_mean_ms,
                estimate_lower_bound_ms,
                estimate_upper_bound_ms,
            ) = dat
            output.write(
                f"{parameter_set},{estimate_mean_ms},"
                f"{estimate_lower_bound_ms},{estimate_upper_bound_ms}\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Parse criterion results to csv file")
    parser.add_argument(
        "--criterion-dir",
        type=str,
        default="target/criterion",
        help="Where to look for criterion result json files",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default="parsed_benches.csv",
        help="Path of the output file, will be csv formatted",
    )

    main(parser.parse_args())
