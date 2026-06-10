import argparse
import subprocess
import sys


# List the gpus for a sub-group (group_index) of gpus grouped
# in num_groups groups. The output string is passed to CUDA_VISIBLE_DEVICES
def get_gpu_count() -> int:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print("Error: nvidia-smi not found", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as err:
        print(f"Error: nvidia-smi failed: {err.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return len(result.stdout.strip().splitlines())


def gpu_list_for_group(num_gpus: int, group_index: int, num_groups: int) -> str:
    # Splits the available gpus un groups and returns
    # the gpus assigned to group group_index.
    if num_gpus < num_groups:
        print(
            f"Error: cannot split {num_gpus} GPU(s) across {num_groups} group(s): "
            "not enough GPUs",
            file=sys.stderr,
        )
        sys.exit(1)
    if num_gpus % num_groups != 0:
        print(
            f"Error: {num_gpus} GPU(s) is not evenly divisible by {num_groups} group(s)",
            file=sys.stderr,
        )
        sys.exit(1)
    gpus_per_group = num_gpus // num_groups
    start = group_index * gpus_per_group
    return ",".join(str(i) for i in range(start, start + gpus_per_group))


parser = argparse.ArgumentParser(
    description="Print the CUDA_VISIBLE_DEVICES value for one process in a multi-GPU split."
)
parser.add_argument("group_index", type=int, help="0-based index of this process group")
parser.add_argument("num_groups", type=int, help="Total number of process groups")

if __name__ == "__main__":
    args = parser.parse_args()
    num_gpus = get_gpu_count()
    print(gpu_list_for_group(num_gpus, args.group_index, args.num_groups))
