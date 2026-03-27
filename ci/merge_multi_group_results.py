#!/usr/bin/env python3
# TODO: ADD COMMENT
import json
import sys


# TODO: ADD COMMENT
def merge_multi_group_results(file1, file2, output_file):
    with open(file1) as f:
        data1 = json.load(f)
    with open(file2) as f:
        data2 = json.load(f)

    # TODO: ADD COMMENT
    points2 = {p["test"]: p for p in data2["points"]}

    merged_points = []
    for point in data1["points"]:
        test = point["test"]
        if test in points2:
            # TODO: ADD COMMENT
            merged = dict(point)
            merged["value"] = point["value"] + points2[test]["value"]
            merged_points.append(merged)
            del points2[test]
        else:
            # TODO: ADD COMMENT
            merged_points.append(point)

    # TODO: ADD COMMENT
    merged_points.extend(points2.values())

    result = dict(data1)
    result["points"] = merged_points

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} file1.json file2.json output.json")
        sys.exit(1)
    merge_multi_group_results(sys.argv[1], sys.argv[2], sys.argv[3])
