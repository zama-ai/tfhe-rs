#!/usr/bin/env python3

# Verify there are not underscores in docs dirs to avoid issues between github and gitbook.
# The mix of both was creating more issues than necessary, so using the least common denominator of
# the "-" instead of "_"

from pathlib import Path
import os

DEBUG = False


def main():
    curr_file_path = Path(__file__)
    root_dir = curr_file_path.parent.parent.resolve()
    docs_dir = root_dir / "tfhe/docs"

    if not docs_dir.exists():
        raise ValueError(f"{docs_dir} does not exist")

    problems = []

    for idx, (subdirs, dirs, files) in enumerate(os.walk(docs_dir)):
        if DEBUG:
            print(idx, (subdirs, dirs, files))

        subdirs = Path(subdirs).resolve()

        for dir_ in dirs:
            if "_" in str(dir_):
                problems.append(
                    f"Found dir: {dir_} in {subdirs} containing a '_' instead of a '-', "
                    f"this is not allowed"
                )

        for file in files:
            if "_" in str(file):
                problems.append(
                    f"Found file: {file} in {subdirs} containing a '_' instead of a '-', "
                    f"this is not allowed"
                )

    if len(problems) != 0:
        for problem in problems:
            print(problem)

        raise ValueError


if __name__ == "__main__":
    main()
