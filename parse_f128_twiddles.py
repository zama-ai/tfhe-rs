#!/usr/bin/env python3
import sys

def parse_file(filename):
    with open(filename, 'r') as f:
        # Read all non-empty lines (you can also filter out comments if needed)
        lines = [line.strip() for line in f if line.strip()]

    # The first line is expected to be the count (e.g. "4096")
    try:
        count = int(lines[0])
    except ValueError:
        sys.exit("Error: The first line must be an integer (the count of data lines).")

    # Initialize lists for each twiddle array.
    neg_twiddles_re_hi = []
    neg_twiddles_re_lo = []
    neg_twiddles_im_hi = []
    neg_twiddles_im_lo = []

    # Process each subsequent line.
    for i, line in enumerate(lines[1:], start=1):
        tokens = line.split()
        if len(tokens) != 4:
            sys.exit(f"Error on line {i+1}: expected 4 tokens, found {len(tokens)}.")
        neg_twiddles_re_hi.append(tokens[0])
        neg_twiddles_re_lo.append(tokens[1])
        neg_twiddles_im_hi.append(tokens[2])
        neg_twiddles_im_lo.append(tokens[3])

    if len(neg_twiddles_re_hi) != count:
        print(f"Warning: Count mismatch. Expected {count} entries but found {len(neg_twiddles_re_hi)}.")
        count = len(neg_twiddles_re_hi)  # adjust count to the actual number of data lines

    return count, neg_twiddles_re_hi, neg_twiddles_re_lo, neg_twiddles_im_hi, neg_twiddles_im_lo

def print_cpp_array(name, count, values, indent=4, per_line=4):
    indent_str = " " * indent
    print(f"__device__ double {name}[{count}] = {{")
    for i, val in enumerate(values):
        # Print a newline every 'per_line' entries.
        if i % per_line == 0:
            print(indent_str, end="")
        print(val, end="")
        if i != len(values) - 1:
            print(", ", end="")
        if (i + 1) % per_line == 0:
            print("")
    # If the last line wasn't completed, print a newline.
    if len(values) % per_line != 0:
        print("")
    print("};\n")

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 generate_twiddles.py <input_file>")

    filename = sys.argv[1]
    count, re_hi, re_lo, im_hi, im_lo = parse_file(filename)

    # Generate C++ arrays.
    print_cpp_array("neg_twiddles_re_hi", count, re_hi)
    print_cpp_array("neg_twiddles_re_lo", count, re_lo)
    print_cpp_array("neg_twiddles_im_hi", count, im_hi)
    print_cpp_array("neg_twiddles_im_lo", count, im_lo)

if __name__ == "__main__":
    main()
