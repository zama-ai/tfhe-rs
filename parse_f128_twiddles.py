import sys

def generate_twiddles(file_path):
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()

        # Parse n
        n_line = lines[0].strip()
        n = int(n_line.split('=')[1].strip())

        # Parse twiddle data
        twiddles = []
        for line in lines[1:]:
            if "twid_re_hi" in line:
                parts = line.split(':')[1].strip().split(',')
                hex_val = parts[0].strip()
                float_val = parts[1].strip()
                twiddles.append((hex_val, float_val))

        # Generate C++ code
        cpp_code = f"double negtwiddles[{n}] = {{\n"
        for hex_val, float_val in twiddles:
            cpp_code += f"     {float_val},\n"
        cpp_code += "};\n"

        print(cpp_code)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python generate_twiddles.py <file_path>")
    else:
        generate_twiddles(sys.argv[1])
