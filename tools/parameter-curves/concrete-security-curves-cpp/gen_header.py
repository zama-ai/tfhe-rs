import sys, json;

def print_curve(data):
    print(f'\tSecurityCurve({data["security_level"]},{data["slope"]}, {data["bias"]}, {data["minimal_lwe_dimension"]}, KeyFormat::BINARY),')

def print_cpp_curves_declaration(datas):
    print("SecurityCurve curves[] = {")
    for data in datas:
        print_curve(data)
    print("};\n")
    print(f"size_t curvesLen = {len(data)};")

print_cpp_curves_declaration(json.load(sys.stdin))
