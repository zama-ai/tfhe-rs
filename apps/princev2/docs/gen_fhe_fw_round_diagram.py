#!/usr/bin/env python3
"""
SVG dataflow of ONE forward round of PRINCEv2 as realised on FHE ciphertexts, i.e. of
`xor_then_fw_round` in `src/cipher.rs`: the xor layer `xor_to_u4` (shared with
`xor_then_mid_round`) followed by the round proper, `fw_round`.

It shows, stage by stage:
  * how the 64 logical state bits are grouped into shortint ciphertexts
    (u2h = 2 bits on the high slots, u2l = 2 bits on the low slots, u4 = a full 4-bit
    nibble, bits = 1 drifted bit),
  * every ciphertext ADDITION  (unchecked_add)                -> drawn as  (+)
  * every ciphertext LUT / PBS (apply_lookup_table)           -> drawn as a coloured box
  * the pure wiring permutation (FHE_M_PERM o P_PERM), which costs no PBS.

The key ciphertexts are in u2l, the state in u2h, so `sum_with_key` does not xor: it PACKS
state and key into the two halves of one nibble. The xor proper is the LUT that follows:
LUT_XOR_FW is the pair [LUT_XOR_TO_HIGH, LUT_XOR_TO_LOW] selected by `out_u2 & 1`, both
computing (x & 3) ^ (x >> 2), the even one keeping the result on the high slots so that the
pair-fold behind it assembles a full u4.

Wiring is taken directly from cipher.rs / tables.rs: the strided gather of
`pack_bit_lanes_to_u4`, and FHE_MP_PERM_FW.
"""

# ---- exact wiring constants from the source -------------------------------------------
# The bit-lane gather of `pack_bit_lanes_to_u4`: out_nibble sums bits first, +4, +8, +12.
def pack_bit_lanes_to_u4_in_bit_idx(out_nibble):
    first = 16 * (out_nibble // 4) + (out_nibble % 4)
    return [first, first + 4, first + 8, first + 12]

# FHE_MP_PERM_FW (gather form: dest i <- src perm[i]); literal from tables::FHE_MP_PERM_FW.
FHE_MP_PERM_FW = [
    0x00,0x05,0x0a,0x0f,0x12,0x17,0x18,0x1d,0x21,0x26,0x2b,0x2c,0x31,0x36,0x3b,0x3c,
    0x13,0x14,0x19,0x1e,0x22,0x27,0x28,0x2d,0x32,0x37,0x38,0x3d,0x01,0x06,0x0b,0x0c,
    0x23,0x24,0x29,0x2e,0x33,0x34,0x39,0x3e,0x02,0x07,0x08,0x0d,0x10,0x15,0x1a,0x1f,
    0x30,0x35,0x3a,0x3f,0x03,0x04,0x09,0x0e,0x11,0x16,0x1b,0x1c,0x20,0x25,0x2a,0x2f,
]

# The fused perm above = M'(bit-reorder) then ShiftRows(nibble-perm). We draw those two
# separately, with the pair-fold add sitting between them. Rebuild both from tables.rs.
FHE_M0_PERM = [0x0,0x5,0xa,0xf,0x3,0x4,0x9,0xe,0x2,0x7,0x8,0xd,0x1,0x6,0xb,0xc]
FHE_M1_PERM = [0x3,0x4,0x9,0xe,0x2,0x7,0x8,0xd,0x1,0x6,0xb,0xc,0x0,0x5,0xa,0xf]
FHE_M_PERM = [0] * 64            # M'-only bit reorder (gather)
for _word in range(4):                       # M0 permutes the outer 16-bit words, M1 the inner ones
    _perm = FHE_M0_PERM if _word in (0, 3) else FHE_M1_PERM
    _word_base = 16 * _word
    for _bit in range(16):
        FHE_M_PERM[_word_base + _bit] = _word_base + _perm[_bit]
P_PERM = [0x0,0x5,0xa,0xf,0x4,0x9,0xe,0x3,0x8,0xd,0x2,0x7,0xc,0x1,0x6,0xb]  # ShiftRows on nibbles
# ShiftRows lifted to the 32 u2h half-nibbles (gather):
#   out_u2 <- 2*P_PERM[out_u2>>1] + (out_u2&1)
P_PERM_U2H = [2 * P_PERM[out_u2 >> 1] + (out_u2 & 1) for out_u2 in range(32)]

# --- faithfulness checks: M'-reorder + fold + ShiftRows(u2h) == fused perm + fold ---------
# The two source bits `sum_adjacent_pairs` folds into output u2h element out_u2.
def sum_adjacent_pairs_src_idx(perm, out_u2):
    return {perm[2 * out_u2], perm[2 * out_u2 + 1]}
for _out_u2 in range(32):
    fused = sum_adjacent_pairs_src_idx(FHE_MP_PERM_FW, _out_u2)   # fused perm, then fold
    split = {FHE_M_PERM[2 * P_PERM_U2H[_out_u2]],                 # M', fold, then ShiftRows
             FHE_M_PERM[2 * P_PERM_U2H[_out_u2] + 1]}
    assert fused == split, (_out_u2, fused, split)
assert sorted(FHE_M_PERM) == list(range(64))
assert sorted(P_PERM_U2H) == list(range(32))

# ---- geometry -------------------------------------------------------------------------
COL   = 22
LEFT  = 118
RGUT  = 250            # right gutter for per-stage annotations
WIDTH = LEFT + 64 * COL + RGUT

def span_center_x(col_a, col_b):      # x centre of a span covering columns [col_a, col_b]
    return LEFT + ((col_a + col_b + 1) / 2) * COL
def col_center_x(col):                # x centre of a single column
    return LEFT + (col + 0.5) * COL

# colours
C_ADD    = "#33384a"
C_XOR    = "#2a9d8f"   # xor LUT (LUT_XOR_FW)
C_SBOX   = "#7b52ab"
C_MEXOR  = "#e07b00"
KEY_FILL = "#fbe6d4"; KEY_STROKE = "#cf9a44"
CT_WIRE  = "#8a94a8"   # colour of a ciphertext wire

svg = []
def emit(svg_fragment): svg.append(svg_fragment)

def xor_node(x, y, r=4.2, color=C_ADD):
    emit(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="white" stroke="{color}" stroke-width="1.3"/>')
    emit(f'<line x1="{x-r+1.3:.1f}" y1="{y:.1f}" x2="{x+r-1.3:.1f}" y2="{y:.1f}" stroke="{color}" stroke-width="1"/>')
    emit(f'<line x1="{x:.1f}" y1="{y-r+1.3:.1f}" x2="{x:.1f}" y2="{y+r-1.3:.1f}" stroke="{color}" stroke-width="1"/>')

def lut_box(x, y, color, label="T", width=13, height=13):
    emit(f'<rect x="{x-width/2:.1f}" y="{y-height/2:.1f}" width="{width}" height="{height}" rx="2.5" '
        f'fill="{color}" stroke="#222" stroke-width="0.7"/>')
    emit(f'<text x="{x:.1f}" y="{y+3:.1f}" text-anchor="middle" font-size="8" '
        f'fill="white" font-weight="bold">{label}</text>')

def wire(x1, y1, x2, y2, color="#b9c0cc", width=1.0, opacity=1.0):
    emit(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        f'stroke="{color}" stroke-width="{width}" opacity="{opacity}"/>')

# A ciphertext is a WIRE, not a box. Its width encodes how many bits it packs:
# thin = 1 bit (bits), medium = 2 bits (u2h), thick = 4-bit nibble (u4).
def ct_wire_width(bits):
    return {1: 1.1, 2: 2.6, 4: 4.6}.get(bits, 1.1)

def ct_wire(x, y0, y1, bits, color=CT_WIRE, opacity=1.0):
    emit(f'<line x1="{x:.1f}" y1="{y0:.1f}" x2="{x:.1f}" y2="{y1:.1f}" '
        f'stroke="{color}" stroke-width="{ct_wire_width(bits)}" opacity="{opacity}"/>')

def band_label(y, text):                # small ct-type tag in the left margin
    emit(f'<text x="{LEFT-8:.1f}" y="{y+3:.1f}" text-anchor="end" '
        f'font-size="8" fill="#667">{text}</text>')

def stage_annotation(y, text, sub=""):
    """`sub` is one caption line, or a tuple of lines stacked under the stage name."""
    x = LEFT + 64 * COL + 16
    emit(f'<text x="{x}" y="{y+2}" font-size="10" font-weight="bold" fill="#334">{text}</text>')
    for k, line in enumerate((sub,) if isinstance(sub, str) else sub):
        if line:
            emit(f'<text x="{x}" y="{y+14+12*k}" font-size="8.5" fill="#778">{line}</text>')

# ---- y-bands --------------------------------------------------------------------------
Y_TOP   = 78      # top of the input-state ct wires
Y_STATE = 96
Y_KEY   = 122
Y_ADD1  = 150
Y_LUT1  = 178
Y_KSUM  = 206
Y_ADD2  = 236
Y_U4A   = 266
Y_LUTS  = 312
Y_B1    = 352
Y_ADD3  = 410
Y_U4B   = 448
Y_LUTM  = 492
Y_B2    = 530
Y_B3    = 594      # after M'-only bit reorder
Y_ADD4  = 628      # pair-fold add
Y_U2HM  = 660      # 32 u2h, "reordered + added"
Y_U2HO  = 740      # after ShiftRows nibble permutation
HEIGHT  = 812

emit(f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
    f'font-family="ui-monospace,Menlo,Consolas,monospace" font-size="9">')
emit(f'<rect width="{WIDTH}" height="{HEIGHT}" fill="#fbfbfd"/>')
emit(f'<text x="{LEFT}" y="34" font-size="15" font-weight="bold" fill="#222">'
    f'PRINCEv2 forward round on FHE ciphertexts &#8212; bit grouping, ct additions, ct LUTs</text>')
emit(f'<text x="{LEFT}" y="52" font-size="10" fill="#666">'
    f'Every ciphertext is a WIRE (no state boxes); wire thickness = ct width: '
    f'thin = 1 bit (bits) &#183; medium = 2 bits (u2h or u2l) &#183; thick = 4-bit nibble (u4). '
    f'(+) = unchecked_add &#183; coloured box = apply_lookup_table (1 PBS).</text>')

# group separators (four 16-bit quad-groups)
for g in range(1, 4):
    x = LEFT + g * 16 * COL
    emit(f'<line x1="{x}" y1="78" x2="{x}" y2="{Y_U2HO+14}" stroke="#e2e5ec" stroke-width="1"/>')

# left brackets for the two source functions
def brace(y0, y1, label, sub):
    emit(f'<line x1="12" y1="{y0}" x2="12" y2="{y1}" stroke="#98a" stroke-width="2"/>')
    emit(f'<line x1="12" y1="{y0}" x2="20" y2="{y0}" stroke="#98a" stroke-width="2"/>')
    emit(f'<line x1="12" y1="{y1}" x2="20" y2="{y1}" stroke="#98a" stroke-width="2"/>')
    ym = (y0 + y1) / 2
    emit(f'<text x="30" y="{ym-2}" font-size="10" font-weight="bold" fill="#546" '
        f'transform="rotate(-90 30 {ym})" text-anchor="middle">{label}</text>')
    emit(f'<text x="44" y="{ym-2}" font-size="8" fill="#889" '
        f'transform="rotate(-90 44 {ym})" text-anchor="middle">{sub}</text>')
brace(Y_STATE-8, Y_U4A+8,  "xor_to_u4", "AddKey (&#8853;)")
brace(Y_LUTS-14, Y_U2HO+8, "fw_round", "R = SR &#183; M&#770; &#183; S")

# ---- R0 state u2h (32) as wires + round-key wires ------------------------------------
emit(f'<text x="{LEFT-4}" y="{Y_KEY+3}" text-anchor="end" font-size="8" fill="#8a5a10">'
    f'ct_k[u2_idx] (u2l)</text>')
for u2_idx in range(32):
    x = span_center_x(2 * u2_idx, 2 * u2_idx + 1)
    ct_wire(x, Y_TOP, Y_ADD1 - 4, 2)                          # state ct (u2h) -> add
    # round-key chip offset to the left so its wire is not collinear with the state's
    kx = x - 10
    emit(f'<rect x="{kx-8:.1f}" y="{Y_KEY-6:.1f}" width="16" height="12" rx="2.5" '
        f'fill="{KEY_FILL}" stroke="{KEY_STROKE}" stroke-width="1" stroke-dasharray="3 2"/>')
    emit(f'<text x="{kx:.1f}" y="{Y_KEY+3:.1f}" text-anchor="middle" font-size="7.5" fill="#8a5a10">k</text>')
    wire(kx, Y_KEY + 6, x, Y_ADD1 - 3, color=KEY_STROKE, width=2.0)  # round-key ct (u2l) -> add
    xor_node(x, Y_ADD1)
    ct_wire(x, Y_ADD1 + 4, Y_LUT1 - 6, 4)                     # packed nibble -> LUT_XOR_FW PBS
    lut_box(x, Y_LUT1, C_XOR)                               # LUT_XOR_FW PBS
    ct_wire(x, Y_LUT1 + 6, Y_KSUM, 2)                         # xored 2 bits flow on
band_label((Y_TOP + Y_ADD1) / 2, "32&#215;u2h")
band_label((Y_ADD1 + Y_LUT1) / 2, "u2h|u2l")
band_label((Y_LUT1 + Y_KSUM) / 2 + 6, "u2h / u2l")
stage_annotation(Y_ADD1, "32 &#215; sum_with_key", "packs state (u2h) + key (u2l) into one nibble")
stage_annotation(Y_LUT1, "32 &#215; LUT_XOR_FW", "xors the halves &#8594; hi (even u2) / lo (odd u2)")

# ---- fold pairs -> u4 (16) ------------------------------------------------------------
for out_nibble in range(16):
    xl = span_center_x(4 * out_nibble, 4 * out_nibble + 1)      # u2h[2*out_nibble]
    xr = span_center_x(4 * out_nibble + 2, 4 * out_nibble + 3)  # u2h[2*out_nibble+1]
    xo = span_center_x(4 * out_nibble, 4 * out_nibble + 3)
    wire(xl, Y_KSUM, xo, Y_ADD2 - 4, width=2.2)
    wire(xr, Y_KSUM, xo, Y_ADD2 - 4, width=2.2)
    xor_node(xo, Y_ADD2)
    ct_wire(xo, Y_ADD2 + 4, Y_U4A, 4)                         # u4 ct (nibble) flows on
band_label((Y_ADD2 + Y_U4A) / 2, "u4")
stage_annotation(Y_ADD2, "16 &#215; sum_adjacent_pairs", "fold hi+lo &#8594; 16 u4 nibbles")
emit(f'<text x="{LEFT}" y="{Y_U4A+22}" font-size="9" fill="#889">'
    f'&#8595; state is now 16 full nibbles (ct_xor_u4). Start of fw_round.</text>')

# ---- sbox_to_bits: each u4 -> 4 drifted bits (64 PBS) --------------------------------
for nibble in range(16):
    xin = span_center_x(4 * nibble, 4 * nibble + 3)
    for bit_in_nibble in range(4):
        xo = col_center_x(4 * nibble + bit_in_nibble)
        wire(xin, Y_U4A, xo, Y_LUTS - 7, color="#c9c0e0", width=0.9)  # u4 fans out to 4 bits
        lut_box(xo, Y_LUTS, C_SBOX)
        ct_wire(xo, Y_LUTS + 7, Y_B1, 1)                         # single-bit ct
band_label((Y_LUTS + Y_B1) / 2, "bits")
stage_annotation(Y_LUTS, "64 &#215; sbox_to_bits", "LUT_*_SBOX_* &#8594; 4 single bits")

# ---- pack_bit_lanes_to_u4 gather -> u4 (16), 4-way sum = 3 adds each ------------------
for out_nibble in range(16):
    xo = span_center_x(4 * out_nibble, 4 * out_nibble + 3)
    for src in pack_bit_lanes_to_u4_in_bit_idx(out_nibble):
        wire(col_center_x(src), Y_B1, xo, Y_ADD3 - 4, width=0.9)
    xor_node(xo, Y_ADD3, r=4.6)
    ct_wire(xo, Y_ADD3 + 4.6, Y_U4B, 4)                          # u4 ct
band_label((Y_ADD3 + Y_U4B) / 2, "u4")
stage_annotation(Y_ADD3, "48 &#215; pack_bit_lanes_to_u4", "gather 0-4-8-c &#8594; u4 (3 adds &#215;16)")

# ---- m_layer: each u4 -> 4 bits (64 PBS) ---------------------------------------------
for nibble in range(16):
    xin = span_center_x(4 * nibble, 4 * nibble + 3)
    for bit_in_nibble in range(4):
        xo = col_center_x(4 * nibble + bit_in_nibble)
        wire(xin, Y_U4B, xo, Y_LUTM - 7, color="#f2cf9c", width=0.9)  # u4 fans out to 4 bits
        lut_box(xo, Y_LUTM, C_MEXOR)
        ct_wire(xo, Y_LUTM + 7, Y_B2, 1)                         # single-bit ct
band_label((Y_LUTM + Y_B2) / 2, "bits")
stage_annotation(Y_LUTM, "64 &#215; m_layer", "LUT_EXOR_FW: near-MDS \"xor of 3\", per nibble")

# ====================================================================================
# Permutation (1): FHE_M_PERM, the M'-only half of the FHE_MP_PERM_FW gather that m_layer
# applies, drawn together with the `sum_adjacent_pairs` pair-fold it feeds.
# ====================================================================================
for i in range(64):
    wire(col_center_x(FHE_M_PERM[i]), Y_B2, col_center_x(i), Y_B3,
         color="#9aa3b5", width=0.8, opacity=0.85)
# pair-fold: bits[2*out_u2] + bits[2*out_u2+1] -> u2h[out_u2]
for out_u2 in range(32):
    xo = span_center_x(2 * out_u2, 2 * out_u2 + 1)
    wire(col_center_x(2 * out_u2),     Y_B3, xo, Y_ADD4 - 4)
    wire(col_center_x(2 * out_u2 + 1), Y_B3, xo, Y_ADD4 - 4)
    xor_node(xo, Y_ADD4)
    ct_wire(xo, Y_ADD4 + 4, Y_U2HM, 2)                          # u2h ct
# bracket the reorder+add as one conceptual permutation
emit(f'<rect x="{LEFT-4}" y="{Y_B2+3}" width="{64*COL+8}" height="{Y_U2HM-Y_B2-6}" '
    f'rx="6" fill="none" stroke="#9aa3b5" stroke-width="1" stroke-dasharray="4 3"/>')
band_label((Y_B2 + Y_B3) / 2, "bits")
band_label((Y_ADD4 + Y_U2HM) / 2, "u2h")
stage_annotation((Y_B2 + Y_B3) // 2, "permutation &#9312;", "FHE_M_PERM (M' bit-reorder)")
stage_annotation(Y_ADD4, "32 &#215; sum_adjacent_pairs", "&#8230; then pair-fold &#8594; 32 u2h")

# ====================================================================================
# Permutation (2): ShiftRows only -- a nibble permutation on the 32 u2h (each nibble =
# 2 u2h half-nibbles, drawn as one thick bundle).  Wiring only, 0 PBS.
# ====================================================================================
def nibble_center_x(nibble):
    return span_center_x(4 * nibble, 4 * nibble + 3)
for i in range(16):                    # out nibble i <- in nibble P_PERM[i]
    src = P_PERM[i]
    hue = (src // 4) * 90
    color = f'hsl({hue},45%,45%)'
    x_src, x_dst = nibble_center_x(src), nibble_center_x(i)
    ym = (Y_U2HM + Y_U2HO) / 2
    emit(f'<path d="M {x_src:.1f} {Y_U2HM:.1f} C {x_src:.1f} {ym:.1f} '
        f'{x_dst:.1f} {ym:.1f} {x_dst:.1f} {Y_U2HO:.1f}" '
        f'fill="none" stroke="{color}" stroke-width="4.4" opacity="0.5"/>')
for u2_idx in range(32):
    ct_wire(span_center_x(2 * u2_idx, 2 * u2_idx + 1), Y_U2HO, Y_U2HO + 10, 2)  # output u2h wires
band_label((Y_U2HM + Y_U2HO) / 2, "u2h")
stage_annotation((Y_U2HM + Y_U2HO) // 2, "permutation &#9313;", "P_PERM (ShiftRows on nibbles) &#8212; 0 PBS")
emit(f'<text x="{LEFT}" y="{Y_U2HO+28}" font-size="9" fill="#889">'
    f'&#8595; 32 u2h &#8212; input state of the next forward round.</text>')

# ---- legend / totals ------------------------------------------------------------------
# One term per stage drawn above, in drawing order.
ADDS = 32 + 16 + 16 * 3 + 32   # sum_with_key, pair-fold, pack_bit_lanes_to_u4, pair-fold
PBS = 32 + 64 + 64             # LUT_XOR_FW, sbox_to_bits, m_layer

lx = LEFT + 64 * COL + 16
ly = HEIGHT - 92
emit(f'<rect x="{lx-6}" y="{ly-16}" width="{RGUT-24}" height="92" rx="5" '
    f'fill="#ffffff" stroke="#cfd4de"/>')
emit(f'<text x="{lx}" y="{ly}" font-size="9.5" font-weight="bold" fill="#334">per forward round</text>')
for k, (color, label) in enumerate([
    (C_XOR, "LUT_XOR_FW"), (C_SBOX, "LUT_*_SBOX_*"), (C_MEXOR, "LUT_EXOR_FW"),
]):
    yy = ly + 12 + k * 12
    lut_box(lx + 6, yy - 3, color, width=11, height=11)
    emit(f'<text x="{lx+18}" y="{yy}" font-size="8.5" fill="#556">{label}</text>')
xor_node(lx + 120, ly + 9)
emit(f'<text x="{lx+130}" y="{ly+12}" font-size="8.5" fill="#556">unchecked_add</text>')
# ct-wire thickness key
for k, (bits, label) in enumerate([(1, "bits: 1 bit"), (2, "u2h: 2 bits"), (4, "u4: nibble")]):
    yy = ly + 24 + k * 12
    emit(f'<line x1="{lx+120}" y1="{yy-3}" x2="{lx+140}" y2="{yy-3}" '
        f'stroke="{CT_WIRE}" stroke-width="{ct_wire_width(bits)}"/>')
    emit(f'<text x="{lx+146}" y="{yy}" font-size="8.5" fill="#556">{label}</text>')
emit(f'<text x="{lx}" y="{ly+70}" font-size="9.5" font-weight="bold" fill="#a23">'
    f'{PBS} PBS  &#183;  {ADDS} ct-adds</text>')

emit('</svg>')

out = __file__.rsplit("/", 1)[0] + "/princev2_fhe_fw_round.svg"
with open(out, "w") as f:
    f.write("\n".join(svg))

print("wrote", out, " size", WIDTH, "x", HEIGHT)
print("ct-adds:", ADDS, " PBS:", PBS)
assert sorted(FHE_MP_PERM_FW) == list(range(64)), "perm not a bijection!"
print("perm OK (bijection over 0..63)")
