#!/usr/bin/env python3
"""
SVG dataflow of ONE BACKWARD round of PRINCEv2 as realised on FHE ciphertexts, drawn
BOTTOM-TO-TOP so that it reads as the inverse of the forward round (see
gen_fhe_fw_round_diagram.py). Same conventions as that diagram:

  * every ciphertext is a WIRE, thickness = ct width (thin = 1 bit `bits`, medium = 2 bits
    `u2h` or `u2l`, thick = 4-bit nibble `u4`);
  * every ciphertext ADDITION (unchecked_add) is drawn as (+);
  * every ciphertext LUT / PBS (apply_lookup_table) is a coloured box;
  * pure wiring permutations cost no PBS.

This is `xor_then_bw_round` in `src/cipher.rs`: the xor layer `xor_to_bits` (the same layer
`mid_round` applies after its S-layer) followed by the round proper, `bw_round`. Compared
with the forward round the layer order is reversed and inverted:

    forward  (top -> bottom):   xor_to_u4   -> sbox_to_bits -> m_layer -> (FHE_M_PERM ; P_PERM)
    backward (bottom -> top):   xor_to_bits -> (INV_P_PERM ; m_layer with FHE_M_PERM)
                                            -> sbox_to_u2h

The key ciphertexts are in u2l, the state in u2h, so `sum_with_key` does not xor: it PACKS
state and key into the two halves of one nibble. The xor proper is the LUT that follows,
LUT_XOR_BIT_*, which maps a nibble to one bit of (x & 3) ^ (x >> 2), drifted into place.

Concretely, reading UP:
    32 u2h (+) key (u2l) -> one nibble -> LUT_XOR_BIT_* -> 64 bits
      -> INV_P_PERM (inverse ShiftRows on nibbles), unfused from the gather above
      -> pack_bit_lanes_to_u4 gather + 4-way sum -> 16 u4
      -> m_layer (LUT_EXOR_BW) -> 64 bits -> FHE_M_PERM bit-reorder
      -> two `sum_adjacent_pairs` -> 16 u4
      -> sbox_to_u2h (LUT_*_INV_SBOX_*) -> 32 u2h   (input state of the next backward round)

`pack_bit_lanes_to_u4_inv_p` FUSES inverse ShiftRows into its gather. Exactly as the forward
diagram splits ShiftRows out of `FHE_MP_PERM_FW`, we split it out here: an INV_P_PERM nibble
permutation on the 64 bits, followed by the forward round's unfused `pack_bit_lanes_to_u4`
gather+fold, reproduces the fused gather (checked below).

Wiring constants are taken directly from cipher.rs / tables.rs (INV_P_PERM, FHE_M_PERM).
"""

# ---- exact wiring constants from the source -------------------------------------------
# Prince inverse ShiftRows permutation on nibbles (gather), literal from tables::INV_P_PERM.
INV_P_PERM = [0x0, 0xd, 0xa, 0x7, 0x4, 0x1, 0xe, 0xb, 0x8, 0x5, 0x2, 0xf, 0xc, 0x9, 0x6, 0x3]

# FHE_M_PERM (gather form: dest i <- src perm[i]); the M'-only bit reorder, rebuilt from tables.rs.
FHE_M0_PERM = [0x0,0x5,0xa,0xf,0x3,0x4,0x9,0xe,0x2,0x7,0x8,0xd,0x1,0x6,0xb,0xc]
FHE_M1_PERM = [0x3,0x4,0x9,0xe,0x2,0x7,0x8,0xd,0x1,0x6,0xb,0xc,0x0,0x5,0xa,0xf]
FHE_M_PERM = [0] * 64
for _word in range(4):                       # M0 permutes the outer 16-bit words, M1 the inner ones
    _perm = FHE_M0_PERM if _word in (0, 3) else FHE_M1_PERM
    _word_base = 16 * _word
    for _bit in range(16):
        FHE_M_PERM[_word_base + _bit] = _word_base + _perm[_bit]

# The gather of `pack_bit_lanes_to_u4_inv_p`, with inverse ShiftRows fused in:
#   out_nibble gathers bits (out_nibble & 3) + 4*INV_P_PERM[4*(out_nibble>>2) + b], b = 0..4.
def pack_bit_lanes_to_u4_inv_p_in_bit_idx(out_nibble):
    return [(out_nibble & 0x3) + 4 * INV_P_PERM[4 * (out_nibble >> 2) + b] for b in range(4)]

# The unfused strided gather of `pack_bit_lanes_to_u4`, as used by the forward round.
def pack_bit_lanes_to_u4_in_bit_idx(out_nibble):
    first = 16 * (out_nibble // 4) + (out_nibble % 4)
    return [first, first + 4, first + 8, first + 12]

# The two chained `sum_adjacent_pairs` bridging M-layer -> S-box: one contiguous quad.
def sum_adjacent_pairs_to_u4_in_bit_idx(out_nibble):
    return [4 * out_nibble, 4 * out_nibble + 1, 4 * out_nibble + 2, 4 * out_nibble + 3]

# INV_P_PERM lifted from nibbles to bit indices.
def inv_p_perm_bit_idx(bit_idx):
    nibble, bit_in_nibble = bit_idx // 4, bit_idx % 4
    return 4 * INV_P_PERM[nibble] + bit_in_nibble

# --- faithfulness checks --------------------------------------------------------------------
# Unfuse inverse ShiftRows from the first fold: the nibble permutation on the 64 bits, followed
# by the unfused strided gather, reproduces the fused gather nibble by nibble.
for _out_nibble in range(16):
    assert pack_bit_lanes_to_u4_inv_p_in_bit_idx(_out_nibble) == [
        inv_p_perm_bit_idx(b) for b in pack_bit_lanes_to_u4_in_bit_idx(_out_nibble)
    ], _out_nibble
assert sorted(
    b for out_nibble in range(16) for b in pack_bit_lanes_to_u4_inv_p_in_bit_idx(out_nibble)
) == list(range(64))
assert sorted(FHE_M_PERM) == list(range(64))
assert sorted(INV_P_PERM) == list(range(16))

# ---- geometry (identical to the forward diagram, so the two line up side-by-side) ------
COL   = 22
LEFT  = 118
RGUT  = 250            # right gutter for per-stage annotations
WIDTH = LEFT + 64 * COL + RGUT

def span_center_x(col_a, col_b):      # x centre of a span covering columns [col_a, col_b]
    return LEFT + ((col_a + col_b + 1) / 2) * COL
def col_center_x(col):                # x centre of a single column
    return LEFT + (col + 0.5) * COL

# colours (same meaning as forward: teal = xor/extract, purple = S-box, orange = M-layer)
C_ADD    = "#33384a"
C_EXTR   = "#2a9d8f"   # xor_to_bits LUT (LUT_XOR_BIT_HIGH / _LOW)
C_SBOX   = "#7b52ab"   # sbox_to_u2h LUT
C_MEXOR  = "#e07b00"   # m_layer LUT
KEY_FILL = "#fbe6d4"; KEY_STROKE = "#cf9a44"
CT_WIRE  = "#8a94a8"   # ciphertext wire colour

svg = []
def emit(svg_fragment): svg.append(svg_fragment)

def ct_wire_width(bits):
    return {1: 1.1, 2: 2.6, 4: 4.6}.get(bits, 1.1)

def ct_wire(x, y0, y1, bits, color=CT_WIRE, opacity=1.0):
    emit(f'<line x1="{x:.1f}" y1="{y0:.1f}" x2="{x:.1f}" y2="{y1:.1f}" '
        f'stroke="{color}" stroke-width="{ct_wire_width(bits)}" opacity="{opacity}"/>')

def band_label(y, text):
    emit(f'<text x="{LEFT-8:.1f}" y="{y+3:.1f}" text-anchor="end" '
        f'font-size="8" fill="#667">{text}</text>')

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

def stage_annotation(y, text, sub=""):
    """`sub` is one caption line, or a tuple of lines stacked under the stage name."""
    x = LEFT + 64 * COL + 16
    emit(f'<text x="{x}" y="{y+2}" font-size="10" font-weight="bold" fill="#334">{text}</text>')
    for k, line in enumerate((sub,) if isinstance(sub, str) else sub):
        if line:
            emit(f'<text x="{x}" y="{y+14+12*k}" font-size="8.5" fill="#778">{line}</text>')

# ---- y-bands (OUTPUT at the top, INPUT at the bottom: data flows UP) -------------------
Y_OUT   = 92       # 32 u2h output wires (top)
Y_LUTS  = 136      # sbox_to_u2h LUT (32 PBS)
Y_U4S   = 178      # u4 feeding sbox_to_u2h (16)
Y_ADDF  = 220      # two chained sum_adjacent_pairs (+)  [48 adds]
Y_BRE   = 258      # 64 bits after FHE_M_PERM reorder
Y_BMX   = 320      # 64 bits out of m_layer (reorder wiring links BMX -> BRE)
Y_LUTM  = 358      # m_layer LUT (64 PBS)
Y_U4M   = 400      # u4 feeding m_layer (16)
Y_ADDI  = 442      # pack_bit_lanes_to_u4 gather + 4-way sum (+)  [48 adds]
Y_BSR   = 480      # 64 bits after INV_P_PERM
Y_BIN   = 560      # 64 bits from xor_to_bits (INV_P_PERM bundles span 560 -> 480)
Y_LUT1  = 598      # LUT_XOR_BIT_* (64 PBS)
Y_KSUM  = 638      # ct_key_sum (2-bit) after the AddKey add
Y_ADD1  = 666      # AddKey (+)
Y_KEY   = 692      # round-key chips
Y_INBOT = 716      # bottom of input u2h wires
HEIGHT  = 740

emit(f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
    f'font-family="ui-monospace,Menlo,Consolas,monospace" font-size="9">')
emit(f'<rect width="{WIDTH}" height="{HEIGHT}" fill="#fbfbfd"/>')
emit(f'<text x="{LEFT}" y="34" font-size="15" font-weight="bold" fill="#222">'
    f'PRINCEv2 backward round on FHE ciphertexts &#8212; drawn bottom-to-top (inverse of the forward round)</text>')
emit(f'<text x="{LEFT}" y="52" font-size="10" fill="#666">'
    f'Every ciphertext is a WIRE (thickness = width: thin = 1 bit `bits` &#183; medium = 2 bits `u2h` or `u2l` &#183; thick = 4-bit nibble `u4`). '
    f'(+) = unchecked_add &#183; coloured box = apply_lookup_table (1 PBS). Reading UP undoes a forward round.</text>')

# group separators (four 16-bit quad-groups)
for g in range(1, 4):
    x = LEFT + g * 16 * COL
    emit(f'<line x1="{x}" y1="{Y_OUT-14}" x2="{x}" y2="{Y_INBOT}" stroke="#e2e5ec" stroke-width="1"/>')

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
brace(Y_BIN, Y_INBOT, "xor_to_bits", "AddKey (&#8853;)")
brace(Y_OUT-8, Y_BIN, "bw_round", "R&#8315;&#185; = S&#8315;&#185; &#183; M&#770; &#183; iSR")

# ---- input state u2h (32) as wires + round-key wires (bottom) -------------------------
emit(f'<text x="{LEFT-4}" y="{Y_KEY+3}" text-anchor="end" font-size="8" fill="#8a5a10">'
    f'ct_k[u2_idx] (u2l)</text>')
for u2_idx in range(32):
    x = span_center_x(2 * u2_idx, 2 * u2_idx + 1)
    ct_wire(x, Y_INBOT, Y_ADD1 + 4, 2)                        # input state ct (u2h) -> add
    kx = x - 10
    emit(f'<rect x="{kx-8:.1f}" y="{Y_KEY-6:.1f}" width="16" height="12" rx="2.5" '
        f'fill="{KEY_FILL}" stroke="{KEY_STROKE}" stroke-width="1" stroke-dasharray="3 2"/>')
    emit(f'<text x="{kx:.1f}" y="{Y_KEY+3:.1f}" text-anchor="middle" font-size="7.5" fill="#8a5a10">k</text>')
    wire(kx, Y_KEY - 6, x, Y_ADD1 + 3, color=KEY_STROKE, width=2.0)  # round-key ct (u2l) -> add
    xor_node(x, Y_ADD1)
    ct_wire(x, Y_ADD1 - 4, Y_KSUM, 4)                         # ct_key_sum: one packed nibble
band_label((Y_INBOT + Y_ADD1) / 2, "32&#215;u2h")
band_label((Y_LUT1 + Y_KSUM) / 2 - 6, "u2h|u2l")
stage_annotation(Y_ADD1, "32 &#215; sum_with_key", "packs state (u2h) + key (u2l) into one nibble")
stage_annotation(Y_LUT1, "64 &#215; LUT_XOR_BIT_*", "xors the halves &#8594; single drifted bits")

# ---- xor_to_bits: each u2h -> 2 single bits (64 PBS) ---------------------------------
for u2_idx in range(32):
    xin = span_center_x(2 * u2_idx, 2 * u2_idx + 1)
    for bit_in_u2 in range(2):
        xo = col_center_x(2 * u2_idx + bit_in_u2)
        wire(xin, Y_KSUM, xo, Y_LUT1 + 7, color="#a9d8cf", width=0.9)  # u2h fans out to 2 bits
        lut_box(xo, Y_LUT1, C_EXTR)
        ct_wire(xo, Y_LUT1 - 7, Y_BIN, 1)                        # single-bit ct
band_label((Y_LUT1 + Y_BIN) / 2 - 4, "bits")

# ==== INV_P_PERM (inverse ShiftRows on nibbles) as a separate permutation: 0 PBS ==========
# out nibble g <- in nibble INV_P_PERM[g]; the 64 bits at the bottom (Y_BIN) -> at the top (Y_BSR).
def nibble_center_x(nibble):
    return span_center_x(4 * nibble, 4 * nibble + 3)
for out_nibble in range(16):
    src = INV_P_PERM[out_nibble]
    hue = (src // 4) * 90
    color = f'hsl({hue},45%,45%)'
    ym = (Y_BIN + Y_BSR) / 2
    emit(f'<path d="M {nibble_center_x(src):.1f} {Y_BIN:.1f} C {nibble_center_x(src):.1f} {ym:.1f} '
        f'{nibble_center_x(out_nibble):.1f} {ym:.1f} {nibble_center_x(out_nibble):.1f} {Y_BSR:.1f}" '
        f'fill="none" stroke="{color}" stroke-width="4.4" opacity="0.5"/>')
band_label((Y_BIN + Y_BSR) / 2, "bits")
stage_annotation((Y_BIN + Y_BSR) // 2, "permutation",
                 ("INV_P_PERM (inverse ShiftRows) &#8212; 0 PBS;",
                  "the code fuses it into the gather above,",
                  "as pack_bit_lanes_to_u4_inv_p"))

# ---- pack_bit_lanes_to_u4 gather + fold -> u4 (16): the unfused half of the gather ------
for out_nibble in range(16):
    xo = span_center_x(4 * out_nibble, 4 * out_nibble + 3)
    for src in pack_bit_lanes_to_u4_in_bit_idx(out_nibble):
        wire(col_center_x(src), Y_BSR, xo, Y_ADDI + 4, width=0.9)
    xor_node(xo, Y_ADDI, r=4.6)
    ct_wire(xo, Y_ADDI - 4.6, Y_U4M, 4)                          # u4 ct
band_label((Y_ADDI + Y_U4M) / 2, "u4")
stage_annotation(Y_ADDI, "48 &#215; pack_bit_lanes_to_u4", "gather 0-4-8-c &#8594; u4 (3 adds &#215;16)")

# ---- m_layer: each u4 -> 4 bits (64 PBS) ---------------------------------------------
for nibble in range(16):
    xin = span_center_x(4 * nibble, 4 * nibble + 3)
    for bit_in_nibble in range(4):
        xo = col_center_x(4 * nibble + bit_in_nibble)
        wire(xin, Y_U4M, xo, Y_LUTM + 7, color="#f2cf9c", width=0.9)  # u4 fans out to 4 bits
        lut_box(xo, Y_LUTM, C_MEXOR)
        ct_wire(xo, Y_LUTM - 7, Y_BMX, 1)                        # single-bit ct
band_label((Y_LUTM + Y_BMX) / 2, "bits")
stage_annotation(Y_LUTM, "64 &#215; m_layer", "LUT_EXOR_BW: near-MDS \"xor of 3\", per nibble")

# ==== M'-only bit reorder (FHE_M_PERM): dest i <- src FHE_M_PERM[i], pure wiring ======
for i in range(64):
    wire(col_center_x(FHE_M_PERM[i]), Y_BMX, col_center_x(i), Y_BRE,
         color="#9aa3b5", width=0.8, opacity=0.85)
emit(f'<rect x="{LEFT-4}" y="{Y_BRE-6}" width="{64*COL+8}" height="{Y_BMX-Y_BRE+6}" '
    f'rx="6" fill="none" stroke="#9aa3b5" stroke-width="1" stroke-dasharray="4 3"/>')
band_label((Y_BMX + Y_BRE) / 2, "bits")
stage_annotation((Y_BMX + Y_BRE) // 2, "permutation", "FHE_M_PERM (M' bit-reorder)")

# ---- sum_adjacent_pairs twice -> u4 (16): bridge m_layer -> sbox_to_u2h ---------------
for out_nibble in range(16):
    xo = span_center_x(4 * out_nibble, 4 * out_nibble + 3)
    for src in sum_adjacent_pairs_to_u4_in_bit_idx(out_nibble):
        wire(col_center_x(src), Y_BRE, xo, Y_ADDF + 4, width=0.9)
    xor_node(xo, Y_ADDF, r=4.6)
    ct_wire(xo, Y_ADDF - 4.6, Y_U4S, 4)                          # u4 ct
band_label((Y_ADDF + Y_U4S) / 2, "u4")
stage_annotation(Y_ADDF, "48 &#215; sum_adjacent_pairs", "twice: fold 4n..4n+3 &#8594; u4 (3 adds &#215;16)")

# ---- sbox_to_u2h: each u4 -> 2 u2h half-nibbles (32 PBS) ------------------------------
for nibble in range(16):
    xin = span_center_x(4 * nibble, 4 * nibble + 3)
    for pair in range(2):
        out_u2 = 2 * nibble + pair
        xo = span_center_x(2 * out_u2, 2 * out_u2 + 1)
        wire(xin, Y_U4S, xo, Y_LUTS + 6, color="#c9c0e0", width=0.9)  # u4 fans out to 2 u2h
        lut_box(xo, Y_LUTS, C_SBOX)
        ct_wire(xo, Y_LUTS - 6, Y_OUT, 2)                        # output u2h ct
band_label((Y_LUTS + Y_OUT) / 2, "u2h")
stage_annotation(Y_LUTS, "32 &#215; sbox_to_u2h", "LUT_*_INV_SBOX_* &#8594; 2,2 bits on high slots")
emit(f'<text x="{LEFT}" y="{Y_OUT-18}" font-size="9" fill="#889">'
    f'&#8593; 32 u2h &#8212; input state of the next backward round.</text>')

# ---- legend / totals ------------------------------------------------------------------
# One term per stage drawn above, in drawing order.
ADDS = 32 + 48 + 48   # sum_with_key, pack_bit_lanes_to_u4, the two chained pair-folds
PBS = 64 + 64 + 32    # LUT_XOR_BIT_*, m_layer, sbox_to_u2h

lx = LEFT + 64 * COL + 16
ly = HEIGHT - 92
emit(f'<rect x="{lx-6}" y="{ly-16}" width="{RGUT-24}" height="92" rx="5" '
    f'fill="#ffffff" stroke="#cfd4de"/>')
emit(f'<text x="{lx}" y="{ly}" font-size="9.5" font-weight="bold" fill="#334">per backward round</text>')
for k, (color, label) in enumerate([
    (C_EXTR, "LUT_XOR_BIT_*"), (C_MEXOR, "LUT_EXOR_BW"), (C_SBOX, "LUT_*_INV_SBOX_*"),
]):
    yy = ly + 12 + k * 12
    lut_box(lx + 6, yy - 3, color, width=11, height=11)
    emit(f'<text x="{lx+18}" y="{yy}" font-size="8.5" fill="#556">{label}</text>')
xor_node(lx + 120, ly + 9)
emit(f'<text x="{lx+130}" y="{ly+12}" font-size="8.5" fill="#556">unchecked_add</text>')
for k, (bits, label) in enumerate([(1, "bits: 1 bit"), (2, "u2h: 2 bits"), (4, "u4: nibble")]):
    yy = ly + 24 + k * 12
    emit(f'<line x1="{lx+120}" y1="{yy-3}" x2="{lx+140}" y2="{yy-3}" '
        f'stroke="{CT_WIRE}" stroke-width="{ct_wire_width(bits)}"/>')
    emit(f'<text x="{lx+146}" y="{yy}" font-size="8.5" fill="#556">{label}</text>')
emit(f'<text x="{lx}" y="{ly+70}" font-size="9.5" font-weight="bold" fill="#a23">'
    f'{PBS} PBS  &#183;  {ADDS} ct-adds</text>')

emit('</svg>')

out = __file__.rsplit("/", 1)[0] + "/princev2_fhe_bw_round.svg"
with open(out, "w") as f:
    f.write("\n".join(svg))

print("wrote", out, " size", WIDTH, "x", HEIGHT)
print("ct-adds:", ADDS, " PBS:", PBS)
print("perm OK (INV_P_PERM + pack_bit_lanes_to_u4 == pack_bit_lanes_to_u4_inv_p; FHE_M_PERM bijective)")
