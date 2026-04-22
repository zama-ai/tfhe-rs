#!/usr/bin/env python3
"""
Generate an SVG wiring diagram of ONE BACKWARD round of PRINCEv2, drawn BOTTOM-TO-TOP so
that it reads as the mirror / inverse of the forward round (see gen_fw_round_diagram.py).

This is the cipher as specified: one layer per stage, in spec order. The wiring constants come
from `src/tables.rs`, but the implementation does not evaluate the layers in this shape — it
folds the round constants into the S-box LUTs (`build_lut_xor_sbox_xor`) and fuses inverse
ShiftRows into the M-layer gather. See `gen_fhe_bw_round_diagram.py` for the dataflow actually
evaluated.

A backward round is:  s ^= k ; s ^= RC ; s = ShiftRows^{-1}(s) ; s = M-hat(s) ; s = SubCells^{-1}(s)
which is exactly a forward round with the layer order reversed and every layer replaced by
its inverse (M-hat is involutive, so it is its own inverse).

    forward  (top -> bottom):   AddKey -> AddRC -> SubCells -> M-hat -> ShiftRows
    backward (bottom -> top):   AddKey -> AddRC -> ShiftRows^{-1} -> M-hat -> SubCells^{-1}

Data flows UPWARD here: input state at the BOTTOM, output at the TOP. Placed beside the
forward diagram (which flows top-to-bottom) the two visibly undo one another.

State layout (same as `src/u64_conv.rs` and `src/tables.rs`):
  - 64-bit block = 16 nibbles, nibble 0 = most-significant.
  - within a nibble, bit_in_nibble = 0..3, with 0 = most-significant bit.
  - global wire index used here: bit_idx = 4*nibble + bit_in_nibble (bit_idx 0 = overall MSB).
"""

# Inverse ShiftRows nibble permutation (gather form: out[i] = in[INV_P_PERM[i]]), from tables::INV_P_PERM
INV_P_PERM = [0x0, 0xd, 0xa, 0x7, 0x4, 0x1, 0xe, 0xb, 0x8, 0x5, 0x2, 0xf, 0xc, 0x9, 0x6, 0x3]


def m_layer_edges():
    """Return list of (in_wire, out_wire, bitplane) for the M-hat (mprime) layer.

    M-hat is involutive, so the backward round uses exactly the same edges as the forward one.
    """
    edges = []
    for chunk in range(4):
        rotate = 0 if chunk in (0, 3) else 1  # M0_hat for chunks 0,3 ; M1_hat for 1,2
        for out_nibble_in_chunk in range(4):
            out_nibble = 4 * chunk + out_nibble_in_chunk
            for bit_in_nibble in range(4):    # bit position (0 = MSB)
                # One bit-plane of a chunk is the u4 that `pack_bit_lanes_to_u4` builds; the
                # xor below is `u4_exor`, which drops exactly one bit of that u4.
                excluded_u4_bit = (bit_in_nibble + 8 - out_nibble_in_chunk - rotate) % 4
                out_bit = 4 * out_nibble + bit_in_nibble
                for u4_bit in range(4):       # input nibbles of the chunk, packed as a u4
                    if u4_bit != excluded_u4_bit:   # "XOR of all but one"
                        in_nibble = 4 * chunk + u4_bit
                        in_bit = 4 * in_nibble + bit_in_nibble
                        edges.append((in_bit, out_bit, bit_in_nibble))
    return edges


# --- faithfulness check: ShiftRows^-1 + M-hat above == what `bw_round` evaluates -------------
# `pack_bit_lanes_to_u4_inv_p` packs bit-plane `m` of the four nibbles INV_P_PERM[4g..4g+4] into
# one u4; the position a bit takes there is fixed by the drift `xor_to_bits` gave it, 3 - (n % 4)
# for source nibble n. `m_layer` then drops one bit per output (`u4_exor`) through the FHE_M_PERM
# gather, and two chained pair-folds reassemble four e-xor results into one output nibble.
# Replaying that on bit indices must reproduce the edges drawn above, inverse ShiftRows included.
FHE_M0_PERM = [0x0, 0x5, 0xa, 0xf, 0x3, 0x4, 0x9, 0xe, 0x2, 0x7, 0x8, 0xd, 0x1, 0x6, 0xb, 0xc]
FHE_M1_PERM = [0x3, 0x4, 0x9, 0xe, 0x2, 0x7, 0x8, 0xd, 0x1, 0x6, 0xb, 0xc, 0x0, 0x5, 0xa, 0xf]
FHE_M_PERM = [0] * 64
for _chunk in range(4):                  # M0 permutes the outer 16-bit chunks, M1 the inner ones
    _perm = FHE_M0_PERM if _chunk in (0, 3) else FHE_M1_PERM
    for _bit in range(16):
        FHE_M_PERM[16 * _chunk + _bit] = 16 * _chunk + _perm[_bit]

packed_u4 = []                # packed_u4[u4_idx][pos] = the bit index held there (pos 0 = MSB)
for u4_idx in range(16):
    chunk, plane = u4_idx >> 2, u4_idx & 3
    by_pos = {INV_P_PERM[4 * chunk + i] % 4: 4 * INV_P_PERM[4 * chunk + i] + plane
              for i in range(4)}
    assert sorted(by_pos) == [0, 1, 2, 3], "drifted bits collide inside the packed u4"
    packed_u4.append([by_pos[pos] for pos in range(4)])

replayed = set()
for out_nibble in range(16):
    bits_hit = set()
    for fold_idx in range(4):
        src = FHE_M_PERM[4 * out_nibble + fold_idx]
        u4_idx, excluded_u4_bit = src >> 2, src & 3
        # LUT_EXOR_BW cycles TO_3..TO_0 by u4 index, so the u4 picks the output bit position
        out_bit = 4 * out_nibble + u4_idx % 4
        bits_hit.add(out_bit)
        for pos in range(4):
            if pos != excluded_u4_bit:
                replayed.add((packed_u4[u4_idx][pos], out_bit))
    assert len(bits_hit) == 4, "the chained folds collide inside an output nibble"
# The drawn edges start after inverse ShiftRows; pull their input side back to the round input.
assert replayed == {(4 * INV_P_PERM[in_bit >> 2] + (in_bit & 3), out_bit)
                    for in_bit, out_bit, _ in m_layer_edges()}, "M-hat wiring no longer matches"

# ----------------------------------------------------------------------------- geometry
BIT_DX   = 16          # spacing between the 4 wires of one nibble
NIB_GAP  = 14          # extra gap between nibbles
CHUNK_GAP = 34         # extra gap between 16-bit chunks
LEFT     = 90          # left margin (room for stage labels)
RIGHT    = 40

# per bit-plane colours (j = 0..3, 0 = MSB)
PLANE_COL = ["#d1495b", "#2a9d8f", "#3d5a80", "#e08e0b"]

def bit_wire_x(bit_idx):
    nibble = bit_idx >> 2
    bit_in_nibble = bit_idx & 3
    chunk = nibble // 4
    nibble_in_chunk = nibble % 4
    x = LEFT
    x += chunk * (4 * (4 * BIT_DX + NIB_GAP) + CHUNK_GAP)
    x += nibble_in_chunk * (4 * BIT_DX + NIB_GAP)
    x += bit_in_nibble * BIT_DX
    return x

LEGEND_W = 150         # reserved right gutter for the bit-plane legend
WIDTH = bit_wire_x(63) + RIGHT + LEGEND_W

# ----------------------------------------------------------------------------- y-bands
# OUTPUT sits at the TOP, INPUT at the BOTTOM: data flows upward.
Y_TITLE   = 34
Y_OUT_LBL = 66          # output bit labels (top)
Y_OUT     = 86          # top of output wires
Y_SBOX_T  = 122         # S^{-1} boxes top
Y_SBOX_B  = 170         # S^{-1} boxes bottom
Y_M_NODE  = 224         # base y for M-hat XOR nodes (staggered per bit-plane, downward)
Y_M_TAP   = 312         # where the ShiftRows^{-1} outputs tap into the M-hat fan-in
Y_SR_T    = 340         # ShiftRows^{-1} bundles top (output side, feeds M-hat)
Y_SR_B    = 428         # ShiftRows^{-1} bundles bottom (input side, from AddKey)
Y_KEY     = 466         # AddKey / AddRC XOR row
Y_IN      = 504         # bottom of input wires
Y_IN_LBL  = 524         # input bit labels (bottom)
HEIGHT    = 572

svg = []
def emit(svg_fragment): svg.append(svg_fragment)

emit(f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
    f'font-family="ui-monospace,Menlo,Consolas,monospace" font-size="9">')
emit(f'<rect width="{WIDTH}" height="{HEIGHT}" fill="#fbfbfd"/>')
emit(f'<text x="{LEFT}" y="{Y_TITLE}" font-size="15" font-weight="bold" fill="#222">'
    f'PRINCEv2 — one backward round (drawn bottom-to-top: the inverse of a forward round)</text>')
emit(f'<text x="{LEFT}" y="{Y_TITLE+16}" font-size="10" fill="#666">'
    f'reading UP: &#8853; k &#8594; &#8853; RC &#8594; ShiftRows&#8315;&#185; &#8594; M&#770; (involutive) '
    f'&#8594; SubCells&#8315;&#185; (S&#8315;&#185;).  Thin wire = 1 bit; thick line = whole nibble.</text>')

# stage labels on the left (top -> bottom: S^{-1}, M-hat, ShiftRows^{-1}, key)
def stage_label(y, text):
    emit(f'<text x="8" y="{y}" font-size="10" font-weight="bold" fill="#334">{text}</text>')
stage_label((Y_SBOX_T+Y_SBOX_B)//2+3, "S&#8315;&#185;")
stage_label(Y_M_NODE+3, "M&#770;")
stage_label((Y_SR_T+Y_SR_B)//2,    "Shift")
stage_label((Y_SR_T+Y_SR_B)//2+12, "Rows&#8315;&#185;")
stage_label(Y_KEY+3,   "&#8853; k")
stage_label(Y_KEY+15,  "&#8853; RC")

def nibble_center_x(nibble):
    return (bit_wire_x(4 * nibble) + bit_wire_x(4 * nibble + 3)) / 2

# ------- input nibble group brackets + labels at the BOTTOM (thick = nibble bundle) -------
for nibble in range(16):
    x0 = bit_wire_x(4 * nibble) - 5
    x1 = bit_wire_x(4 * nibble + 3) + 5
    emit(f'<rect x="{x0}" y="{Y_IN-6}" width="{x1-x0}" height="12" rx="3" '
        f'fill="none" stroke="#8894aa" stroke-width="2.2"/>')
    emit(f'<text x="{(x0+x1)/2:.1f}" y="{Y_IN_LBL+8}" text-anchor="middle" '
        f'font-size="9" font-weight="bold" fill="#556">N{nibble}</text>')
    for bit_in_nibble in range(4):
        bit_idx = 4 * nibble + bit_in_nibble
        emit(f'<text x="{bit_wire_x(bit_idx)}" y="{Y_IN_LBL-4}" text-anchor="middle" '
            f'font-size="7.5" fill="#99a">{bit_idx}</text>')

# chunk separators / labels (near the M-hat band)
for chunk in range(4):
    xa = bit_wire_x(16 * chunk) - 12
    xb = bit_wire_x(16 * chunk + 15) + 12
    mtype = "M0&#770;" if chunk in (0, 3) else "M1&#770;"
    emit(f'<text x="{(xa+xb)/2:.1f}" y="{Y_M_NODE-24:.1f}" text-anchor="middle" '
        f'font-size="9" fill="#889">chunk {chunk} ({mtype})</text>')

# ---------------------------------------------------------------- input wires -> key (upward)
for bit_idx in range(64):
    x = bit_wire_x(bit_idx)
    emit(f'<line x1="{x}" y1="{Y_IN}" x2="{x}" y2="{Y_KEY}" stroke="#c7ccd6" stroke-width="1"/>')

# AddKey / AddRC : one XOR node per wire, then a wire UP into the ShiftRows^{-1} band
for bit_idx in range(64):
    x = bit_wire_x(bit_idx)
    emit(f'<circle cx="{x}" cy="{Y_KEY}" r="3.4" fill="white" stroke="#333" stroke-width="1"/>')
    emit(f'<line x1="{x-2.4}" y1="{Y_KEY}" x2="{x+2.4}" y2="{Y_KEY}" stroke="#333" stroke-width="0.8"/>')
    emit(f'<line x1="{x}" y1="{Y_KEY-2.4}" x2="{x}" y2="{Y_KEY+2.4}" stroke="#333" stroke-width="0.8"/>')
    emit(f'<line x1="{x}" y1="{Y_KEY-3.4}" x2="{x}" y2="{Y_SR_B}" stroke="#c7ccd6" stroke-width="1"/>')

# ---------------------------------------------------------------- ShiftRows^{-1} (nibble bundles)
# out nibble i = in nibble INV_P_PERM[i]; input side at the bottom (Y_SR_B), output side at top (Y_SR_T).
for i in range(16):
    src = INV_P_PERM[i]
    x_src = nibble_center_x(src)      # input nibble (bottom)
    x_dst = nibble_center_x(i)        # output nibble (top)
    hue = (src // 4) * 90          # colour bundles by source chunk for readability
    col = f'hsl({hue},45%,45%)'
    emit(f'<path d="M {x_src:.1f} {Y_SR_B} C {x_src:.1f} {(Y_SR_T+Y_SR_B)/2:.1f} '
        f'{x_dst:.1f} {(Y_SR_T+Y_SR_B)/2:.1f} {x_dst:.1f} {Y_SR_T:.1f}" '
        f'fill="none" stroke="{col}" stroke-width="4.2" opacity="0.55"/>')
# split each output nibble back into 4 single bit-wires feeding the M-hat fan-in
for bit_idx in range(64):
    x = bit_wire_x(bit_idx)
    emit(f'<line x1="{x}" y1="{Y_SR_T}" x2="{x}" y2="{Y_M_TAP}" stroke="#c7ccd6" stroke-width="1"/>')

# ---------------------------------------------------------------- M-hat layer (fan-in from below)
edges = m_layer_edges()
from collections import defaultdict
ins = defaultdict(list)
for in_bit, out_bit, bit_in_nibble in edges:
    ins[out_bit].append((in_bit, bit_in_nibble))

def exor_node_y(bit_in_nibble):
    return Y_M_NODE + bit_in_nibble * 13       # stagger downward, toward the taps

# fan-in wires: from the ShiftRows^{-1} taps (below) up to each node
for out_bit, srcs in ins.items():
    bit_in_nibble = out_bit & 3
    xo = bit_wire_x(out_bit)
    ny = exor_node_y(bit_in_nibble)
    color = PLANE_COL[bit_in_nibble]
    for in_bit, _ in srcs:
        xi = bit_wire_x(in_bit)
        emit(f'<line x1="{xi}" y1="{Y_M_TAP}" x2="{xo}" y2="{ny}" '
            f'stroke="{color}" stroke-width="0.9" opacity="0.8"/>')

# XOR nodes + wire UP into the S^{-1} boxes
for out_bit in range(64):
    bit_in_nibble = out_bit & 3
    xo = bit_wire_x(out_bit)
    ny = exor_node_y(bit_in_nibble)
    color = PLANE_COL[bit_in_nibble]
    emit(f'<circle cx="{xo}" cy="{ny}" r="3.6" fill="white" stroke="{color}" stroke-width="1.3"/>')
    emit(f'<line x1="{xo-2.5}" y1="{ny}" x2="{xo+2.5}" y2="{ny}" stroke="{color}" stroke-width="0.9"/>')
    emit(f'<line x1="{xo}" y1="{ny-2.5}" x2="{xo}" y2="{ny+2.5}" stroke="{color}" stroke-width="0.9"/>')
    emit(f'<line x1="{xo}" y1="{ny-3.6}" x2="{xo}" y2="{Y_SBOX_B}" stroke="#c7ccd6" stroke-width="1"/>')

# bit-plane legend (right gutter, clear of the wires)
lx = bit_wire_x(63) + RIGHT
emit(f'<text x="{lx}" y="{Y_M_NODE-40}" font-size="9" font-weight="bold" fill="#556">M&#770; bit-planes</text>')
for bit_in_nibble in range(4):
    yy = Y_M_NODE - 28 + bit_in_nibble * 12
    emit(f'<line x1="{lx}" y1="{yy}" x2="{lx+16}" y2="{yy}" '
        f'stroke="{PLANE_COL[bit_in_nibble]}" stroke-width="2"/>')
    tag = "MSB" if bit_in_nibble == 0 else ("LSB" if bit_in_nibble == 3 else "")
    emit(f'<text x="{lx+22}" y="{yy+3}" font-size="8" fill="#556">bit {bit_in_nibble} {tag}</text>')

# ---------------------------------------------------------------- S^{-1} boxes (per nibble)
for nibble in range(16):
    x0 = bit_wire_x(4 * nibble) - 6
    x1 = bit_wire_x(4 * nibble + 3) + 6
    emit(f'<rect x="{x0}" y="{Y_SBOX_T}" width="{x1-x0}" height="{Y_SBOX_B-Y_SBOX_T}" '
        f'rx="4" fill="#eef1f6" stroke="#6b7a99" stroke-width="1.4"/>')
    emit(f'<text x="{(x0+x1)/2:.1f}" y="{(Y_SBOX_T+Y_SBOX_B)/2+4:.1f}" text-anchor="middle" '
        f'font-size="11" font-weight="bold" fill="#334">S&#8315;&#185;</text>')
    # outputs of S^{-1} rise to the output labels
    for bit_in_nibble in range(4):
        x = bit_wire_x(4 * nibble + bit_in_nibble)
        emit(f'<line x1="{x}" y1="{Y_SBOX_T}" x2="{x}" y2="{Y_OUT}" stroke="#c7ccd6" stroke-width="1"/>')

# ---------------------------------------------------------------- output labels (top)
for nibble in range(16):
    x0 = bit_wire_x(4 * nibble) - 5
    x1 = bit_wire_x(4 * nibble + 3) + 5
    emit(f'<rect x="{x0}" y="{Y_OUT-6}" width="{x1-x0}" height="12" rx="3" '
        f'fill="none" stroke="#8894aa" stroke-width="2.2"/>')
    emit(f'<text x="{(x0+x1)/2:.1f}" y="{Y_OUT_LBL-4}" text-anchor="middle" '
        f'font-size="9" font-weight="bold" fill="#556">N{nibble}</text>')

emit('</svg>')

out = __file__.rsplit("/", 1)[0] + "/princev2_bw_round.svg"
with open(out, "w") as f:
    f.write("\n".join(svg))
print("wrote", out, "  size", WIDTH, "x", HEIGHT)
print("Mhat edges:", len(edges), "(should be 64*3 = 192)")
assert sorted(INV_P_PERM) == list(range(16)), "INV_P_PERM not a permutation!"
print("INV_P_PERM OK (permutation over 0..15)")
