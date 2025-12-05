; IOp Asm snippets sample that depicts all available format
; with the != available arguments modes

; Simple Mode:
; 1 destination, 2 sources, no immediate
; With raw opcode -> 0x35
IOP[0x35] <I8 I8> <I8@0x08> <I8@0x0 I8@0x4>
; With raw opcode -> 40 and dynamic Fw generation
; IOP[0x35] <dyn I8 -> I8> <I8@0x08> <I8@0x0 I8@0x4>
IOP[0x35] <dyn I8 I8> <I8@0x08> <I8@0x0 I8@0x4>
; With opcode alias -> MUL
MUL <I8 I8> <I8@0x08> <I8@0x0 I4@0x4>

; Simple Mode with immediate
; Source operands are defined through vector mode
MULS <I8 I8> <I8@0x8> <I8[2]@0x0> <0xaf>

; Vectorized mode with opcode alias
; ADDV <I16 I8> <I16@0x10> <I8[8]@0x0>
; Nb: not implemented yet, use raw format instead
IOP[0x20] <I16 I8> <I16@0x10> <I8[8]@0x0>

; Two destination w.o. opcode alias
; I.e. could be a div euclide which output divider and remainder
IOP[0x60] <dyn I8 I8> <I8@0x10 I8@0x14> <I8@0x0 I8@0x4>
; Previous operation could be defined with vector format.
IOP[0x40] <dyn I8 I8> <I8[2]@0x10> <I8[2]@0x0>

; With multiple immediate
; Example this operation could compute D <- A*4 + B*8  
IOP[0x0] <I16 I16> <I16@16> <I16@0x0 I8@0x8> <0xdeadc0de>
