; IOp Asm snippets sample that depicts all available format
; with the != available arguments modes
; OPCODE <PROTO> <MAPPING> <DST> <SRC> [<IMM>]

; Simple Mode:
; 1 destination, 2 sources, no immediate
; With raw opcode -> 0x35
; All operand belong to Hpu 2
; 4 Hpu involved with 2 used as main one
IOP[0x35] <I8 I8> <2,0,1,3> <I8@0x08{Hpu2}> <I8@0x0{Hpu2} I8@0x4{Hpu2}>
; With raw opcode -> 40 and dynamic Fw generation
; Dst on Hpu 0, Src on Hpu 1 and 2
; 4 Hpu involved with 0 used as main one
IOP[0x35] <dyn I8 I8> <0,1,2,3> <I8@0x08{Hpu0}> <I8@0x0{Hpu1} I8@0x4{Hpu2}>
; With opcode alias -> MUL
; All operand on Hpu 1
; 8 Hpu involved, 1 used as main
MUL <I64 I64> <1,2,0,4,3,5,6,7> <I64@0x08{Hpu1}> <I64@0x0{Hpu1} I64@0x10{Hpu1}>

; Simple Mode with immediate
; Source operands are defined through vector mode
; Dst on Hpu 0, Src on Hpu 2
; 4 Hpu involved with 0 used as main one
MULS <I8 I8> <0,1,2,3> <I8@0x8{Hpu0}> <I8[2]@0x0{Hpu2}> <0xaf>

; Vectorized mode with opcode alias
; ADDV <I16 I8> <I16@0x10> <I8[8]@0x0>
; Nb: not implemented yet, use raw format instead
; All operand belong to Hpu4
; Only Hpu4 involved
IOP[0x20] <I16 I8> <4> <I16@0x10{Hpu4}> <I8[8]@0x0{Hpu4}>

; Two destination w.o. opcode alias
; I.e. could be a div euclide which output divider and remainder
; All operand belong to Hpu0
; Only Hpu0 involved
IOP[0x60] <dyn I8 I8> <0> <I8@0x10{Hpu0} I8@0x14{Hpu0}> <I8@0x0{Hpu0} I8@0x4{Hpu0}>
; Previous operation could be defined with vector format.
IOP[0x40] <dyn I8 I8> <0> <I8[2]@0x10{Hpu0}> <I8[2]@0x0{Hpu0}>

; With multiple immediat
; All operand belong to Hpu0
; Only Hpu0 involved
; Example this operation could compute D <- A*4 + B*8  
IOP[0x0] <I16 I16> <0> <I16@16{Hpu0}> <I16@0x0{Hpu0} I8@0x8{Hpu0}> <0xdeadc0de>
