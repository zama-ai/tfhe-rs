; CUST_9
; Simple IOp to check the ALU Scalar operation 
; Dst[0].0 <- Src[0].0 + Imm[0].0
LD R1 TS[0].0
ADDS R0 R1 TI[0].0
ST TD[0].0 R0 

; Dst[0].1 <- Src[0].1 - Imm[0].1
LD R5 TS[0].1
SUBS R4 R5 TI[0].1
ST TD[0].1 R4 

; Dst[0].2 <- Imm[0].2 - Src[0].2
LD R9 TS[0].2
SSUB R8 R9 TI[0].2
ST TD[0].2 R8 

; Dst[0].3 <- Src[0].3 * Imm[0].3
LD R13 TS[0].3
MULS R12 R13 TI[0].3
ST TD[0].3 R12 
