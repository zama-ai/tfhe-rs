; CUST_8
; Simple IOp to check the ALU operation 
; Dst[0].0 <- Src[0].0 + Src[1].0
LD R1 TS[0].0
LD R2 TS[1].0
ADD R0 R1 R2
ST TD[0].0 R0 

; Dst[0].1 <- Src[0].1 - Src[1].1
LD R5 TS[0].1
LD R6 TS[1].1
SUB R4 R5 R6
ST TD[0].1 R4 

; Dst[0].2 <- Src[0].2 + (Src[1].2 *4)
LD R9 TS[0].2
LD R10 TS[1].2
MAC R8 R9 R10 4
ST TD[0].2 R8 
