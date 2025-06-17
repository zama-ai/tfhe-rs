; DOp Asm snippets sample that depicts all available format
; with the != available arguments modes
; Test LD with various template format
LD R1 @0x400
LD R2 @386
LD R3 TS[8].4
LD R3 TD[8].4
LD R4 TH.60

; Test ST with various template format
ST @0x400   R1 
ST @386     R2 
ST TS[8].4 R3 
ST TD[4].0 R4 
ST TH.60  R4 

; Test Arith operation
ADD R2 R1 R3
SUB R2 R1 R3
; MUL R2 R1 R3 ; Must failed, MUL isn't supported on Digit
MAC R2 R1 R3 4

; Test ArithMsg operation with various immediate template format
ADDS R2 R1 10
SUBS R2 R1 TI[4].0
SSUB R2 R1 TI[2].4
SUBS R2 R1 TI[4].0

; Test Pbs operation
PBS R2 R1 PbsNone
PBS_F R2 R1 PbsCarryInMsg

; Test Ucore operation
SYNC   N0 BH.0
SYNC   N2 BH.1
SYNC   N2 TS[0]
WAIT   N0 BH.0
LD_B2B N0 TS[0]
