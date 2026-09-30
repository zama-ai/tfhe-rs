; IOp to validate behavior of wait without attach data
; This IOp has two actors: one consumer and one producer.
; 1. NodeA produce a notify then wait for data from nodeB
; 2. NodeB sync with nodeA (without associated data), then load source and send it to NodeA
; 3. NodeA store received data in dst
; ------------------------------------------------------------------------------
; !preamble {
; [signature]
; Ciphertext<8, 2, 2> -> Ciphertext<8, 2, 2>
; 
; [lut]
; None: [0,1,2,3,5,4,6,7,8,9,10,11,12,13,14,15]
; } ----------------------------------------------------------------------------

LD_B2B F10   TH.0
LD_B2B F11   TH.1
LD_B2B F12   TH.2
LD_B2B F13   TH.3

NOTIFY N1    F1    @0

WAIT   F10   TH.0
WAIT   F11   TH.1
WAIT   F12   TH.2
WAIT   F13   TH.3

LD     R0      TH.0  
LD     R1      TH.1  
LD     R2      TH.2  
LD     R3      TH.3  

PBS    R10     R0    PbsNone
PBS    R11     R1    PbsNone
PBS    R12     R2    PbsNone
PBS_F  R13     R3    PbsNone

ST     TD[0].0 R10
ST     TD[0].1 R11
ST     TD[0].2 R12
ST     TD[0].3 R13
