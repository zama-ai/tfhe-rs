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


; Wait for sync without data
WAIT   F1

LD     R0    TS[0].0             
LD     R1    TS[0].1             
LD     R2    TS[0].2             
LD     R3    TS[0].3             


PBS_F  R10   R0      PbsNone
ST     TH.0  R10
NOTIFY N0    F10     TH.0

PBS_F  R11   R1      PbsNone
ST     TH.1  R11
NOTIFY N0    F11     TH.1

PBS_F  R12   R2      PbsNone
ST     TH.2  R12
NOTIFY N0    F12     TH.2

PBS_F  R13   R3      PbsNone
ST     TH.3  R13
NOTIFY N0    F13     TH.3
