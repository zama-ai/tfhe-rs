# CUST_1
# Simple IOp to check the xfer between Hpu/Cpu
# Dest <- Src_a
LD R0   TS[0].0
LD R1   TS[0].1
LD R2   TS[0].2
LD R3   TS[0].3
ST TD[0].0 R0 
ST TD[0].1 R1 
ST TD[0].2 R2 
ST TD[0].3 R3 
