# CUST_2
# Simple IOp to check the xfer between Hpu/Cpu
# Dest <- Src_b
LD R0   TS[1].0
LD R1   TS[1].1
LD R2   TS[1].2
LD R3   TS[1].3
ST TD[0].0 R0 
ST TD[0].1 R1 
ST TD[0].2 R2 
ST TD[0].3 R3 
