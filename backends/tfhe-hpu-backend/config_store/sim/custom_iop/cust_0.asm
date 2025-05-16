# CUST_0
# Simple IOp to check the xfer between Hpu/Cpu
# Construct constant in dest slot -> 249 (0xf9)
SUB R0 R0 R0
ADDS R0 R0 1
ST TD[0].0 R0 
SUB R1 R1 R1
ADDS R1 R1 2
ST TD[0].1 R1 
SUB R2 R2 R2
ADDS R2 R2 3
ST TD[0].2 R2 
SUB R3 R3 R3
ADDS R3 R3 3
ST TD[0].3 R3 
