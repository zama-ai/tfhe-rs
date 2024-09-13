# Config_gen parameters
## 64b_7324cb (i.e. 64b pfail 2**-40)
-> Coefs32 (i.e. PSI16)
```
./target/release/config_gen --coef-w 64 --glwe-n 2048 --glwe-k 1 --lwe-k 710 --ks-cycles 416 --br-load-cycles 96 --batch-pbs 8 --config-file mockups/tfhe-hpu-mockup/params/pe/hpu_64b_7324cb_32coefs.ron
```
## 64b_secure (i.e. 64b pfail 2**-64)
-> Coefs64 (i.e. PSI32)
```
./target/release/config_gen --coef-w 64 --glwe-n 2048 --glwe-k 1 --lwe-k 786 --ks-cycles 238 --br-load-cycles 64 --batch-pbs 8 --config-file mockups/tfhe-hpu-mockup/params/pe/hpu_64b_secure_64coefs.ron
```
-> Coefs128 (i.e. PSI64)
```
./target/release/config_gen --coef-w 64 --glwe-n 2048 --glwe-k 1 --lwe-k 786 --ks-cycles 357 --br-load-cycles 32 --batch-pbs 12 --config-file mockups/tfhe-hpu-mockup/params/pe/hpu_64b_secure_128coefs.ron
```
