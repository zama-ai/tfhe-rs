import scipy.stats as stats
from scipy.special import erfcinv, erfc
import math

# utilities
t = 1 / (2 ** (4 + 2))  # noise bound
standard_score = lambda p_fail: math.sqrt(2) * erfcinv(p_fail)  # standard score

pfail = lambda z: erfc(z / math.sqrt(2))

# Noise squashing after compression
# measured_variance = 7.598561171474912e-35
# variance_after_flood = measured_variance * (2**40 * 100) ** 2

# measured_std_dev = math.sqrt(variance_after_flood)

# New params GPU before MS 128
# measured_variance = 1.438540449823688e-6
# Rerand noise
# measured_variance = 1.4064222454361346e-6
# measured_variance = 1.408401059719539e-6

# measured_variance = 1.4120971218065554e-6 #KS32
measured_variance = 1.4150031500067098e-6
measured_std_dev = math.sqrt(measured_variance)

measured_std_score = t / measured_std_dev

estimated_pfail = pfail(measured_std_score)

print(estimated_pfail, math.log2(estimated_pfail))


# Compression encoding for 2_2
t_compression = 1 / (2 ** (2 + 2))
measured_variance = 1.0216297411906617e-5
measured_std_dev = math.sqrt(measured_variance)

measured_std_score = t_compression / measured_std_dev

estimated_pfail = pfail(measured_std_score)
print(estimated_pfail, math.log2(estimated_pfail))
