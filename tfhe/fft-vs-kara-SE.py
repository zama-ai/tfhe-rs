#!/usr/bin/env python3

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator

IN_FILE_FMT = "samples/%s_noise_thread_%d_input_msg_%d.npy"
CT_MOD = 2.0**64

FIG_W = 2400
FIG_H = 1200
DPI = 96

NB_TESTS = 500
# ~ NB_TESTS = 10

msg = 0
thread = 0

# load everything into a single array
data_len = len(np.load(IN_FILE_FMT % ("fft", thread, msg)))
f = [np.array([]) for _ in range(0,data_len)]
k = [np.array([]) for _ in range(0,data_len)]

for thread in range(0,NB_TESTS):
    fi = np.load(IN_FILE_FMT % ("fft", thread, msg)) / CT_MOD
    ki = np.load(IN_FILE_FMT % ("karatsuba", thread, msg)) / CT_MOD

    f = np.column_stack([f,fi])
    k = np.column_stack([k,ki])

# compute diff (shall be aligned s.t. the same sample is calculated at respective index)
fk = f - k

#TODO histograms for selected indexes:

for i in [1, 2, 4, 8, 32, 128, 321]:
    plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() # ; plt.ylim(-1.5e-4,1.5e-4)
    plt.hist(f[i-1], 50)
    plt.title("FFT distro at step %d" % (i))
    plt.savefig("FFT-distro-%d.png" % (i)) # , format="pdf", bbox_inches="tight"
    # ~ plt.show()
    plt.close()

# ====    FFT    ===============================================================
f_means = [np.mean(fi) for fi in f]
f_vars  = [np.var (fi) for fi in f]
f_stdvs = [np.std (fi) for fi in f]

plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() ; plt.ylim(-1.5e-4,1.5e-4)
plt.errorbar(
    np.arange(len(f_means)),
    f_means,
    yerr = f_stdvs,
    fmt ='o',
)
plt.title("FFT mean & std-dev")
plt.savefig("FFT-mean-stddev.png") # , format="pdf", bbox_inches="tight"
# ~ plt.show()
plt.close()

# ====    Karatsuba    =========================================================
k_means = [np.mean(ki) for ki in k]
k_vars  = [np.var (ki) for ki in k]
k_stdvs = [np.std (ki) for ki in k]

plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() ; plt.ylim(-1.5e-4,1.5e-4)
plt.errorbar(
    np.arange(len(k_means)),
    k_means,
    yerr = k_stdvs,
    fmt ='o',
)
plt.title("Karatsuba mean & std-dev")
plt.savefig("Kara-mean-stddev.png") # , format="pdf", bbox_inches="tight"
# ~ plt.show()
plt.close()

# ====    Diff    ==============================================================
fk_means = [np.mean(fki) for fki in fk]
fk_vars  = [np.var (fki) for fki in fk]
fk_stdvs = [np.std (fki) for fki in fk]

plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() ; plt.ylim(-1.5e-4,1.5e-4)
plt.errorbar(
    np.arange(len(fk_means)),
    fk_means,
    yerr = fk_stdvs,
    fmt ='o',
)
plt.title("(FFT-Kara) mean & std-dev")
plt.savefig("FFT-Kara-diff-mean-stddev.png") # , format="pdf", bbox_inches="tight"
# ~ plt.show()
plt.close()

# ====    Both    ==============================================================
fig = plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI)

plt.tight_layout() ; plt.grid() ; plt.ylim(-.5e-9,1.0e-8) ; plt.gca().yaxis.set_major_locator(MultipleLocator(1e-9))
plt.title("FFT vs. Kara var's")
plt.plot(f_vars, label='FFT')
plt.plot(k_vars, label='Karatsuba')

plt.savefig("variances-FFT-Kara.png") # , format="pdf", bbox_inches="tight"
# ~ plt.show()
plt.close()
