#!/usr/bin/env python3

import numpy as np
import os.path as osp
import json
from scipy.optimize import curve_fit
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator

EXP_NAME = "wide-search-2000" # wide-search-2000   gpu-gauss

IN_FILE_FMT = "results/" + EXP_NAME + "/samples/%s-id=%d-gf=%d-logB=%d-l=%d-k=%d-N=%d-distro=%s.npy"
OUT_FILE_FMT = "results/" + EXP_NAME + "/graphs/%s-gf=%d-logB=%d-l=%d-k=%d-N=%d-distro=%s-nsamples=%d.png"
EXP_VAR_FILE_FMT = "results/" + EXP_NAME + "/expected-variances-gf=%d-logB=%d-l=%d-k=%d-N=%d-distro=%s.json"
CT_MOD = 2.0**64

FIG_W = 2400
FIG_H = 1200
DPI = 96

NB_TESTS_MAX = 2501

fft_noises = {}
kara_noises = {}

for gf in range(3,3+1):
    # ~ for logbase in [3*i for i in range(3,10+1)]:
    for logbase in range(3,30+1):
        for level in range(1,4+1):
            if logbase * level < 15 or logbase * level > 30:
                continue
            for k in range(1,3+1):
                for logN in range(9,13+1):

                    # Convert dictionary to tuple (sorted to make it deterministic)
                    params = tuple(sorted({
                        "gf": gf,
                        "logbase": logbase,
                        "level": level,
                        "k": k,
                        "logN": logN,
                    }.items()))

                    # load predicted noise
                    if not osp.isfile(EXP_VAR_FILE_FMT % (gf, logbase, level, k, 1<<logN, "GAUSSIAN")):
                        continue
                    with open(EXP_VAR_FILE_FMT % (gf, logbase, level, k, 1<<logN, "GAUSSIAN")) as file_exp_var:
                        exp_vars = json.load(file_exp_var)
                    y_dimension = exp_vars["input_lwe_dimension"] / gf
                    measured_variance_kara = exp_vars["measured_variance_kara"]
                    expected_variance_kara = exp_vars["expected_variance_kara"]
                    measured_variance_fft  = exp_vars["measured_variance_fft"]
                    expected_variance_fft  = exp_vars["expected_variance_fft"]

                    # load noise measurements into a single array
                    data_len = len(np.load(IN_FILE_FMT % ("fft", 0, gf, logbase, level, k, 1<<logN, "GAUSSIAN")))
                    fft_noises[params] = [np.array([]) for _ in range(0,data_len)]
                    kara_noises[params] = [np.array([]) for _ in range(0,data_len)]

                    for thread_id in range(0,NB_TESTS_MAX):
                        if not osp.isfile(IN_FILE_FMT % ("fft", thread_id, gf, logbase, level, k, 1<<logN, "GAUSSIAN")):
                            total_samples = thread_id
                            break
                        fi = np.load(IN_FILE_FMT % ("fft", thread_id, gf, logbase, level, k, 1<<logN, "GAUSSIAN")) / CT_MOD
                        ki = np.load(IN_FILE_FMT % ("kara", thread_id, gf, logbase, level, k, 1<<logN, "GAUSSIAN")) / CT_MOD
                        fft_noises[params] = np.column_stack([fft_noises[params],fi])
                        kara_noises[params] = np.column_stack([kara_noises[params],ki])

                    # x-axis values: [1,2,3,4,...,321]
                    x_vals = np.arange(1,len(fft_noises[params])+1)

                    # compute diff (shall be aligned s.t. the same sample is calculated at respective index)
                    fk = fft_noises[params] - kara_noises[params]

                    # ~ # ====    Histograms for selected indexes    ===================================
                    # ~ for i in [1, 2, 4, 8, 32, 128, 321]:
                    # ~ # for i in [1, 2]:
                        # ~ plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() # ; plt.ylim(-1.5e-4,1.5e-4)
                        # ~ plt.hist(fft_noises[i-1], 50)
                        # ~ plt.title(f"FFT distro at step {i} {params}")
                        # ~ plt.savefig(---"FFT-distro-%d.png" % (i)) # , format="pdf", bbox_inches="tight"
                        # ~ # plt.show()
                        # ~ plt.close()

                    # ~ for i in [1, 2, 4, 8, 32, 128, 321]:
                    # ~ # for i in [1, 2]:
                        # ~ plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() # ; plt.ylim(-1.5e-4,1.5e-4)
                        # ~ plt.hist(kara_noises[i-1], 50)
                        # ~ plt.title(f"Karatsuba distro at step {i} {params}")
                        # ~ plt.savefig(---"Karatsuba-distro-%d.png" % (i)) # , format="pdf", bbox_inches="tight"
                        # ~ # plt.show()
                        # ~ plt.close()

                    # ====    FFT    ===============================================================
                    f_means = [np.mean(fi) for fi in fft_noises[params]]
                    f_vars  = [np.var (fi) for fi in fft_noises[params]]
                    f_stdvs = [np.std (fi) for fi in fft_noises[params]]

                    # mean + std-dev error bars
                    plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() # ; plt.ylim(-1.5e-4,1.5e-4)
                    plt.errorbar(
                        x_vals,
                        f_means,
                        yerr = f_stdvs,
                        fmt ='o',
                    )
                    plt.title(f"FFT mean & std-dev {params}")
                    plt.savefig(OUT_FILE_FMT % ("stddev-mean-fft", gf, logbase, level, k, 1<<logN, "GAUSSIAN", total_samples)) # , format="pdf", bbox_inches="tight"
                    # plt.show()
                    plt.close()

                    # ====    Karatsuba    =========================================================
                    k_means = [np.mean(ki) for ki in kara_noises[params]]
                    k_vars  = [np.var (ki) for ki in kara_noises[params]]
                    k_stdvs = [np.std (ki) for ki in kara_noises[params]]

                    # mean + std-dev error bars
                    plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() # ; plt.ylim(-1.5e-4,1.5e-4)
                    plt.errorbar(
                        x_vals,
                        k_means,
                        yerr = k_stdvs,
                        fmt ='o', color='tab:orange',
                    )
                    plt.title(f"Karatsuba mean & std-dev {params}")
                    plt.savefig(OUT_FILE_FMT % ("stddev-mean-kara", gf, logbase, level, k, 1<<logN, "GAUSSIAN", total_samples)) # , format="pdf", bbox_inches="tight"
                    # plt.show()
                    plt.close()

                    # # ====    Diff    ==============================================================
                    # # ... is a piece of shit: starting from after-2nd ext-prod, the FFT and Kara samples are completely different
                    # fk_means = [np.mean(fki) for fki in fk]
                    fk_vars  = [np.var (fki) for fki in fk] # just once checked
                    # fk_stdvs = [np.std (fki) for fki in fk]

                    # plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() ; plt.ylim(-1.5e-4,1.5e-4)
                    # plt.errorbar(
                        # x_vals,
                        # fk_means,
                        # yerr = fk_stdvs,
                        # fmt ='o',
                    # )
                    # plt.title(f"(FFT-Kara) mean & std-dev {params}")
                    # plt.savefig(---"FFT-Kara-diff-mean-stddev.png") # , format="pdf", bbox_inches="tight"
                    # # plt.show()
                    # plt.close()

                    # ====    Both    ==============================================================
                    # ~ kara_avg_slope = np.mean(np.array(k_vars)/x_vals)
                    # ~ fft_avg_slope  = np.mean(np.array(f_vars)/x_vals)
                    kara_avg_slope_2nd_half = np.mean(np.array(k_vars[len(k_vars)//2:])/x_vals[len(k_vars)//2:])
                    fft_avg_slope_2nd_half  = np.mean(np.array(f_vars[len(f_vars)//2:])/x_vals[len(f_vars)//2:])

                    # calc the value of a
                    bits_lost = 11 # (a + c*logN**2)
                    fft_var_without_a = 1.0 * level*(k+1) * (1<<logbase)**2 * 2**(2*bits_lost) * k * (1<<logN)**2 / (CT_MOD**2)
                    fft_a = (fft_avg_slope_2nd_half - kara_avg_slope_2nd_half) / fft_var_without_a

                    plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI)
                    plt.tight_layout() ; plt.grid() # ; plt.ylim(-.2e-9,5.0e-9) ; plt.gca().yaxis.set_major_locator(MultipleLocator(.5e-9))
                    plt.title(f"FFT vs. Kara var's {params}. FFT-only slope: {fft_avg_slope_2nd_half - kara_avg_slope_2nd_half}, FFT-only terms: {fft_var_without_a}, FFT-only 'a': {fft_a}")
                    plt.plot(x_vals, f_vars, '.', label='meas FFT', color='tab:blue')
                    plt.plot([0,y_dimension], [0.0,expected_variance_fft], '.', label='exp FFT', color='tab:blue', linestyle='dotted', marker=',')
                    plt.plot([0,y_dimension], [0.0,fft_avg_slope_2nd_half*y_dimension], '.', label='avg. slope FFT', color='tab:blue', linestyle='dashed', marker=',')
                    plt.plot(x_vals, k_vars, '.', label='Karatsuba', color='tab:orange')
                    plt.plot([0,y_dimension], [0.0,expected_variance_kara], '.', label='exp Kara', color='tab:orange', linestyle='dotted', marker=',')
                    plt.plot([0,y_dimension], [0.0,kara_avg_slope_2nd_half*y_dimension], '.', label='avg. slope Kara', color='tab:orange', linestyle='dashed', marker=',')
                    plt.savefig(OUT_FILE_FMT % ("variances-FFT-Kara", gf, logbase, level, k, 1<<logN, "GAUSSIAN", total_samples)) # , format="pdf", bbox_inches="tight"
                    # plt.show()
                    plt.close()

                    # start: 1..3
                    plt.figure(figsize=(FIG_W/DPI/2, FIG_H/DPI/2), dpi=DPI)
                    plt.tight_layout() ; plt.grid() ; plt.xlim(-.2,3.2) # ; plt.ylim(-.2e-11,4.0e-11) ; plt.gca().yaxis.set_major_locator(MultipleLocator(.5e-11))
                    plt.title(f"FFT vs. Kara var's, start {params}")
                    plt.plot(x_vals[0:4], f_vars[0:4], marker='o', label='meas FFT', color='tab:blue')
                    plt.plot([0,4], [0.0,expected_variance_fft/y_dimension*4], '.', label='exp FFT', color='tab:blue', linestyle='dotted', marker=',')
                    plt.plot(x_vals[0:4], k_vars[0:4], marker='o', label='meas Karatsuba', color='tab:orange')
                    plt.plot([0,4], [0.0,expected_variance_kara/y_dimension*4], '.', label='exp Kara', color='tab:orange', linestyle='dotted', marker=',')
                    plt.ylim(bottom=0) # after plotting the data: https://stackoverflow.com/a/11745291/1869446
                    plt.savefig(OUT_FILE_FMT % ("variances-start-FFT-Kara", gf, logbase, level, k, 1<<logN, "GAUSSIAN", total_samples)) # , format="pdf", bbox_inches="tight"
                    # plt.show()
                    plt.close()

                    # diff growth
                    diff_vars = np.insert(np.array(f_vars) - np.array(k_vars), 0, 0.0)
                    diff_vars_growth = np.diff(diff_vars)

                    # ~ plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI)
                    # ~ plt.tight_layout() ; plt.grid() # ; plt.ylim(-.2e-9,5.0e-10) ; plt.gca().yaxis.set_major_locator(MultipleLocator(.5e-10))
                    # ~ plt.title(f"Growth of diff: FFT - Kara {params}")
                    # ~ plt.plot(x_vals, diff_vars_growth, '.', label='Growth')
                    # ~ plt.savefig(OUT_FILE_FMT % ("growth-FFT-Kara", gf, logbase, level, k, 1<<logN, "GAUSSIAN", total_samples)) # , format="pdf", bbox_inches="tight"
                    # ~ # plt.show()
                    # ~ plt.close()

                    # just slope of diff
                    plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI)
                    plt.tight_layout() ; plt.grid() # ; plt.ylim(-.2e-11,2.0e-11) ; plt.gca().yaxis.set_major_locator(MultipleLocator(.1e-11))
                    plt.title(f"FFT vs. Kara var's {params}")
                    plt.plot(x_vals, np.array(f_vars)/x_vals, '.', label='meas FFT', color='tab:blue')
                    plt.plot([0,y_dimension], [expected_variance_fft/y_dimension,expected_variance_fft/y_dimension], '.', label='exp FFT', color='tab:blue', linestyle='dotted', marker=',')
                    plt.plot([0,y_dimension], [fft_avg_slope_2nd_half,fft_avg_slope_2nd_half], '.', label='avg. slope FFT', color='tab:blue', linestyle='dashed', marker=',')
                    plt.plot(x_vals, np.array(k_vars)/x_vals, '.', label='meas Karatsuba', color='tab:orange')
                    plt.plot([0,y_dimension], [expected_variance_kara/y_dimension,expected_variance_kara/y_dimension], '.', label='exp Kara', color='tab:orange', linestyle='dotted', marker=',')
                    plt.plot([0,y_dimension], [kara_avg_slope_2nd_half,kara_avg_slope_2nd_half], '.', label='avg. slope Kara', color='tab:orange', linestyle='dashed', marker=',')
                    plt.ylim(bottom=0)
                    plt.savefig(OUT_FILE_FMT % ("variances-per-step-FFT-Kara", gf, logbase, level, k, 1<<logN, "GAUSSIAN", total_samples)) # , format="pdf", bbox_inches="tight"
                    # plt.show()
                    plt.close()

                    # print some values
                    print(f"\nParameters: {params}\n")

                    wk, _ = curve_fit(lambda x, a: a*x, x_vals, k_vars)
                    wf, _ = curve_fit(lambda x, a: a*x, x_vals, f_vars)
                    print("Kara linear fit:", wk[0])
                    print("Kara avg  slope:", kara_avg_slope_2nd_half)
                    print("FFT  linear fit:", wf[0])
                    print("FFT  avg  slope:", fft_avg_slope_2nd_half)
                    print("FFT-only as diff of linear fits:", (wf - wk)[0])
                    print("FFT-only as diff of  avg slopes:", fft_avg_slope_2nd_half - kara_avg_slope_2nd_half)
                    # ~ print("----")
                    # ~ print("Kara first:", k_vars[0])
                    # ~ print("FFT  first:", f_vars[0])
                    print("----")
                    print("Value of a:", fft_a)
                    print("----")
                    print("FFT excess 0..1:", diff_vars_growth[0])
                    # ~ print("FFT excess 0..1 from plain diff (close to prev?):", fk_vars[0])
                    print("FFT excess 1..2:", diff_vars_growth[1])
                    print("FFT excess 2..3:", diff_vars_growth[2])
                    # ~ print("----")
                    # ~ print("FFT excess growth mean (close to .. from slope?):", np.mean(diff_vars_growth))
                    print("=" * 80)
