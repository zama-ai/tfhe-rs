#!/usr/bin/env python3

import numpy as np
import os.path as osp
import json
from scipy.optimize import curve_fit
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator

EXP_NAME = "fft-with-gap" # wide-search-2000-gauss   wide-search-2000-tuniform   gpu-gauss   gpu-tuniform   log-b-problem

IN_FILE_FMT  = "results/" + EXP_NAME + "/samples/%s-id=%d-gf=%d-logB=%d-l=%d-k=%d-N=%d-distro=%s.npy"
GRAPH_FILE_FMT = "results/" + EXP_NAME + "/graphs/%s-gf=%d-logB=%d-l=%d-k=%d-N=%d-distro=%s-nsamples=%d.png"
LOG_B_FILE_FMT = "results/" + EXP_NAME + "/graphs/logB_issue-gf=%d-distro=%s.dat"
EXP_VAR_FILE_FMT  = "results/" + EXP_NAME + "/expected-variances-gf=%d-logB=%d-l=%d-k=%d-N=%d-distro=%s.json"
# ~ MEAS_VAR_FILE_FMT = "results/" + EXP_NAME + "/measured-variances-gf=%d-logB=%d-l=%d-k=%d-N=%d-distro=%s.json"
LOG_CT_MOD = 64
CT_MOD = 2.0**LOG_CT_MOD
MANTISSA = 53

FIG_W = 2400
FIG_H = 1200
DPI = 96

NB_TESTS_MAX = 2501

fft_noises = {}
kara_noises = {}

def log_B_bound(N, k, level, mantissa=MANTISSA, nb_bodies=1):
    return (mantissa + 5 - np.log2(level*N*(k+nb_bodies))) / (level+1)

def fft_var_base(N,k,level,base,modulus=CT_MOD,mantissa=MANTISSA,nb_bodies=1):
    bits_lost = max(0, np.log2(modulus) - mantissa)
    return (base ** 2 * 2**(2*bits_lost) * k) / (modulus ** 2)

# keep here a copy of the FFT noise prediction from the optimizer (required to make sure where the log-B-bound is)
def fft_variance(N,k,level,base,grouping_factor,modulus=CT_MOD,mantissa=MANTISSA,nb_bodies=1):
    # heuristically derived bound where the next round's decomposition reaches the end of the f64's mantissa (after iFFT of the previous round)
    log_B_bnd = log_B_bound(N, k, level, mantissa, nb_bodies)
    fft_base = fft_var_base(N, k, level, base, modulus, mantissa, nb_bodies)
    plateau = fft_var_base(N, k, level, 2.0**log_B_bnd, modulus, mantissa, nb_bodies)

    match grouping_factor:
        case 1: # unclear why no gap is visible around log-B-bound
            return 0.008123839635618114 * fft_base * (level*(k+nb_bodies))**1.1654625080569405 * N**2.1868139742256645
        case 2:
            ae0 = [0.0016164663250953194,1.7723465249981651,2.823854616672861]
            ae1 = [0.03599200920446593,1.134176035036238,2.199976884576144]
        case 3:
            ae0 = [0.001992664372777639,1.5646501444166445,2.9546582263796637]
            ae1 = [0.08716929989326194,1.100161733092288,2.186096703735851]
        case 4:
            ae0 = [0.007837346866432544,1.444815803227099,2.8850256339231044]
            ae1 = [0.21946020970040536,1.1208479503946256,2.165413038755238]
        case _:
            exit(f"!! Grouping factor {grouping_factor} not supported !!")

    return min( \
        ae0[0] * fft_base * (level*(k+nb_bodies))**ae0[1] * N**ae0[2], \
        max( \
            ae0[0] * plateau  * (level*(k+nb_bodies))**ae0[1] * N**ae0[2], \
            ae1[0] * fft_base * (level*(k+nb_bodies))**ae1[1] * N**ae1[2]) \
    )


# ~ for distro in ["TUNIFORM", "GAUSSIAN"]:
for distro in ["GAUSSIAN"]:
    for gf in range(1,4+1):
        a0_N_vals = []
        a1_N_vals = []
        a0_N_kl_vals = []
        a1_N_kl_vals = []
        with open(LOG_B_FILE_FMT % (gf, distro), "w") as logB_file:
            logB_file.write(   "#  Excess FFT noise\n")
            logB_file.write(   "#  log B   level       k   log N  pred.slope   avg.slope     meas/pred    bnd_flag\n")
            for k in range(1,4+1):
                for logN in range(9,13+1):
                    N = 1<<logN
                    for level in range(1,6+1):
                        # ~ for logbase in [3*i for i in range(3,10+1)]:
                        for logbase in range(5,30+1):
                            base = 1<<logbase
                            # ~ if logbase * level < 15 or logbase * level > 36:
                                # ~ continue

                            # Convert dictionary to tuple (sorted to make it deterministic)
                            params = tuple(sorted({
                                "gf": gf,
                                "logbase": logbase,
                                "level": level,
                                "k": k,
                                "logN": logN,
                            }.items()))

                            # load predicted noise
                            if not osp.isfile(EXP_VAR_FILE_FMT % (gf, logbase, level, k, N, distro)):
                                continue
                            with open(EXP_VAR_FILE_FMT % (gf, logbase, level, k, N, distro)) as file_exp_var:
                                exp_vars = json.load(file_exp_var)
                            y_dimension = exp_vars["lwe_dimension"] / gf
                            expected_variance_kara = exp_vars["expected_variance_kara"]
                            expected_variance_fft  = exp_vars["expected_variance_fft"]

                            # load noise measurements into a single array
                            data_len = len(np.load(IN_FILE_FMT % ("fft", 0, gf, logbase, level, k, N, distro)))
                            fft_noises[params] = [np.array([]) for _ in range(0,data_len)]
                            kara_noises[params] = [np.array([]) for _ in range(0,data_len)]

                            for thread_id in range(0,NB_TESTS_MAX):
                                if not osp.isfile(IN_FILE_FMT % ("fft", thread_id, gf, logbase, level, k, N, distro)):
                                    total_samples = thread_id
                                    break
                                fi = np.load(IN_FILE_FMT % ("fft", thread_id, gf, logbase, level, k, N, distro)) / CT_MOD
                                ki = np.load(IN_FILE_FMT % ("kara", thread_id, gf, logbase, level, k, N, distro)) / CT_MOD
                                fft_noises[params] = np.column_stack([fft_noises[params],fi])
                                kara_noises[params] = np.column_stack([kara_noises[params],ki])

                            # ~ print(f"Processing {params} with {thread_id} samples ...")

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

                            # ~ # mean + std-dev error bars
                            # ~ plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() # ; plt.ylim(-1.5e-4,1.5e-4)
                            # ~ plt.errorbar(
                                # ~ x_vals,
                                # ~ f_means,
                                # ~ yerr = f_stdvs,
                                # ~ fmt ='o',
                            # ~ )
                            # ~ plt.title(f"FFT mean & std-dev {params}")
                            # ~ plt.savefig(GRAPH_FILE_FMT % ("stddev-mean-fft", gf, logbase, level, k, N, distro, total_samples)) # , format="pdf", bbox_inches="tight"
                            # ~ # plt.show()
                            # ~ plt.close()

                            # ====    Karatsuba    =========================================================
                            k_means = [np.mean(ki) for ki in kara_noises[params]]
                            k_vars  = [np.var (ki) for ki in kara_noises[params]]
                            k_stdvs = [np.std (ki) for ki in kara_noises[params]]

                            # ~ # mean + std-dev error bars
                            # ~ plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI) ; plt.tight_layout() ; plt.grid() # ; plt.ylim(-1.5e-4,1.5e-4)
                            # ~ plt.errorbar(
                                # ~ x_vals,
                                # ~ k_means,
                                # ~ yerr = k_stdvs,
                                # ~ fmt ='o', color='tab:orange',
                            # ~ )
                            # ~ plt.title(f"Karatsuba mean & std-dev {params}")
                            # ~ plt.savefig(GRAPH_FILE_FMT % ("stddev-mean-kara", gf, logbase, level, k, N, distro, total_samples)) # , format="pdf", bbox_inches="tight"
                            # ~ # plt.show()
                            # ~ plt.close()

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

                            # calc the value of FFT variance in various configs
                            fft_var = fft_variance(N,k,level,base,gf)
                            log_B_bnd = log_B_bound(N,k,level)
                            bits_lost = LOG_CT_MOD - MANTISSA
                            fft_var_without_a_N_kl = 1.0 * base**2 * 2**(2*bits_lost) * k / (CT_MOD**2)
                            fft_var_without_a_N = fft_var_without_a_N_kl * level*(k+1)
                            fft_a_N = (fft_avg_slope_2nd_half - kara_avg_slope_2nd_half) / fft_var_without_a_N
                            fft_a_N_kl = (fft_avg_slope_2nd_half - kara_avg_slope_2nd_half) / fft_var_without_a_N_kl

                            # significant FFT contribution?
                            if fft_avg_slope_2nd_half/kara_avg_slope_2nd_half < 1.2:
                                logB_file.write("# ")   # comment out anything insignificant
                            else:
                                logB_file.write("  ")
                                # values for curve fit
                                bnd_flag = 0
                                if logbase < log_B_bnd: # testing without -0.5
                                    a0_N_vals.append([fft_a_N, logN])
                                    a0_N_kl_vals.append([fft_a_N_kl, logN, (k+1)*level])
                                    bnd_flag = -1
                                elif fft_var > fft_variance(N, k, level, 2.0**log_B_bnd, gf) * 1.1:
                                    a1_N_vals.append([fft_a_N, logN])
                                    a1_N_kl_vals.append([fft_a_N_kl, logN, (k+1)*level])
                                    bnd_flag = 1

                            # export values:   #  log B   level       k   log N  pred.slope   avg.slope     meas/pred    bnd_flag
                            logB_file.write("%6d %7d %7d %7d  %10.3e  %10.3e  %10.3e %11d\n" % (logbase, level, k, logN, fft_var, fft_avg_slope_2nd_half - kara_avg_slope_2nd_half, (fft_avg_slope_2nd_half - kara_avg_slope_2nd_half) / ((expected_variance_fft - expected_variance_kara)/y_dimension), bnd_flag))

                            continue ###########################################



                            plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI)
                            plt.tight_layout() ; plt.grid() # ; plt.ylim(-.2e-9,5.0e-9) ; plt.gca().yaxis.set_major_locator(MultipleLocator(.5e-9))
                            plt.title(f"FFT vs. Kara var's {params}. FFT-only slope: {fft_avg_slope_2nd_half - kara_avg_slope_2nd_half}")
                            plt.plot(x_vals, f_vars, '.', label='meas FFT', color='tab:blue')
                            plt.plot([0,y_dimension], [0.0,expected_variance_fft], '.', label='exp FFT', color='tab:blue', linestyle='dotted', marker=',')
                            plt.plot([0,y_dimension], [0.0,fft_avg_slope_2nd_half*y_dimension], '.', label='avg. slope FFT', color='tab:blue', linestyle='dashed', marker=',')
                            plt.plot(x_vals, k_vars, '.', label='Karatsuba', color='tab:orange')
                            plt.plot([0,y_dimension], [0.0,expected_variance_kara], '.', label='exp Kara', color='tab:orange', linestyle='dotted', marker=',')
                            plt.plot([0,y_dimension], [0.0,kara_avg_slope_2nd_half*y_dimension], '.', label='avg. slope Kara', color='tab:orange', linestyle='dashed', marker=',')
                            plt.savefig(GRAPH_FILE_FMT % ("variances-FFT-Kara", gf, logbase, level, k, N, distro, total_samples)) # , format="pdf", bbox_inches="tight"
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
                            plt.savefig(GRAPH_FILE_FMT % ("variances-start-FFT-Kara", gf, logbase, level, k, N, distro, total_samples)) # , format="pdf", bbox_inches="tight"
                            # plt.show()
                            plt.close()

                            # diff growth
                            diff_vars = np.insert(np.array(f_vars) - np.array(k_vars), 0, 0.0)
                            diff_vars_growth = np.diff(diff_vars)

                            # ~ plt.figure(figsize=(FIG_W/DPI, FIG_H/DPI), dpi=DPI)
                            # ~ plt.tight_layout() ; plt.grid() # ; plt.ylim(-.2e-9,5.0e-10) ; plt.gca().yaxis.set_major_locator(MultipleLocator(.5e-10))
                            # ~ plt.title(f"Growth of diff: FFT - Kara {params}")
                            # ~ plt.plot(x_vals, diff_vars_growth, '.', label='Growth')
                            # ~ plt.savefig(GRAPH_FILE_FMT % ("growth-FFT-Kara", gf, logbase, level, k, N, distro, total_samples)) # , format="pdf", bbox_inches="tight"
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
                            plt.savefig(GRAPH_FILE_FMT % ("variances-per-step-FFT-Kara", gf, logbase, level, k, N, distro, total_samples)) # , format="pdf", bbox_inches="tight"
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
                            print("Noise base w/o N^2:", fft_var_without_a_N)
                            print("----")
                            print("FFT excess 0..1:", diff_vars_growth[0])
                            # ~ print("FFT excess 0..1 from plain diff (close to prev?):", fk_vars[0])
                            print("FFT excess 1..2:", diff_vars_growth[1])
                            print("FFT excess 2..3:", diff_vars_growth[2])
                            # ~ print("----")
                            # ~ print("FFT excess growth mean (close to .. from slope?):", np.mean(diff_vars_growth))
                            print("=" * 80)

        # for distro, gf:
        print(f"\n==== gf = {gf} ====")
        print("a0_N values:", a0_N_vals, "... of size:", len(a0_N_vals))
        print("a0_N_kl values:", a0_N_kl_vals, "... of size:", len(a0_N_kl_vals))
        print("----")
        print("a1_N values:", a1_N_vals, "... of size:", len(a1_N_vals))
        print("a1_N_kl values:", a1_N_kl_vals, "... of size:", len(a1_N_kl_vals))
        print("----")

        if len(a0_N_vals) > 0:
            ab0_N, _ = curve_fit(lambda logN, log_a, b: log_a + b*logN, [a0i[1] for a0i in a0_N_vals], [np.log2(a0i[0]) for a0i in a0_N_vals])
            print(f"curve fit in N, before logB bound: {2.0**ab0_N[0]} N^{ab0_N[1]}")
            ab0_kl, _ = curve_fit(lambda kl, a, b: a*kl**b, [ai[2] for ai in a0_N_kl_vals], [ai[0] / ((2.0**ai[1])**ab0_N[1]) for ai in a0_N_kl_vals])
            print(f"curve fit in (k+1)l, before logB bound: {ab0_kl[0]} ((k+1)l)^{ab0_kl[1]} N^{ab0_N[1]}")
        if len(a1_N_vals) > 0:
            ab1_N, _ = curve_fit(lambda logN, log_a, b: log_a + b*logN, [a1i[1] for a1i in a1_N_vals], [np.log2(a1i[0]) for a1i in a1_N_vals])
            print(f"curve fit in N, after  logB bound: {2.0**ab1_N[0]} N^{ab1_N[1]}")
            #TODO FIXME try log-fit here, too
            ab1_kl, _ = curve_fit(lambda kl, a, b: a*kl**b, [ai[2] for ai in a1_N_kl_vals], [ai[0] / ((2.0**ai[1])**ab1_N[1]) for ai in a1_N_kl_vals])
            print(f"curve fit in (k+1)l, after  logB bound: {ab1_kl[0]} ((k+1)l)^{ab1_kl[1]} N^{ab1_N[1]}")

