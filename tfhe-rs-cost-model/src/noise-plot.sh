#!/usr/bin/env gnuplot

GF = 2
PATH = "fft-kara"
SFX = "" # -suffix
# sort by 4-th column
DATAFILE_BY_L = "< sort -nk4 ".PATH."/gf=".GF.SFX.".dat"
# sort by 2-nd column
DATAFILE_BY_N = "< sort -nk2 ".PATH."/gf=".GF.SFX.".dat"

set term pngcairo size 1800,1000 # linewidth 2
set datafile separator ","

set grid
set xtics 2
set xrange [0:21]

#~ do for [nu=9:14] {
do for [nu=8:12] {
#~ do for [k=1:2] {
do for [k=1:3] {
    if (nu==8 && k==1) {continue} # no data points here
    N = 2**nu
    set out PATH."/l-noise-gf=".GF."-k=".k."-N=".N.SFX.".png"
    set multiplot layout 2,1

    # ====    Measured & Predicted Noise    ====================================
    set logscale y # 2 or 10
    set yrange [1e12:1e19]
    # or: set datafile missing NaN
    x0 = y0 = NaN
    cmd_0 = "plot "
    do for [logb=1:5] {
        cmd_0 = cmd_0."DATAFILE_BY_L u (($2 == N && $3 == k && $5 == ".logb.") ? (y0=$8,x0=$4) : x0):(y0) w l  lt ".logb." dt 3 t 'measured B = 2^".logb."', "
        cmd_0 = cmd_0."''   u (x0 = NaN):(y0 = NaN) notitle, "
        cmd_0 = cmd_0."''   u (($2 == N && $3 == k && $5 == ".logb.") ? (y0=$7,x0=$4) : x0):(y0) w lp lt ".logb." t 'curve fit B = 2^".logb."', "
        cmd_0 = cmd_0."''   u (x0 = NaN):(y0 = NaN) notitle, "
    }
    evaluate(cmd_0)

                #~ 2./3 * x * (k+1) * N * (2.**(2* 1 )+2)/12 * (k*N == 1024 ? 6.108061203662351e+24 : 2754771905.051562) * 2**GF + \
                #~ 2. * (2**128 - 2.**(2* 1 *x)) / (24 * 2.**(2* 1 *x)) * k*N * .5 \
                    #~ w l lt 1 dt 2 t 'new fit B = 2^1', \
            #~ ''   u (x0 = NaN):(y0 = NaN) notitle, \
                #~ 7./8 * x * (k+1) * N * (2.**(2* 2 )+2)/12 * (k*N == 1024 ? 6.108061203662351e+24 : 2754771905.051562) * 2**GF + \
                #~ 2. * (2**128 - 2.**(2* 2 *x)) / (24 * 2.**(2* 2 *x)) * k*N * .5 \
                    #~ w l lt 2 dt 2 t 'new fit B = 2^2', \
            #~ ''   u (x0 = NaN):(y0 = NaN) notitle, \

    # ====    Ratio of Measured / Predicted Noise    ===========================
    #~ unset logscale y
    set yrange [.5:4]
    x0 = y0 = NaN
    cmd_1 = "plot "
    do for [logb=1:5] {
        cmd_1 = cmd_1."DATAFILE_BY_L u (($2 == N && $3 == k && $5 == ".logb.") ? (y0=$7/$8,x0=$4) : x0):(y0) w lp lt ".logb." t 'meas/fit B = 2^".logb."', "
        cmd_1 = cmd_1."''   u (x0 = NaN):(y0 = NaN) notitle, "
    }
    evaluate(cmd_1)

    unset multiplot
}
}

#~ set xtics 2
set xrange [128:8192]
set logscale x

do for [k=1:3] {
do for [logb=1:5] {
    set out PATH."/N-noise-gf=".GF."-k=".k."-logB=".logb.SFX.".png"
    set multiplot layout 2,1

    # ====    Measured & Predicted Noise    ====================================
    set logscale y # 2 or 10
    set yrange [1e12:2e18]
    #~ set yrange [0:5e15]
    # or: set datafile missing NaN
    x0 = y0 = NaN
    cmd_2 = "plot "
    do for [lvl=3:12] {
        cmd_2 = cmd_2."DATAFILE_BY_N u (($5 == logb && $3 == k && $4 == ".lvl.") ? (y0=$8,x0=$2) : x0):(y0) w l  lt ".(lvl-2)." dt 3 t 'l = ".lvl."', "
        cmd_2 = cmd_2."''   u (x0 = NaN):(y0 = NaN) notitle, "
        cmd_2 = cmd_2."''   u (($5 == logb && $3 == k && $4 == ".lvl.") ? (y0=$7,x0=$2) : x0):(y0) w lp lt ".(lvl-2)." t 'l = ".lvl."', "
        cmd_2 = cmd_2."''   u (x0 = NaN):(y0 = NaN) notitle, "
    }
    evaluate(cmd_2)

    # ====    Ratio of Measured / Predicted Noise    ===========================
    set yrange [.5:4]
    x0 = y0 = NaN
    cmd_3 = "plot "
    do for [lvl=3:12] {
        cmd_3 = cmd_3."DATAFILE_BY_N u (($5 == logb && $3 == k && $4 == ".lvl.") ? (y0=$7/$8,x0=$2) : x0):(y0) w lp lt ".(lvl-2)." t 'l = ".lvl."', "
        cmd_3 = cmd_3."''   u (x0 = NaN):(y0 = NaN) notitle, "
    }
    evaluate(cmd_3)

    unset multiplot
}
}
