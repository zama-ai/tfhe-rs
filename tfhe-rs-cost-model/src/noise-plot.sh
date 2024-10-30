#!/usr/bin/env gnuplot

GF = 2
PATH = "bsk-0"
SFX = "-s-1-corr-2x" # -suffix
# sort by 4-th column
DATAFILE = "< sort -nk4 ".PATH."/gf-".GF.SFX.".dat"

set term pngcairo size 1800,1000 # linewidth 2

set grid
set xtics 2
set xrange [0:21]

#~ do for [nu=9:14] {
do for [nu=10:11] {
#~ do for [k=1:2] {
do for [k=1:1] {
    N = 2**nu
    set out PATH."/noise-gf=".GF."-k=".k."-N=".N.SFX.".png"
    set multiplot layout 2,1

    # ====    Measured & Predicted Noise    ====================================
    set logscale y # 2 or 10
    set yrange [1e15:1e40]
    #~ set yrange [0:5e15]
    # or: set datafile missing NaN
    x0 = y0 = NaN
    plot \
        DATAFILE u (($2 == N && $3 == k && $5 == 1) ? (y0=$6,x0=$4) : x0):(y0) w l  lt 1 dt 3 t 'B = 2^1', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
                2./3 * x * (k+1) * N * (2.**(2* 1 )+2)/12 * (k*N == 1024 ? 6.108061203662351e+24 : 2754771905.051562) * 2**GF + \
                2. * (2**128 - 2.**(2* 1 *x)) / (24 * 2.**(2* 1 *x)) * k*N * .5 \
                    w l lt 1 dt 2 t 'new fit B = 2^1', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 1) ? (y0=$7,x0=$4) : x0):(y0) w lp lt 1 t 'B = 2^1', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 2) ? (y0=$6,x0=$4) : x0):(y0) w l  lt 2 dt 3 t 'B = 2^2', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
                7./8 * x * (k+1) * N * (2.**(2* 2 )+2)/12 * (k*N == 1024 ? 6.108061203662351e+24 : 2754771905.051562) * 2**GF + \
                2. * (2**128 - 2.**(2* 2 *x)) / (24 * 2.**(2* 2 *x)) * k*N * .5 \
                    w l lt 2 dt 2 t 'new fit B = 2^2', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 2) ? (y0=$7,x0=$4) : x0):(y0) w lp lt 2 t 'B = 2^2', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 3) ? (y0=$6,x0=$4) : x0):(y0) w l  lt 3 dt 3 t 'B = 2^3', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 3) ? (y0=$7,x0=$4) : x0):(y0) w lp lt 3 t 'B = 2^3', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 4) ? (y0=$6,x0=$4) : x0):(y0) w l  lt 4 dt 3 t 'B = 2^4', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 4) ? (y0=$7,x0=$4) : x0):(y0) w lp lt 4 t 'B = 2^4', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 5) ? (y0=$6,x0=$4) : x0):(y0) w l  lt 5 dt 3 t 'B = 2^5', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 5) ? (y0=$7,x0=$4) : x0):(y0) w lp lt 5 t 'B = 2^5'

    # ====    Log of Measured / Predicted Noise    =============================
    #~ unset logscale y
    #~ set yrange [-.6:1.2]
    set yrange [.5:4]
    x0 = y0 = NaN
    plot \
        DATAFILE u (($2 == N && $3 == k && $5 == 1) ? (y0=$7/$6,x0=$4) : x0):(y0) w lp lt 1 t 'B = 2^1', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 1) ? (y0=$7 / ( \
                2./3 * $4 * (k+1) * N * (2.**(2* 1 )+2)/12 * (k*N == 1024 ? 6.108061203662351e+24 : 2754771905.051562) * 2**GF + \
                2. * (2**128 - 2.**(2* 1 *$4)) / (24 * 2.**(2* 1 *$4)) * k*N * .5 \
                ),x0=$4) : x0):(y0) w l  lt 1 dt 2 t 'new fit B = 2^1', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 2) ? (y0=$7/$6,x0=$4) : x0):(y0) w lp lt 2 t 'B = 2^2', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 2) ? (y0=$7 / ( \
                7./8 * $4 * (k+1) * N * (2.**(2* 2 )+2)/12 * (k*N == 1024 ? 6.108061203662351e+24 : 2754771905.051562) * 2**GF + \
                2. * (2**128 - 2.**(2* 2 *$4)) / (24 * 2.**(2* 2 *$4)) * k*N * .5 \
                ),x0=$4) : x0):(y0) w l  lt 2 dt 2 t 'new fit B = 2^2', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 3) ? (y0=$7/$6,x0=$4) : x0):(y0) w lp lt 3 t 'B = 2^3', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 4) ? (y0=$7/$6,x0=$4) : x0):(y0) w lp lt 4 t 'B = 2^4', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 5) ? (y0=$7/$6,x0=$4) : x0):(y0) w lp lt 5 t 'B = 2^5'

    unset multiplot
}
}

