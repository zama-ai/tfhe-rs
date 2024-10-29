#!/usr/bin/env gnuplot

GF = 2
SFX = "-new" # -tanh
# sort by 4-th column
DATAFILE = "< sort -nk4 log-real-to-pred-".GF.SFX.".dat"

set term pngcairo size 1800,600 linewidth 2

set grid
set xtics 2
set yrange [-.6:1.2]

do for [nu=9:14] {
do for [k=1:2] {
    N = 2**nu
    set out "new/logratio-".GF."-k=".k."-N=".N.SFX.".png"

    x0 = y0 = NaN
    plot \
        DATAFILE u (($2 == N && $3 == k && $5 == 1) ? (y0=$1,x0=$4) : x0):(y0) w lp lt 1 t 'B = 2^1', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 2) ? (y0=$1,x0=$4) : x0):(y0) w lp lt 2 t 'B = 2^2', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 3) ? (y0=$1,x0=$4) : x0):(y0) w lp lt 3 t 'B = 2^3', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 4) ? (y0=$1,x0=$4) : x0):(y0) w lp lt 4 t 'B = 2^4', \
            ''   u (x0 = NaN):(y0 = NaN) notitle, \
            ''   u (($2 == N && $3 == k && $5 == 5) ? (y0=$1,x0=$4) : x0):(y0) w lp lt 5 t 'B = 2^5'
}
}
