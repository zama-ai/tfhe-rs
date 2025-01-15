#!/usr/bin/gnuplot

file_exists(file) = system("[ -f '".file."' ] && echo '1' || echo '0'") + 0

IN_FMT = "logB_issue-gf=%d-distro=GAUSSIAN.dat"
OUT_LOG_B_FMT = "plot-logB-gf=%d-k=%d-N=%d-distro=GAUSSIAN.png"
OUT_N_FMT = "plot-N-gf=%d-k=%d-distro=GAUSSIAN.png"

set term pngcairo size 1200,900 linewidth 2

set logscale y
set datafile missing NaN
set grid
set key top left

do for [gf=1:4] {
f = sprintf(IN_FMT, gf)
if (file_exists(f)) {
    # log-B
    set xrange [5:30]
    set yrange [1e-21:1e-6]
    do for [k=1:4] {
        do for [logN=9:13] {
            N = 1 << logN ; hovno = 1 << 2
            set output sprintf(OUT_LOG_B_FMT, gf, k, N)
            plot \
                f u 1:(($2 == 1 && $3 == k && $4 == logN) ? $5 : NaN) w lp t 'pred. slope, l=1', \
                f u 1:(($2 == 1 && $3 == k && $4 == logN) ? $6 : NaN) w lp t 'meas. slope, l=1', \
                f u 1:(($2 == 2 && $3 == k && $4 == logN) ? $5 : NaN) w lp t 'pred. slope, l=2', \
                f u 1:(($2 == 2 && $3 == k && $4 == logN) ? $6 : NaN) w lp t 'meas. slope, l=2', \
                f u 1:(($2 == 3 && $3 == k && $4 == logN) ? $5 : NaN) w lp t 'pred. slope, l=3', \
                f u 1:(($2 == 3 && $3 == k && $4 == logN) ? $6 : NaN) w lp t 'meas. slope, l=3', \
                f u 1:(($2 == 4 && $3 == k && $4 == logN) ? $5 : NaN) w lp t 'pred. slope, l=4', \
                f u 1:(($2 == 4 && $3 == k && $4 == logN) ? $6 : NaN) w lp t 'meas. slope, l=4', \
                f u 1:(($2 == 5 && $3 == k && $4 == logN) ? $5 : NaN) w lp t 'pred. slope, l=5', \
                f u 1:(($2 == 5 && $3 == k && $4 == logN) ? $6 : NaN) w lp t 'meas. slope, l=5', \
                f u 1:(($2 == 6 && $3 == k && $4 == logN) ? $5 : NaN) w lp t 'pred. slope, l=6', \
                f u 1:(($2 == 6 && $3 == k && $4 == logN) ? $6 : NaN) w lp t 'meas. slope, l=6'
        }
    }

    # log-N
    set xrange [8:15]
    set yrange [1e-21:1e-6]
    # logB_l = [[18,2], [28,1], [22,1], [14,2]]
    do for [k=1:4] {
        set output sprintf(OUT_N_FMT, gf, k, N)
        plot \
            f u 4:(($2 == 1 && $1 == 22 && $3 == k) ? $5 : NaN) w lp t 'pred. slope, logB=22, l=1', \
            f u 4:(($2 == 1 && $1 == 22 && $3 == k) ? $6 : NaN) w lp t 'meas. slope, logB=22, l=1', \
            f u 4:(($2 == 1 && $1 == 28 && $3 == k) ? $5 : NaN) w lp t 'pred. slope, logB=28, l=1', \
            f u 4:(($2 == 1 && $1 == 28 && $3 == k) ? $6 : NaN) w lp t 'meas. slope, logB=28, l=1', \
            f u 4:(($2 == 2 && $1 == 14 && $3 == k) ? $5 : NaN) w lp t 'pred. slope, logB=14, l=2', \
            f u 4:(($2 == 2 && $1 == 14 && $3 == k) ? $6 : NaN) w lp t 'meas. slope, logB=14, l=2', \
            f u 4:(($2 == 2 && $1 == 18 && $3 == k) ? $5 : NaN) w lp t 'pred. slope, logB=18, l=2', \
            f u 4:(($2 == 2 && $1 == 18 && $3 == k) ? $6 : NaN) w lp t 'meas. slope, logB=18, l=2'
    }
}
}
