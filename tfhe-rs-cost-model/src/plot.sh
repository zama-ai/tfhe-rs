#!/usr/bin/env gnuplot

DATAFILE = "log_real_to_pred.dat"

set style fill solid 0.5 # fill style

min=-3. # min value
max= 3. # max value
n = 200
width=(max-min)/n # interval width
set boxwidth width*0.8
hist(x,width)=width*floor(x/width)+width/2.0

plot DATAFILE u (hist($1,width)):(1.0) smooth freq w boxes lc rgb "green" notitle
