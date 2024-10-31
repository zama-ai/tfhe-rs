#!/usr/bin/env gnuplot

GF = 2
SFX = "-new-nofft" # -tanh
DATAFILE = PATH."/gf=".GF.SFX.".dat"

set term pngcairo size 640,480
set datafile separator ","
set out "new/histogram-".GF.SFX.".png"

set style fill solid 0.5 # fill style
set xrange [-4:4]
set yrange [0:600]

min=-3. # min value
max= 3. # max value
n = 200
width=(max-min)/n # interval width
set boxwidth width*0.8
hist(x,width)=width*floor(x/width)+width/2.0

plot DATAFILE u (hist($1,width)):(1.0) smooth freq w boxes lc rgb "green" notitle
