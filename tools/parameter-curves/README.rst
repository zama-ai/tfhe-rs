=========
Parameter Curves
=========

This folder contains the code used to choose secure parameters using the Lattice-Estimator_. In particular, we use data obtained from calls to the lattice estimator to generate parameter curves of the form: ``sigma(n) = a * n + b`` which can then be used to choose a suitable error standard deviation `sigma` for a given LWE dimension n. 

Usage
---------

To generate the raw data from the lattice estimator, use::

    make generate-curves

by default, this script will generate parameter curves for {80, 112, 128, 192} bits of security, using ``log_2(q) = 64``.

To compare the current curves with the output of the lattice estimator, use::

    make compare-curves

this will compare the four curves generated above against the output of the version of the lattice estimator found in /third_party. 

To generate the associated cpp and rust code, use::

    make generate-code

further advanced options can be found inside the Makefile.

Current curves
---------

Current versions of the curves can be found in the ``sage-object`` folder_. To view the raw data used to generate a curve, load one of the files contained in the director sage-object in Sagemath::
    
    sage: X = load("128.sobj")

entries are tuples of the form: ``(n, log_2(q), log_2(sd), \lambda)``. We can view individual entries via::

    sage: X["128"][0]
    (2366, 64.0, 4.0, 128.51)



.. _Lattice-Estimator: https://github.com/malb/lattice-estimator
.. _folder: https://github.com/zama-ai/concrete/tree/main/tools/parameter-curves/sage-object
