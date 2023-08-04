import sys
sys.path.insert(1, 'lattice-estimator')
from estimator import *


model = RC.BDGL16

load("boolean_parameters_lattice_estimator.sage")

params_to_update = []

for param in all_params:
    print("parameters = {}".format(param.tag))
    try:
        usvp_level = LWE.primal_usvp(param, red_cost_model = model)
        dual_level = LWE.dual_hybrid(param, red_cost_model = model)
        estimator_level = log(min(usvp_level["rop"], dual_level["rop"]),2)
        if 128 > estimator_level:
            print("target security level = 128")
            print("attained security level = {}".format(estimator_level))
            params_to_update.append(param)
        else:
            print("pass.")
    except Exception as e:
        print(e)
        print("fail.")

print(params_to_update)
