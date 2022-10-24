#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

void test_default_keygen(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;

  int gen_keys_ok = booleans_gen_keys_with_default_parameters(&cks, &sks);

  assert(gen_keys_ok == 0);

  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);
}

void test_predefiend_keygen(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;

  int gen_keys_ok = booleans_gen_keys_with_predefined_parameters_set(
      BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS, &cks, &sks);

  assert(gen_keys_ok == 0);

  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);

  gen_keys_ok = booleans_gen_keys_with_predefined_parameters_set(
      BOOLEAN_PARAMETERS_SET_THFE_LIB_PARAMETERS, &cks, &sks);

  assert(gen_keys_ok == 0);

  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);
}

void test_custom_keygen(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;
  BooleanParameters *params = NULL;

  int params_ok = create_boolean_parameters(10, 1, 1024, 10e-100, 10e-100, 3, 1, 4, 2, &params);
  assert(params_ok == 0);

  int gen_keys_ok = booleans_gen_keys_with_parameters(params, &cks, &sks);

  assert(gen_keys_ok == 0);

  destroy_boolean_parameters(params);
  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);
}

int main(void) {
  test_default_keygen();
  test_predefiend_keygen();
  test_custom_keygen();
  return EXIT_SUCCESS;
}
