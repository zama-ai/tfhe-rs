#include "tfhe.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

// Encrypts a string in a FheUint array
// No error handling is made, it asserts on all error for demo purposes
FheUint8 **encrypt_str(const char *const str, const size_t str_len, const ClientKey *ck) {
  assert(str != NULL && str_len > 0);

  FheUint8 **result = malloc(sizeof(*result) * str_len);
  assert(result != NULL);

  for (size_t i = 0; i < str_len; ++i) {
    assert(fhe_uint8_try_encrypt_with_client_key_u8(str[i], ck, &result[i]) == 0);
  }
  return result;
}

void destroy_fhe_uint8_array(FheUint8 **begin, const size_t len) {
  for (size_t i = 0; i < len; ++i) {
    fhe_uint8_destroy(begin[i]);
  }
  free(begin);
}

int main(void) {
  int ok = 0;
  ConfigBuilder *builder;
  Config *config;

  config_builder_default(&builder);
  config_builder_build(builder, &config);

  ClientKey *client_key = NULL;
  ServerKey *server_key = NULL;

  ok = generate_keys(config, &client_key, &server_key);
  assert(ok == 0);

  ok = set_server_key(server_key);
  assert(ok == 0);

  char const *const sentence = "The quick brown fox jumps over the lazy dog";
  char const *const pattern_1 = "wn fox ";
  char const *const pattern_2 = "tfhe-rs";

  size_t sentence_len = strlen(sentence);
  size_t pattern_1_len = strlen(pattern_1);
  size_t pattern_2_len = strlen(pattern_2);

  assert(pattern_1_len == pattern_2_len); // We use this later in the tests

  FheUint8 **encrypted_sentence = encrypt_str(sentence, sentence_len, client_key);
  FheUint8 **encrypted_pattern_1 = encrypt_str(pattern_1, pattern_1_len, client_key);
  FheUint8 **encrypted_pattern_2 = encrypt_str(pattern_2, pattern_2_len, client_key);

  // Equality
  {
    FheBool *result;
    bool clear_result;

    // This one is trivial as the length are not the same
    ok = fhe_uint8_array_eq(encrypted_sentence, sentence_len, encrypted_pattern_1, pattern_1_len,
                            &result);
    assert(ok == 0);
    ok = fhe_bool_decrypt(result, client_key, &clear_result);
    assert(ok == 0 && clear_result == false);
    fhe_bool_destroy(result);

    ok = fhe_uint8_array_eq(encrypted_pattern_2, pattern_2_len, encrypted_pattern_1, pattern_1_len,
                            &result);
    assert(ok == 0);
    ok = fhe_bool_decrypt(result, client_key, &clear_result);
    assert(ok == 0 && clear_result == false);
    fhe_bool_destroy(result);

    ok = fhe_uint8_array_eq(encrypted_sentence, sentence_len, encrypted_sentence, sentence_len,
                            &result);
    assert(ok == 0);
    ok = fhe_bool_decrypt(result, client_key, &clear_result);
    assert(ok == 0 && clear_result == true);
    fhe_bool_destroy(result);
  }

  // contains sub slice
  {
    FheBool *result;
    bool clear_result;

    // This one is trivial as the length are not the same
    ok = fhe_uint8_array_contains_sub_slice(encrypted_sentence, sentence_len, encrypted_pattern_1,
                                            pattern_1_len, &result);
    assert(ok == 0);
    ok = fhe_bool_decrypt(result, client_key, &clear_result);
    assert(ok == 0 && clear_result == true);
    fhe_bool_destroy(result);

    ok = fhe_uint8_array_contains_sub_slice(encrypted_sentence, sentence_len, encrypted_pattern_2,
                                            pattern_2_len, &result);
    assert(ok == 0);
    ok = fhe_bool_decrypt(result, client_key, &clear_result);
    assert(ok == 0 && clear_result == false);
    fhe_bool_destroy(result);

    ok = fhe_uint8_array_contains_sub_slice(encrypted_sentence, sentence_len, encrypted_sentence,
                                            sentence_len, &result);
    assert(ok == 0);
    ok = fhe_bool_decrypt(result, client_key, &clear_result);
    assert(ok == 0 && clear_result == true);
    fhe_bool_destroy(result);
  }

  destroy_fhe_uint8_array(encrypted_sentence, sentence_len);
  destroy_fhe_uint8_array(encrypted_pattern_1, pattern_1_len);
  destroy_fhe_uint8_array(encrypted_pattern_2, pattern_2_len);

  client_key_destroy(client_key);
  server_key_destroy(server_key);
  return 0;
}
