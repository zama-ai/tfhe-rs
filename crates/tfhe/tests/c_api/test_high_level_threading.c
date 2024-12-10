/* Test threading context.
 *
 * Uses C11 standard's threads to run a FHE multiplication in
 * each of them, it also uses TfheThreadingContext in order to limit
 * the number of threads the operation can use.
 *
 * The TfheThreadingContext is like a thread pool, so when created, it creates
 * threads that operation run inside the context will use.
 *
 * Because of that, in a real application it would be a good idea to limit
 * the number of TfheThreadingContext that exist, and reuse them.
 *
 * Which this test does not do, meaning that if you modify
 * NUM_C_THREADS and/or NUM_TFHE_THREAD_PER_CONTEXT it might end up
 * creating too many threads and you'll get a panic with a IoError.
 *
 * To count the number of threads a process has on linux one can do:
 * `ps -o thcount <pid>`
 *
 * If used on a running process of this program the expected value should
 * be:
 * ` NUM_CPU + NUM_C_THREADS + (NUM_C_THREADS * NUM_TFHE_THREAD_PER_CONTEXT) + 1
 *  with
 *      - NUM_CPU: number of CPU threads (tfhe internally automatically creates them)
 */

#include "tfhe.h"

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

// The number of threads, on the C side,
// handling request or what your program needs to handle.
#define NUM_C_THREADS 12

// Number of thread each TfheThreadingContext will have
#define NUM_TFHE_THREAD_PER_CONTEXT 2

/* Struct used to pass to a TfheThreadingContext some data
 * mainly input(s)/output(s)
 */
typedef struct {
  // The 2 operands of multiplication
  FheUint64 *inputs[2];
  // The result of the multiplication
  FheUint64 *result;
} WorkerData;

// The callback/function to be run in a threading context
int do_work_in_tfhe_threading_context(void *vdata) {
  WorkerData *data = vdata;

  int status = fhe_uint64_mul(data->inputs[0], data->inputs[1], &data->result);
  if (status != 0) {
    data->result = NULL;
  }
  return status;
}

/* Struct used to pass data as the argument of the function
 * that a C thread will run
 */
typedef struct {
  TfheThreadingContext *context;
  WorkerData *data;
} CThreadData;

// The callback/function to be run in a C thread
void *c_threads_callback(void *vdata) {
  CThreadData *request = vdata;

  tfhe_threading_context_run(request->context, do_work_in_tfhe_threading_context,
                             (void *)request->data);
  return (void *)request->data->result;
}

// Main part of the work, spawns threads and puts calculations on them
void do_thing(const ClientKey *client_key, const ServerKey *server_key) {

  int status;

  uint64_t clear_inputs[NUM_C_THREADS][2];
  uint64_t counter = 0;
  for (size_t i = 0; i < NUM_C_THREADS; ++i) {
    clear_inputs[i][0] = counter++;
    clear_inputs[i][1] = counter++;
  }

  WorkerData data[NUM_C_THREADS];
  for (size_t i = 0; i < NUM_C_THREADS; ++i) {
    status = fhe_uint64_try_encrypt_with_client_key_u64(clear_inputs[i][0], client_key,
                                                        &data[i].inputs[0]);
    assert(status == 0);
    status = fhe_uint64_try_encrypt_with_client_key_u64(clear_inputs[i][1], client_key,
                                                        &data[i].inputs[1]);
    assert(status == 0);

    data[i].result = NULL;
  }

  TfheThreadingContext *contexts[NUM_C_THREADS] = {NULL};
  for (size_t i = 0; i < NUM_C_THREADS; ++i) {
    status = tfhe_threading_context_create(NUM_TFHE_THREAD_PER_CONTEXT, &contexts[i]);
    assert(status == 0);

    status = tfhe_threading_context_set_server_key(contexts[i], server_key);
    assert(status == 0);
  }

  pthread_t c_threads[NUM_C_THREADS] = {0};
  CThreadData c_callback_data[NUM_C_THREADS];
  for (size_t i = 0; i < NUM_C_THREADS; ++i) {
    c_callback_data[i] = (CThreadData){
        .context = contexts[i],
        .data = &data[i],
    };

    status = pthread_create(&c_threads[i], NULL /* default attributes */, c_threads_callback,
                            &c_callback_data[i]);
    assert(status == 0);
  }

  for (size_t i = 0; i < NUM_C_THREADS; ++i) {
    void *void_ret;
    status = pthread_join(c_threads[i], &void_ret);
    assert(status == 0);
    assert(data[i].result == void_ret); /* sanity check */
    assert(void_ret != NULL);

    uint64_t clear_result;
    status = fhe_uint64_decrypt((FheUint64 *)void_ret, client_key, &clear_result);
    assert(status == 0);

    uint64_t expected_result = clear_inputs[i][0] * clear_inputs[i][1];
    assert(clear_result == expected_result);
  }

  for (size_t i = 0; i < NUM_C_THREADS; ++i) {
    fhe_uint64_destroy(data[i].result);
    tfhe_threading_context_destroy(contexts[i]);
    fhe_uint64_destroy(data[i].inputs[0]);
    fhe_uint64_destroy(data[i].inputs[1]);
  }
}

int main(void) {
  int ok = 0;
  ConfigBuilder *builder;
  Config *config;

  ok = config_builder_default(&builder);
  assert(ok == 0);
  ok = config_builder_build(builder, &config);
  assert(ok == 0);

  ClientKey *client_key = NULL;
  ServerKey *server_key = NULL;

  ok = generate_keys(config, &client_key, &server_key);
  assert(ok == 0);

  do_thing(client_key, server_key);

  client_key_destroy(client_key);
  server_key_destroy(server_key);

  return ok;
}
