#include "curve.h"
#include "device.h"
#include <gtest/gtest.h>
#include <iostream>

// Test fixture for projective coordinate operations
class ProjectiveTest : public ::testing::Test {
protected:
  void *stream;
  int gpu_index;

  void SetUp() override {
    gpu_index = 0;
    stream = cuda_stream_create(gpu_index);
  }

  void TearDown() override { cuda_stream_destroy(stream, gpu_index); }
};

// Test: Convert affine -> projective -> affine (round trip)
TEST_F(ProjectiveTest, G1RoundTrip) {
  uint64_t size_tracker = 0;
  // Get generator in Montgomery form
  G1Affine G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);

  // Convert to projective
  G1ProjectivePoint G_proj;
  affine_to_projective(G_proj, G_mont);

  // Convert back to affine
  G1Affine G_back;
  projective_to_affine_g1(G_back, G_proj);

  // Convert from Montgomery
  G1Affine G_result;
  fp_from_montgomery(G_result.x, G_back.x);
  fp_from_montgomery(G_result.y, G_back.y);
  G_result.infinity = G_back.infinity;

  // Compare
  EXPECT_EQ(fp_cmp(G_result.x, G.x), FpComparison::Equal)
      << "X coordinate mismatch in round-trip";
  EXPECT_EQ(fp_cmp(G_result.y, G.y), FpComparison::Equal)
      << "Y coordinate mismatch in round-trip";
  EXPECT_EQ(G_result.infinity, G.infinity) << "Infinity flag mismatch";
}

// Test: Projective doubling vs affine doubling
TEST_F(ProjectiveTest, G1DoublingVsAffine) {
  uint64_t size_tracker = 0;
  // Get generator in Montgomery form
  G1Affine G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);
  G_mont.infinity = false;

  // Affine doubling: 2*G using existing point_add
  G1Affine *d_G = (G1Affine *)cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true);
  G1Affine *d_2G_affine = (G1Affine *)cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);
  point_add<G1Affine>(stream, gpu_index, d_2G_affine, d_G, d_G);

  G1Affine result_affine;
  cuda_memcpy_async_to_cpu(&result_affine, d_2G_affine, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Projective doubling
  G1ProjectivePoint G_proj;
  affine_to_projective(G_proj, G_mont);

  G1ProjectivePoint G2_proj;
  projective_point_double(G2_proj, G_proj);

  // Convert back to affine
  G1Affine result_proj;
  projective_to_affine_g1(result_proj, G2_proj);

  // Compare (both are in Montgomery form)
  EXPECT_EQ(fp_cmp(result_proj.x, result_affine.x), FpComparison::Equal)
      << "X coordinate mismatch: projective doubling vs affine doubling";
  EXPECT_EQ(fp_cmp(result_proj.y, result_affine.y), FpComparison::Equal)
      << "Y coordinate mismatch: projective doubling vs affine doubling";

  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_2G_affine, stream, gpu_index, true);
}

// Test: Projective addition vs affine addition
TEST_F(ProjectiveTest, G1AdditionVsAffine) {
  uint64_t size_tracker = 0;
  // Get generator in Montgomery form
  G1Affine G = g1_generator();
  G1Affine G_mont = G;
  point_to_montgomery_inplace(G_mont);
  G_mont.infinity = false;

  // Compute 2*G in affine
  G1Affine *d_G = (G1Affine *)cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true);
  G1Affine *d_2G = (G1Affine *)cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true);
  cuda_memcpy_with_size_tracking_async_to_gpu(d_G, &G_mont, sizeof(G1Affine),
                                              stream, gpu_index, true);
  point_add<G1Affine>(stream, gpu_index, d_2G, d_G, d_G);

  G1Affine G2_mont;
  cuda_memcpy_async_to_cpu(&G2_mont, d_2G, sizeof(G1Affine), stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Compute G + 2G = 3G in affine
  G1Affine *d_3G_affine = (G1Affine *)cuda_malloc_with_size_tracking_async(
      sizeof(G1Affine), stream, gpu_index, size_tracker, true);
  point_add<G1Affine>(stream, gpu_index, d_3G_affine, d_G, d_2G);

  G1Affine result_affine;
  cuda_memcpy_async_to_cpu(&result_affine, d_3G_affine, sizeof(G1Affine),
                           stream, gpu_index);
  cuda_synchronize_stream(stream, gpu_index);

  // Compute G + 2G = 3G in projective
  G1ProjectivePoint G_proj, G2_proj, G3_proj;
  affine_to_projective(G_proj, G_mont);
  affine_to_projective(G2_proj, G2_mont);
  projective_point_add(G3_proj, G_proj, G2_proj);

  // Convert back to affine
  G1Affine result_proj;
  projective_to_affine_g1(result_proj, G3_proj);

  // Compare (both are in Montgomery form)
  EXPECT_EQ(fp_cmp(result_proj.x, result_affine.x), FpComparison::Equal)
      << "X coordinate mismatch: projective addition vs affine addition";
  EXPECT_EQ(fp_cmp(result_proj.y, result_affine.y), FpComparison::Equal)
      << "Y coordinate mismatch: projective addition vs affine addition";

  cuda_drop_with_size_tracking_async(d_G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_2G, stream, gpu_index, true);
  cuda_drop_with_size_tracking_async(d_3G_affine, stream, gpu_index, true);
}
