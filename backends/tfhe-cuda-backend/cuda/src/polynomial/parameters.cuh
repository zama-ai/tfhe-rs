#ifndef CUDA_PARAMETERS_CUH
#define CUDA_PARAMETERS_CUH

constexpr int tfhe_fft_default_radix() { return 2; }

constexpr int tfhe_log2(int n) { return (n <= 1) ? 0 : 1 + tfhe_log2(n / 2); }

template <typename T> constexpr T tfhe_min(T a, T b) { return a < b ? a : b; }
template <typename T> constexpr T tfhe_max(T a, T b) { return a > b ? a : b; }

constexpr int choose_opt_amortized(int degree, int radix) {
  return tfhe_max(2 * radix, (degree <= 1024)   ? 4
                             : (degree == 2048) ? 8
                             : (degree == 4096) ? 16
                             : (degree == 8192) ? 32
                                                : 64);
}

constexpr int choose_opt(int degree, int radix) {
  return tfhe_max(2 * radix, (degree <= 1024)    ? 4
                             : (degree == 2048)  ? 4
                             : (degree == 4096)  ? 4
                             : (degree == 8192)  ? 8
                             : (degree == 16384) ? 16
                                                 : 64);
}
template <class params, int radix = tfhe_fft_default_radix()> class HalfDegree {
public:
  constexpr static int degree = params::degree / 2;
  constexpr static int opt = tfhe_max(radix, params::opt / 2);
  constexpr static int log2_degree = params::log2_degree - 1;
};

template <int N, int radix = tfhe_fft_default_radix()> class Degree {
public:
  constexpr static int degree = N;
  constexpr static int opt = choose_opt(N, radix);
  constexpr static int log2_degree = tfhe_log2(N);
};

template <int N, int radix = tfhe_fft_default_radix()> class AmortizedDegree {
public:
  constexpr static int degree = N;
  constexpr static int opt = choose_opt_amortized(N, radix);
  constexpr static int log2_degree = tfhe_log2(N);
};
enum sharedMemDegree { NOSM = 0, PARTIALSM = 1, FULLSM = 2 };

class ForwardFFT {
public:
  constexpr static int direction = 0;
};

class BackwardFFT {
public:
  constexpr static int direction = 1;
};

class ReorderFFT {
  constexpr static int reorder = 1;
};
class NoReorderFFT {
  constexpr static int reorder = 0;
};

template <class params, class direction, class reorder = ReorderFFT>
class FFTDegree : public params {
public:
  constexpr static int fft_direction = direction::direction;
  constexpr static int fft_reorder = reorder::reorder;
};

template <int N, class direction, class reorder = ReorderFFT,
          int radix = tfhe_fft_default_radix()>
class FFTParams : public Degree<N, radix> {
public:
  constexpr static int fft_direction = direction::direction;
  constexpr static int fft_reorder = reorder::reorder;
};

#endif // CNCRT_PARAMETERS_H
