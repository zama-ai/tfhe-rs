#ifndef CUDA_PARAMETERS_CUH
#define CUDA_PARAMETERS_CUH

constexpr int log2(int n) { return (n <= 2) ? 1 : 1 + log2(n / 2); }

constexpr int choose_opt_amortized(int degree) {
  if (degree <= 1024)
    return 4;
  else if (degree == 2048)
    return 8;
  else if (degree == 4096)
    return 16;
  else if (degree == 8192)
    return 32;
  else
    return 64;
}

constexpr int choose_opt(int degree) {
  if (degree <= 1024)
    return 4;
  else if (degree == 2048)
    return 4;
  else if (degree == 4096)
    return 4;
  else if (degree == 8192)
    return 8;
  else if (degree == 16384)
    return 16;
  else
    return 64;
}
template <class params> class HalfDegree {
public:
  constexpr static int degree = params::degree / 2;
  constexpr static int opt = params::opt / 2;
  constexpr static int log2_degree = params::log2_degree - 1;
};

template <int N> class Degree {
public:
  constexpr static int degree = N;
  constexpr static int opt = choose_opt(N);
  constexpr static int log2_degree = log2(N);
};

template <int N> class AmortizedDegree {
public:
  constexpr static int degree = N;
  constexpr static int opt = choose_opt_amortized(N);
  constexpr static int log2_degree = log2(N);
};
enum sharedMemDegree {
  NOSM = 0,
  PARTIALSM = 1,
  FULLSM = 2

};

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

template <int N, class direction, class reorder = ReorderFFT>
class FFTParams : public Degree<N> {
public:
  constexpr static int fft_direction = direction::direction;
  constexpr static int fft_reorder = reorder::reorder;
};

#endif // CNCRT_PARAMETERS_H
