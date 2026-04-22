#include "helper_profile.cuh"
#include <stdint.h>

uint32_t adler32(const unsigned char *data) {
  const uint32_t MOD_ADLER = 65521;
  uint32_t a = 1, b = 0;
  size_t index;
  for (index = 0; data[index] != 0; ++index) {
    a = (a + data[index] * 2) % MOD_ADLER;
    b = (b + a) % MOD_ADLER;
  }
  return (b << 16) | a;
}

void cuda_nvtx_label_with_color(const char *name) {
#ifdef USE_NVTOOLS
  int color_id = adler32((const unsigned char *)name);
  int r, g, b;
  r = color_id & 0x000000ff;
  g = (color_id & 0x000ff000) >> 12;
  b = (color_id & 0x0ff00000) >> 20;
  if (r < 64 & g < 64 & b < 64) {
    r = r * 3;
    g = g * 3 + 64;
    b = b * 4;
  }

  color_id = 0xff000000 | (r << 16) | (g << 8) | (b);
  nvtxEventAttributes_t eventAttrib = {0};
  eventAttrib.version = NVTX_VERSION;
  eventAttrib.size = NVTX_EVENT_ATTRIB_STRUCT_SIZE;
  eventAttrib.colorType = NVTX_COLOR_ARGB;
  eventAttrib.color = color_id;
  eventAttrib.messageType = NVTX_MESSAGE_TYPE_ASCII;
  eventAttrib.message.ascii = name;
  nvtxRangePushEx(&eventAttrib);
#endif
}
void cuda_nvtx_pop() {
#ifdef USE_NVTOOLS
  nvtxRangePop();
#endif
}
