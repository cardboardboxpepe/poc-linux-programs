#include <assert.h>

#include "base64.h"

char *b64encode(unsigned char *__src, size_t __n) {
  // Base64 expands every 3 bytes into 4 characters; +1 for NULL terminator
  size_t out_len = 4 * ((__n + 2) / 3) + 1;

  // make chunk
  char *out = calloc(1, out_len);
  if (out == NULL) {
    return NULL;
  }

  // encode block
  int encoded_len = EVP_EncodeBlock((unsigned char *)out, __src, (int)__n);
  if (encoded_len < 0) {
    free(out);
    return NULL;
  }

  // return blob
  return out;
}

unsigned char *b64decode(char *__src, size_t __n) {
  // Base64 shrinks by 3/4; +3 to avoid underallocation on padding
  size_t out_len = __n * 3 / 4 + 3;
  assert(__n % 4 == 0);

  // make chunk
  unsigned char *out = calloc(1, out_len);
  if (out == NULL) {
    return NULL;
  }

  // decode block
  int decoded_len = EVP_DecodeBlock(out, (unsigned char *)__src, (int)__n);
  if (decoded_len < 0) {
#if DEBUG
    printf("input %s (len %lu) is not valid base64\n", __src, __n);
#endif
    // Invalid base64 input
    free(out);
    return NULL;
  }

  // return result
  return out;
}