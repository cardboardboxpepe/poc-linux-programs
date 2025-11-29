#include "abel.h"

// key for encryption/decryption
#define KEY_LEN 4
const int key[KEY_LEN] = {0xde, 0xad, 0xbe, 0xef};

// a simple xor cipher on some bytes
void xor_cipher(unsigned char *restrict __dest, unsigned char *restrict __src,
                size_t len) {
  for (size_t i = 0; i < len; ++i) {
    __dest[i] = __src[i] ^ key[i % KEY_LEN];
#if DEBUG
    printf("%p[%d] = %x[%d] ^ %x = %x\n", __dest, i, __src[i], i,
           key[i % KEY_LEN], __dest[i]);
#endif
  }
};

void compare_flags(const char *result) {
  // decoded buffer
  char *buf = NULL;

#if DEBUG
  printf("comparing input %s to flag %s\n", result, FLAG);
#endif

  // compare to flag
  if (strncmp(result, FLAG, sizeof(FLAG)) == 0) {
    // won!
    if ((buf = (char *)b64decode(FLAG_OK, sizeof(FLAG_OK) - 1)) == NULL) {
      perror("malloc");
      return;
    }
  } else {
    // nope
    if ((buf = (char *)b64decode(FLAG_FAIL, sizeof(FLAG_FAIL) - 1)) == NULL) {
      perror("malloc");
      return;
    }
  }

  // print message
  puts(buf);

  // cleanup
  free(buf);
}

// gotta return can't exit since that would kill the main program
ABEL_API void check() {
  // malloc buffer
  char *buffer = malloc(0x100);
  char *xor = malloc(0x100);
  if (xor == NULL || buffer == NULL) {
    perror("malloc");
    return;
  }

  // prompt for and get input
  printf("Check your flag: ");
  fgets(buffer, 0x100, stdin);
  size_t len = strlen(buffer) - 1;

  // xor the user input
  xor_cipher((unsigned char *)xor, (unsigned char *)buffer, len);

#if DEBUG
  printf("xor cipher len: %lu\n", strlen(xor));
#endif

  // encode it
  char *result = b64encode((unsigned char *)xor, len);
  if (result == NULL) {
    perror("malloc");
    return;
  }

#if DEBUG
  printf("base64 enc user input: %s\n", result);
#endif

  // compare it to the flag
  compare_flags(result);

  // cleanup
  free(result);
  free(xor);
  free(buffer);
}