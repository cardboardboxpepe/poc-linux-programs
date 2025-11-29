#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"

#ifndef __CYBERSEC_ABEL__
#define __CYBERSEC_ABEL__ 1

#ifndef DEBUG
#define DEBUG 1
#endif

#define FLAG "{{ FLAG }}"
#define FLAG_OK "{{ FLAG_OK }}"
#define FLAG_FAIL "{{ FLAG_FAIL }}"

#define ABEL_API __attribute_noinline__ __attribute__((visibility("default")))

// Encodes data using base64
char *b64encode(unsigned char *__src, size_t __n);

// Decodes data using base64
unsigned char *b64decode(char *__src, size_t __n);

#endif // __CYBERSEC_ABEL__