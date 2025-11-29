#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __CYBERSEC_BASE64__
#define __CYBERSEC_BASE64__ 1

// Encodes data using base64
char *b64encode(unsigned char *__src, size_t __n);

// Decodes data using base64
unsigned char *b64decode(char *__src, size_t __n);

#endif // __CYBERSEC_BASE64__