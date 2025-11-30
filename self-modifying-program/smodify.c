#include <dlfcn.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// shorthand to control visibility
#define publish __attribute__((visibility("default")))

// GNU features
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// addresses for the obscure function
extern void *__obscure_start;
extern void *__obscure_end;

// addresses for the hidden function
extern void *__hidden_start;
extern void *__hidden_end;

// addresses of the text section, needed for mprotect
extern void *__text_start;
extern void *__text_end;

// the function to be obscured
void obscure() { puts("hello from obscure"); }

// a second function to be obscured
int hidden() {
  puts("hello from hidden, here's 42");
  return 42;
}

// unpack obscure
void unpack_into(void *target, char *payload) {
  // calculate size
  size_t sz = strlen(payload);

  // helper
  printf("size of payload 0x%lx\n", sz);
  fflush(stdout);

  // decode binary text
  int nbwritten = EVP_DecodeBlock(target, (unsigned char *)payload, sz);
  if (nbwritten == -1) {
    puts("failed to unpack");
    return;
  }

  // logging
  printf("unpacked 0x%x bytes to %p\n", nbwritten, target);
}

int main(int argc, char **argv) {
  // calculate size of the text section
  size_t sz = &__text_end - &__text_start;
  // alignment
  sz = (sz + 0xFFF) & ~0xFFF;

  // set protections
  mprotect(&__text_start, sz, PROT_EXEC | PROT_READ | PROT_WRITE);

  // logging
  printf("__obscure_start @ %p\n", &__obscure_start);
  printf("__obscure_start @ %p\n", &__obscure_end);

  // unpack obscure
  puts("unpacking obscure");
  unpack_into(&obscure, (char *)&__obscure_start);

  // call obscure
  puts("calling obscure");
  obscure();

  // unpack obscure
  puts("unpacking hidden");
  unpack_into(&hidden, (char *)&__hidden_start);

  // call hidden
  int result = hidden();
  printf("result from hidden: %d\n", result);
}
