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

// addresses of the text section
extern void *__text_start;
extern void *__text_end;

// function to be called from the new mmap'd page
void obscure() { printf("hello from obscure\n"); }

// unpack obscure
void unpack_obscure() {
  // get handle to function
  void *target = &obscure;
  void *ptr = (void *)&__obscure_start;

  // logging
  printf("__obscure_start @ %p\n", &__obscure_start);
  printf("__obscure_start @ %p\n", &__obscure_end);

  // calculate size
  size_t sz = strlen(ptr);

  // helper
  printf("size of payload %lx\n", sz);
  fflush(stdout);

  // decode binary text
  if (EVP_DecodeBlock(target, ptr, sz) == -1) {
    puts("failed to decode obscure");
  } else {
    puts("decoded obscure into function");
  }
}

int main(int argc, char **argv) {
  // calculate size of the text section
  size_t sz = &__text_end - &__text_start;
  // alignment
  sz = (sz + 0xFFF) & ~0xFFF;

  // set protections
  mprotect(&__text_start, sz, PROT_EXEC | PROT_READ | PROT_WRITE);

  // unpack obscure
  puts("unpacking obscure");
  unpack_obscure();

  // call obscure
  puts("calling obscure");
  obscure();
}
