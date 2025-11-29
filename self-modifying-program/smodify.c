#include <dlfcn.h>
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

typedef void (*smodify_t)(void*);

// function to be called from the regular mapped section
void from_local() { printf("hello from from_local"); }

// function to be called from the new mmap'd page
void from_page(void (*__printf)(char *, ...)) {
  __printf("hello from from_page\n");
}

// test returning a value
int ret42() { return 42; }

int main(int argc, char **argv) {
  // create new mmap page
  smodify_t page = mmap(NULL, 0x1000, PROT_EXEC | PROT_WRITE | PROT_READ,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    perror("failed to create the mapping");
    exit(1);
  }

  // copy function into it
  memcpy(page, &from_page, 0x200);

  // logging
  printf("addr of from_local: %p\n", &from_local);
  printf("addr of from_page: %p\n", &from_page);
  printf("page is at %p\n", page);

  // call the new function
  page(&printf);

  munmap(page, 0x1000);
}
