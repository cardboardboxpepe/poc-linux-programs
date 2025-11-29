#include "cain.h"
#include <fcntl.h>

// Cleans up the program and removes abel from disk.
CAIN_API void cleanup(int fd, void *dlhandle) {
  // close the handle to the SO
  if (dlclose(dlhandle) != 0) {
    // I don't care to actually exit the program here tbh
    perror("dlclose");
  }

  // close the fd
  close(fd);

  // decode filename
  // decode the name of the file
  char *fname = (char *)b64decode(ABEL_FILE_NAME, sizeof(ABEL_FILE_NAME) - 1);
  if (fname == NULL) {
    fputs("cleanup", stderr);
    exit(1);
  }

  // remove from disk
  if (remove(fname) != 0) {
    // I don't care to error here
    perror("remove");
  }

  // free filename
  free(fname);
}

CAIN_API int mkabel() {
  // decode the name of the file
  char *fname = (char *)b64decode(ABEL_FILE_NAME, sizeof(ABEL_FILE_NAME) - 1);
  if (fname == NULL) {
    fputs("mkabel", stderr);
    exit(1);
  }

  // open the file
  int fd = open(fname, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG);

  // return
  free(fname);
  return fd;
}

// writes abel to disk and loads it into memory using dlopen
CAIN_API void *unpack_abel(int fd) {
  // calculate where abel is
  size_t size = (size_t)&__libabel_end - (size_t)&__libabel_start;

  // write to disk
  size_t nbwritten = write(fd, &__libabel_start, size);
  if (nbwritten != size) {
    perror("write");
    exit(1);
  }

  // decode the format string
  char *fmt = (char *)b64decode(ABEL_DLOPEN, sizeof(ABEL_DLOPEN) - 1);

  // build the path name
  char fname[128] = {0};
  snprintf(fname, sizeof(fname), fmt, fd);

  // open using dlopen
  void *handle = dlopen(fname, RTLD_NOW);

  // free filename
  free(fmt);

  // return handle
  return handle;
}

// i forgor :(
CAIN_API int integrity_check(const char *filename) { return 0; }

// the main function
CAIN_API void vuln(const char *filename) {
  // perform integrity check?
  if (integrity_check(filename) != 0) {
    fputs("integrity", stderr);
    exit(1);
  }

  // create temp dir
  int fd = mkabel();
  if (fd < 0) {
    perror("open");
    exit(1);
  }

  // unpack SO
  void *abel = unpack_abel(fd);
  if (abel == NULL) {
    fputs("dlopen failure", stderr);
    exit(1);
  }

  // decode abel's main function
  char *func_name =
      (char *)b64decode(ABEL_MAIN_FUNC, sizeof(ABEL_MAIN_FUNC) - 1);
  if (func_name == NULL) {
    fputs("func", stderr);
    exit(1);
  }

  // load abel
  flag_check_t flag_check = (flag_check_t)dlsym(abel, func_name);
  if (flag_check == NULL) {
    perror("dlsym");
    exit(1);
  }

  // call flag check function
  flag_check();

  // cleanup
  cleanup(fd, abel);
}

int main(int argc, char **argv) {
  // call inner function
  vuln(argv[0]);

  // return OK
  return 0;
}