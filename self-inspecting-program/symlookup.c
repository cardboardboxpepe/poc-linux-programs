#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define publish __attribute__((visibility("default")))

typedef struct {
    const char *dli_fname; /* Pathname of shared object that
                              contains address */
    void *dli_fbase;       /* Address at which shared object
                              is loaded */
    const char *dli_sname; /* Name of nearest symbol with address
                              lower than addr */
    void *dli_saddr;       /* Exact address of symbol named
                              in dli_sname */
} Dl_info;

// linker stuff
extern int dladdr(void *addr, Dl_info *info);
extern void *dlvsym(void *handle, char *symbol, char *version);

int sym1 = 0xaabbccdd;
int sym2 = 0x2233ffee;

publish int open_self_exe(void) {
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(/proc/self/exe) failed: %s\n", strerror(errno));
        return -1;
    }
    return fd;
}

publish void *open_self_dl(const char *path) { return dlopen(path, RTLD_NOW | RTLD_GLOBAL); }

publish int main(int argc, char **argv) {
    // open self
    // int fd = open_self_exe();
    // printf("opened self with fd %d\n", fd);

    // // open myself using the linker
    // void *handle = open_self_dl("/proc/self/exe");
    // // void *handle = open_self_dl(argv[0]);

    // // lookup addr of open_self_dl
    // void *dl_addr = dlsym(handle, "main");
    // if (dl_addr == NULL) {
    //     fputs("failed to find main\n", stderr);
    //     fprintf(stderr, "reason: %s\n", dlerror());
    // }

    // // compare
    // printf("main from this binary: %p\n", &main);
    // printf("main from dlsym: %p\n", dl_addr);

    Dl_info info;
    dladdr(&open_self_dl, &info);

    // info.dli_saddr = virtual address
    // info.dli_fbase = load base (PIE offset)
    uintptr_t file_va = (uintptr_t)info.dli_saddr;
    uintptr_t base_va = (uintptr_t)info.dli_fbase;

    printf("Symbol name:       %s\n", info.dli_sname);
    printf("Object file:       %s\n", info.dli_fname);
    printf("Symbol address:    %p\n", info.dli_saddr);
    printf("Library base addr: %p\n", info.dli_fbase);

    uintptr_t relative_va = file_va - base_va; // offset into mapped image

    printf("offset of open_self_dl into the file %lx\n", relative_va);

    // open up the file
    int fd = open_self_exe();
    lseek(fd, relative_va, SEEK_CUR);

#define BUFCMP 0x10
    // read in from the file
    uint8_t *buf = malloc(BUFCMP);
    read(fd, buf, BUFCMP);

    // read our function into a buffer
    uint8_t *buf2 = malloc(BUFCMP);
    memcpy(buf2, &open_self_dl, BUFCMP);

    // memcmp
    int result = memcmp(buf, buf2, BUFCMP);
    printf("result of memcmp: %d\n", result);

    // print out bytes
    for (int i = 0; i < BUFCMP; ++i) {
        printf("open_self_dl: %02x\t buf: %02x\t equal? %d\n", buf2[i], buf[i], buf[i] == buf2[i]);
    }
}
