#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <linux/prctl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base64.h"

#ifndef __CYBERSEC_CAIN__
#define __CYBERSEC_CAIN__ 1

// for certain features
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// shorthands
#define CAIN_API __attribute_noinline__

// bc I have to specifically define this
extern int mkostemp(char *temp, int flags);

// name of the file that gets unpacked
#define ABEL_FILE_NAME "{{ ABEL_FILE_NAME }}"
#define ABEL_DLOPEN "{{ ABEL_DLOPEN }}"
#define ABEL_MAIN_FUNC "{{ ABEL_MAIN_FUNC }}"

// linker stuff
extern const void *__text_start;
extern const void *__text_end;

// packed binary stuff
extern const void *__libabel_start;
extern const void *__libabel_end;

// typedef for the inner flag-check function
typedef void (*flag_check_t)(void);

#endif // __CYBERSEC_CAIN__