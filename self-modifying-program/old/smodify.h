#ifndef __SMODIFY_H__
#define __SMODIFY_H__

// shorthand to control visibility
#define publish __attribute__((visibility("default")))

// GNU features
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

typedef void (*smodify_t)(void*);

#endif // __SMODIFY_H__