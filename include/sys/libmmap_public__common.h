#ifndef LIBMMAP__PUBLIC_COMMON_H
#define LIBMMAP__PUBLIC_COMMON_H

#include <sys/libmmap_compile_info.h>

#ifdef LIBMMAP_IS_DEBUG
#define LIBMMAP_DEBUG_PRINTF(what, ...) printf(what, ## __VA_ARGS__)
#else
#define LIBMMAP_DEBUG_PRINTF(what, ...)
#endif

#endif // LIBMMAP__PUBLIC_COMMON_H
