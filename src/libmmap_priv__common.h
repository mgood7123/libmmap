#ifndef LIBMMAP__PRIVATE_COMMON__H
#define LIBMMAP__PRIVATE_COMMON__H

#include <wtypes.h>

#ifndef __cplusplus
# ifndef nullptr
typedef void* nullptr_t;
#  define nullptr (nullptr_t)NULL
# endif
#endif


#if __cplusplus
#include <vector>
#else
#define VECTOR_TYPE void*
#define VECTOR_PREFIX libmmap_ptr_vector
#include "libmmap_priv__cvector.h"
#endif


struct LIBMMAP__MAP_INFO {
    HANDLE file_mapping;
    void* begin_address;
    void* end_address;
#if __cplusplus
    std::vector<void*> _64_kb_sections;
#else
    struct vector_libmmap_ptr_vector _64_kb_sections;
#endif
};


#if __cplusplus
#else
#define VECTOR_TYPE struct LIBMMAP__MAP_INFO*
#define VECTOR_PREFIX libmmap_info_vector
#include "libmmap_priv__cvector.h"
#endif


#if __cplusplus
static std::vector<LIBMMAP__MAP_INFO*> libmmap_mapping_information;
#else
static struct vector_libmmap_info_vector libmmap_mapping_information;
static bool libmmap_mapping_information_initialized = false;
#endif


#define roundup(x, y)	((((x) + ((y) - 1)) / (y)) * (y))
#define rounddown(x, y)	(((x) / (y)) * (y))


#define PROT_TO_PAGE(prot, is_private) \
 (prot == PROT_NONE ? PAGE_NOACCESS \
: prot == PROT_READ ? PAGE_READONLY \
: prot == PROT_WRITE ? (is_private ? PAGE_WRITECOPY : PAGE_READWRITE) \
: prot == PROT_EXECUTE ? PAGE_EXECUTE \
: (prot & (PROT_READ|PROT_WRITE|PROT_EXECUTE)) == (PROT_READ|PROT_WRITE|PROT_EXECUTE) ? (is_private ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE_READWRITE) \
: (prot & (PROT_WRITE|PROT_EXECUTE)) == (PROT_WRITE|PROT_EXECUTE) ? (is_private ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE_READWRITE) \
: (prot & (PROT_READ|PROT_EXECUTE)) == (PROT_READ|PROT_EXECUTE) ? PAGE_EXECUTE_READ \
: (is_private ? PAGE_WRITECOPY : PAGE_READWRITE))
// the last can only be
//   (prot & (PROT_READ|PROT_WRITE)) == (PROT_READ|PROT_WRITE)


#define PROT_TO_PAGE_STR(prot, is_private) \
 (prot == PROT_NONE ? "PAGE_NOACCESS" \
: prot == PROT_READ ? "PAGE_READONLY" \
: prot == PROT_WRITE ? (is_private ? "PAGE_WRITECOPY" : "PAGE_READWRITE") \
: prot == PROT_EXECUTE ? "PAGE_EXECUTE" \
: (prot & (PROT_READ|PROT_WRITE|PROT_EXECUTE)) == (PROT_READ|PROT_WRITE|PROT_EXECUTE) ? (is_private ? "PAGE_EXECUTE_WRITECOPY" : "PAGE_EXECUTE_READWRITE") \
: (prot & (PROT_WRITE|PROT_EXECUTE)) == (PROT_WRITE|PROT_EXECUTE) ? (is_private ? "PAGE_EXECUTE_WRITECOPY" : "PAGE_EXECUTE_READWRITE") \
: (prot & (PROT_READ|PROT_EXECUTE)) == (PROT_READ|PROT_EXECUTE) ? "PAGE_EXECUTE_READ" \
: (is_private ? "PAGE_WRITECOPY" : "PAGE_READWRITE"))
// the last can only be
//   (prot & (PROT_READ|PROT_WRITE)) == (PROT_READ|PROT_WRITE)

#define PROT_TO_FILE_MAP(prot, is_private) \
 (prot == PROT_READ ? FILE_MAP_READ \
: prot == PROT_WRITE ? (is_private ? FILE_MAP_COPY : FILE_MAP_WRITE) \
: prot == PROT_EXECUTE ? FILE_MAP_EXECUTE \
: (prot & (PROT_READ|PROT_WRITE|PROT_EXECUTE)) == (PROT_READ|PROT_WRITE|PROT_EXECUTE) ? (is_private ? FILE_MAP_EXECUTE|FILE_MAP_COPY : FILE_MAP_READ|FILE_MAP_WRITE|FILE_MAP_EXECUTE) \
: (prot & (PROT_WRITE|PROT_EXECUTE)) == (PROT_WRITE|PROT_EXECUTE) ? (is_private ? FILE_MAP_EXECUTE|FILE_MAP_COPY : FILE_MAP_WRITE|FILE_MAP_EXECUTE) \
: (prot & (PROT_READ|PROT_EXECUTE)) == (PROT_READ|PROT_EXECUTE) ? FILE_MAP_READ|FILE_MAP_EXECUTE \
: (is_private ? FILE_MAP_COPY : FILE_MAP_READ|FILE_MAP_WRITE))
// the last can only be
//   (prot & (PROT_READ|PROT_WRITE)) == (PROT_READ|PROT_WRITE)

#define PROT_TO_FILE_MAP_STR(prot, is_private) \
 (prot == PROT_READ ? "FILE_MAP_READ" \
: prot == PROT_WRITE ? (is_private ? "FILE_MAP_COPY" : "FILE_MAP_WRITE") \
: prot == PROT_EXECUTE ? "FILE_MAP_EXECUTE" \
: (prot & (PROT_READ|PROT_WRITE|PROT_EXECUTE)) == (PROT_READ|PROT_WRITE|PROT_EXECUTE) ? (is_private ? "FILE_MAP_EXECUTE|FILE_MAP_COPY" : "FILE_MAP_READ|FILE_MAP_WRITE|FILE_MAP_EXECUTE") \
: (prot & (PROT_WRITE|PROT_EXECUTE)) == (PROT_WRITE|PROT_EXECUTE) ? (is_private ? "FILE_MAP_EXECUTE|FILE_MAP_COPY" : "FILE_MAP_WRITE|FILE_MAP_EXECUTE") \
: (prot & (PROT_READ|PROT_EXECUTE)) == (PROT_READ|PROT_EXECUTE) ? "FILE_MAP_READ|FILE_MAP_EXECUTE" \
: (is_private ? "FILE_MAP_COPY" : "FILE_MAP_READ|FILE_MAP_WRITE"))
// the last can only be
//   (prot & (PROT_READ|PROT_WRITE)) == (PROT_READ|PROT_WRITE)

#define libmmap__________________last_error __________________________________________________________libmmap_________________last_error
#define libmmap__________________last_errno __________________________________________________________libmmap_________________last_errno


#define libmmap__________________init_error() \
    DWORD libmmap__________________last_error = 0; \
    int libmmap__________________last_errno = 0; \


#define libmmap__________________save_error() \
    libmmap__________________last_errno = errno; \
    libmmap__________________last_error = GetLastError() \


#define libmmap__________________restore_error() \
    SetLastError(libmmap__________________last_error); \
    errno = libmmap__________________last_errno


#define libmmap____ret(e, val) errno = e; return val

#endif // LIBMMAP__PRIVATE_COMMON__H
