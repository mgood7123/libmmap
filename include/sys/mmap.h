#define NOMINMAX
#include <Windows.h>

#include <sys/mmap_defines.h>

#ifndef __BEGIN_DECLS
/* C++ needs to know that types and declarations are C, not C++.  */
# ifdef	__cplusplus
#  define __BEGIN_DECLS	extern "C" {
#  define __END_DECLS	}
# else
#  define __BEGIN_DECLS
#  define __END_DECLS
# endif
#endif

__BEGIN_DECLS
__declspec(dllexport) void* mmap(void * addr, size_t length, int prot, int flags, int fd, off_t offset);
__declspec(dllexport) int munmap(void* addr, size_t length);
__END_DECLS
