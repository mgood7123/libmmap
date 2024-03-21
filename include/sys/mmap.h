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

// $ grep _SC_PAGE_SIZE /usr/include/sys/*
//   /usr/include/sys/unistd.h:# define _SC_PAGE_SIZE 3001 /* PAGE_SIZE
#define _SC_PAGE_SIZE 3001
#define _SC_PAGESIZE _SC_PAGE_SIZE
#define PAGE_SIZE _SC_PAGE_SIZE
#define PAGESIZE _SC_PAGE_SIZE


/*
       The function getpagesize() returns the number of bytes in a
       memory page, where "page" is a fixed-length block, the unit for
       memory allocation and file mapping performed by mmap(2).
*/
__declspec(dllexport) int getpagesize(void);
/*
       The function sysconf(), when given _SC_PAGE_SIZE or PAGE_SIZE or PAGESIZE,
       returns the number of bytes in a memory page, where "page" is a fixed-length
       block, the unit for memory allocation and file mapping performed by mmap(2).
*/
__declspec(dllexport) long sysconf(int name);

__declspec(dllexport) void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
__declspec(dllexport) int munmap(void* addr, size_t length);
__declspec(dllexport) int mprotect(void* addr, size_t length, int prot);

// note
// 
// int pkey_mprotect(void* addr, size_t len, int prot, int pkey);
//
// https://man7.org/linux/man-pages/man2/pkey_alloc.2.html
// https://man7.org/linux/man-pages/man7/pkeys.7.html
// https://xem.github.io/minix86/manual/intel-x86-and-64-manual-vol3/o_fe12b1e2a880e0ce-82.html
// If CPUID.(EAX=07H,ECX=0H):ECX.PKU [bit 3] = 1, the processor supports the protection-key feature for IA-32e paging

__END_DECLS
