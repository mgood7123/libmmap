#include <sys/mmap.h>

#include <memoryapi.h>
#include <io.h>
#include <synchapi.h>

#include <stdio.h>

#include <sys/libmmap_compile_info.h>
#include <sys/libmmap_public__common.h>
#include "libmmap_priv__common.h"

#define FREE_FILE_MAPPING(mapping) \
if (!CloseHandle(mapping)) { \
    libmmap__________________save_error(); \
    print_last_error("failed to close mapping", libmmap__________________last_error); \
    libmmap__________________restore_error(); \
    libmmap____ret(-ENOMEM, MAP_FAILED); \
} \
mapping = INVALID_HANDLE_VALUE;

#define FREE_VIRTUAL_MEMORY_AND_ON_FAILURE_FREE_FILE_MAPPING(ptr, mapping) \
if (!VirtualFree(ptr, 0, MEM_RELEASE)) { \
    libmmap__________________save_error(); \
    print_last_error("failed to free reserved memory", libmmap__________________last_error); \
    FREE_FILE_MAPPING(mapping); \
    libmmap__________________restore_error(); \
    libmmap____ret(-ENOMEM, MAP_FAILED); \
} \
ptr = nullptr;

static CRITICAL_SECTION __libmmap_mapping_information__lock = { 0 };
static CRITICAL_SECTION * libmmap_mapping_information__lock = nullptr;
static DWORD granularity;
static DWORD page_size;

// Global variable for one-time initialization structure
static INIT_ONCE g_InitOnce = INIT_ONCE_STATIC_INIT; // Static initialization

// Initialization callback function that creates the event object 
BOOL CALLBACK InitHandleFunction(
    PINIT_ONCE InitOnce,        // Pointer to one-time initialization structure        
    PVOID Parameter,            // Optional parameter passed by InitOnceExecuteOnce            
    PVOID* lpContext            // Receives pointer to event object           
) {
    SYSTEM_INFO sys;
    GetSystemInfo(&sys);
    granularity = sys.dwAllocationGranularity;
    page_size = sys.dwPageSize;
    libmmap_mapping_information__lock = &__libmmap_mapping_information__lock;
    InitializeCriticalSection(libmmap_mapping_information__lock);

    LIBMMAP_DEBUG_PRINTF("mmap initialized\n");

    return TRUE;
}

static inline void print_last_error(const char* msg, DWORD dwErrorCode) {
    LPTSTR psz = nullptr;
    const DWORD cchMsg = FormatMessage(
          FORMAT_MESSAGE_FROM_SYSTEM
        | FORMAT_MESSAGE_IGNORE_INSERTS
        | FORMAT_MESSAGE_ALLOCATE_BUFFER,
        nullptr, // (not used with FORMAT_MESSAGE_FROM_SYSTEM)
        dwErrorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&psz,
        0,
        nullptr);
    if (cchMsg > 0)
    {
        if (msg == nullptr) {
            printf(
                "  Last Error Code:\n"
                "    Value:    %ld\n"
                "    Message:  %s\n\n"
                , dwErrorCode, psz
            );
        }
        else {
            printf(
                "%s\n"
                "  Last Error Code:\n"
                "    Value:    %ld\n"
                "    Message:  %s\n\n"
                , msg, dwErrorCode, psz
            );
        }
    }
    else
    {
        if (msg == nullptr) {
            printf(
                "  <Failed to retrieve error message string.>\n"
                "  Last Error Code:\n"
                "    Value:    %ld\n"
                , dwErrorCode
            );
        }
        else {
            printf(
                "%s\n"
                "  <Failed to retrieve error message string.>\n"
                "  Last Error Code:\n"
                "    Value:    %ld\n"
                , msg, dwErrorCode
            );
        }
    }
}

void* prepopulate_array(struct LIBMMAP__MAP_INFO* a_map, HANDLE mapping) {
    libmmap__________________init_error();
    for (uint8_t* begin = (uint8_t*)a_map->begin_address; begin != a_map->end_address; begin += granularity) {
        // populate with nullptr
        intptr_t ri = (intptr_t)nullptr;
#if __cplusplus
        a_map->_64_kb_sections.emplace_back((void*)ri);
#else
        if (!v_libmmap_ptr_vector_push(&a_map->_64_kb_sections, (void**)&ri)) {
            libmmap__________________save_error();

            print_last_error("failed to reallocate sections for a mapping array", libmmap__________________last_error);
            // lock our dll array
            EnterCriticalSection(libmmap_mapping_information__lock);
            v_libmmap_info_vector_erase(&libmmap_mapping_information, &a_map);
            for (void** section = a_map->_64_kb_sections.vec; section <= &a_map->_64_kb_sections.vec[a_map->_64_kb_sections.size-1]; section++) {
                if (*section != nullptr) {
                    if (!UnmapViewOfFile(*section)) {
                        libmmap__________________save_error();
                        print_last_error("failed to unmap a section in a section array for a mapping array, continuing", libmmap__________________last_error);
                    }
                    *section = nullptr;
                }
            }
            free(a_map->_64_kb_sections.vec);
            free(a_map);
            // unlock our dll array
            LeaveCriticalSection(libmmap_mapping_information__lock);
            FREE_FILE_MAPPING(mapping);

            libmmap__________________restore_error();
            libmmap____ret(-ENOMEM, MAP_FAILED);
        }
#endif
    }
    return nullptr;
}

void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {

    while (!InitOnceExecuteOnce(
        &g_InitOnce,          // One-time initialization structure
        InitHandleFunction,   // Pointer to initialization callback function
        NULL,                 // Optional parameter to callback function (not used)
        nullptr               // Receives pointer to event object stored in g_InitOnce (not used)
    )) {}

    // EINVAL (since Linux 2.6.12) length was 0.
    //
    if (length == 0) {
        LIBMMAP_DEBUG_PRINTF("mmap: length must not be zero\n");
        libmmap____ret(-EINVAL, MAP_FAILED);
    }

    // PROT_NONE cannot be combined
    if ((prot & PROT_NONE) == PROT_NONE) {
        if (prot != PROT_NONE) {
            LIBMMAP_DEBUG_PRINTF("mmap: PROT_NONE cannot be combined with any other PROT flags\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        // PROT_NONE
    }

    // if MAP_POPULATE is given, we require either READ access or WRITE access
    if ((flags & MAP_POPULATE) == MAP_POPULATE) {
        if ((prot & PROT_READ) != PROT_READ || (prot & PROT_WRITE) != PROT_WRITE) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_POPULATE must be given PROT_READ or PROT_WRITE\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
    }

#define LIBMMAP__ILLEGAL_FLAGS(F1, F2, F3) \
    if ((flags & F1) == F1 && (flags & F2) == F2 && (flags & F3) == F3) { \
        LIBMMAP_DEBUG_PRINTF("mmap: " #F1 " and " #F2 " and " #F3 " cannot be specified together\n"); \
        libmmap____ret(-EINVAL, MAP_FAILED); \
    } else if ((flags & F1) == F1 && (flags & F3) == F3 && (flags & F2) == F2) { \
        LIBMMAP_DEBUG_PRINTF("mmap: " #F1 " and " #F3 " and " #F2 " cannot be specified together\n"); \
        libmmap____ret(-EINVAL, MAP_FAILED); \
    } else if ((flags & F2) == F2 && (flags & F1) == F1 && (flags & F3) == F3) { \
        LIBMMAP_DEBUG_PRINTF("mmap: " #F2 " and " #F1 " and " #F3 " cannot be specified together\n"); \
        libmmap____ret(-EINVAL, MAP_FAILED); \
    } else if ((flags & F2) == F2 && (flags & F3) == F3 && (flags & F1) == F1) { \
        LIBMMAP_DEBUG_PRINTF("mmap: " #F2 " and " #F3 " and " #F1 " cannot be specified together\n"); \
        libmmap____ret(-EINVAL, MAP_FAILED); \
    } else if ((flags & F3) == F3 && (flags & F1) == F1 && (flags & F2) == F2) { \
        LIBMMAP_DEBUG_PRINTF("mmap: " #F3 " and " #F1 " and " #F2 " cannot be specified together\n"); \
        libmmap____ret(-EINVAL, MAP_FAILED); \
    } else if ((flags & F3) == F3 && (flags & F2) == F2 && (flags & F1) == F1) { \
        LIBMMAP_DEBUG_PRINTF("mmap: " #F3 " and " #F2 " and " #F1 " cannot be specified together\n"); \
        libmmap____ret(-EINVAL, MAP_FAILED); \
    }

    LIBMMAP__ILLEGAL_FLAGS(MAP_PRIVATE, MAP_SHARED, MAP_SHARED_VALIDATE);

#undef LIBMMAP__ILLEGAL_FLAGS

    /*
           EPERM  The MAP_HUGETLB flag was specified, but the caller was not
                  privileged (did not have the CAP_IPC_LOCK capability) and
                  is not a member of the sysctl_hugetlb_shm_group group; see
                  the description of /proc/sys/vm/sysctl_hugetlb_shm_group
                  in
    */
    // assume we dont have caps
    if ((flags & MAP_HUGETLB) == MAP_HUGETLB) {
        LIBMMAP_DEBUG_PRINTF("mmap: MAP_HUGETBL is not supported\n");
        libmmap____ret(-EPERM, MAP_FAILED);
    }

    /*
           EINVAL We don't like addr, length, or offset (e.g., they are too
                  large, or not aligned on a page boundary).
    */
    // length can ONLY be align to granularity boundary
    if ((length % granularity) != 0) {
        LIBMMAP_DEBUG_PRINTF("mmap: length (%zu) must be a multiple of the allocation granularity (%lu)\n", length, granularity);
        libmmap____ret(-EINVAL, MAP_FAILED);
    }

    /*
           EINVAL We don't like addr, length, or offset (e.g., they are too
                  large, or not aligned on a page boundary).
    */
    // address can ONLY be align to granularity boundary since we do not support
    //   virtual alloc for MAP_PRIVATE
    if ((((intptr_t)addr) % granularity) != 0) {
        LIBMMAP_DEBUG_PRINTF("mmap: address (0x%p) must be a multiple of the allocation granularity (%lu)\n", addr, granularity);
        libmmap____ret(-EINVAL, MAP_FAILED);
    }

    /*
           EINVAL We don't like addr, length, or offset (e.g., they are too
                  large, or not aligned on a page boundary).
    */
    // offset can ONLY be align to granularity boundary
    if ((offset % granularity) != 0) {
        LIBMMAP_DEBUG_PRINTF("mmap: offset (%lu) must be a multiple of the allocation granularity (%lu)\n", offset, granularity);
        libmmap____ret(-EINVAL, MAP_FAILED);
    }
    // we have two situations
    // 1. we pass an fd
    // 2. we pass -1 for fd

    HANDLE handle = INVALID_HANDLE_VALUE;

    if ((flags & MAP_ANONYMOUS) == MAP_ANONYMOUS) {
        // we map from memory via paging file, fd is ignored but should be -1

#if LIBMMAP_IS_DEBUG
        // filter out flags we do not support with a paging file

        if (!((flags & MAP_PRIVATE) == MAP_PRIVATE)) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_PRIVATE was not passed\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        if ((flags & MAP_SHARED) == MAP_SHARED) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_SHARED is not supported for page mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        if ((flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_SHARED_VALIDATE is not supported for page mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        if ((flags & MAP_FIXED_NOREPLACE) == MAP_FIXED_NOREPLACE) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_FIXED_NOREPLACE is not supported for page mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        // MAP_NONBLOCK only works on VERY old kernels
        // || (flags & MAP_NONBLOCK) == MAP_NONBLOCK
        // we cannot control where the range of a mapping will be placed, although it IS possible
        // || (flags & MAP_32BIT) == MAP_32BIT
        // ignored
        // || (flags & MAP_DENYWRITE) == MAP_DENYWRITE
        // ignored
        // || (flags & MAP_EXECUTABLE) == MAP_EXECUTABLE
        // ignored
        // || (flags & MAP_FILE) == MAP_FILE
        // TODO
        //  - https://learn.microsoft.com/en-us/windows/win32/Memory/creating-guard-pages
        if ((flags & MAP_GROWSDOWN) == MAP_GROWSDOWN) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_GROWSDOWN is not supported for page mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        // TODO
        if ((flags & MAP_LOCKED) == MAP_LOCKED) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_LOCKED is not supported for page mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
            // no-op on linux
            // || (flags & MAP_STACK) == MAP_STACK
            // only valid for a file mapping
        if ((flags & MAP_SYNC) == MAP_SYNC) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_SYNC is not supported for page mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        // impossible to support since we cannot change the protection level of malloc'd data
        if ((flags & MAP_UNINITIALIZED) == MAP_UNINITIALIZED) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_UNINITIALIZED is not supported for page mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
#else
        // filter out flags we do not support with a paging file
        if (
            // paging files MUST be MAP_PRIVATE
            !((flags & MAP_PRIVATE) == MAP_PRIVATE)
            // MAP_ANONYMOUS paging files cannot be shared, windows cannot fork()
            || (flags & MAP_SHARED) == MAP_SHARED
            // paging files cannot be shared, windows cannot fork()
            || (flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE
            // it is impossible to map a fixed address and check for mapping collisions atomically
            || (flags & MAP_FIXED_NOREPLACE) == MAP_FIXED_NOREPLACE
            // MAP_NONBLOCK only works on VERY old kernels
            // || (flags & MAP_NONBLOCK) == MAP_NONBLOCK
            // we cannot control where the range of a mapping will be placed, although it IS possible
            // || (flags & MAP_32BIT) == MAP_32BIT
            // ignored
            // || (flags & MAP_DENYWRITE) == MAP_DENYWRITE
            // ignored
            // || (flags & MAP_EXECUTABLE) == MAP_EXECUTABLE
            // ignored
            // || (flags & MAP_FILE) == MAP_FILE
            // TODO
            //  - https://learn.microsoft.com/en-us/windows/win32/Memory/creating-guard-pages
            || (flags & MAP_GROWSDOWN) == MAP_GROWSDOWN
            // TODO
            || (flags & MAP_LOCKED) == MAP_LOCKED
            // no-op on linux
            // || (flags & MAP_STACK) == MAP_STACK
            // only valid for a file mapping
            || (flags & MAP_SYNC) == MAP_SYNC
            // impossible to support since we cannot change the protection level of malloc'd data
            || (flags & MAP_UNINITIALIZED) == MAP_UNINITIALIZED
        ) {
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
#endif

        // a page file does not support an offset
        if (offset != 0) {
            LIBMMAP_DEBUG_PRINTF("mmap: a page mapping must specify an offset of zero\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }

        /*
            If the MAP_FIXED flag is specified, and addr is 0 (NULL), then the
            mapped address will be 0 (NULL).
            
            // we assume this ONLY happens if mmap is passed fd -1
        */
        if (addr == 0 && (flags & MAP_FIXED) == MAP_FIXED) {
            return nullptr;
        }
    }
    else {
        // we map from fd

#if LIBMMAP_IS_DEBUG
        // filter out flags we do not support with a paging file

        if (!((flags & MAP_PRIVATE) == MAP_PRIVATE || (flags & MAP_SHARED) == MAP_SHARED)) {
            LIBMMAP_DEBUG_PRINTF("mmap: the following flags where not passed: MAP_PRIVATE or MAP_SHARED\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        if ((flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_SHARED_VALIDATE is not supported for file mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        if ((flags & MAP_FIXED_NOREPLACE) == MAP_FIXED_NOREPLACE) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_FIXED_NOREPLACE is not supported for file mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        // MAP_NONBLOCK only works on VERY old kernels
        // || (flags & MAP_NONBLOCK) == MAP_NONBLOCK
        // we cannot control where the range of a mapping will be placed, although it IS possible
        // || (flags & MAP_32BIT) == MAP_32BIT
        // ignored
        // || (flags & MAP_DENYWRITE) == MAP_DENYWRITE
        // ignored
        // || (flags & MAP_EXECUTABLE) == MAP_EXECUTABLE
        // ignored
        // || (flags & MAP_FILE) == MAP_FILE
        if ((flags & MAP_GROWSDOWN) == MAP_GROWSDOWN) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_GROWSDOWN is not supported for file mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        // TODO
        if ((flags & MAP_LOCKED) == MAP_LOCKED) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_LOCKED is not supported for file mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        // no-op on linux
        // || (flags & MAP_STACK) == MAP_STACK
        if ((flags & MAP_SYNC) == MAP_SYNC) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_SYNC is not supported for file mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
        // impossible to support since we cannot change the protection level of malloc'd data
        if ((flags & MAP_UNINITIALIZED) == MAP_UNINITIALIZED) {
            LIBMMAP_DEBUG_PRINTF("mmap: MAP_UNINITIALIZED is not supported for file mappings\n");
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
#else
        // filter out flags we do not support with a file handle
        if (
            // file handles MUST be MAP_PRIVATE or MAP_SHARED
            !((flags & MAP_PRIVATE) == MAP_PRIVATE || (flags & MAP_SHARED) == MAP_SHARED)
            // we dont know what exactly this means yet
            || (flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE
            // it is impossible to map a fixed address and check for mapping collisions atomically
            // TODO: this is now possible
            || (flags & MAP_FIXED_NOREPLACE) == MAP_FIXED_NOREPLACE
            // MAP_NONBLOCK only works on VERY old kernels
            // || (flags & MAP_NONBLOCK) == MAP_NONBLOCK
            // we cannot control where the range of a mapping will be placed
            // TODO: this is actually possible via NT section view
            // || (flags & MAP_32BIT) == MAP_32BIT
            // ignored
            // || (flags & MAP_DENYWRITE) == MAP_DENYWRITE
            // ignored
            // || (flags & MAP_EXECUTABLE) == MAP_EXECUTABLE
            // ignored
            // || (flags & MAP_FILE) == MAP_FILE
            // file handles do not support this
            || (flags & MAP_GROWSDOWN) == MAP_GROWSDOWN
            // TODO
            || (flags & MAP_LOCKED) == MAP_LOCKED
            // no-op on linux
            // || (flags & MAP_STACK) == MAP_STACK
            // TODO: we do not know what exactly this means yet
            || (flags & MAP_SYNC) == MAP_SYNC
            // impossible to support since we cannot change its protection level it
            || (flags & MAP_UNINITIALIZED) == MAP_UNINITIALIZED
        ) {
            libmmap____ret(-EINVAL, MAP_FAILED);
        }
#endif

        /*

                we ignore the following because we do not have any equivalent

                ENOMEM The process's maximum number of mappings would have been
                        exceeded.  This error can also occur for munmap(), when
                        unmapping a region in the middle of an existing mapping,
                        since this results in two smaller mappings on either side
                        of the region being unmapped.

                ENOMEM (since Linux 4.7) The process's RLIMIT_DATA limit,
                        described in getrlimit(2), would have been exceeded.

                ENFILE The system-wide limit on the total number of open files
                        has been reached.

        */

        // EBADF  fd is not a valid file descriptor (and MAP_ANONYMOUS was not set).
        //   note: the below does https://learn.microsoft.com/en-us/cpp/c-runtime-library/parameter-validation?view=msvc-170
        //         this is a global state and cannot be atomically changed
        //         we MAY fail
        handle = (HANDLE)_get_osfhandle(fd);
        if (handle == INVALID_HANDLE_VALUE) {
            LIBMMAP_DEBUG_PRINTF("mmap: the passed file descriptor is invalid for a file mapping\n");
            libmmap____ret(-EBADF, MAP_FAILED);
        }

        // the handle is valid

        // EACCES A file descriptor refers to a non-regular file.
        if (GetFileType(handle) != FILE_TYPE_DISK) {
            LIBMMAP_DEBUG_PRINTF("mmap: the passed file descriptor must refer to a regular disk file for a file mapping\n");
            libmmap____ret(-EACCES, MAP_FAILED);
        }

        // EACCES A file mapping was requested, but fd is not open for reading
        //
        // we cannot check this

        // EACCESS MAP_SHARED was requested and PROT_WRITE is set, but fd is
        //         not open in read/write (O_RDWR) mode
        //
        // we cannot check this

        // EACCESS PROT_WRITE is set, but the file is append-only
        //
        // we cannot check this

        // EPERM  The prot argument asks for PROT_EXEC but the mapped area
        //         belongs to a file on a filesystem that was mounted no-
        //         exec.
        //
        // we cannot check this

        // ENODEV The underlying filesystem of the specified file does not
        //        support memory mapping.
        //
        // we cannot check this

        // EAGAIN The file has been locked, or too much memory has been
        //         locked (see setrlimit(2)).
        //
        // we cannot check this

        // EPERM  The operation was prevented by a file seal; see fcntl(2).
        //
        // we cannot check this

        /*
               EINVAL We don't like addr, length, or offset (e.g., they are too
                      large, or not aligned on a page boundary).
        */
        // offset CAN be non-zero for a file mapping so need to check for length + offset overflow
        // we know fd is not -1
        // if this fails, then assume we do not overflow
        BY_HANDLE_FILE_INFORMATION f;
        if (GetFileInformationByHandle(handle, &f)) {
            // unfortunately file information by handle returns low and high
            // these are DWORD each
            // offset is an off_t, which microsoft defines in sys/types.h as long
            // and unfortunately in windows, 'long' is 32 bits
            // and length is a size_t, which clang defines as long long unsigned int
            // large integer is DWORD low and LONG high
            ULARGE_INTEGER l;
            l.HighPart = f.nFileSizeHigh;
            l.LowPart = f.nFileSizeLow;
            ULONGLONG file_end = l.QuadPart;
            if (file_end < (ULONGLONG)offset) {
                LIBMMAP_DEBUG_PRINTF("mmap: the passed offset is greater than the file descriptor's reported file size (%llu)\n", file_end);
                libmmap____ret(-EINVAL, MAP_FAILED);
            }
            else if (offset == 0) {
                if (file_end < (ULONGLONG)offset) {
                    LIBMMAP_DEBUG_PRINTF("mmap: the passed length (with an offset of zero) is greater than the file descriptor's reported file size (%llu)\n", file_end);
                    libmmap____ret(-EINVAL, MAP_FAILED);
                }
            } else if (file_end < ((ULONGLONG) offset + (ULONGLONG) length)) {
                LIBMMAP_DEBUG_PRINTF("mmap: the passed offset+length is greater than the file descriptor's reported file size (%llu)\n", file_end);
                libmmap____ret(-EINVAL, MAP_FAILED);
            }
        }
    }

    const DWORD dwMaxSizeHigh = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)0 : (DWORD)((length >> 32) & 0xFFFFFFFFL);
    const DWORD dwMaxSizeLow = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)length : (DWORD)(length & 0xFFFFFFFFL);

    libmmap__________________init_error();

    // we assume mmap pointers cannot be inherited
    SECURITY_ATTRIBUTES a;
    a.bInheritHandle = false;
    a.nLength = 0;
    a.lpSecurityDescriptor = nullptr;
    LIBMMAP_DEBUG_PRINTF("creating %s file mapping\n", PROT_TO_PAGE_STR(prot, (flags& MAP_PRIVATE) == MAP_PRIVATE));
    HANDLE mapping = CreateFileMappingW(handle, &a, PROT_TO_PAGE(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE), dwMaxSizeHigh, dwMaxSizeLow, NULL);
    if (!mapping) {
        libmmap__________________save_error();
        print_last_error("failed to create mapping", libmmap__________________last_error);
        libmmap__________________restore_error();
        libmmap____ret(-ENOMEM, MAP_FAILED);
    }

    // mapping can reuse an existing mapping, abort
    if (libmmap__________________last_error == ERROR_ALREADY_EXISTS) {
        libmmap__________________save_error();
        print_last_error("failed to create mapping", libmmap__________________last_error);
        libmmap__________________restore_error();
        libmmap____ret(-EEXIST, MAP_FAILED);
    }

    // MAP_ANON specifies random location, addr is HINT,  we ignore it and set to nullptr
    // MAP_FIXED specified fixed location
    // 
    // TODO:
    // MAP_FIXED:
    //                           If the memory region specified
    // by addr and length overlaps pages of any existing
    // mapping(s), then the overlapped part of the existing
    // mapping(s) will be discarded.  If the specified address
    // cannot be used, mmap() will fail.
    //
    void* addr_adjusted = nullptr;
    if (!((flags & MAP_ANONYMOUS) == MAP_ANONYMOUS) && addr != 0) {
        addr_adjusted = (void*)rounddown((intptr_t)addr, granularity);
    }

    // we have an adjusted address
    // attempt to reserve an address, if this fails then we cannot reserve another
    // and must assume we do not have enough free space left (fragmentation will cause this)

    while (true) {
        // address must be aligned to granularity
        // length 
        void* desired_addr_r = VirtualAlloc(addr_adjusted, length, MEM_RESERVE, PAGE_NOACCESS);
        libmmap__________________save_error();
        if (!desired_addr_r) {
            print_last_error("failed to reserve memory", libmmap__________________last_error);
            FREE_FILE_MAPPING(mapping);
            libmmap__________________restore_error();
            libmmap____ret(-ENOMEM, MAP_FAILED);
        }
        // we have managed to reserve an address
        // do any computations now while it is reserved

        // lock our dll array
        EnterCriticalSection(libmmap_mapping_information__lock);

#if __cplusplus
#else
        if (!libmmap_mapping_information_initialized) {
            v_libmmap_info_vector_init(&libmmap_mapping_information);
            libmmap__________________save_error();
            if (!libmmap_mapping_information.vec) {
                // unlock our dll array
                LeaveCriticalSection(libmmap_mapping_information__lock);

                print_last_error("failed to create array", libmmap__________________last_error);
                FREE_VIRTUAL_MEMORY_AND_ON_FAILURE_FREE_FILE_MAPPING(desired_addr_r, mapping);
                FREE_FILE_MAPPING(mapping);
                libmmap__________________restore_error();
                libmmap____ret(-ENOMEM, MAP_FAILED);
            }
            libmmap_mapping_information_initialized = true;
        }
#endif

        // our array has been created if-needed

#if __cplusplus
        struct LIBMMAP__MAP_INFO* a_map = new struct LIBMMAP__MAP_INFO();
#else
        struct LIBMMAP__MAP_INFO* a_map = (struct LIBMMAP__MAP_INFO*) malloc(sizeof(struct LIBMMAP__MAP_INFO));
#endif
        if (!a_map) {
            libmmap__________________save_error();

            print_last_error("failed to allocate a mapping array", libmmap__________________last_error);

            // unlock our dll array
            LeaveCriticalSection(libmmap_mapping_information__lock);

            FREE_VIRTUAL_MEMORY_AND_ON_FAILURE_FREE_FILE_MAPPING(desired_addr_r, mapping);
            FREE_FILE_MAPPING(mapping);

            libmmap__________________restore_error();
            libmmap____ret(-ENOMEM, MAP_FAILED);
        }

        a_map->file_mapping = mapping;
        a_map->begin_address = desired_addr_r;
        a_map->end_address = (uint8_t*)desired_addr_r + length;
#if __cplusplus
#else
        v_libmmap_ptr_vector_init(&a_map->_64_kb_sections);
        if (!a_map->_64_kb_sections.vec) {
            libmmap__________________save_error();
            print_last_error("failed to allocate a section array for a mapping array", libmmap__________________last_error);

            // unlock our dll array
            LeaveCriticalSection(libmmap_mapping_information__lock);
            free(a_map);
            FREE_VIRTUAL_MEMORY_AND_ON_FAILURE_FREE_FILE_MAPPING(desired_addr_r, mapping);
            FREE_FILE_MAPPING(mapping);

            libmmap__________________restore_error();
            libmmap____ret(-ENOMEM, MAP_FAILED);
        }
#endif

#if __cplusplus
        libmmap_mapping_information.emplace_back(a_map);
#else
        if (!v_libmmap_info_vector_push(&libmmap_mapping_information, &a_map)) {
            libmmap__________________save_error();

            print_last_error("failed to reallocate section array for a mapping array", libmmap__________________last_error);

            // unlock our dll array
            LeaveCriticalSection(libmmap_mapping_information__lock);
            free(a_map->_64_kb_sections.vec);
            free(a_map);
            FREE_VIRTUAL_MEMORY_AND_ON_FAILURE_FREE_FILE_MAPPING(desired_addr_r, mapping);
            FREE_FILE_MAPPING(mapping);

            libmmap__________________restore_error();
            libmmap____ret(-ENOMEM, MAP_FAILED);
        }
#endif

        // unlock our dll array
        LeaveCriticalSection(libmmap_mapping_information__lock);

        // pre-populate our array
        if (prepopulate_array(a_map, mapping) == MAP_FAILED) return MAP_FAILED;

        // our array has been prepopulated with dummy sections, we can release the reservation

        // now free it
        if (!VirtualFree(desired_addr_r, 0, MEM_RELEASE)) {
            libmmap__________________save_error();

            print_last_error("failed to free reserved memory", libmmap__________________last_error);

            // lock our dll array
            EnterCriticalSection(libmmap_mapping_information__lock);
#if __cplusplus
            auto it = std::find(libmmap_mapping_information.cbegin(), libmmap_mapping_information.cend(), a_map);
            libmmap_mapping_information.erase(it);
#else
            v_libmmap_info_vector_erase(&libmmap_mapping_information, &a_map);
            free(a_map->_64_kb_sections.vec);
            free(a_map);
#endif
            // unlock our dll array
            LeaveCriticalSection(libmmap_mapping_information__lock);
            FREE_FILE_MAPPING(mapping);

            libmmap__________________restore_error();
            libmmap____ret(-ENOMEM, MAP_FAILED);
        }

        // our reserved memory has just been freed
        //
        // we MUST NOT allocate anything while we are mapping to reserved
        //

        // no longer needed
        desired_addr_r = nullptr;

        off_t mapping_offset = offset;
        for (uint8_t* begin = (uint8_t*)a_map->begin_address; begin != a_map->end_address; begin += granularity) {
            const DWORD dwMaxSizeHigh = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)0 : (DWORD)((mapping_offset >> 32) & 0xFFFFFFFFL);
            const DWORD dwMaxSizeLow = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)mapping_offset : (DWORD)(mapping_offset & 0xFFFFFFFFL);

            void * r = MapViewOfFileEx(
                mapping
                , PROT_TO_FILE_MAP(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE)
                , dwMaxSizeHigh // DWORD, offset high, offset low + high when combined MUST be a multiple of granularity
                , dwMaxSizeLow // DWORD, offset low, offset low + high when combined MUST be a multiple of granularity
                , granularity // SIZE_T, length, can be anything
                , begin // MUST be a multiple of granularity
            );
            if (!r) {
                libmmap__________________save_error();
                if (ERROR_INVALID_ADDRESS == libmmap__________________last_error) {

                    print_last_error("failed to map a section in a section array for a mapping array due to race with another reservation/mapping", libmmap__________________last_error);

                    // lock our dll array
                    EnterCriticalSection(libmmap_mapping_information__lock);
#if __cplusplus
                    for (void* section : a_map->_64_kb_sections) {
                        if (section != nullptr) {
                            if (!UnmapViewOfFile(section)) {
                                libmmap__________________save_error();
                                print_last_error("failed to unmap a section in a section array for a mapping array, continuing", libmmap__________________last_error);
                            }
                        }
                    }
                    auto it = std::find(libmmap_mapping_information.cbegin(), libmmap_mapping_information.cend(), a_map);
                    libmmap_mapping_information.erase(it);
                    delete a_map;
#else
                    v_libmmap_info_vector_erase(&libmmap_mapping_information, &a_map);
                    for (void** section = a_map->_64_kb_sections.vec; section <= &a_map->_64_kb_sections.vec[a_map->_64_kb_sections.size-1]; section++) {
                        if (*section != nullptr) {
                            if (!UnmapViewOfFile(*section)) {
                                libmmap__________________save_error();
                                print_last_error("failed to unmap a section in a section array for a mapping array, continuing", libmmap__________________last_error);
                            }
                            *section = nullptr;
                        }
                    }
                    free(a_map->_64_kb_sections.vec);
                    free(a_map);
#endif
                    // unlock our dll array
                    LeaveCriticalSection(libmmap_mapping_information__lock);
                    FREE_FILE_MAPPING(mapping);

                    libmmap__________________restore_error();
                    break;
                }
                else {
                    print_last_error("failed to map a section in a section array for a mapping array", libmmap__________________last_error);
                    // unknown error, assume no memory

                    // lock our dll array
                    EnterCriticalSection(libmmap_mapping_information__lock);
#if __cplusplus
                    for (void* section : a_map->_64_kb_sections) {
                        if (section != nullptr) {
                            if (!UnmapViewOfFile(section)) {
                                libmmap__________________save_error();
                                print_last_error("failed to unmap a section in a section array for a mapping array, continuing", libmmap__________________last_error);
                            }
                        }
                    }
                    auto it = std::find(libmmap_mapping_information.cbegin(), libmmap_mapping_information.cend(), a_map);
                    libmmap_mapping_information.erase(it);
                    delete a_map;
#else
                    v_libmmap_info_vector_erase(&libmmap_mapping_information, &a_map);
                    for (void** section = a_map->_64_kb_sections.vec; section <= &a_map->_64_kb_sections.vec[a_map->_64_kb_sections.size-1]; section++) {
                        if (*section != nullptr) {
                            if (!UnmapViewOfFile(*section)) {
                                libmmap__________________save_error();
                                print_last_error("failed to unmap a section in a section array for a mapping array, continuing", libmmap__________________last_error);
                            }
                            *section = nullptr;
                        }
                    }
                    free(a_map->_64_kb_sections.vec);
                    free(a_map);
#endif
                    // unlock our dll array
                    LeaveCriticalSection(libmmap_mapping_information__lock);
                    FREE_FILE_MAPPING(mapping);

                    libmmap__________________restore_error();
                    libmmap____ret(-ENOMEM, MAP_FAILED);
                }
            }
            if (r != begin) {
                libmmap__________________save_error();

                print_last_error("failed to map a section (in a section array for a mapping array) at expected address", libmmap__________________last_error);
                // lock our dll array
                EnterCriticalSection(libmmap_mapping_information__lock);
#if __cplusplus
                for (void* section : a_map->_64_kb_sections) {
                    if (section != nullptr) {
                        if (!UnmapViewOfFile(section)) {
                            libmmap__________________save_error();
                            print_last_error("failed to unmap a section in a section array for a mapping array, continuing", libmmap__________________last_error);
                        }
                    }
                }
                auto it = std::find(libmmap_mapping_information.cbegin(), libmmap_mapping_information.cend(), a_map);
                libmmap_mapping_information.erase(it);
                delete a_map;
#else
                v_libmmap_info_vector_erase(&libmmap_mapping_information, &a_map);
                for (void** section = a_map->_64_kb_sections.vec; section <= &a_map->_64_kb_sections.vec[a_map->_64_kb_sections.size-1]; section++) {
                    if (*section != nullptr) {
                        if (!UnmapViewOfFile(*section)) {
                            libmmap__________________save_error();
                            print_last_error("failed to unmap a section in a section array for a mapping array, continuing", libmmap__________________last_error);
                        }
                        *section = nullptr;
                    }
                }
                free(a_map->_64_kb_sections.vec);
                free(a_map);
#endif
                // unlock our dll array
                LeaveCriticalSection(libmmap_mapping_information__lock);
                FREE_FILE_MAPPING(mapping);

                libmmap__________________restore_error();
                break;
            }
            mapping_offset += granularity;
        }
        if (a_map == INVALID_HANDLE_VALUE) continue;

        // we have mapped all our sections, it is safe to allocate now

        size_t section_index = 0;
        for (uint8_t* begin = (uint8_t*)a_map->begin_address; begin != a_map->end_address; begin += granularity) {
            const DWORD dwMaxSizeHigh = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)0 : (DWORD)((mapping_offset >> 32) & 0xFFFFFFFFL);
            const DWORD dwMaxSizeLow = (sizeof(off_t) <= sizeof(DWORD)) ? (DWORD)mapping_offset : (DWORD)(mapping_offset & 0xFFFFFFFFL);

            LIBMMAP_DEBUG_PRINTF("created %s section at address %p at offset %ld\n", PROT_TO_FILE_MAP_STR(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE), begin, mapping_offset);
            for (intptr_t ri = (intptr_t)begin; ri < (intptr_t)begin + granularity; ri += granularity) {
                LIBMMAP_DEBUG_PRINTF("assigning section 0x%p to index %zu\n", (void*)ri, section_index);
#if __cplusplus
                a_map->_64_kb_sections[section_index] = (void*)ri;
#else
                v_libmmap_ptr_vector_atref(&a_map->_64_kb_sections, section_index)[0] = (void*)ri;
#endif
                section_index++;
            }
            mapping_offset += granularity;
        }


        // at this point, all our sections have been commited

        if ((flags & MAP_NORESERVE) == MAP_NORESERVE) {
            for (uint8_t* begin = (uint8_t*)a_map->begin_address; begin != a_map->end_address; begin += granularity) {
                if (!VirtualLock(begin, granularity)) {
                    libmmap__________________save_error();

                    print_last_error("failed to lock sections (in a section array for a mapping array)", libmmap__________________last_error);
                    // lock our dll array
                    EnterCriticalSection(libmmap_mapping_information__lock);
#if __cplusplus
                    for (void* section : a_map->_64_kb_sections) {
                        if (section != nullptr) {
                            if (!UnmapViewOfFile(section)) {
                                libmmap__________________save_error();
                                print_last_error("failed to unmap a section in a section array for a mapping array, continuing", libmmap__________________last_error);
                            }
                        }
                    }
                    auto it = std::find(libmmap_mapping_information.cbegin(), libmmap_mapping_information.cend(), a_map);
                    libmmap_mapping_information.erase(it);
                    delete a_map;
#else
                    v_libmmap_info_vector_erase(&libmmap_mapping_information, &a_map);
                    for (void** b = a_map->_64_kb_sections.vec; b <= &a_map->_64_kb_sections.vec[a_map->_64_kb_sections.size-1]; b++) {
                        if (*b != nullptr) {
                            if (!UnmapViewOfFile(*b)) {
                                libmmap__________________save_error();
                                print_last_error("failed to unmap a section in a section array for a mapping array, continuing", libmmap__________________last_error);
                            }
                            *b = nullptr;
                        }
                    }
                    free(a_map->_64_kb_sections.vec);
                    free(a_map);
#endif
                    // unlock our dll array
                    LeaveCriticalSection(libmmap_mapping_information__lock);
                    FREE_FILE_MAPPING(mapping);

                    libmmap__________________restore_error();
                    libmmap____ret(-ENOMEM, MAP_FAILED);
                }
            }
        }
        if ((flags & MAP_POPULATE) == MAP_POPULATE) {
            // we MUST do this page-by-page, not section-by-section
            // prevent the compiler from optimizing this out
            if ((prot & PROT_READ) == PROT_READ) {
                // readable
                for (volatile uint8_t* begin = (volatile uint8_t*)a_map->begin_address; begin != (volatile uint8_t*)a_map->end_address; begin += page_size) {
                    volatile uint8_t c = begin[0]; // trigger a page-fault
                }
            }
            else if ((prot & PROT_WRITE) == PROT_WRITE) {
                // writable but not readable
                for (volatile uint8_t* begin = (volatile uint8_t*)a_map->begin_address; begin != (volatile uint8_t*)a_map->end_address; begin += page_size) {
                    begin[0] = begin[0]; // trigger a page-fault
                }
            }
        }
        return a_map->begin_address;
    }
}

int munmap(void* addr, size_t length) {
    // length specifies that we must be able to split a file mapping into subsections (delete from start)
    // for now we just unmap the entire length regardless
    //
    // munmap is also capable of splitting an existing mapping into two smaller mappings (separated by a gap)
    //
#if LIBMMAP_IS_DEBUG
    if (addr == nullptr) {
        LIBMMAP_DEBUG_PRINTF("munmap: the passed address cannot be nullptr (NULL or 0x0)\n");
        libmmap____ret(-EINVAL, -1);
    }
    else if (length == 0) {
        LIBMMAP_DEBUG_PRINTF("munmap: the passed length cannot be zero\n");
        libmmap____ret(-EINVAL, -1);
    }
    else if (addr == MAP_FAILED) {
        LIBMMAP_DEBUG_PRINTF("munmap: the passed address cannot be MAP_FAILED\n");
        libmmap____ret(-EINVAL, -1);
    }
#else
    if (addr == nullptr || length == 0 || addr == MAP_FAILED) {
        libmmap____ret(-EINVAL, -1);
    }
#endif

    libmmap__________________init_error();
    
    uint8_t* begin_address = (uint8_t*) rounddown((intptr_t)addr, granularity);
    uint8_t* end_address = (uint8_t*) roundup((intptr_t)addr + length, granularity);
    LIBMMAP_DEBUG_PRINTF("rounded address 0x%p to begin address 0x%p\n", addr, begin_address);
    LIBMMAP_DEBUG_PRINTF("rounded address 0x%p to end address 0x%p\n", addr, end_address);

    // lock our dll array
    EnterCriticalSection(libmmap_mapping_information__lock);

#define LIBMMAP__TEST_OVERLAP2(space, x1, x2, y1, y2) \
    LIBMMAP_DEBUG_PRINTF("%stesting if [%p,%p] overlaps [%p,%p] = %s\n", space, x1, x2, y1, y2, (x1 < y2 && y1 < x2) ? "true" : "false"); \
    if (x1 < y2 && y1 < x2)

    LIBMMAP_DEBUG_PRINTF("starting unmap process\n");
#if __cplusplus
    LIBMMAP_DEBUG_PRINTF("  iterating %zu mappings\n", libmmap_mapping_information.size());
#else
    LIBMMAP_DEBUG_PRINTF("  iterating %zu mappings\n", libmmap_mapping_information.size);
#endif
#if __cplusplus
    if (libmmap_mapping_information.size() != 0) {
#else
    if (libmmap_mapping_information.size != 0) {
#endif
        bool map_done = false;
#if __cplusplus
        for (size_t idx = libmmap_mapping_information.size() - 1; idx != -1; idx--) {
            struct LIBMMAP__MAP_INFO** map = &libmmap_mapping_information[idx];
#else
        for (size_t idx = libmmap_mapping_information.size - 1; idx != -1; idx--) {
            struct LIBMMAP__MAP_INFO** map = &libmmap_mapping_information.vec[idx];
#endif
            LIBMMAP_DEBUG_PRINTF("  considering map information 0x%p\n", *map);
            if (*map != nullptr) {
                LIBMMAP_DEBUG_PRINTF("    considering the following:\n");
                LIBMMAP_DEBUG_PRINTF("        begin address:        0x%p\n", (**map).begin_address);
                LIBMMAP_DEBUG_PRINTF("        wanted begin address: 0x%p\n", begin_address);
                LIBMMAP_DEBUG_PRINTF("        end address:          0x%p\n", (**map).end_address);
                LIBMMAP_DEBUG_PRINTF("        wanted end address:   0x%p\n", end_address);
                LIBMMAP__TEST_OVERLAP2("        - ", (**map).begin_address, (**map).end_address, begin_address, end_address) {
                    // found address range
                    // locate section that address belongs to
#if __cplusplus
                    LIBMMAP_DEBUG_PRINTF("        iterating %zu sections\n", (**map)._64_kb_sections.size());
#else
                    LIBMMAP_DEBUG_PRINTF("        iterating %zu sections\n", (**map)._64_kb_sections.size);
#endif
#if __cplusplus
                    if ((**map)._64_kb_sections.size() != 0) {
#else
                    if ((**map)._64_kb_sections.size != 0) {
#endif
                        bool section_done = false;
#if __cplusplus
                        for (size_t idx = (**map)._64_kb_sections.size() - 1; idx != -1; idx--) {
                            void** section = &(**map)._64_kb_sections[idx];
#else
                        for (size_t idx = (**map)._64_kb_sections.size - 1; idx != -1; idx--) {
                            struct LIBMMAP__MAP_INFO** map = &(**map)._64_kb_sections.vec[idx];
#endif
                            LIBMMAP_DEBUG_PRINTF("            considering section 0x%p\n", *section);
                            if (*section != nullptr) {
                                uint8_t* begin_section = (uint8_t*)*section;
                                uint8_t* end_section = (uint8_t*)begin_section + granularity;
                                LIBMMAP_DEBUG_PRINTF("                considering the following:\n");
                                LIBMMAP_DEBUG_PRINTF("                    begin address:        0x%p\n", begin_section);
                                LIBMMAP_DEBUG_PRINTF("                    wanted begin address: 0x%p\n", begin_address);
                                LIBMMAP_DEBUG_PRINTF("                    end address:          0x%p\n", end_section);
                                LIBMMAP_DEBUG_PRINTF("                    wanted end address:   0x%p\n", end_address);
                                LIBMMAP__TEST_OVERLAP2("                    - ", begin_section, end_section, begin_address, end_address) {
                                    LIBMMAP_DEBUG_PRINTF("                        unmapping section 0x%p\n", *section);
                                    // found section that address belongs to
                                    if (!UnmapViewOfFile(*section)) {
                                        // unlock our dll array
                                        LeaveCriticalSection(libmmap_mapping_information__lock);
                                        libmmap__________________save_error();
                                        print_last_error("failed to unmap a section", libmmap__________________last_error);
                                        libmmap__________________restore_error();
                                        libmmap____ret(-EINVAL, -1);
                                    }
                                    LIBMMAP_DEBUG_PRINTF("                        removing section 0x%p\n", *section);
#if __cplusplus
                                    auto it = std::find((**map)._64_kb_sections.cbegin(), (**map)._64_kb_sections.cend(), *section);
                                    // *section = nullptr;
                                    (**map)._64_kb_sections.erase(it);
#else
                                    v_libmmap_ptr_vector_erase(&(**map)._64_kb_sections, section);
#endif
                                    if (begin_section == begin_address) {
                                        LIBMMAP_DEBUG_PRINTF("                        begin address reached\n");
                                        section_done = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if (section_done) {
                            map_done = true;
                        }
                    }
                }
#if __cplusplus
                if ((**map)._64_kb_sections.size() == 0) {
#else
                if ((**map)._64_kb_sections.size == 0) {
#endif
                    LIBMMAP_DEBUG_PRINTF("    removing map 0x%p\n", *map);
#if __cplusplus
                    auto it = std::find(libmmap_mapping_information.cbegin(), libmmap_mapping_information.cend(), *map);
                    // *map = nullptr;
                    libmmap_mapping_information.erase(it);
#else
                    v_libmmap_ptr_vector_erase(&libmmap_mapping_information, map);
#endif
                }
                if (map_done) {
                    break;
                }
            }
        }
        if (map_done) {
            // munmap complete
            // unlock our dll array
            LeaveCriticalSection(libmmap_mapping_information__lock);
            return 0;
        }
    }
#undef TEST_OVERLAP2
    // unlock our dll array
    LeaveCriticalSection(libmmap_mapping_information__lock);
    
    // partially unmapped, the requested length was not fully unmapped
    // it is not an error if the address cannot be found
    return 0;
}
