#ifndef LIBMMAP__PRIVATE_COMMON__H
#define LIBMMAP__PRIVATE_COMMON__H

#include <wtypes.h>
#include <vector>

#include <sys/libmmap_compile_info.h>
#include <sys/libmmap_public__common.h>
#include <sys/mmap_defines.h>

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


struct ReservedVirtualMemory {
    void* result = nullptr;
    void* addr = nullptr;
    SIZE_T length = 0;
    inline bool create(void* addr, SIZE_T length) {
        this->addr = addr;
        this->length = length;
        result = VirtualAlloc(addr, length, MEM_RESERVE, PAGE_NOACCESS);
        return result;
    }
    inline bool destroy() {
        if (result) {
            bool r = VirtualFree(result, 0, MEM_RELEASE);
            result = nullptr;
            return r;
        }
        return true;
    }
};

struct LIBMMAP_SECTION_INFO {
    HANDLE mapping = INVALID_HANDLE_VALUE;
    void* address = nullptr;
    int prot = 0;
    int flags = 0;
    DWORD dwFileOffsetHigh = 0;
    DWORD dwFileOffsetLow = 0;
    SIZE_T length;
    bool prepared = false;
    ReservedVirtualMemory mem;
    libmmap__________________init_error();

    inline bool operator ==(const LIBMMAP_SECTION_INFO & other) const {
        return other.address == address;
    }

    inline bool operator !=(const LIBMMAP_SECTION_INFO& other) const {
        return other.address != address;
    }

    inline void prepare (
        HANDLE mapping,
        void* address,
        int flags,
        DWORD dwFileOffsetHigh,
        DWORD dwFileOffsetLow,
        SIZE_T length
    ) {
        this->mapping = mapping;
        this->address = address;
        this->flags = flags;
        this->dwFileOffsetHigh = dwFileOffsetHigh;
        this->dwFileOffsetLow = dwFileOffsetLow;
        this->length = length;
        this->prepared = true;
        LIBMMAP_DEBUG_PRINTF("attempting to create a %s file section mapping\n", PROT_TO_FILE_MAP_STR(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE));
    }

    inline bool remap(int prot) {
        if (prepared) {
            // fast path, we previously we called prepare and should assume we are currently unmapped
            if (prot == PROT_NONE) {
                bool r = mem.create(address, length);
                // we either succeeded or failed
                if (r) {
                    // if we succeeded, update current prot
                    this->prepared = false;
                    this->prot = prot;
                }
                return r;
            }
            else {
                void * result = MapViewOfFileEx(
                    mapping
                    , PROT_TO_FILE_MAP(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE)
                    , dwFileOffsetHigh // DWORD, offset high, offset low + high when combined MUST be a multiple of granularity
                    , dwFileOffsetLow // DWORD, offset low, offset low + high when combined MUST be a multiple of granularity
                    , length // SIZE_T, length, can be anything
                    , address // MUST be a multiple of granularity
                );
                // we either succeeded or failed
                libmmap__________________save_error();
                bool e = !result || ERROR_INVALID_ADDRESS == libmmap__________________last_error || result != address;
                libmmap__________________restore_error();
                if (!e) {
                    // if we succeeded, update current prot
                    this->prepared = false;
                    this->prot = prot;
                }
                return !e;
            }
        }
        // slow path, we did not call prepare so we might be mapped
        this->prepared = false;
        if (this->prot == prot) {
            // prot unchanged
            return true;
        }
        void* result = nullptr;
        bool r = false;
        bool e = false;
        if (this->prot == PROT_NONE) {
            // current prot is none, we might have prepared it as none
            if (mem.result) {
                // our memory is reserved, and we are specifying a new prot, destroy and map quickly
                if (mem.destroy()) {
                    result = MapViewOfFileEx(
                        mapping
                        , PROT_TO_FILE_MAP(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE)
                        , dwFileOffsetHigh // DWORD, offset high, offset low + high when combined MUST be a multiple of granularity
                        , dwFileOffsetLow // DWORD, offset low, offset low + high when combined MUST be a multiple of granularity
                        , length // SIZE_T, length, can be anything
                        , address // MUST be a multiple of granularity
                    );
                    // we either succeeded or failed
                    libmmap__________________save_error();
                    bool e = !result || ERROR_INVALID_ADDRESS == libmmap__________________last_error || result != address;
                    libmmap__________________restore_error();
                    if (!e) {
                        // if we succeeded, update current prot
                        this->prot = prot;
                    }
                    return !e;
                }
                else {
                    // we failed to destroy our reserved memory so leave prot as PROT_NONE
                    return false;
                }
            }
            else {
                // our memory was prepared but not applied, and we are specifying a new prot
                // since our current prot is PROT_NONE but it is currently not applied, we do not need to unmap
                result = MapViewOfFileEx(
                    mapping
                    , PROT_TO_FILE_MAP(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE)
                    , dwFileOffsetHigh // DWORD, offset high, offset low + high when combined MUST be a multiple of granularity
                    , dwFileOffsetLow // DWORD, offset low, offset low + high when combined MUST be a multiple of granularity
                    , length // SIZE_T, length, can be anything
                    , address // MUST be a multiple of granularity
                );
                // we either succeeded or failed
                libmmap__________________save_error();
                bool e = !result || ERROR_INVALID_ADDRESS == libmmap__________________last_error || result != address;
                libmmap__________________restore_error();
                if (!e) {
                    // if we succeeded, update current prot
                    this->prot = prot;
                }
                return !e;
            }
        }
        else {
            // we are not prot none
            if (address) {
                // and we have an existing mapping
                if (prot == PROT_NONE) {
                    // and we want to unmap it but keep its space as reserved
                    if (UnmapViewOfFile(address)) {
                        // we unmapped the file, now quickly reserve its place
                        r = mem.create(address, length);
                        // we either succeeded or failed
                        if (r) {
                            // if we succeeded, update current prot
                            this->prot = prot;
                        }
                        return r;
                    }
                    else {
                        // we failed to unmap our file so leave prot unchanged
                        return false;
                    }
                }
                else {
                    // and we want to keep it mapped
                    if (UnmapViewOfFile(address)) {
                        // we unmapped the file, now quickly remap it with a different prot
                        result = MapViewOfFileEx(
                            mapping
                            , PROT_TO_FILE_MAP(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE)
                            , dwFileOffsetHigh // DWORD, offset high, offset low + high when combined MUST be a multiple of granularity
                            , dwFileOffsetLow // DWORD, offset low, offset low + high when combined MUST be a multiple of granularity
                            , length // SIZE_T, length, can be anything
                            , address // MUST be a multiple of granularity
                        );
                        // we either succeeded or failed
                        libmmap__________________save_error();
                        bool e = !result || ERROR_INVALID_ADDRESS == libmmap__________________last_error || result != address;
                        libmmap__________________restore_error();
                        if (!e) {
                            // if we succeeded, update current prot
                            this->prot = prot;
                        }
                        return !e;
                    }
                    else {
                        // we failed to unmap our file so leave prot unchanged
                        return false;
                    }
                }
            }
            else {
                // and we have no existing mapping
                if (prot == PROT_NONE) {
                    // and we want to reserve it
                    r = mem.create(address, length);
                    // we either succeeded or failed
                    if (r) {
                        // if we succeeded, update current prot
                        this->prot = prot;
                    }
                    return r;
                }
                else {
                    // and we want to map it
                    result = MapViewOfFileEx(
                        mapping
                        , PROT_TO_FILE_MAP(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE)
                        , dwFileOffsetHigh // DWORD, offset high, offset low + high when combined MUST be a multiple of granularity
                        , dwFileOffsetLow // DWORD, offset low, offset low + high when combined MUST be a multiple of granularity
                        , length // SIZE_T, length, can be anything
                        , address // MUST be a multiple of granularity
                    );
                    // we either succeeded or failed
                    libmmap__________________save_error();
                    bool e = !result || ERROR_INVALID_ADDRESS == libmmap__________________last_error || result != address;
                    libmmap__________________restore_error();
                    if (!e) {
                        // if we succeeded, update current prot
                        this->prot = prot;
                    }
                    return !e;
                }
            }
        }
    }

    inline bool unmap() {
        if (prepared) {
            // fast path, we previously we called prepare so we have nothing to do
            return true;
        }
        // slow path, we did not call prepare so we might be mapped
        void* result = nullptr;
        bool r = false;
        bool e = false;
        if (this->prot == PROT_NONE) {
            // current prot is none, we might have prepared it as none
            if (mem.result) {
                // our memory is reserved, and we are unmapping it
                return mem.destroy();
            }
            else {
                // and our memory was not applied yet
                return true;
            }
        }
        else {
            // we are not prot none
            if (address) {
                // and we have an existing mapping and we want to unmap
                return UnmapViewOfFile(address);
            }
            else {
                // and we have no existing mapping
                return true;
            }
        }
    }
};

struct FileMapping {
    std::vector<LIBMMAP_SECTION_INFO> _64_kb_sections;
    HANDLE result = INVALID_HANDLE_VALUE;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES fileMappingAttributes;
    int prot = PROT_NONE;
    int flags = 0;
    DWORD dwMaximumSizeHigh = 0;
    DWORD dwMaximumSizeLow = 0;

    inline bool create(
        HANDLE hFile, SECURITY_ATTRIBUTES fileMappingAttributes,
        int prot, int flags,
        DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow
    ) {
        this->hFile = hFile;
        this->fileMappingAttributes = fileMappingAttributes;
        this->prot = prot;
        this->flags = flags;
        this->dwMaximumSizeHigh = dwMaximumSizeHigh;
        this->dwMaximumSizeLow = dwMaximumSizeLow;
        LIBMMAP_DEBUG_PRINTF("attempting to create a %s file mapping\n", PROT_TO_PAGE_STR(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE));
        result = CreateFileMappingW(hFile, &fileMappingAttributes, PROT_TO_PAGE(prot, (flags & MAP_PRIVATE) == MAP_PRIVATE), dwMaximumSizeHigh, dwMaximumSizeLow, NULL);
        return result;
    }

    inline bool destroy() {
        if (result != INVALID_HANDLE_VALUE) {
            bool r = CloseHandle(result);
            result = INVALID_HANDLE_VALUE;
            return r;
        }
        return true;
    }

    inline bool prepare(
        HANDLE mapping,
        void* address,
        int flags,
        DWORD dwFileOffsetHigh,
        DWORD dwFileOffsetLow,
        SIZE_T length
    ) {
        LIBMMAP_SECTION_INFO section;
        section.prepare(mapping, address, flags, dwFileOffsetHigh, dwFileOffsetLow, length);
        try {
            _64_kb_sections.emplace_back(section);
        }
        catch (std::bad_alloc) {
            return false;
        }
        return true;
    }

    inline LIBMMAP_SECTION_INFO * find(void* address) {
        for (LIBMMAP_SECTION_INFO& s : _64_kb_sections) {
            if (s.address == address) {
                return &s;
            }
        }
        return nullptr;
    }
};

struct LIBMMAP__MAP_INFO {
    FileMapping mapping;
    void* begin_address;
    void* end_address;

    inline bool operator ==(const LIBMMAP__MAP_INFO& other) const {
        return other.begin_address == begin_address;
    }

    inline bool operator !=(const LIBMMAP__MAP_INFO& other) const {
        return other.begin_address == begin_address;
    }
};

static std::vector<LIBMMAP__MAP_INFO> libmmap_mapping_information;

#endif // LIBMMAP__PRIVATE_COMMON__H
