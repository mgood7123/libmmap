#include <sys/mman.h>
#include <iostream>
#include <io.h>

#if LIBMMAP_IS_DEBUG_OR_UNOPTIMIZED_RELEASE
#include <libassert/assert.hpp>
#else
#define LIBASSERT_ASSUME_VAL(expr, ...)
#define LIBASSERT_ASSERT_VAL(expr, ...)
#endif

#include <setjmp.h>

jmp_buf restore;

auto PageGuardMemory(void* address, const SIZE_T length) -> void
{
    DWORD oldProtect;
    MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery(static_cast<const void*>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    VirtualProtect(address, length, mbi.Protect | PAGE_GUARD, &oldProtect);
    printf("installed PAGE_GUARD to address %p\n", address);
}

auto UnPageGuardMemory(void* address, const SIZE_T length) -> void
{
    DWORD oldProtect;
    MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery(static_cast<const void*>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    VirtualProtect(address, length, mbi.Protect & ~PAGE_GUARD, &oldProtect);
    printf("uninstalled PAGE_GUARD from address %p\n", address);
}

char* reason = "";

LONG CALLBACK VectoredExceptionHandler(_EXCEPTION_POINTERS* ep)
{
    LIBMMAP_DEBUG_PRINTF("VEH called\n");
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        if (reason == "UNEXPECTED ") printf("%sACCESS VIOLATION at address %p\n", reason, ep->ExceptionRecord->ExceptionAddress);
        longjmp(restore, 1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#define PAGE_SHOULD_BE_MAPPED(addr, offset) \
    LIBMMAP_DEBUG_PRINTF("testing if the address 0x%p is MAPPED\n", (((uint8_t*)(addr))+(offset))); \
    if (!setjmp(restore)) { \
        reason = "UNEXPECTED "; \
        *(((uint8_t*)(addr))+(offset)) = 0; \
        page_is_unmapped = false; \
        printf("the address 0x%p is MAPPED\n", (((uint8_t*)(addr))+(offset))); \
    } \
    else { \
        page_is_unmapped = true; \
        printf("the address 0x%p is UNMAPPED\n", (((uint8_t*)(addr))+(offset))); \
    } \
    LIBASSERT_ASSERT_VAL(page_is_unmapped == false);

#define PAGE_SHOULD_BE_UNMAPPED(addr, offset) \
    LIBMMAP_DEBUG_PRINTF("testing if address 0x%p is UNMAPPED\n", (((uint8_t*)(addr))+(offset))); \
    if (!setjmp(restore)) { \
        reason = "EXPECTED "; \
        *(((uint8_t*)(addr))+(offset)) = 0; \
        page_is_unmapped = false; \
        printf("the address 0x%p is MAPPED\n", (((uint8_t*)(addr))+(offset))); \
    } \
    else { \
        page_is_unmapped = true; \
        printf("the address 0x%p is UNMAPPED\n", (((uint8_t*)(addr))+(offset))); \
    } \
    LIBASSERT_ASSERT_VAL(page_is_unmapped == true);

#define PAGE_SHOULD_BE_MAPPED_r(addr, offset) \
    LIBMMAP_DEBUG_PRINTF("testing if the address 0x%p is MAPPED\n", (((uint8_t*)(addr))+(offset))); \
    if (!setjmp(restore)) { \
        reason = "UNEXPECTED "; \
        volatile uint8_t value = *(((uint8_t*)(addr))+(offset)); \
        page_is_unmapped = false; \
        printf("the address 0x%p is MAPPED\n", (((uint8_t*)(addr))+(offset))); \
    } \
    else { \
        page_is_unmapped = true; \
        printf("the address 0x%p is UNMAPPED\n", (((uint8_t*)(addr))+(offset))); \
    } \
    LIBASSERT_ASSERT_VAL(page_is_unmapped == false);

#define PAGE_SHOULD_BE_UNMAPPED_r(addr, offset) \
    LIBMMAP_DEBUG_PRINTF("testing if address 0x%p is UNMAPPED\n", (((uint8_t*)(addr))+(offset))); \
    if (!setjmp(restore)) { \
        reason = "EXPECTED "; \
        volatile uint8_t value = *(((uint8_t*)(addr))+(offset)); \
        page_is_unmapped = false; \
        printf("the address 0x%p is MAPPED\n", (((uint8_t*)(addr))+(offset))); \
    } \
    else { \
        page_is_unmapped = true; \
        printf("the address 0x%p is UNMAPPED\n", (((uint8_t*)(addr))+(offset))); \
    } \
    LIBASSERT_ASSERT_VAL(page_is_unmapped == true);

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

int main()
{
    std::cout << "Hello CMake." << std::endl;

    SYSTEM_INFO sys;
    GetSystemInfo(&sys);
    DWORD page_size = sys.dwAllocationGranularity;

    void* addr = nullptr;
    int r;

    bool page_is_unmapped;

    AddVectoredExceptionHandler(1ul, VectoredExceptionHandler);
    printf("VEH added\n");

    printf("tests in progress...\n");

    int test_number = 1;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = munmap(addr, page_size);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    r = munmap(addr, page_size);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED(addr, 0);
    PAGE_SHOULD_BE_MAPPED(addr, page_size);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = munmap(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED(addr, 0);
    PAGE_SHOULD_BE_MAPPED(addr, page_size);
    PAGE_SHOULD_BE_MAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_MAPPED(addr, page_size);
    PAGE_SHOULD_BE_MAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED(addr, 0);
    PAGE_SHOULD_BE_MAPPED(addr, page_size);
    PAGE_SHOULD_BE_MAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(((uint8_t*)addr) + page_size, page_size);

    PAGE_SHOULD_BE_MAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_MAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED(addr, 0);
    PAGE_SHOULD_BE_MAPPED(addr, page_size);
    PAGE_SHOULD_BE_MAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(((uint8_t*)addr) + page_size + page_size, page_size);

    PAGE_SHOULD_BE_MAPPED(addr, 0);
    PAGE_SHOULD_BE_MAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED(addr, 0);
    PAGE_SHOULD_BE_MAPPED(addr, page_size);
    PAGE_SHOULD_BE_MAPPED(addr, page_size * 2);


    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr))+(0)) == 0);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr))+(page_size)) == 0);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr))+(page_size*2)) == 0);

    *(((uint8_t*)(addr))+(0)) = 1;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 0);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 0);

    *(((uint8_t*)(addr)) + (page_size)) = 2;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 0);

    *(((uint8_t*)(addr)) + (page_size * 2)) = 3;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 3);

    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    FILE * file = fopen("test", "w+");
    uint8_t buffer[page_size*3];
    memset(buffer, 5, page_size * 3);
    fwrite(buffer, sizeof(uint8_t), page_size*3, file);
    fflush(file);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_SHARED, _fileno(file), 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (0)) = 1;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (page_size)) = 2;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (page_size * 2)) = 3;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 3);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    fclose(file);
    file = nullptr;

    printf("TEST %d\n", test_number);
    file = fopen("test", "r");

    addr = mmap(nullptr, page_size * 3, PROT_READ, MAP_SHARED, _fileno(file), 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 3);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    fclose(file);
    file = nullptr;
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    file = fopen("test2", "w+");
    fwrite(buffer, sizeof(uint8_t), page_size * 3, file);
    fflush(file);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_SHARED, _fileno(file), 0);
    // file should be closable without affecting map
    fclose(file);
    file = nullptr;
    PAGE_SHOULD_BE_MAPPED_r(addr, 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (0)) = 81;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 81);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (page_size)) = 82;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 81);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 82);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (page_size * 2)) = 83;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 81);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 82);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 83);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    file = fopen("test2", "r");

    addr = mmap(nullptr, page_size * 3, PROT_READ, MAP_SHARED, _fileno(file), 0);
    // file should be closable without affecting map
    fclose(file);
    file = nullptr;
    PAGE_SHOULD_BE_MAPPED_r(addr, 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 81);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 82);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 83);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    // test private

    printf("TEST %d\n", test_number);
    file = fopen("test3", "w+");
    fwrite(buffer, sizeof(uint8_t), page_size * 3, file);
    fflush(file);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE, _fileno(file), 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (0)) = 1;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (page_size)) = 2;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (page_size * 2)) = 3;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 1);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 3);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    fclose(file);
    file = nullptr;

    printf("TEST %d\n", test_number);
    file = fopen("test3", "r");

    addr = mmap(nullptr, page_size * 3, PROT_READ, MAP_PRIVATE, _fileno(file), 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    fclose(file);
    file = nullptr;
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    file = fopen("test4", "w+");
    fwrite(buffer, sizeof(uint8_t), page_size * 3, file);
    fflush(file);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE, _fileno(file), 0);
    // file should be closable without affecting map
    fclose(file);
    file = nullptr;
    PAGE_SHOULD_BE_MAPPED_r(addr, 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (0)) = 81;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 81);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (page_size)) = 82;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 81);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 82);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);

    *(((uint8_t*)(addr)) + (page_size * 2)) = 83;

    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 81);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 82);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 83);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    file = fopen("test4", "r");

    addr = mmap(nullptr, page_size * 3, PROT_READ, MAP_PRIVATE, _fileno(file), 0);
    // file should be closable without affecting map
    fclose(file);
    file = nullptr;
    PAGE_SHOULD_BE_MAPPED_r(addr, 0);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_r(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (0) + 1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size)+1) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2)) == 5);
    LIBASSERT_ASSERT_VAL(*(((uint8_t*)(addr)) + (page_size * 2) + 1) == 5);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    {
#define granularity page_size
#define add(length) mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#define remove(addr, length) munmap(addr, length)
        void* addr;
        addr = add(granularity);
        remove(addr, granularity);
        void* addr1 = add(granularity);
        addr = add(granularity * 4);
        remove(addr, granularity);
        remove(addr1, granularity);
        remove(((uint8_t*)addr) + granularity, granularity * 3);
    }
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("tests complete\n");

    return 0;
}
