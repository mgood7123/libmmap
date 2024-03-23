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

const char* reason = "";
const char* reason_EXPECTED = "EXPECTED ";
const char* reason_UNEXPECTED = "UNEXPECTED ";

LONG CALLBACK VectoredExceptionHandler(_EXCEPTION_POINTERS* ep)
{
    LIBMMAP_DEBUG_PRINTF("VEH called\n");
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        if (reason == reason_UNEXPECTED) printf("%sACCESS VIOLATION at address %p\n", reason, ep->ExceptionRecord->ExceptionAddress);
        longjmp(restore, 1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#define PAGE_SHOULD_BE__W(addr, offset, str1, str2, str3, page_is_unmapped__expected_value, expect_segv) \
    LIBMMAP_DEBUG_PRINTF("testing if the address 0x%p is %s\n", (((uint8_t*)(addr))+(offset)), str1); \
    if (!setjmp(restore)) { \
        reason = expect_segv ? reason_EXPECTED : reason_UNEXPECTED; \
        *(((uint8_t*)(addr))+(offset)) = 0; \
        page_is_unmapped = false; \
        printf("the address 0x%p is %s\n", (((uint8_t*)(addr))+(offset)), str2); \
    } \
    else { \
        page_is_unmapped = true; \
        printf("the address 0x%p is %s\n", (((uint8_t*)(addr))+(offset)), str3); \
    } \
    LIBASSERT_ASSERT_VAL(page_is_unmapped == page_is_unmapped__expected_value);

#define PAGE_SHOULD_BE__R(addr, offset, str1, str2, str3, page_is_unmapped__expected_value, expect_segv) \
    LIBMMAP_DEBUG_PRINTF("testing if the address 0x%p is %s\n", (((uint8_t*)(addr))+(offset)), str1); \
    if (!setjmp(restore)) { \
        reason = expect_segv ? reason_EXPECTED : reason_UNEXPECTED; \
        volatile uint8_t value = *(((uint8_t*)(addr))+(offset)); \
        page_is_unmapped = false; \
        printf("the address 0x%p is %s\n", (((uint8_t*)(addr))+(offset)), str2); \
    } \
    else { \
        page_is_unmapped = true; \
        printf("the address 0x%p is %s\n", (((uint8_t*)(addr))+(offset)), str3); \
    } \
    LIBASSERT_ASSERT_VAL(page_is_unmapped == page_is_unmapped__expected_value);

#define PAGE_SHOULD_BE_READABLE(addr, offset) PAGE_SHOULD_BE__R(addr, offset, "READABLE", "READABLE", "NOT READABLE", false, false)
#define PAGE_SHOULD_BE_WRITABLE(addr, offset) PAGE_SHOULD_BE__W(addr, offset, "WRITABLE", "WRITABLE", "WRITABLE", false, false)

#define PAGE_SHOULD_BE_NON_READABLE(addr, offset) PAGE_SHOULD_BE__R(addr, offset, "NOT READABLE", "READABLE", "NOT READABLE", true, true)
#define PAGE_SHOULD_BE_NON_WRITABLE(addr, offset) PAGE_SHOULD_BE__W(addr, offset, "NOT WRITABLE", "READABLE", "NOT WRITABLE", true, true)

#define PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, offset) PAGE_SHOULD_BE__R(addr, offset, "MAPPED", "MAPPED", "NOT MAPPED", false, false)
#define PAGE_SHOULD_BE_MAPPED_AND_WRITABLE(addr, offset) PAGE_SHOULD_BE__W(addr, offset, "MAPPED", "MAPPED", "NOT MAPPED", false, false)

#define PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, offset) PAGE_SHOULD_BE__R(addr, offset, "UNMAPPED", "NOT UNMAPPED", "UNMAPPED", true, true)
#define PAGE_SHOULD_BE_UNMAPPED_AND_WRITABLE(addr, offset) PAGE_SHOULD_BE__W(addr, offset, "UNMAPPED", "NOT UNMAPPED", "UNMAPPED", true, true)

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

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = munmap(addr, page_size);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    r = munmap(addr, page_size);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = munmap(addr, page_size * 2);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(((uint8_t*)addr) + page_size, page_size);

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(((uint8_t*)addr) + page_size + page_size, page_size);

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    munmap(addr, page_size * 3);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);


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

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
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
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
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

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    fclose(file);
    file = nullptr;

    printf("TEST %d\n", test_number);
    file = fopen("test", "r");

    addr = mmap(nullptr, page_size * 3, PROT_READ, MAP_SHARED, _fileno(file), 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
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

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
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
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
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

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    file = fopen("test2", "r");

    addr = mmap(nullptr, page_size * 3, PROT_READ, MAP_SHARED, _fileno(file), 0);
    // file should be closable without affecting map
    fclose(file);
    file = nullptr;
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
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

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
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
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
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

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    fclose(file);
    file = nullptr;

    printf("TEST %d\n", test_number);
    file = fopen("test3", "r");

    addr = mmap(nullptr, page_size * 3, PROT_READ, MAP_PRIVATE, _fileno(file), 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
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

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
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
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
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

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    file = fopen("test4", "r");

    addr = mmap(nullptr, page_size * 3, PROT_READ, MAP_PRIVATE, _fileno(file), 0);
    // file should be closable without affecting map
    fclose(file);
    file = nullptr;
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, page_size * 2);
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

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size);
    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, page_size * 2);
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

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = mprotect(addr, page_size, PROT_READ);
    LIBASSERT_ASSERT_VAL(r == 0);
    PAGE_SHOULD_BE_READABLE(addr, 0);
    PAGE_SHOULD_BE_NON_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = munmap(addr, page_size);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;


    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);

    PAGE_SHOULD_BE_MAPPED_AND_READABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = mprotect(addr, page_size, PROT_WRITE);
    LIBASSERT_ASSERT_VAL(r == 0);
    // a writable page MUST be readable
    PAGE_SHOULD_BE_READABLE(addr, 0);
    PAGE_SHOULD_BE_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = mprotect(addr, page_size, PROT_READ);
    LIBASSERT_ASSERT_VAL(r == 0);
    PAGE_SHOULD_BE_READABLE(addr, 0);
    PAGE_SHOULD_BE_NON_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = mprotect(addr, page_size, PROT_WRITE);
    LIBASSERT_ASSERT_VAL(r == 0);
    // a writable page MUST be readable
    PAGE_SHOULD_BE_READABLE(addr, 0);
    PAGE_SHOULD_BE_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = mprotect(addr, page_size, PROT_NONE);
    LIBASSERT_ASSERT_VAL(r == 0);
    PAGE_SHOULD_BE_NON_READABLE(addr, 0);
    PAGE_SHOULD_BE_NON_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = munmap(addr, page_size);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);
    PAGE_SHOULD_BE_NON_READABLE(addr, 0);
    PAGE_SHOULD_BE_NON_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = munmap(addr, page_size);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    addr = mmap(nullptr, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    LIBASSERT_ASSERT_VAL(addr != MAP_FAILED);
    PAGE_SHOULD_BE_NON_READABLE(addr, 0);
    PAGE_SHOULD_BE_NON_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = mprotect(addr, page_size, PROT_WRITE);
    LIBASSERT_ASSERT_VAL(r == 0);
    // a writable page MUST be readable
    PAGE_SHOULD_BE_READABLE(addr, 0);
    PAGE_SHOULD_BE_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = mprotect(addr, page_size, PROT_READ);
    LIBASSERT_ASSERT_VAL(r == 0);
    PAGE_SHOULD_BE_READABLE(addr, 0);
    PAGE_SHOULD_BE_NON_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = mprotect(addr, page_size, PROT_WRITE);
    LIBASSERT_ASSERT_VAL(r == 0);
    // a writable page MUST be readable
    PAGE_SHOULD_BE_READABLE(addr, 0);
    PAGE_SHOULD_BE_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = mprotect(addr, page_size, PROT_NONE);
    LIBASSERT_ASSERT_VAL(r == 0);
    PAGE_SHOULD_BE_NON_READABLE(addr, 0);
    PAGE_SHOULD_BE_NON_WRITABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("TEST %d\n", test_number);
    r = munmap(addr, page_size);
    LIBASSERT_ASSERT_VAL(r == 0);

    PAGE_SHOULD_BE_UNMAPPED_AND_READABLE(addr, 0);
    printf("TEST %d PASS\n", test_number);
    test_number++;

    printf("tests complete\n");

    return 0;
}
