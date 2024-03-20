// https://www.unknowncheats.me/forum/general-programming-and-reversing/281302-using-veh-page_guard-memory-catch.html

#include <iostream>
#include <Windows.h>

//some section of memory which has something we want to check R/W on
int SOME_DATA[999999];

void* breakpointAddress;

auto PageGuardMemory(void* address, const SIZE_T length) -> void
{
    DWORD oldProtect;
    MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery(static_cast<const void*>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    VirtualProtect(address, length, mbi.Protect | PAGE_GUARD, &oldProtect);
}

auto UnPageGuardMemory(void* address, const SIZE_T length) -> void
{
    DWORD oldProtect;
    MEMORY_BASIC_INFORMATION mbi;

    VirtualQuery(static_cast<const void*>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    VirtualProtect(address, length, mbi.Protect & ~PAGE_GUARD, &oldProtect);
}

auto CALLBACK VectoredExceptionHandler(_EXCEPTION_POINTERS* ep) -> LONG
{
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
    {
        if (ep->ExceptionRecord->ExceptionInformation[1] == reinterpret_cast<ULONG_PTR>(breakpointAddress))
        {
            std::cout << "Memory access at address " << std::hex << ep->ExceptionRecord->ExceptionAddress <<
                ", address accessed: " << ep->ExceptionRecord->ExceptionInformation[1] << std::dec << std::endl;
        }

        ep->ContextRecord->EFlags |= 0x100ui32;

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        //try not to cross page boundaries and slam two with PAGE_GUARD!!
        PageGuardMemory(breakpointAddress, 1);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

auto initializeBreakpoint(void* address) -> void
{
    //create our "breakpoint" by doing an initial PAGE_GUARD on target memory
    breakpointAddress = address;
    PageGuardMemory(breakpointAddress, 1ui64);
}

auto disableBreakpoint(void* address) -> void
{
    breakpointAddress = nullptr;
    UnPageGuardMemory(address, 1ui64);
}

int main()
{
    AddVectoredExceptionHandler(1ul, VectoredExceptionHandler);
    initializeBreakpoint(&SOME_DATA[123456]);

    std::cout << SOME_DATA[123456] << std::endl;
    SOME_DATA[123456] = 55;
    std::cout << SOME_DATA[123456] << std::endl;

    disableBreakpoint(&SOME_DATA[123456]);
    std::cout << "Breakpoint disabled" << std::endl;

    std::cout << SOME_DATA[123456] << std::endl;
    SOME_DATA[123456] = 0;
    std::cout << SOME_DATA[123456] << std::endl;

    getchar();
}