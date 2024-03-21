# libmmap


implemented functions:

```c
void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void* addr, size_t length);
int mprotect(void* addr, size_t length, int prot);
int getpagesize(void);

// accepts _SC_PAGE_SIZE, _SC_PAGE_SIZE, PAGE_SIZE, and PAGESIZE
// rejects all others
long sysconf(int name);
```

the page size is limited to 64 kb

on windows, a memory mapping must be aligned to a 4 kb boundary
on windows, a file mapping must be aligned to a 64 kb boundary

