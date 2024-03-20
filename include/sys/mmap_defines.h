#define __need_size_t
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// mingw
#if !defined(_OFF_T_) && (!defined(_FILE_OFFSET_BITS_SET_OFFT) && !(!defined(NO_OLDNAMES) || defined(POSIX)))
    // CRT
    #ifdef _OFF_T_DEFINED
        #if (defined _CRT_DECLARE_NONSTDC_NAMES && _CRT_DECLARE_NONSTDC_NAMES) || (!defined _CRT_DECLARE_NONSTDC_NAMES && !__STDC__)
        #else
            #ifdef __USE_FILE_OFFSET64
                typedef int64_t off_t;
            #else
                typedef int32_t off_t;
            #endif
        #endif
    #endif
#endif

#if (!defined(_MODE_T_) || defined(NO_OLDNAMES)) && !defined(__mode_t_defined)
typedef uint32_t mode_t;
# define __mode_t_defined
#endif

/* Return value of `mmap' in case of an error.  */
#define MAP_FAILED	((void *) -1)

#define PROT_NONE 1 << 0
#define PROT_READ 1 << 1
#define PROT_WRITE 1 << 2
#define PROT_EXECUTE 1 << 3

//  Share this mapping.  Updates to the mapping are visible to
//  other processes mapping the same region, and (in the case
//  of file-backed mappings) are carried through to the
//  underlying file.
//
#define MAP_SHARED (1 << 0)

// This flag provides the same behavior as MAP_SHARED except
// that MAP_SHARED mappings ignore unknown flags in flags.
// By contrast, when creating a mapping using
// MAP_SHARED_VALIDATE, the kernel verifies all passed flags
// are known and fails the mapping with the error EOPNOTSUPP
// for unknown flags.  This mapping type is also required to
// be able to use some mapping flags(e.g., MAP_SYNC)
//
// MAP_SHARED_VALIDATE is a Linux extension.
//
#define MAP_SHARED_VALIDATE (1 << 1)

// Create a private copy-on-write mapping.  Updates to the
// mapping are not visible to other processes mapping the
// same file, and are not carried through to the underlying
// file.  It is unspecified whether changes made to the file
// after the mmap() call are visible in the mapped region.
//
#define MAP_PRIVATE (1 << 2)

// In addition, zero or more of the following values can be ORed in
// flags

// Put the mapping into the first 2 Gigabytes of the process
// address space.  This flag is supported only on x86-64, for
// 64-bit programs.  It was added to allow thread stacks to
// be allocated somewhere in the first 2 GB of memory, so as
// to improve context-switch performance on some early 64-bit
// processors.  Modern x86-64 processors no longer have this
// performance problem, so use of this flag is not required
// on those systems.  The MAP_32BIT flag is ignored when
// MAP_FIXED is set
//
#define MAP_32BIT (1 << 3)

// The mapping is not backed by any file; its contents are
// initialized to zero.  The fd argument is ignored; however,
// some implementations require fd to be -1 if MAP_ANONYMOUS
// (or MAP_ANON) is specified, and portable applications
// should ensure this.  The offset argument should be zero.
// Support for MAP_ANONYMOUS in conjunction with MAP_SHARED
// was added in Linux 2.4.
//
#define MAP_ANONYMOUS (1 << 4)

// Synonym for MAP_ANONYMOUS; provided for compatibility with
// other implementations.
//
#define MAP_ANON MAP_ANONYMOUS

// This flag is ignored.  (Long ago—Linux 2.0 and earlier—it
// signaled that attempts to write to the underlying file
// should fail with ETXTBSY.  But this was a source of
// denial-of-service attacks.)
//
#define MAP_DENYWRITE (1 << 5)

// This flag is ignored.
//
#define MAP_EXECUTABLE (1 << 6)

// Compatibility flag.  Ignored.
//
#define MAP_FILE (1 << 7)

// Don't interpret addr as a hint: place the mapping at
// exactly that address.  addr must be suitably aligned : for
// most architectures a multiple of the page size is
// sufficient; however, some architectures may impose
// additional restrictions.  If the memory region specified
// by addr and length overlaps pages of any existing
// mapping(s), then the overlapped part of the existing
// mapping(s) will be discarded.  If the specified address
// cannot be used, mmap() will fail.
//
// Software that aspires to be portable should use the
// MAP_FIXED flag with care, keeping in mind that the exact
// layout of a process's memory mappings is allowed to change
// significantly between Linux versions, C library versions,
// and operating system releases.
//
#define MAP_FIXED (1 << 8)

// This flag provides behavior that is similar to MAP_FIXED
// with respect to the addr enforcement, but differs in that
// MAP_FIXED_NOREPLACE never clobbers a preexisting mapped
// range.  If the requested range would collide with an
// existing mapping, then this call fails with the error
// EEXIST.  This flag can therefore be used as a way to
// atomically(with respect to other threads) attempt to map
// an address range : one thread will succeed; all others will
// report failure.
//
// Note that older kernels which do not recognize the
// MAP_FIXED_NOREPLACE flag will typically(upon detecting a
// collision with a preexisting mapping) fall back to a “non -
// MAP_FIXED” type of behavior : they will return an address
// that is different from the requested address.  Therefore,
// backward-compatible software should check the returned
// address against the requested address.
//
#define MAP_FIXED_NOREPLACE (1 << 9)

// This flag is used for stacks.  It indicates to the kernel
// virtual memory system that the mapping should extend
// downward in memory.  The return address is one page lower
// than the memory area that is actually created in the
// process's virtual address space.  Touching an address in
// the "guard" page below the mapping will cause the mapping
// to grow by a page.  This growth can be repeated until the
// mapping grows to within a page of the high end of the next
// lower mapping, at which point touching the "guard" page
// will result in a SIGSEGV signal.
//
#define MAP_GROWSDOWN (1 << 10)

// Allocate the mapping using "huge" pages.  See the Linux
// kernel source file https://www.kernel.org/doc/Documentation/admin-guide/mm/hugetlbpage.rst
// for further information.
//
#define MAP_HUGETLB (1 << 11)

/* When MAP_HUGETLB is set bits [26:31] encode the log2 of the huge page size.  */
#define MAP_HUGE_SHIFT  26
#define MAP_HUGE_MASK   0x3f

// Used in conjunction with MAP_HUGETLB to select alternative
// hugetlb page sizes(respectively, 2 MB and 1 GB) on
// systems that support multiple hugetlb page sizes.
//
// More generally, the desired huge page size can be
// configured by encoding the base-2 logarithm of the desired
// page size in the six bits at the offset MAP_HUGE_SHIFT.
// (A value of zero in this bit field provides the default
// huge page size
//
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)

// Used in conjunction with MAP_HUGETLB to select alternative
// hugetlb page sizes(respectively, 2 MB and 1 GB) on
// systems that support multiple hugetlb page sizes.
//
// More generally, the desired huge page size can be
// configured by encoding the base-2 logarithm of the desired
// page size in the six bits at the offset MAP_HUGE_SHIFT.
// (A value of zero in this bit field provides the default
// huge page size
//
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)

// Mark the mapped region to be locked in the same way as
// mlock(2).  This implementation will try to populate
// (prefault) the whole range but the mmap() call doesn't
// fail with ENOMEM if this fails.  Therefore major faults
// might happen later on.  So the semantic is not as strong
// as mlock(2).  One should use mmap() plus mlock(2) when
// major faults are not acceptable after the initialization
// of the mapping.  The MAP_LOCKED flag is ignored in older
// kernels.
//
#define MAP_LOCKED (1 << 12)

// This flag is meaningful only in conjunction with
// MAP_POPULATE.  Don't perform read-ahead: create page
// tables entries only for pages that are already present in
// RAM.  Since Linux 2.6.23, this flag causes MAP_POPULATE to
// do nothing.  One day, the combination of MAP_POPULATE and
// MAP_NONBLOCK may be reimplemented.
//
#define MAP_NONBLOCK (1 << 13)

// Do not reserve swap space for this mapping.  When swap
// space is reserved, one has the guarantee that it is
// possible to modify the mapping.  When swap space is not
// reserved one might get SIGSEGV upon a write if no physical
// memory is available.  See also the discussion of the file
// /proc/sys/vm/overcommit_memory in proc(5).  Before Linux
// 2.6, this flag had effect only for private writable
// mappings.
//
#define MAP_NORESERVE (1 << 14)

// Populate (prefault) page tables for a mapping.  For a file
// mapping, this causes read-ahead on the file.  This will
// help to reduce blocking on page faults later.  The mmap()
// call doesn't fail if the mapping cannot be populated (for
// example, due to limitations on the number of mapped huge
// pages when using MAP_HUGETLB).  Support for MAP_POPULATE
// in conjunction with private mappings was added in Linux
// 2.6.23.
//
#define MAP_POPULATE (1 << 15)

// Allocate the mapping at an address suitable for a process
// or thread stack.
//
// This flag is currently a no-op on Linux.  However, by
// employing this flag, applications can ensure that they
// transparently obtain support if the flag is implemented in
// the future.  Thus, it is used in the glibc threading
// implementation to allow for the fact that some
// architectures may (later) require special treatment for
// stack allocations.  A further reason to employ this flag
// is portability: MAP_STACK exists (and has an effect) on
// some other systems (e.g., some of the BSDs).
//
#define MAP_STACK (1 << 16)

// This flag is available only with the MAP_SHARED_VALIDATE
// mapping type; mappings of type MAP_SHARED will silently
// ignore this flag.  This flag is supported only for files
// supporting DAX (direct mapping of persistent memory).  For
// other files, creating a mapping with this flag results in
// an EOPNOTSUPP error.

// Shared file mappings with this flag provide the guarantee
// that while some memory is mapped writable in the address
// space of the process, it will be visible in the same file
// at the same offset even after the system crashes or is
// rebooted.  In conjunction with the use of appropriate CPU
// instructions, this provides users of such mappings with a
// more efficient way of making data modifications
// persistent.
//
#define MAP_SYNC (1 << 17)

// Don't clear anonymous pages.  This flag is intended to
// improve performance on embedded devices.  This flag is
// honored only if the kernel was configured with the
// CONFIG_MMAP_ALLOW_UNINITIALIZED option.  Because of the
// security implications, that option is normally enabled
// only on embedded devices (i.e., devices where one has
// complete control of the contents of user memory).
//
#define MAP_UNINITIALIZED (1 << 18)

