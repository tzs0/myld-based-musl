#include "libfunc.h"
#include <stdint.h>
#include <stdarg.h>
#include "syscall.h"
#include "mman.h"
#include "atomic_arch_x86_64.h"


struct cookie {
	char* s;
	size_t n;
};

#define makedev(x,y) ( \
        (((x)&0xfffff000ULL) << 32) | \
	(((x)&0x00000fffULL) << 8) | \
        (((y)&0xffffff00ULL) << 12) | \
	(((y)&0x000000ffULL)) )
#define EOF (-1)
#define ALIGN (sizeof(size_t))
#define ONES ((size_t)-1/UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX/2+1))
#define HASZERO(x) ((x)-ONES & ~(x) & HIGHS)

extern void* memcpy(void* __restrict, const void* __restrict, size_t);


int strcmp(const char* l, const char* r)
{
	for(; *l==*r && *l; l++, r++);
	return *(unsigned char*)l - *(unsigned char*)r;
}

/*heap-operation-start> come from 13.1.2heap realize */
typedef struct _heap_header {
	enum {
		HEAP_BLOCK_FREE = 0xABABABAB, /* magic number of free block */
		HEAP_BLOCK_USED = 0xCDCDCDCD, /* magic number of used block */
	} type;

	unsigned size;              /* block size including header */
	struct _heap_header* next;
	struct _heap_header* prev;
} heap_header;
#define ADDR_ADD(a,o)   (((char *)(a))+o)
#define HEADER_SIZE     (sizeof(heap_header))
static heap_header* list_head = NULL;

hidden int heap_init(void)
{
	void* base = NULL;
	heap_header* header = NULL;
	/* 32M heap size */
	unsigned heap_size = 1024*1024*32;

	base = (void*)brk(0);
	void* end = ADDR_ADD(base, heap_size);
	end = (void*)brk(end);
	if(!end) {
		return 0;
	}

	header = (heap_header*)base;
	header->size = heap_size;
	header->type = HEAP_BLOCK_FREE;
	header->next = NULL;
	header->prev = NULL;

	list_head = header;
	return 1;
}
void* malloc(size_t size)
{
	static volatile int heap_init_flag = 1;
	if(1==heap_init_flag) {
		if(1==heap_init()) {
			heap_init_flag = 0;
		}
	}

	heap_header* header;

	if(0==size) {
		return NULL;
	}
	header = list_head;
	while(0!=header) {
		if(HEAP_BLOCK_USED==header->type) {
			header = header->next;
			continue;
		}
		if((header->size>(size+HEADER_SIZE))&&(header->size<=(size+HEADER_SIZE*2))) {
			header->type = HEAP_BLOCK_USED; /* not enough */
		}
		if(header->size>size+HEADER_SIZE*2) {
			/* split */
			heap_header* next = (heap_header*)ADDR_ADD(header, size+HEADER_SIZE);
			next->prev = header;
			next->next = header->next;
			next->type = HEAP_BLOCK_FREE;
			next->size = header->size-(size-HEADER_SIZE);
			header->next = next;
			header->size = size+HEADER_SIZE;
			header->type = HEAP_BLOCK_USED;
			return ADDR_ADD(header, HEADER_SIZE);
		}
		header = header->next;
	}

	return NULL;
}
void free(void* ptr)
{
	heap_header* header = (heap_header*)ADDR_ADD(ptr, -HEADER_SIZE);
	if(HEAP_BLOCK_USED!=header->type) {
		return;
	}
	header->type = HEAP_BLOCK_FREE;
	if(header->prev != NULL && header->prev->type == HEAP_BLOCK_FREE) {
		header->prev->next = header->next;
		if(NULL!=header->next) {
			header->next->prev = header->prev;
		}
		header->prev->size += header->size; /* combine with up */
		header = header->prev;
	}

	if(NULL!=header->next && header->next->type == HEAP_BLOCK_FREE) {
		header->size += header->next->size;
		header->next = header->next->next; /* combine with low */
	}
}
/*heap-operation-end> come from 13.1.2heap realize */

static volatile int vmlock[2];
volatile int* const __vmlock_lockptr = vmlock;

void __wait(volatile int* addr, volatile int* waiters, int val, int priv)
{
	int spins=100;
	if(priv) {
		priv = FUTEX_PRIVATE;
	}
	while(spins-- && (!waiters || !*waiters)) {
		if(*addr==val) {
			a_spin();
		}
		else {
			return;
		}
	}
	if(waiters) {
		a_inc(waiters);
	}
	while(*addr==val) {
		__syscall(SYS_futex, addr, FUTEX_WAIT|priv, val, 0) != -ENOSYS
		|| __syscall(SYS_futex, addr, FUTEX_WAIT, val, 0);
	}
	if(waiters) {
		a_dec(waiters);
	}
}

void __vm_wait()
{
	int tmp;
	while((tmp=vmlock[0])) {
		__wait(vmlock, vmlock+1, tmp, 1);
	}
}
void __vm_lock()
{
	a_inc(vmlock);
}
void __vm_unlock()
{
	if(a_fetch_add(vmlock, -1)==1 && vmlock[1]) {
		__wake(vmlock, -1, 1);
	}
}

int strncmp(const char* _l, const char* _r, size_t n)
{
	const unsigned char* l=(void*)_l, *r=(void*)_r;
	if(!n--) {
		return 0;
	}
	for(; *l && *r && n && *l == *r ; l++, r++, n--);
	return *l - *r;
}

size_t strlen(const char* s)
{
	const char* a = s;
#ifdef __GNUC__
	typedef size_t __attribute__((__may_alias__)) word;
	const word* w;
	for(; (uintptr_t)s % ALIGN; s++)
		if(!*s) {
			return s-a;
		}
	for(w = (const void*)s; !HASZERO(*w); w++);
	s = (const void*)w;
#endif
	for(; *s; s++);
	return s-a;
}

int memcmp(const void* vl, const void* vr, size_t n)
{
	const unsigned char* l=vl, *r=vr;
	for(; n && *l == *r; n--, l++, r++);
	return n ? *l-*r : 0;
}

int open(const char* filename, int flags, ...)
{
	mode_t mode = 0;

	if((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	int fd = __sys_open_cp(filename, flags, mode);
	if(fd>=0 && (flags & O_CLOEXEC)) {
		__syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC);
	}

	return __syscall_ret(fd);
}

weak_alias(open, open64);

int close(int fd)
{
//	fd = __aio_close(fd);
	int r = __syscall_cp(SYS_close, fd);
	if(r == -EINTR) {
		r = 0;
	}
	return __syscall_ret(r);
}

hidden long __syscall_cp_c();

static long sccp(syscall_arg_t nr,
                 syscall_arg_t u, syscall_arg_t v, syscall_arg_t w,
                 syscall_arg_t x, syscall_arg_t y, syscall_arg_t z)
{
	return __syscall(nr, u, v, w, x, y, z);
}

weak_alias(sccp, __syscall_cp_c);

long (__syscall_cp)(syscall_arg_t nr,
                    syscall_arg_t u, syscall_arg_t v, syscall_arg_t w,
                    syscall_arg_t x, syscall_arg_t y, syscall_arg_t z)
{
	return __syscall_cp_c(nr, u, v, w, x, y, z);
}

long __syscall_ret(unsigned long r)
{
	if(r > -4096UL) {
//		errno = -r;
		return -1;
	}
	return r;
}

int* __errno_location(void)
{
//	return &__pthread_self()->errno_val;
}

weak_alias(__errno_location, ___errno_location);

_Noreturn void _Exit(int ec)
{
	__syscall(SYS_exit_group, ec);
	for(;;) {
		__syscall(SYS_exit, ec);
	}
}

_Noreturn void _exit(int status)
{
	_Exit(status);
}

size_t read(int fd, void* buf, size_t count)
{
	return syscall_cp(SYS_read, fd, buf, count);
}

size_t write(int fd, void* buf, size_t count)
{
	return syscall_cp(SYS_write, fd, buf, count);
}

#define UNIT SYSCALL_MMAP2_UNIT
#define OFF_MASK ((-0x2000ULL << (8*sizeof(syscall_arg_t)-1)) | (UNIT-1))

void* __mmap(void* start, size_t len, int prot, int flags, int fd, off_t off)
{
	long ret;
	if(off & OFF_MASK) {
		errno = EINVAL;
		return MAP_FAILED;
	}
	if(len >= PTRDIFF_MAX) {
		errno = ENOMEM;
		return MAP_FAILED;
	}
	if(flags & MAP_FIXED) {
		__vm_wait();
	}
#ifdef SYS_mmap2
	ret = __syscall(SYS_mmap2, start, len, prot, flags, fd, off/UNIT);
#else
	ret = __syscall(SYS_mmap, start, len, prot, flags, fd, off);
#endif
	/* Fixup incorrect EPERM from kernel. */
	if(ret == -EPERM && !start && (flags&MAP_ANON) && !(flags&MAP_FIXED)) {
		ret = -ENOMEM;
	}
	return (void*)__syscall_ret(ret);
}

weak_alias(__mmap, mmap);

weak_alias(mmap, mmap64);

int __munmap(void* start, size_t len)
{
	__vm_wait();
	return syscall(SYS_munmap, start, len);
}

weak_alias(__munmap, munmap);

ssize_t pread(int fd, void* buf, size_t size, off_t ofs)
{
	return syscall_cp(SYS_pread, fd, buf, size, __SYSCALL_LL_PRW(ofs));
}

weak_alias(pread, pread64);

void* memset(void* dest, int c, size_t n)
{
	unsigned char* s = dest;
	size_t k;

	/* Fill head and tail with minimal branching. Each
	 * conditional ensures that all the subsequently used
	 * offsets are well-defined and in the dest region. */

	if(!n) {
		return dest;
	}
	s[0] = c;
	s[n-1] = c;
	if(n <= 2) {
		return dest;
	}
	s[1] = c;
	s[2] = c;
	s[n-2] = c;
	s[n-3] = c;
	if(n <= 6) {
		return dest;
	}
	s[3] = c;
	s[n-4] = c;
	if(n <= 8) {
		return dest;
	}

	/* Advance pointer to align it at a 4-byte boundary,
	 * and truncate n to a multiple of 4. The previous code
	 * already took care of any head/tail that get cut off
	 * by the alignment. */

	k = -(uintptr_t)s & 3;
	s += k;
	n -= k;
	n &= -4;

#ifdef __GNUC__
	typedef uint32_t __attribute__((__may_alias__)) u32;
	typedef uint64_t __attribute__((__may_alias__)) u64;

	u32 c32 = ((u32)-1)/255 * (unsigned char)c;

	/* In preparation to copy 32 bytes at a time, aligned on
	 * an 8-byte bounary, fill head/tail up to 28 bytes each.
	 * As in the initial byte-based head/tail fill, each
	 * conditional below ensures that the subsequent offsets
	 * are valid (e.g. !(n<=24) implies n>=28). */

	*(u32*)(s+0) = c32;
	*(u32*)(s+n-4) = c32;
	if(n <= 8) {
		return dest;
	}
	*(u32*)(s+4) = c32;
	*(u32*)(s+8) = c32;
	*(u32*)(s+n-12) = c32;
	*(u32*)(s+n-8) = c32;
	if(n <= 24) {
		return dest;
	}
	*(u32*)(s+12) = c32;
	*(u32*)(s+16) = c32;
	*(u32*)(s+20) = c32;
	*(u32*)(s+24) = c32;
	*(u32*)(s+n-28) = c32;
	*(u32*)(s+n-24) = c32;
	*(u32*)(s+n-20) = c32;
	*(u32*)(s+n-16) = c32;

	/* Align to a multiple of 8 so we can fill 64 bits at a time,
	 * and avoid writing the same bytes twice as much as is
	 * practical without introducing additional branching. */

	k = 24 + ((uintptr_t)s & 4);
	s += k;
	n -= k;

	/* If this loop is reached, 28 tail bytes have already been
	 * filled, so any remainder when n drops below 32 can be
	 * safely ignored. */

	u64 c64 = c32 | ((u64)c32 << 32);
	for(; n >= 32; n-=32, s+=32) {
		*(u64*)(s+0) = c64;
		*(u64*)(s+8) = c64;
		*(u64*)(s+16) = c64;
		*(u64*)(s+24) = c64;
	}
#else
	/* Pure C fallback with no aliasing violations. */
	for(; n; n--, s++) {
		*s = c;
	}
#endif

	return dest;
}

off_t __lseek(int fd, off_t offset, int whence)
{
#ifdef SYS__llseek
	off_t result;
	return syscall(SYS__llseek, fd, offset>>32, offset, &result, whence) ? -1 : result;
#else
	return syscall(SYS_lseek, fd, offset, whence);
#endif
}

weak_alias(__lseek, lseek);

off_t seek(void* f, off_t off, int whence)
{
	return __lseek(((FILE*)f)->fd, off, whence);
}

int __mprotect(void* addr, size_t len, int prot)
{
	size_t start, end;
	start = (size_t)addr & -PAGE_SIZE;
	end = (size_t)((char*)addr + len + PAGE_SIZE-1) & -PAGE_SIZE;
	return syscall(SYS_mprotect, start, end-start, prot);
}

weak_alias(__mprotect, mprotect);


static unsigned char buf_in[BUFSIZ+UNGET];
hidden FILE __stdin_FILE = {
	.buf = buf_in+UNGET,
	.buf_size = sizeof buf_in-UNGET,
	.fd = 0,
	.flags = F_PERM | F_NOWR,
	.read = read,
	.seek = seek,
	.close = close,
	.lock = -1,
};
FILE* const stdin = &__stdin_FILE;
FILE* volatile __stdin_used = &__stdin_FILE;

static unsigned char buf_out[BUFSIZ+UNGET];
hidden FILE __stdout_FILE = {
	.buf = buf_out+UNGET,
	.buf_size = sizeof buf_out-UNGET,
	.fd = 1,
	.flags = F_PERM | F_NORD,
	.lbf = '\n',
	.write = write,
	.seek = seek,
	.close = close,
	.lock = -1,
};
FILE* const stdout = &__stdout_FILE;
FILE* volatile __stdout_used = &__stdout_FILE;

static unsigned char buf_err[UNGET];
hidden FILE __stderr_FILE = {
	.buf = buf_err+UNGET,
	.buf_size = 0,
	.fd = 2,
	.flags = F_PERM | F_NORD,
	.lbf = -1,
	.write = write,
	.seek = seek,
	.close = close,
	.lock = -1,
};
FILE* const stderr = &__stderr_FILE;
FILE* volatile __stderr_used = &__stderr_FILE;

FILE* fopen(const char* filename, const char* mode)
{
	int fd = -1;
	int flags = 0;
	int access = 00700;

	if(0==strcmp(mode, "w")) {
		flags |= O_WRONLY | O_CREAT | O_TRUNC;
	}
	if(0==strcmp(mode, "w+")) {
		flags |= O_RDWR | O_CREAT | O_TRUNC;
	}
	if(0==strcmp(mode, "r")) {
		flags |= O_RDONLY;
	}
	if(0==strcmp(mode, "r+")) {
		flags |= O_RDWR | O_CREAT;
	}

	fd = open(filename, flags, access);

	return (FILE*)fd;
}

int fread(void* buffer, int size, int count, FILE* stream)
{
	return read(stream->fd, buffer, size * count);
}

int fwrite(void* buffer, int size, int count, FILE* stream)
{
	return write(stream->fd, buffer, size * count);
}

//int fclose(FILE* fp)
//{
//	return close((int)fp);
//}

//int fseek(FILE* fp, int offset, int set)
//{
//	return seek((int)fp, offset, set);
//}

int fputc(int c, FILE* stream)
{
	if(fwrite(&c, 1, 1, stream)!=1) {
		return EOF;
	}
	else {
		return c;
	}
}

int fputs(char* str, FILE* stream)
{
	int len = strlen(str);
	if(fwrite(str, 1, len, stream)!=len) {
		return EOF;
	}
	else {
		return len;
	}
}

char* itoa(int n, char* str, int radix)
{
	char digit[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char* p = str;
	char* head = str;
	if(!p || radix<2 || radix>36) {
		return p;
	}
	if(radix!=10 && n<0) {
		return p;
	}
	if(0==n) {
		*p++ = '0';
		*p = 0;
		return p;
	}
	if(10==radix && n<0) {
		*p++ = '-';
		n = -n;
	}
	while(n) {
		*p++ = digit[n%radix];
		n /= radix;
	}
	*p = 0;
	for(--p; head<p; ++head,--p) {
		char temp = *head;
		*head = *p;
		*p = temp;
	}

	return str;
}

int vfprintf(FILE* stream, const char* fmt, va_list ap)
{
	int translating = 0;
	int ret = 0;
	const char* p = 0;
	for(p=fmt; *p!='\0'; ++p) {
		switch(*p) {
			case '%':
				if(!translating) {
					translating = 1;
				}
				else {
					if(fputc('%', stream)<0) {
						return EOF;
					}
					++ret;
					translating = 0;
				}
				break;
			case 'd':
				if(translating) {
					char buf[16];
					translating = 0;
					itoa(va_arg(ap, int), buf, 10);
					if(fputs(buf, stream)<0) {
						return EOF;
					}
					ret += strlen(buf);
				}
				else if(fputc('d', stream)<0) {
					return EOF;
				}
				else {
					++ret;
				}
				break;
			case 's':
				if(translating) {
					const char* str = va_arg(ap, const char*);
					translating = 0;
					if(fputs((char*)str, stream)<0) {
						return EOF;
					}
					ret += strlen(str);
				}
				else if(fputc('s', stream)<0) {
					return EOF;
				}
				else {
					++ret;
				}
				break;
			default:
				if(translating) {
					translating = 0;
				}
				if(fputc(*p, stream)<0) {
					return EOF;
				}
				else {
					++ret;
				}
				break;
		}
	}
	return ret;
}

int printf(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	return vfprintf(stdout, fmt, ap);
}

int fprintf(FILE* stream, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	return vfprintf(stream, fmt, ap);
}

char* __strchrnul(const char* s, int c)
{
	c = (unsigned char)c;
	if(!c) {
		return (char*)s + strlen(s);
	}

#ifdef __GNUC__
	typedef size_t __attribute__((__may_alias__)) word;
	const word* w;
	for(; (uintptr_t)s % ALIGN; s++)
		if(!*s || *(unsigned char*)s == c) {
			return (char*)s;
		}
	size_t k = ONES * c;
	for(w = (void*)s; !HASZERO(*w) && !HASZERO(*w^k); w++);
	s = (void*)w;
#endif
	for(; *s && *(unsigned char*)s != c; s++);
	return (char*)s;
}

weak_alias(__strchrnul, strchrnul);

char* strchr(const char* s, int c)
{
	char* r = __strchrnul(s, c);
	return *(unsigned char*)r == (unsigned char)c ? r : 0;
}

#define BITOP(a,b,op) \
 ((a)[(size_t)(b)/(8*sizeof *(a))] op (size_t)1<<((size_t)(b)%(8*sizeof *(a))))

size_t strspn(const char* s, const char* c)
{
	const char* a = s;
	size_t byteset[32/sizeof(size_t)] = { 0 };

	if(!c[0]) {
		return 0;
	}
	if(!c[1]) {
		for(; *s == *c; s++);
		return s-a;
	}

	for(; *c && BITOP(byteset, *(unsigned char*)c, |=); c++);
	for(; *s && BITOP(byteset, *(unsigned char*)s, &); s++);
	return s-a;
}

size_t strcspn(const char* s, const char* c)
{
	const char* a = s;
	size_t byteset[32/sizeof(size_t)];

	if(!c[0] || !c[1]) {
		return __strchrnul(s, *c)-a;
	}

	memset(byteset, 0, sizeof byteset);
	for(; *c && BITOP(byteset, *(unsigned char*)c, |=); c++);
	for(; *s && !BITOP(byteset, *(unsigned char*)s, &); s++);
	return s-a;
}

int vsnprintf(char* restrict s, size_t n, const char* restrict fmt, va_list ap)
{
	unsigned char buf[1];
	char dummy[1];
	struct cookie c = { .s = n ? s : dummy, .n = n ? n-1 : 0 };
	FILE f = {
		.lbf = EOF,
		.write = write,
		.lock = -1,
		.buf = buf,
		.cookie = &c,
	};

	if(n > INT_MAX) {
//		errno = EOVERFLOW;
		return -1;
	}

	*c.s = 0;
	return vfprintf(&f, fmt, ap);
}

int snprintf(char* restrict s, size_t n, const char* restrict fmt, ...)
{
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ret = vsnprintf(s, n, fmt, ap);
	va_end(ap);
	return ret;
}

struct statx {
	uint32_t stx_mask;
	uint32_t stx_blksize;
	uint64_t stx_attributes;
	uint32_t stx_nlink;
	uint32_t stx_uid;
	uint32_t stx_gid;
	uint16_t stx_mode;
	uint16_t pad1;
	uint64_t stx_ino;
	uint64_t stx_size;
	uint64_t stx_blocks;
	uint64_t stx_attributes_mask;
	struct {
		int64_t tv_sec;
		uint32_t tv_nsec;
		int32_t pad;
	} stx_atime, stx_btime, stx_ctime, stx_mtime;
	uint32_t stx_rdev_major;
	uint32_t stx_rdev_minor;
	uint32_t stx_dev_major;
	uint32_t stx_dev_minor;
	uint64_t spare[14];
};

static int fstatat_statx(int fd, const char* restrict path, struct stat* restrict st, int flag)
{
	struct statx stx;

	int ret = __syscall(SYS_statx, fd, path, flag, 0x7ff, &stx);
	if(ret) {
		return ret;
	}

	*st = (struct stat) {
		.st_dev = makedev(stx.stx_dev_major, stx.stx_dev_minor),
		.st_ino = stx.stx_ino,
		.st_mode = stx.stx_mode,
		.st_nlink = stx.stx_nlink,
		.st_uid = stx.stx_uid,
		.st_gid = stx.stx_gid,
		.st_rdev = makedev(stx.stx_rdev_major, stx.stx_rdev_minor),
		.st_size = stx.stx_size,
		.st_blksize = stx.stx_blksize,
		.st_blocks = stx.stx_blocks,
		.st_atim.tv_sec = stx.stx_atime.tv_sec,
		.st_atim.tv_nsec = stx.stx_atime.tv_nsec,
		.st_mtim.tv_sec = stx.stx_mtime.tv_sec,
		.st_mtim.tv_nsec = stx.stx_mtime.tv_nsec,
		.st_ctim.tv_sec = stx.stx_ctime.tv_sec,
		.st_ctim.tv_nsec = stx.stx_ctime.tv_nsec,
#if _REDIR_TIME64
		.__st_atim32.tv_sec = stx.stx_atime.tv_sec,
		.__st_atim32.tv_nsec = stx.stx_atime.tv_nsec,
		.__st_mtim32.tv_sec = stx.stx_mtime.tv_sec,
		.__st_mtim32.tv_nsec = stx.stx_mtime.tv_nsec,
		.__st_ctim32.tv_sec = stx.stx_ctime.tv_sec,
		.__st_ctim32.tv_nsec = stx.stx_ctime.tv_nsec,
#endif
	};
	return 0;
}

hidden void __procfdname(char* buf, unsigned fd)
{
	unsigned i, j;
	for(i=0; (buf[i] = "/proc/self/fd/"[i]); i++);
	if(!fd) {
		buf[i] = '0';
		buf[i+1] = 0;
		return;
	}
	for(j=fd; j; j/=10, i++);
	buf[i] = 0;
	for(; fd; fd/=10) {
		buf[--i] = '0' + fd%10;
	}
}

static int fstatat_kstat(int fd, const char* restrict path, struct stat* restrict st, int flag)
{
	int ret;
	struct kstat kst;

	if(flag==AT_EMPTY_PATH && fd>=0 && !*path) {
		ret = __syscall(SYS_fstat, fd, &kst);
		if(ret==-EBADF && __syscall(SYS_fcntl, fd, F_GETFD)>=0) {
			ret = __syscall(SYS_fstatat, fd, path, &kst, flag);
			if(ret==-EINVAL) {
				char buf[15+3*sizeof(int)];
				__procfdname(buf, fd);
#ifdef SYS_stat
				ret = __syscall(SYS_stat, buf, &kst);
#else
				ret = __syscall(SYS_fstatat, AT_FDCWD, buf, &kst, 0);
#endif
			}
		}
	}
#ifdef SYS_lstat
	else if((fd == AT_FDCWD || *path=='/') && flag==AT_SYMLINK_NOFOLLOW) {
		ret = __syscall(SYS_lstat, path, &kst);
	}
#endif
#ifdef SYS_stat
	else if((fd == AT_FDCWD || *path=='/') && !flag) {
		ret = __syscall(SYS_stat, path, &kst);
	}
#endif
	else {
		ret = __syscall(SYS_fstatat, fd, path, &kst, flag);
	}

	if(ret) {
		return ret;
	}

	*st = (struct stat) {
		.st_dev = kst.st_dev,
		.st_ino = kst.st_ino,
		.st_mode = kst.st_mode,
		.st_nlink = kst.st_nlink,
		.st_uid = kst.st_uid,
		.st_gid = kst.st_gid,
		.st_rdev = kst.st_rdev,
		.st_size = kst.st_size,
		.st_blksize = kst.st_blksize,
		.st_blocks = kst.st_blocks,
		.st_atim.tv_sec = kst.st_atime_sec,
		.st_atim.tv_nsec = kst.st_atime_nsec,
		.st_mtim.tv_sec = kst.st_mtime_sec,
		.st_mtim.tv_nsec = kst.st_mtime_nsec,
		.st_ctim.tv_sec = kst.st_ctime_sec,
		.st_ctim.tv_nsec = kst.st_ctime_nsec,
#if _REDIR_TIME64
		.__st_atim32.tv_sec = kst.st_atime_sec,
		.__st_atim32.tv_nsec = kst.st_atime_nsec,
		.__st_mtim32.tv_sec = kst.st_mtime_sec,
		.__st_mtim32.tv_nsec = kst.st_mtime_nsec,
		.__st_ctim32.tv_sec = kst.st_ctime_sec,
		.__st_ctim32.tv_nsec = kst.st_ctime_nsec,
#endif
	};

	return 0;
}

int fstatat(int fd, const char* restrict path, struct stat* restrict st, int flag)
{
	int ret;
	if(sizeof((struct kstat) {
	0
} .st_atime_sec) < sizeof(time_t)) {
		ret = fstatat_statx(fd, path, st, flag);
		if(ret!=-ENOSYS) {
			return __syscall_ret(ret);
		}
	}
	ret = fstatat_kstat(fd, path, st, flag);
	return __syscall_ret(ret);
}

#if !_REDIR_TIME64
weak_alias(fstatat, fstatat64);
#endif

int fstat(int fd, struct stat* st)
{
	if(fd<0) {
		return __syscall_ret(-EBADF);
	}
	return fstatat(fd, "", st, AT_EMPTY_PATH);
}

#if !_REDIR_TIME64
weak_alias(fstat, fstat64);
#endif

ssize_t readlink(const char* restrict path, char* restrict buf, size_t bufsize)
{
	char dummy[1];
	if(!bufsize) {
		buf = dummy;
		bufsize = 1;
	}
#ifdef SYS_readlink
	int r = __syscall(SYS_readlink, path, buf, bufsize);
#else
	int r = __syscall(SYS_readlinkat, AT_FDCWD, path, buf, bufsize);
#endif
	if(buf == dummy && r > 0) {
		r = 0;
	}
	return __syscall_ret(r);
}

void* __memrchr(const void* m, int c, size_t n)
{
	const unsigned char* s = m;
	c = (unsigned char)c;
	while(n--)
		if(s[n]==c) {
			return (void*)(s+n);
		}
	return 0;
}

weak_alias(__memrchr, memrchr);

char* strrchr(const char* s, int c)
{
	return __memrchr(s, c, strlen(s) + 1);
}

char* __stpcpy(char* restrict d, const char* restrict s)
{
#ifdef __GNUC__
	typedef size_t __attribute__((__may_alias__)) word;
	word* wd;
	const word* ws;
	if((uintptr_t)s % ALIGN == (uintptr_t)d % ALIGN) {
		for(; (uintptr_t)s % ALIGN; s++, d++)
			if(!(*d=*s)) {
				return d;
			}
		wd=(void*)d;
		ws=(const void*)s;
		for(; !HASZERO(*ws); *wd++ = *ws++);
		d=(void*)wd;
		s=(const void*)ws;
	}
#endif
	for(; (*d=*s); s++, d++);

	return d;
}

weak_alias(__stpcpy, stpcpy);

char* strcpy(char* restrict dest, const char* restrict src)
{
	__stpcpy(dest, src);
	return dest;
}

static size_t mal0_clear(char* p, size_t n)
{
	const size_t pagesz = 4096; /* arbitrary */
	if(n < pagesz) {
		return n;
	}
#ifdef __GNUC__
	typedef uint64_t __attribute__((__may_alias__)) T;
#else
	typedef unsigned char T;
#endif
	char* pp = p + n;
	size_t i = (uintptr_t)pp & (pagesz - 1);
	for(;;) {
		pp = memset(pp - i, 0, i);
		if(pp - p < pagesz) {
			return pp - p;
		}
		for(i = pagesz; i; i -= 2*sizeof(T), pp -= 2*sizeof(T))
			if(((T*)pp)[-1] | ((T*)pp)[-2]) {
				break;
			}
	}
}

static int allzerop(void* p)
{
	return 0;
}
weak_alias(allzerop, __malloc_allzerop);

void* calloc(size_t m, size_t n)
{
	if(n && m > (size_t)-1/n) {
		errno = ENOMEM;
		return 0;
	}
	n *= m;
	void* p = malloc(n);
	if(!p) {
		return p;
	}
	n = mal0_clear(p, n);
	return memset(p, 0, n);
}

