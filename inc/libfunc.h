#ifndef _LIBFUNC_H
#define _LIBFUNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include "stdint.h"
#include "syscall.h"
#include "limits.h"
#include "stdarg.h"

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define SEEK_DATA 3
#define SEEK_HOLE 4

#if __cplusplus >= 201103L
#define NULL nullptr
#elif defined(__cplusplus)
#define NULL 0L
#else
#define NULL ((void*)0)
#endif

#define __NEED_size_t
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) \
 || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
 || defined(_BSD_SOURCE)
#define __NEED_locale_t
#endif

#include "alltypes.h"

#define PAGE_SIZE       4096

#define O_CREAT        0100
#define O_EXCL         0200
#define O_NOCTTY       0400
#define O_TRUNC       01000
#define O_APPEND      02000
#define O_NONBLOCK    04000
#define O_DSYNC      010000
#define O_SYNC     04010000
#define O_RSYNC    04010000
#define O_DIRECTORY 0200000
#define O_NOFOLLOW  0400000
#define O_CLOEXEC  02000000

#define O_ASYNC      020000
#define O_DIRECT     040000
#define O_LARGEFILE 0100000
#define O_NOATIME  01000000
#define O_PATH    010000000
#define O_TMPFILE 020200000
#define O_NDELAY O_NONBLOCK

#define O_SEARCH   O_PATH
#define O_EXEC     O_PATH
#define O_TTY_INIT 0

#define O_ACCMODE (03|O_SEARCH)
#define O_RDONLY  00
#define O_WRONLY  01
#define O_RDWR    02

#define F_DUPFD  0
#define F_GETFD  1
#define F_SETFD  2
#define F_GETFL  3
#define F_SETFL  4

#define F_SETOWN 8
#define F_GETOWN 9
#define F_SETSIG 10
#define F_GETSIG 11

#if __LONG_MAX == 0x7fffffffL
#define F_GETLK 12
#define F_SETLK 13
#define F_SETLKW 14
#else
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#endif

#define F_SETOWN_EX 15
#define F_GETOWN_EX 16

#define F_GETOWNER_UIDS 17

#define FD_CLOEXEC 1

#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR 0x200
#define AT_SYMLINK_FOLLOW 0x400
#define AT_EACCESS 0x200

#define MMAP_THRESHOLD 131052

#define UNIT 16
#define IB 4

#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_FD		2
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8
#define FUTEX_WAIT_BITSET	9

#define FUTEX_PRIVATE 128

#define FUTEX_CLOCK_REALTIME 256

#define brk(p) ((uintptr_t)__syscall(SYS_brk, p))

#define _IOFBF 0
#define _IOLBF 1
#define _IONBF 2

#define BUFSIZ 1024
#define FILENAME_MAX 4096
#define FOPEN_MAX 1000
#define TMP_MAX 10000
#define L_tmpnam 20
#define UNGET 8
#define F_PERM 1
#define F_NORD 4
#define F_NOWR 8
#define F_EOF 16
#define F_ERR 32
#define F_SVB 64
#define F_APP 128

#define AT_NO_AUTOMOUNT 0x800
#define AT_EMPTY_PATH 0x1000
#define AT_STATX_SYNC_TYPE 0x6000
#define AT_STATX_SYNC_AS_STAT 0x0000
#define AT_STATX_FORCE_SYNC 0x2000
#define AT_STATX_DONT_SYNC 0x4000
#define AT_RECURSIVE 0x8000

#define FAPPEND O_APPEND
#define FFSYNC O_SYNC
#define FASYNC O_ASYNC
#define FNONBLOCK O_NONBLOCK
#define FNDELAY O_NDELAY

#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_ULOCK 0
#define F_LOCK  1
#define F_TLOCK 2
#define F_TEST  3

#define F_SETLEASE	1024
#define F_GETLEASE	1025
#define F_NOTIFY	1026
#define F_CANCELLK	1029
#define F_SETPIPE_SZ	1031
#define F_GETPIPE_SZ	1032
#define F_ADD_SEALS	1033
#define F_GET_SEALS	1034

#define F_SEAL_SEAL	0x0001
#define F_SEAL_SHRINK	0x0002
#define F_SEAL_GROW	0x0004
#define F_SEAL_WRITE	0x0008
#define F_SEAL_FUTURE_WRITE	0x0010

#define F_GET_RW_HINT		1035
#define F_SET_RW_HINT		1036
#define F_GET_FILE_RW_HINT	1037
#define F_SET_FILE_RW_HINT	1038

#define RWF_WRITE_LIFE_NOT_SET	0
#define RWH_WRITE_LIFE_NONE	1
#define RWH_WRITE_LIFE_SHORT	2
#define RWH_WRITE_LIFE_MEDIUM	3
#define RWH_WRITE_LIFE_LONG	4
#define RWH_WRITE_LIFE_EXTREME	5

#define DN_ACCESS	0x00000001
#define DN_MODIFY	0x00000002
#define DN_CREATE	0x00000004
#define DN_DELETE	0x00000008
#define DN_RENAME	0x00000010
#define DN_ATTRIB	0x00000020
#define DN_MULTISHOT	0x80000000

#define LOCALE_NAME_MAX 23
struct __locale_map {
	const void* map;
	size_t map_size;
	char name[LOCALE_NAME_MAX+1];
	const struct __locale_map* next;
};

struct __locale_struct {
	const struct __locale_map* cat[6];
};

/* copied from kernel definition, but with padding replaced
 * by the corresponding correctly-sized userspace types. */
struct stat {
	dev_t st_dev;
	ino_t st_ino;
	nlink_t st_nlink;

	mode_t st_mode;
	uid_t st_uid;
	gid_t st_gid;
	unsigned int    __pad0;
	dev_t st_rdev;
	off_t st_size;
	blksize_t st_blksize;
	blkcnt_t st_blocks;

	struct timespec st_atim;
	struct timespec st_mtim;
	struct timespec st_ctim;
	long __unused[3];
};

/*start> x86_64  */
struct kstat {
	dev_t st_dev;
	ino_t st_ino;
	nlink_t st_nlink;

	mode_t st_mode;
	uid_t st_uid;
	gid_t st_gid;
	unsigned int    __pad0;
	dev_t st_rdev;
	off_t st_size;
	blksize_t st_blksize;
	blkcnt_t st_blocks;

	long st_atime_sec;
	long st_atime_nsec;
	long st_mtime_sec;
	long st_mtime_nsec;
	long st_ctime_sec;
	long st_ctime_nsec;
	long __unused[3];
};
/*end> x86_64  */

struct _IO_FILE {
	unsigned flags;
	unsigned char* rpos, *rend;
	int (*close)(int);
	unsigned char* wend, *wpos;
	unsigned char* mustbezero_1;
	unsigned char* wbase;
	size_t (*read)(int, void*, size_t);
	size_t (*write)(int, void*, size_t);
	off_t (*seek)(void*, off_t, int);
	unsigned char* buf;
	size_t buf_size;
	void* prev, *next;
	int fd;
	int pipe_pid;
	long lockcount;
	int mode;
	volatile int lock;
	int lbf;
	void* cookie;
	off_t off;
	char* getln_buf;
	void* mustbezero_2;
	unsigned char* shend;
	off_t shlim, shcnt;
	void* prev_locked, *next_locked;
	struct __locale_struct* locale;
};
typedef struct _IO_FILE FILE;

#ifdef __GNUC__
__attribute__((const))
#endif
hidden int* ___errno_location(void);

#undef errno
#define errno (*___errno_location())


static inline void __wake(volatile void* addr, int cnt, int priv)
{
	if(priv) {
		priv = FUTEX_PRIVATE;
	}
	if(cnt<0) {
		cnt = INT_MAX;
	}
	__syscall(SYS_futex, addr, FUTEX_WAKE|priv, cnt) != -ENOSYS ||
	__syscall(SYS_futex, addr, FUTEX_WAKE, cnt);
}


size_t read(int fd, void* buf, size_t count);
int fstat(int fd, struct stat* st);
int strcmp(const char* l, const char* r);
int strncmp(const char* _l, const char* _r, size_t n);
size_t strlen(const char* s);
int memcmp(const void* vl, const void* vr, size_t n);
int open(const char* filename, int flags, ...);
int close(int fd);
_Noreturn void _exit(int status);
void* malloc(size_t n);
void free(void* ptr);
ssize_t pread(int fd, void* buf, size_t size, off_t ofs);
void* memset(void* dest, int c, size_t n);
off_t lseek(int, off_t, int);
int mprotect(void*, size_t, int);
void* mmap(void*, size_t, int, int, int, off_t);
int munmap(void*, size_t);
int printf(const char* fmt, ...);
int fprintf(FILE* stream, const char* fmt, ...);
int vfprintf(FILE* stream, const char* fmt, va_list ap);
char* strchr(const char* s, int c);
char* strchrnul(const char*, int);
size_t strspn(const char* s, const char* c);
size_t strcspn(const char* s, const char* c);
int snprintf(char* restrict s, size_t n, const char* restrict fmt, ...);
ssize_t readlink(const char* restrict path, char* restrict buf, size_t bufsize);
void* memrchr(const void*, int, size_t);
char* strrchr(const char* s, int c);
char* stpcpy(char* __restrict, const char* __restrict);
char* strcpy(char* restrict dest, const char* restrict src);
hidden int __malloc_allzerop(void*);
void* calloc(size_t m, size_t n);
int fread(void* buffer, int size, int count, FILE* stream);
int fwrite(void* buffer, int size, int count, FILE* stream);    
int fputc(int c, FILE* stream);
int fputs(char* str, FILE* stream);


#ifdef __cplusplus
}
#endif

#endif
