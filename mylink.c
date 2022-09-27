#include "myld.h"
#include "libfunc.h"
#include "syscall_num.h"
#include "mman.h"


typedef uint32_t Elf_Symndx;

struct debug {
	int ver;
	void* head;
	void (*bp)(void);
	int state;
	void* base;
};

struct dso {
	unsigned char* base;
	char* name;
	size_t* dynv;
	struct dso* next, *prev;

	Phdr* phdr;
	int phnum;
	size_t phentsize;
	Sym* syms;
	Elf_Symndx* hashtab;
	uint32_t* ghashtab;
	int16_t* versym;
	char* strings;
	struct dso* syms_next, *lazy_next;
	size_t* lazy, lazy_cnt;
	unsigned char* map;
	size_t map_len;
	dev_t dev;
	ino_t ino;
	char relocated;
	char constructed;
	char kernel_mapped;
	char mark;
	char bfs_built;
	char runtime_loaded;
	struct dso** deps, *needed_by;
	size_t ndeps_direct;
	size_t next_dep;
//	pthread_t ctor_visitor;
	char* rpath_orig, *rpath;
//	struct tls_module tls;
	size_t tls_id;
	size_t relro_start, relro_end;
	uintptr_t* new_dtv;
	unsigned char* new_tls;
	struct td_index* td_index;
	struct dso* fini_next;
	char* shortname;
	struct funcdesc {
		void* addr;
		size_t* got;
	}* funcdescs;
	size_t* got;
	char buf[];
};

struct symdef {
	Sym* sym;
	struct dso* dso;
};

typedef void (*stage3_func)(size_t*, size_t*);
#define laddr(p, v) (void *)((p)->base + (v))
#define laddr_pg(p, v) laddr(p, v)
#define fpaddr(p, v) ((void (*)())laddr(p, v))
#define ADDEND_LIMIT 4096
#define countof(a) ((sizeof (a))/(sizeof (a)[0]))
const char __libc_version[] = "0.0.1";

extern size_t mod0_var;
extern void mod0_test_func0();

extern void* memcpy(void* __restrict, const void* __restrict, size_t);

char** __environ = 0;

static struct dso ldso;
static struct dso* head, *tail, *fini_head, *syms_tail, *lazy_head;
static size_t* saved_addends, *apply_addends_to;
static char* env_path, *sys_path;
static int ldd_mode;
static int ldso_fail;
static struct dso* const no_deps[1];
static int noload;
static struct dso* builtin_deps[2];
static struct debug debug;
static struct dso** main_ctor_queue;
static struct dso* builtin_ctor_queue[4];

//-------------------------------
static void dl_debug_state(void);
static struct dso** queue_ctors(struct dso* dso);
static void add_syms(struct dso* p);
static void load_direct_deps(struct dso* p);
static void load_deps(struct dso* p);
static ssize_t read_loop(int fd, void* p, size_t n);
static int fixup_rpath(struct dso* p, char* buf, size_t buf_size);
static int path_open(const char* name, const char* s, char* buf, size_t buf_size);
static struct dso* load_library(const char* name, struct dso* needed_by);
static void load_preload(char* s);
static void reclaim_gaps(struct dso* dso);
static void* mmap_fixed(void* p, size_t n, int prot, int flags, int fd, off_t off);
static void unmap_library(struct dso* dso);
static void* map_library(int fd, struct dso* dso);
static inline struct symdef find_sym2(struct dso* dso, const char* s, int need_def, int use_deps);
static Sym* gnu_lookup_filtered(uint32_t h1, uint32_t* hashtab, struct dso* dso, const char* s, uint32_t fofs, size_t fmask);
static Sym* gnu_lookup(uint32_t h1, uint32_t* hashtab, struct dso* dso, const char* s);
static Sym* sysv_lookup(const char* s, uint32_t h, struct dso* dso);
static void do_relocs(struct dso* dso, size_t* rel, size_t rel_size, size_t stride);
static void reloc_all(struct dso* p);
static int search_vec(size_t* v, size_t* r, size_t key);
static uint32_t sysv_hash(const char* s0);
static uint32_t gnu_hash(const char* s0);
static void decode_vec(size_t* v, size_t* a, size_t cnt);
static void kernel_mapped_dso(struct dso* p);
static void decode_dyn(struct dso* p);
//-------------------------------
#define a_crash a_crash
static inline void a_crash()
{
	__asm__ __volatile__("hlt" : : : "memory");
}

static void decode_vec(size_t* v, size_t* a, size_t cnt)
{
	size_t i;
	for(i=0; i<cnt; i++) {
		a[i] = 0;
	}
	for(; v[0]; v+=2)
		if(v[0]-1<cnt-1) {
			a[0] |= 1UL<<v[0];
			a[v[0]] = v[1];
		}
}

static int dl_strcmp(const char *l, const char *r)
{
	for (; *l==*r && *l; l++, r++);
	return *(unsigned char *)l - *(unsigned char *)r;
}
#define strcmp(l,r) dl_strcmp(l,r)

static void kernel_mapped_dso(struct dso* p)
{
	size_t min_addr = -1, max_addr = 0, cnt;
	Phdr* ph = p->phdr;
	for(cnt = p->phnum; cnt--; ph = (void*)((char*)ph + p->phentsize)) {
		if(ph->p_type == PT_DYNAMIC) {
			p->dynv = laddr(p, ph->p_vaddr);
		}
		else if(ph->p_type == PT_GNU_RELRO) {
			p->relro_start = ph->p_vaddr & -PAGE_SIZE;
			p->relro_end = (ph->p_vaddr + ph->p_memsz) & -PAGE_SIZE;
		}
		else if(ph->p_type == PT_GNU_STACK) {
			/*if (!runtime && ph->p_memsz > __default_stacksize) {
				__default_stacksize =
					ph->p_memsz < DEFAULT_STACK_MAX ?
					ph->p_memsz : DEFAULT_STACK_MAX;
			}*/
		}
		if(ph->p_type != PT_LOAD) {
			continue;
		}
		if(ph->p_vaddr < min_addr) {
			min_addr = ph->p_vaddr;
		}
		if(ph->p_vaddr+ph->p_memsz > max_addr) {
			max_addr = ph->p_vaddr+ph->p_memsz;
		}
	}
	min_addr &= -PAGE_SIZE;
	max_addr = (max_addr + PAGE_SIZE-1) & -PAGE_SIZE;
	p->map = p->base + min_addr;
	p->map_len = max_addr - min_addr;
	p->kernel_mapped = 1;
}

static void decode_dyn(struct dso* p)
{
	size_t dyn[DYN_CNT];
	decode_vec(p->dynv, dyn, DYN_CNT);
	p->syms = laddr(p, dyn[DT_SYMTAB]);
	p->strings = laddr(p, dyn[DT_STRTAB]);
	if(dyn[0]&(1<<DT_HASH)) {
		p->hashtab = laddr(p, dyn[DT_HASH]);
	}
	if(dyn[0]&(1<<DT_RPATH)) {
		p->rpath_orig = p->strings + dyn[DT_RPATH];
	}
	if(dyn[0]&(1<<DT_RUNPATH)) {
		p->rpath_orig = p->strings + dyn[DT_RUNPATH];
	}
	if(dyn[0]&(1<<DT_PLTGOT)) {
		p->got = laddr(p, dyn[DT_PLTGOT]);
	}
	if(search_vec(p->dynv, dyn, DT_GNU_HASH)) {
		p->ghashtab = laddr(p, *dyn);
	}
	if(search_vec(p->dynv, dyn, DT_VERSYM)) {
		p->versym = laddr(p, *dyn);
	}
}

static int search_vec(size_t* v, size_t* r, size_t key)
{
	for(; v[0]!=key; v+=2)
		if(!v[0]) {
			return 0;
		}
	*r = v[1];
	return 1;
}

static uint32_t sysv_hash(const char* s0)
{
	const unsigned char* s = (void*)s0;
	uint_fast32_t h = 0;
	while(*s) {
		h = 16*h + *s++;
		h ^= h>>24 & 0xf0;
	}
	return h & 0xfffffff;
}

static uint32_t gnu_hash(const char* s0)
{
	const unsigned char* s = (void*)s0;
	uint_fast32_t h = 5381;
	for(; *s; s++) {
		h += h*32 + *s;
	}
	return h;
}

static Sym* sysv_lookup(const char* s, uint32_t h, struct dso* dso)
{
	size_t i;
	Sym* syms = dso->syms;
	Elf_Symndx* hashtab = dso->hashtab;
	char* strings = dso->strings;
	for(i=hashtab[2+h%hashtab[0]]; i; i=hashtab[2+hashtab[0]+i]) {
		if((!dso->versym || dso->versym[i] >= 0)
		   && (!strcmp(s, strings+syms[i].st_name))) {
			return syms+i;
		}
	}
	return 0;
}

static Sym* gnu_lookup(uint32_t h1, uint32_t* hashtab, struct dso* dso, const char* s)
{
	uint32_t nbuckets = hashtab[0];
	uint32_t* buckets = hashtab + 4 + hashtab[2]*(sizeof(size_t)/4);
	uint32_t i = buckets[h1 % nbuckets];

	if(!i) {
		return 0;
	}

	uint32_t* hashval = buckets + nbuckets + (i - hashtab[1]);

	for(h1 |= 1; ; i++) {
		uint32_t h2 = *hashval++;
		if((h1 == (h2|1)) && (!dso->versym || dso->versym[i] >= 0)
		   && !strcmp(s, dso->strings + dso->syms[i].st_name)) {
			return dso->syms+i;
		}
		if(h2 & 1) {
			break;
		}
	}

	return 0;
}

static Sym* gnu_lookup_filtered(uint32_t h1, uint32_t* hashtab, struct dso* dso, const char* s, uint32_t fofs, size_t fmask)
{
	const size_t* bloomwords = (const void*)(hashtab+4);
	size_t f = bloomwords[fofs & (hashtab[2]-1)];
	if(!(f & fmask)) {
		return 0;
	}

	f >>= (h1 >> hashtab[3]) % (8 * sizeof f);
	if(!(f & 1)) {
		return 0;
	}

	return gnu_lookup(h1, hashtab, dso, s);
}

#define OK_TYPES (1<<STT_NOTYPE | 1<<STT_OBJECT | 1<<STT_FUNC | 1<<STT_COMMON | 1<<STT_TLS)
#define OK_BINDS (1<<STB_GLOBAL | 1<<STB_WEAK | 1<<STB_GNU_UNIQUE)

#ifndef ARCH_SYM_REJECT_UND
#define ARCH_SYM_REJECT_UND(s) 0
#endif

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline struct symdef find_sym2(struct dso* dso, const char* s, int need_def, int use_deps)
{
	uint32_t h = 0, gh = gnu_hash(s), gho = gh / (8*sizeof(size_t)), *ght;
	size_t ghm = 1ul << gh % (8*sizeof(size_t));
	struct symdef def = {0};
	struct dso** deps = use_deps ? dso->deps : 0;
	for(; dso; dso=use_deps ? *deps++ : dso->syms_next) {
		Sym* sym;
		if((ght = dso->ghashtab)) {
			sym = gnu_lookup_filtered(gh, ght, dso, s, gho, ghm);
		}
		else {
			if(!h) {
				h = sysv_hash(s);
			}
			sym = sysv_lookup(s, h, dso);
		}
		if(!sym) {
			continue;
		}
		if(!sym->st_shndx)
			if(need_def || (sym->st_info&0xf) == STT_TLS
			   || ARCH_SYM_REJECT_UND(sym)) {
				continue;
			}
		if(!sym->st_value)
			if((sym->st_info&0xf) != STT_TLS) {
				continue;
			}
		if(!(1<<(sym->st_info&0xf) & OK_TYPES)) {
			continue;
		}
		if(!(1<<(sym->st_info>>4) & OK_BINDS)) {
			continue;
		}
		def.sym = sym;
		def.dso = dso;
		break;
	}
	return def;
}

static struct symdef find_sym(struct dso* dso, const char* s, int need_def)
{
	return find_sym2(dso, s, need_def, 0);
}

static void do_relocs(struct dso* dso, size_t* rel, size_t rel_size, size_t stride)
{
	unsigned char* base = dso->base;
	Sym* syms = dso->syms;
	char* strings = dso->strings;
	Sym* sym;
	const char* name;
	void* ctx;
	int type;
	int sym_index;
	struct symdef def;
	size_t* reloc_addr;
	size_t sym_val;
	size_t tls_val;
	size_t addend;
	int skip_relative = 0, reuse_addends = 0, save_slot = 0;

	if(dso == &ldso) {
		/* Only ldso's REL table needs addend saving/reuse. */
		if(rel == apply_addends_to) {
			reuse_addends = 1;
		}
		skip_relative = 1;
	}

	for(; rel_size; rel+=stride, rel_size-=stride*sizeof(size_t)) {
		if(skip_relative && IS_RELATIVE(rel[1], dso->syms)) {
			continue;
		}
		type = R_TYPE(rel[1]);
		if(type == REL_NONE) {
			continue;
		}
		reloc_addr = laddr(dso, rel[0]);

		if(stride > 2) {
			addend = rel[2];
		}
		else if(type==REL_GOT || type==REL_PLT|| type==REL_COPY) {
			addend = 0;
		}
		else if(reuse_addends) {
			/* Save original addend in stage 2 where the dso
			 * chain consists of just ldso; otherwise read back
			 * saved addend since the inline one was clobbered. */
			if(head==&ldso) {
				saved_addends[save_slot] = *reloc_addr;
			}
			addend = saved_addends[save_slot++];
		}
		else {
			addend = *reloc_addr;
		}

		sym_index = R_SYM(rel[1]);
		if(sym_index) {
			sym = syms + sym_index;
			name = strings + sym->st_name;
			ctx = type==REL_COPY ? head->syms_next : head;
			def = (sym->st_info>>4) == STB_LOCAL 
                ? (struct symdef) {.dso = dso, .sym = sym}
                : find_sym(ctx, name, type==REL_PLT); /* 找到符号所在的so，将信息放到def里 */
			if(!def.sym && (sym->st_shndx != SHN_UNDEF
			                || sym->st_info>>4 != STB_WEAK)) {
				if(dso->lazy && (type==REL_PLT || type==REL_GOT)) {
					dso->lazy[3*dso->lazy_cnt+0] = rel[0];
					dso->lazy[3*dso->lazy_cnt+1] = rel[1];
					dso->lazy[3*dso->lazy_cnt+2] = addend;
					dso->lazy_cnt++;
					continue;
				}
//				error("Error relocating %s: %s: symbol not found",
//					dso->name, name);
//				if (runtime) longjmp(*rtld_fail, 1);
				continue;
			}
		}
		else {
			sym = 0;
			def.sym = 0;
			def.dso = dso;
		}

		sym_val = def.sym ? (size_t)laddr(def.dso, def.sym->st_value) : 0;
		tls_val = def.sym ? def.sym->st_value : 0;

//		if ((type == REL_TPOFF || type == REL_TPOFF_NEG)
//		    && def.dso->tls_id > static_tls_cnt) {
//			error("Error relocating %s: %s: initial-exec TLS "
//				"resolves to dynamic definition in %s",
//				dso->name, name, def.dso->name);
//			longjmp(*rtld_fail, 1);
//		}

		switch(type) {
			case REL_OFFSET:
				addend -= (size_t)reloc_addr;
			case REL_SYMBOLIC:
			case REL_GOT:
			case REL_PLT:
				*reloc_addr = sym_val + addend;
				break;
			case REL_USYMBOLIC:
				memcpy(reloc_addr, &(size_t) {
					sym_val + addend
				}, sizeof(size_t)); /* 还没重定位OK能使用memcpy?? */
				break;
			case REL_RELATIVE:
				*reloc_addr = (size_t)base + addend;
				break;
			case REL_SYM_OR_REL:
				if(sym) {
					*reloc_addr = sym_val + addend;
				}
				else {
					*reloc_addr = (size_t)base + addend;
				}
				break;
			case REL_COPY:
				memcpy(reloc_addr, (void*)sym_val, sym->st_size);  /* 还没重定位OK能使用memcpy?? */
				break;
			case REL_OFFSET32:
				*(uint32_t*)reloc_addr = sym_val + addend
				                         - (size_t)reloc_addr;
				break;
			case REL_FUNCDESC:
				*reloc_addr = def.sym ? (size_t)(def.dso->funcdescs
				                                 + (def.sym - def.dso->syms)) : 0;
				break;
			case REL_FUNCDESC_VAL:
				if((sym->st_info&0xf) == STT_SECTION) {
					*reloc_addr += sym_val;
				}
				else {
					*reloc_addr = sym_val;
				}
				reloc_addr[1] = def.sym ? (size_t)def.dso->got : 0;
				break;
			case REL_DTPMOD:
				*reloc_addr = def.dso->tls_id;
				break;
#if 0
			case REL_DTPOFF:
				*reloc_addr = tls_val + addend - DTP_OFFSET;
				break;
#ifdef TLS_ABOVE_TP
			case REL_TPOFF:
				*reloc_addr = tls_val + def.dso->tls.offset + TPOFF_K + addend;
				break;
#else
			case REL_TPOFF:
				*reloc_addr = tls_val - def.dso->tls.offset + addend;
				break;
			case REL_TPOFF_NEG:
				*reloc_addr = def.dso->tls.offset - tls_val + addend;
				break;
#endif
			case REL_TLSDESC:
				if(stride<3) {
					addend = reloc_addr[1];
				}
				if(def.dso->tls_id > static_tls_cnt) {
					struct td_index* new = malloc(sizeof *new);
					if(!new) {
						error(
						    "Error relocating %s: cannot allocate TLSDESC for %s",
						    dso->name, sym ? name : "(local)");
						longjmp(*rtld_fail, 1);
					}
					new->next = dso->td_index;
					dso->td_index = new;
					new->args[0] = def.dso->tls_id;
					new->args[1] = tls_val + addend - DTP_OFFSET;
					reloc_addr[0] = (size_t)__tlsdesc_dynamic;
					reloc_addr[1] = (size_t)new;
				}
				else {
					reloc_addr[0] = (size_t)__tlsdesc_static;
#ifdef TLS_ABOVE_TP
					reloc_addr[1] = tls_val + def.dso->tls.offset
					                + TPOFF_K + addend;
#else
					reloc_addr[1] = tls_val - def.dso->tls.offset
					                + addend;
#endif
				}
#ifdef TLSDESC_BACKWARDS
				/* Some archs (32-bit ARM at least) invert the order of
				 * the descriptor members. Fix them up here. */
				size_t tmp = reloc_addr[0];
				reloc_addr[0] = reloc_addr[1];
				reloc_addr[1] = tmp;
#endif
				break;

#endif
			default:
//			error("Error relocating %s: unsupported relocation type %d",
//				dso->name, type);   /* 还没重定位OK能使用error?? */
//			if (runtime) longjmp(*rtld_fail, 1);
				continue;
		}
	}
}

static void reloc_all(struct dso* p)
{
	size_t dyn[DYN_CNT];
	for(; p; p=p->next) {
		if(p->relocated) {
			continue;
		}
		decode_vec(p->dynv, dyn, DYN_CNT);
//		if (NEED_MIPS_GOT_RELOCS)
//			do_mips_relocs(p, laddr(p, dyn[DT_PLTGOT]));
		do_relocs(p, laddr(p, dyn[DT_JMPREL]), dyn[DT_PLTRELSZ],
		          2+(dyn[DT_PLTREL]==DT_RELA)); /* rel.plt */
		do_relocs(p, laddr(p, dyn[DT_REL]), dyn[DT_RELSZ], 2); /* rel.dyn */
		do_relocs(p, laddr(p, dyn[DT_RELA]), dyn[DT_RELASZ], 3); /* rel.dyn */


		/* TODO */
//		if (head != &ldso && p->relro_start != p->relro_end &&
//		    mprotect(laddr(p, p->relro_start), p->relro_end-p->relro_start, PROT_READ)
//		    && errno != ENOSYS) {
//			error("Error relocating %s: RELRO protection failed: %m",
//				p->name);
//			if (runtime) longjmp(*rtld_fail, 1);
//		}

		p->relocated = 1;
	}
}

int isspace(int c)
{
	return c == ' ' || (unsigned)c-'\t' < 5;
}

static int path_open(const char* name, const char* s, char* buf, size_t buf_size)
{
	size_t l;
	int fd;
	for(;;) {
		s += strspn(s, ":\n");
		l = strcspn(s, ":\n");
		if(l-1 >= INT_MAX) {
			return -1;
		}
		if(snprintf(buf, buf_size, "%.*s/%s", (int)l, s, name) < buf_size) {
			if((fd = open(buf, O_RDONLY|O_CLOEXEC))>=0) {
				return fd;
			}
			switch(errno) {
				case ENOENT:
				case ENOTDIR:
				case EACCES:
				case ENAMETOOLONG:
					break;
				default:
					/* Any negative value but -1 will inhibit
					 * futher path search. */
					return -2;
			}
		}
		s += l;
	}
}

static struct dso** queue_ctors(struct dso* dso)
{
	size_t cnt, qpos, spos, i;
	struct dso* p, **queue, **stack;

	if(ldd_mode) {
		return 0;
	}

	/* Bound on queue size is the total number of indirect deps.
	 * If a bfs deps list was built, we can use it. Otherwise,
	 * bound by the total number of DSOs, which is always safe and
	 * is reasonable we use it (for main app at startup). */
	if(dso->bfs_built) {
		for(cnt=0; dso->deps[cnt]; cnt++) {
			dso->deps[cnt]->mark = 0;
		}
		cnt++; /* self, not included in deps */
	}
	else {
		for(cnt=0, p=head; p; cnt++, p=p->next) {
			p->mark = 0;
		}
	}
	cnt++; /* termination slot */
	if(dso==head && cnt <= countof(builtin_ctor_queue)) {
		queue = builtin_ctor_queue;
	}
	else {
		queue = calloc(cnt, sizeof *queue);
	}

	if(!queue) {
		printf("\n!!!Error!!! allocating constructor queue: %m\n");
//		if (runtime) longjmp(*rtld_fail, 1);
		return 0;
	}

	/* Opposite ends of the allocated buffer serve as an output queue
	 * and a working stack. Setup initial stack with just the argument
	 * dso and initial queue empty... */
	stack = queue;
	qpos = 0;
	spos = cnt;
	stack[--spos] = dso;
	dso->next_dep = 0;
	dso->mark = 1;

	/* Then perform pseudo-DFS sort, but ignoring circular deps. */
	while(spos<cnt) {
		p = stack[spos++];
		while(p->next_dep < p->ndeps_direct) {
			if(p->deps[p->next_dep]->mark) {
				p->next_dep++;
			}
			else {
				stack[--spos] = p;
				p = p->deps[p->next_dep];
				p->next_dep = 0;
				p->mark = 1;
			}
		}
		queue[qpos++] = p;
	}
	queue[qpos] = 0;
	for(i=0; i<qpos; i++) {
		queue[i]->mark = 0;
	}
//	for (i=0; i<qpos; i++)
//		if (queue[i]->ctor_visitor && queue[i]->ctor_visitor->tid < 0) {
//			printf("\n!!!Error!!! State of %s is inconsistent due to multithreaded fork\n",
//				queue[i]->name);
//			free(queue);
//			if (runtime) longjmp(*rtld_fail, 1);
//		}

	return queue;
}

static int fixup_rpath(struct dso* p, char* buf, size_t buf_size)
{
	size_t n, l;
	const char* s, *t, *origin;
	char* d;
	if(p->rpath || !p->rpath_orig) {
		return 0;
	}
	if(!strchr(p->rpath_orig, '$')) {
		p->rpath = p->rpath_orig;
		return 0;
	}
	n = 0;
	s = p->rpath_orig;
	while((t=strchr(s, '$'))) {
		if(strncmp(t, "$ORIGIN", 7) && strncmp(t, "${ORIGIN}", 9)) {
			return 0;
		}
		s = t+1;
		n++;
	}
	if(n > SSIZE_MAX/PATH_MAX) {
		return 0;
	}

	if(p->kernel_mapped) {
		/* $ORIGIN searches cannot be performed for the main program
		 * when it is suid/sgid/AT_SECURE. This is because the
		 * pathname is under the control of the caller of execve.
		 * For libraries, however, $ORIGIN can be processed safely
		 * since the library's pathname came from a trusted source
		 * (either system paths or a call to dlopen). */
//		if (libc.secure)
//			return 0;
		l = readlink("/proc/self/exe", buf, buf_size);
		if(l == -1)
			switch(errno) {
				case ENOENT:
				case ENOTDIR:
				case EACCES:
					break;
				default:
					return -1;
			}
		if(l >= buf_size) {
			return 0;
		}
		buf[l] = 0;
		origin = buf;
	}
	else {
		origin = p->name;
	}
	t = strrchr(origin, '/');
	if(t) {
		l = t-origin;
	}
	else {
		/* Normally p->name will always be an absolute or relative
		 * pathname containing at least one '/' character, but in the
		 * case where ldso was invoked as a command to execute a
		 * program in the working directory, app.name may not. Fix. */
		origin = ".";
		l = 1;
	}
	/* Disallow non-absolute origins for suid/sgid/AT_SECURE. */
//	if (libc.secure && *origin != '/')
//		return 0;
	p->rpath = malloc(strlen(p->rpath_orig) + n*l + 1);
	if(!p->rpath) {
		return -1;
	}

	d = p->rpath;
	s = p->rpath_orig;
	while((t=strchr(s, '$'))) {
		memcpy(d, s, t-s);
		d += t-s;
		memcpy(d, origin, l);
		d += l;
		/* It was determined previously that the '$' is followed
		 * either by "ORIGIN" or "{ORIGIN}". */
		s = t + 7 + 2*(t[1]=='{');
	}
	strcpy(d, s);
	return 0;
}

static ssize_t read_loop(int fd, void* p, size_t n)
{
	for(size_t i=0; i<n;) {
		ssize_t l = read(fd, (char*)p+i, n-i);
		if(l<0) {
//			if (errno==EINTR) continue;
//			else return -1;
			return -1;
		}
		if(l==0) {
			return i;
		}
		i += l;
	}
	return n;
}

static struct dso* load_library(const char* name, struct dso* needed_by)
{
	char buf[2*NAME_MAX+2];
	const char* pathname;
	unsigned char* map;
	struct dso* p, temp_dso = {0};
	int fd;
	struct stat st;
	size_t alloc_size;
	int n_th = 0;
	int is_self = 0;

	if(!*name) {
//		errno = EINVAL;
		return 0;
	}

	/* Catch and block attempts to reload the implementation itself */
	if(name[0]=='l' && name[1]=='i' && name[2]=='b') {
		static const char reserved[] =
		    "c.pthread.rt.m.dl.util.xnet.";
		const char* rp, *next;
		for(rp=reserved; *rp; rp=next) {
			next = strchr(rp, '.') + 1;
			if(strncmp(name+3, rp, next-rp) == 0) {
				break;
			}
		}
		if(*rp) {
			if(ldd_mode) {
				/* Track which names have been resolved
				 * and only report each one once. */
				static unsigned reported;
				unsigned mask = 1U<<(rp-reserved);
				if(!(reported & mask)) {
					reported |= mask;
					printf("\t%s => %s (%p)\n", name, ldso.name, ldso.base);
				}
			}
			is_self = 1;
		}
	}
	if(!strcmp(name, ldso.name)) {
		is_self = 1;
	}
	if(is_self) {
		if(!ldso.prev) {
			tail->next = &ldso;
			ldso.prev = tail;
			tail = &ldso;
		}
		return &ldso;
	}
	if(strchr(name, '/')) {
		pathname = name;
		fd = open(name, O_RDONLY|O_CLOEXEC);
	}
	else {
		/* Search for the name to see if it's already loaded */
		for(p=head->next; p; p=p->next) {
			if(p->shortname && !strcmp(p->shortname, name)) {
				return p;
			}
		}
		if(strlen(name) > NAME_MAX) {
			return 0;
		}
		fd = -1;
		if(env_path) {
			fd = path_open(name, env_path, buf, sizeof buf);
		}
		for(p=needed_by; fd == -1 && p; p=p->needed_by) {
			if(fixup_rpath(p, buf, sizeof buf) < 0) {
				fd = -2;    /* Inhibit further search. */
			}
			if(p->rpath) {
				fd = path_open(name, p->rpath, buf, sizeof buf);
			}
		}
		if(fd == -1) {
			if(!sys_path) {
				char* prefix = 0;
				size_t prefix_len;
				if(ldso.name[0]=='/') {
					char* s, *t, *z;
					for(s=t=z=ldso.name; *s; s++)
						if(*s=='/') {
							z=t, t=s;
						}
					prefix_len = z-ldso.name;
					if(prefix_len < PATH_MAX) {
						prefix = ldso.name;
					}
				}
				if(!prefix) {
					prefix = "";
					prefix_len = 0;
				}
				char etc_ldso_path[prefix_len + 1
				                              + sizeof "/etc/ld-musl-" LDSO_ARCH ".path"];
				snprintf(etc_ldso_path, sizeof etc_ldso_path,
				         "%.*s/etc/ld-musl-" LDSO_ARCH ".path",
				         (int)prefix_len, prefix);
				fd = open(etc_ldso_path, O_RDONLY|O_CLOEXEC);
				if(fd>=0) {
					size_t n = 0;
					if(!fstat(fd, &st)) {
						n = st.st_size;
					}
					if((sys_path = malloc(n+1))) {
						sys_path[n] = 0;
					}
					if(!sys_path || read_loop(fd, sys_path, n)<0) {
						free(sys_path);
						sys_path = "";
					}
					close(fd);
				}
				else if(errno != ENOENT) {
					sys_path = "";
				}
			}
			if(!sys_path) {
				sys_path = "/lib:/usr/local/lib:/usr/lib";
			}
			fd = path_open(name, sys_path, buf, sizeof buf);
		}
		pathname = buf;
	}
	if(fd < 0) {
		return 0;
	}
	if(fstat(fd, &st) < 0) {
		close(fd);
		return 0;
	}
	for(p=head->next; p; p=p->next) {
		if(p->dev == st.st_dev && p->ino == st.st_ino) {
			/* If this library was previously loaded with a
			 * pathname but a search found the same inode,
			 * setup its shortname so it can be found by name. */
			if(!p->shortname && pathname != name) {
				p->shortname = strrchr(p->name, '/')+1;
			}
			close(fd);
			return p;
		}
	}
	map = noload ? 0 : map_library(fd, &temp_dso);
	close(fd);
	if(!map) {
		return 0;
	}

	/* Avoid the danger of getting two versions of libc mapped into the
	 * same process when an absolute pathname was used. The symbols
	 * checked are chosen to catch both musl and glibc, and to avoid
	 * false positives from interposition-hack libraries. */
	decode_dyn(&temp_dso);
	if(find_sym(&temp_dso, "__libc_start_main", 1).sym &&
	   find_sym(&temp_dso, "stdin", 1).sym) {
		unmap_library(&temp_dso);
		return load_library("libc.so", needed_by);
	}
	/* Past this point, if we haven't reached runtime yet, ldso has
	 * committed either to use the mapped library or to abort execution.
	 * Unmapping is not possible, so we can safely reclaim gaps. */
//	if (!runtime) reclaim_gaps(&temp_dso);

	/* Allocate storage for the new DSO. When there is TLS, this
	 * storage must include a reservation for all pre-existing
	 * threads to obtain copies of both the new TLS, and an
	 * extended DTV capable of storing an additional slot for
	 * the newly-loaded DSO. */
	alloc_size = sizeof *p + strlen(pathname) + 1;
//	if (runtime && temp_dso.tls.image) {
//		size_t per_th = temp_dso.tls.size + temp_dso.tls.align
//			+ sizeof(void *) * (tls_cnt+3);
//		n_th = libc.threads_minus_1 + 1;
//		if (n_th > SSIZE_MAX / per_th) alloc_size = SIZE_MAX;
//		else alloc_size += n_th * per_th;
//	}
	p = calloc(1, alloc_size);
	if(!p) {
		unmap_library(&temp_dso);
		return 0;
	}
	memcpy(p, &temp_dso, sizeof temp_dso);
	p->dev = st.st_dev;
	p->ino = st.st_ino;
	p->needed_by = needed_by;
	p->name = p->buf;
//	p->runtime_loaded = runtime;
	strcpy(p->name, pathname);
	/* Add a shortname only if name arg was not an explicit pathname. */
	if(pathname != name) {
		p->shortname = strrchr(p->name, '/')+1;
	}
//	if (p->tls.image) {
//		p->tls_id = ++tls_cnt;
//		tls_align = MAXP2(tls_align, p->tls.align);
//#ifdef TLS_ABOVE_TP
//		p->tls.offset = tls_offset + ( (p->tls.align-1) &
//			(-tls_offset + (uintptr_t)p->tls.image) );
//		tls_offset = p->tls.offset + p->tls.size;
//#else
//		tls_offset += p->tls.size + p->tls.align - 1;
//		tls_offset -= (tls_offset + (uintptr_t)p->tls.image)
//			& (p->tls.align-1);
//		p->tls.offset = tls_offset;
//#endif
//		p->new_dtv = (void *)(-sizeof(size_t) &
//			(uintptr_t)(p->name+strlen(p->name)+sizeof(size_t)));
//		p->new_tls = (void *)(p->new_dtv + n_th*(tls_cnt+1));
//		if (tls_tail) tls_tail->next = &p->tls;
//		else libc.tls_head = &p->tls;
//		tls_tail = &p->tls;
//	}

	tail->next = p;
	p->prev = tail;
	tail = p;

//	if (DL_FDPIC) makefuncdescs(p);

	if(ldd_mode) {
		printf("\t%s => %s (%p)\n", name, pathname, p->base);
	}

	return p;
}

static void load_preload(char* s)
{
	int tmp;
	char* z;
	for(z=s; *z; s=z) {
		for(; *s && (isspace(*s) || *s==':'); s++);
		for(z=s; *z && !isspace(*z) && *z!=':'; z++);
		tmp = *z;
		*z = 0;
		load_library(s, 0);
		*z = tmp;
	}
}

static void reclaim_gaps(struct dso* dso)
{
	Phdr* ph = dso->phdr;
	size_t phcnt = dso->phnum;

	for(; phcnt--; ph=(void*)((char*)ph+dso->phentsize)) {
		if(ph->p_type!=PT_LOAD) {
			continue;
		}
		if((ph->p_flags&(PF_R|PF_W))!=(PF_R|PF_W)) {
			continue;
		}

		/* TODO: */
//		reclaim(dso, ph->p_vaddr & -PAGE_SIZE, ph->p_vaddr);
//		reclaim(dso, ph->p_vaddr+ph->p_memsz,
//			ph->p_vaddr+ph->p_memsz+PAGE_SIZE-1 & -PAGE_SIZE);
	}
}

static void unmap_library(struct dso* dso)
{
	if(dso->map && dso->map_len) {
		munmap(dso->map, dso->map_len);
	}
}

static void* mmap_fixed(void* p, size_t n, int prot, int flags, int fd, off_t off)
{
	static int no_map_fixed;
	char* q;
	if(!n) {
		return p;
	}
	if(!no_map_fixed) {
		q = mmap(p, n, prot, flags|MAP_FIXED, fd, off);
		if(!DL_NOMMU_SUPPORT || q != MAP_FAILED || errno != EINVAL) {
			return q;
		}
		no_map_fixed = 1;
	}
	/* Fallbacks for MAP_FIXED failure on NOMMU kernels. */
	if(flags & MAP_ANONYMOUS) {
		memset(p, 0, n);
		return p;
	}
	ssize_t r;
	if(lseek(fd, off, SEEK_SET) < 0) {
		return MAP_FAILED;
	}
	for(q=p; n; q+=r, off+=r, n-=r) {
		r = read(fd, q, n);
		if(r < 0 /* && errno != EINTR */) {
			return MAP_FAILED;
		}
		if(!r) {
			memset(q, 0, n);
			break;
		}
	}
	return p;
}

static void* map_library(int fd, struct dso* dso)
{
	Ehdr buf[(896+sizeof(Ehdr))/sizeof(Ehdr)];
	void* allocated_buf=0;
	size_t phsize;
	size_t addr_min=SIZE_MAX, addr_max=0, map_len;
	size_t this_min, this_max;
	size_t nsegs = 0;
	off_t off_start;
	Ehdr* eh;
	Phdr* ph, *ph0;
	unsigned prot;
	unsigned char* map=MAP_FAILED, *base;
	size_t dyn=0;
	size_t tls_image=0;
	size_t i;

	ssize_t l = read(fd, buf, sizeof buf);
	eh = buf;
	if(l<0) {
		return 0;
	}
	if(l<sizeof *eh || (eh->e_type != ET_DYN && eh->e_type != ET_EXEC)) {
		goto noexec;
	}
	phsize = eh->e_phentsize * eh->e_phnum;
	if(phsize > sizeof buf - sizeof *eh) {
		allocated_buf = malloc(phsize);
		if(!allocated_buf) {
			return 0;
		}
		l = pread(fd, allocated_buf, phsize, eh->e_phoff);
		if(l < 0) {
			goto error;
		}
		if(l != phsize) {
			goto noexec;
		}
		ph = ph0 = allocated_buf;
	}
	else if(eh->e_phoff + phsize > l) {
		l = pread(fd, buf+1, phsize, eh->e_phoff);
		if(l < 0) {
			goto error;
		}
		if(l != phsize) {
			goto noexec;
		}
		ph = ph0 = (void*)(buf + 1);
	}
	else {
		ph = ph0 = (void*)((char*)buf + eh->e_phoff);
	}
	for(i=eh->e_phnum; i; i--, ph=(void*)((char*)ph+eh->e_phentsize)) {
		if(ph->p_type == PT_DYNAMIC) {
			dyn = ph->p_vaddr;
		}
		else if(ph->p_type == PT_TLS) {
//			tls_image = ph->p_vaddr;
//			dso->tls.align = ph->p_align;
//			dso->tls.len = ph->p_filesz;
//			dso->tls.size = ph->p_memsz;
		}
		else if(ph->p_type == PT_GNU_RELRO) {
			dso->relro_start = ph->p_vaddr & -PAGE_SIZE;
			dso->relro_end = (ph->p_vaddr + ph->p_memsz) & -PAGE_SIZE;
		}
		else if(ph->p_type == PT_GNU_STACK) {
//			if (!runtime && ph->p_memsz > __default_stacksize) {
//				__default_stacksize =
//					ph->p_memsz < DEFAULT_STACK_MAX ?
//					ph->p_memsz : DEFAULT_STACK_MAX;
//			}
		}
		if(ph->p_type != PT_LOAD) {
			continue;
		}
		nsegs++;
		if(ph->p_vaddr < addr_min) {
			addr_min = ph->p_vaddr;
			off_start = ph->p_offset;
			prot = (((ph->p_flags&PF_R) ? PROT_READ : 0) |
			        ((ph->p_flags&PF_W) ? PROT_WRITE: 0) |
			        ((ph->p_flags&PF_X) ? PROT_EXEC : 0));
		}
		if(ph->p_vaddr+ph->p_memsz > addr_max) {
			addr_max = ph->p_vaddr+ph->p_memsz;
		}
	}
	if(!dyn) {
		goto noexec;
	}

	addr_max += PAGE_SIZE-1;
	addr_max &= -PAGE_SIZE;
	addr_min &= -PAGE_SIZE;
	off_start &= -PAGE_SIZE;
	map_len = addr_max - addr_min + off_start;
	/* The first time, we map too much, possibly even more than
	 * the length of the file. This is okay because we will not
	 * use the invalid part; we just need to reserve the right
	 * amount of virtual address space to map over later. */
	map = DL_NOMMU_SUPPORT
	      ? mmap((void*)addr_min, map_len, PROT_READ|PROT_WRITE|PROT_EXEC,
	             MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
	      : mmap((void*)addr_min, map_len, prot,
	             MAP_PRIVATE, fd, off_start);
	if(map==MAP_FAILED) {
		goto error;
	}
	dso->map = map;
	dso->map_len = map_len;
	/* If the loaded file is not relocatable and the requested address is
	 * not available, then the load operation must fail. */
	if(eh->e_type != ET_DYN && addr_min && map!=(void*)addr_min) {
		errno = EBUSY;
		goto error;
	}
	base = map - addr_min;
	dso->phdr = 0;
	dso->phnum = 0;
	for(ph=ph0, i=eh->e_phnum; i; i--, ph=(void*)((char*)ph+eh->e_phentsize)) {
		if(ph->p_type != PT_LOAD) {
			continue;
		}
		/* Check if the programs headers are in this load segment, and
		 * if so, record the address for use by dl_iterate_phdr. */
		if(!dso->phdr && eh->e_phoff >= ph->p_offset
		   && eh->e_phoff+phsize <= ph->p_offset+ph->p_filesz) {
			dso->phdr = (void*)(base + ph->p_vaddr
			                    + (eh->e_phoff-ph->p_offset));
			dso->phnum = eh->e_phnum;
			dso->phentsize = eh->e_phentsize;
		}
		this_min = ph->p_vaddr & -PAGE_SIZE;
		this_max = ph->p_vaddr+ph->p_memsz+PAGE_SIZE-1 & -PAGE_SIZE;
		off_start = ph->p_offset & -PAGE_SIZE;
		prot = (((ph->p_flags&PF_R) ? PROT_READ : 0) |
		        ((ph->p_flags&PF_W) ? PROT_WRITE: 0) |
		        ((ph->p_flags&PF_X) ? PROT_EXEC : 0));
		/* Reuse the existing mapping for the lowest-address LOAD */
		if((ph->p_vaddr & -PAGE_SIZE) != addr_min || DL_NOMMU_SUPPORT)
			if(mmap_fixed(base+this_min, this_max-this_min, prot, MAP_PRIVATE|MAP_FIXED, fd, off_start) == MAP_FAILED) {
				goto error;
			}
		if(ph->p_memsz > ph->p_filesz && (ph->p_flags&PF_W)) {
			size_t brk = (size_t)base+ph->p_vaddr+ph->p_filesz;
			size_t pgbrk = brk+PAGE_SIZE-1 & -PAGE_SIZE;
			memset((void*)brk, 0, pgbrk-brk & PAGE_SIZE-1);
			if(pgbrk-(size_t)base < this_max && mmap_fixed((void*)pgbrk, (size_t)base+this_max-pgbrk, prot, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
				goto error;
			}
		}
	}
	for(i=0; ((size_t*)(base+dyn))[i]; i+=2)
		if(((size_t*)(base+dyn))[i]==DT_TEXTREL) {
			if(mprotect(map, map_len, PROT_READ|PROT_WRITE|PROT_EXEC)
			   && errno != ENOSYS) {
				goto error;
			}
			break;
		}
done_mapping:
	dso->base = base;
	dso->dynv = laddr(dso, dyn);
//	if (dso->tls.size) dso->tls.image = laddr(dso, tls_image);
	free(allocated_buf);
	return map;
noexec:
//	errno = ENOEXEC;
error:
	if(map!=MAP_FAILED) {
		unmap_library(dso);
	}
	free(allocated_buf);
	return 0;
}

hidden void __dls2(unsigned char* base, size_t* sp)
{
	size_t i = 0;
	size_t j = 0;

	size_t* auxv;
	for(auxv=sp+1+*sp+1; *auxv; auxv++); /* 移动过环境变量 */
	auxv++; /* 跳过环境变量后面的0 */

	ldso.base = base;
	Ehdr* ehdr = (void*)ldso.base;
	ldso.name = ldso.shortname = "libc.so";
	ldso.phnum = ehdr->e_phnum;
	ldso.phdr = laddr(&ldso, ehdr->e_phoff);
	ldso.phentsize = ehdr->e_phentsize;
	kernel_mapped_dso(&ldso);
	decode_dyn(&ldso);

	/* Prepare storage for to save clobbered REL addends so they
	 * can be reused in stage 3. There should be very few. If
	 * something goes wrong and there are a huge number, abort
	 * instead of risking stack overflow. */
	size_t dyn[DYN_CNT];
	decode_vec(ldso.dynv, dyn, DYN_CNT);
	size_t* rel = laddr(&ldso, dyn[DT_REL]);
	size_t rel_size = dyn[DT_RELSZ];
	size_t symbolic_rel_cnt = 0;
	apply_addends_to = rel;
	for(; rel_size; rel+=2, rel_size-=2*sizeof(size_t))
		if(!IS_RELATIVE(rel[1], ldso.syms)) {
			symbolic_rel_cnt++;
		}
	if(symbolic_rel_cnt >= ADDEND_LIMIT) {
		a_crash();
	}
	size_t addends[symbolic_rel_cnt+1];
	saved_addends = addends;

	head = &ldso;
	reloc_all(&ldso);

	ldso.relocated = 0;

	/* !!! Now life is sane; we can call functions and access global data. !!!
	rela.dyn R_X86_64_GLOB_DAT */
	mod0_var = 1; /* yes, we can access test var: mod0_var */
	printf("\n\nCongratulation! Life is sane now, we can call functions and access global data! \n\n");
	mod0_test_func0();
    printf("\nmod0_var:%d\n", mod0_var);
//    _exit(0);    
//	return;


	/* Call dynamic linker stage-2b, __dls2b, looking it up
	 * symbolically as a barrier against moving the address
	 * load across the above relocation processing. */
	struct symdef dls2b_def = find_sym(&ldso, "__dls2b", 0);
	((stage3_func)laddr(&ldso, dls2b_def.sym->st_value))(sp, auxv);

	/* this method is also ok */
//    stage3_func dls2b;
//    GETFUNCSYM(&dls2b, __dls2b);
//    dls2b(sp, auxv);
}

/* Stage 2b sets up a valid thread pointer, which requires relocations
 * completed in stage 2, and on which stage 3 is permitted to depend.
 * This is done as a separate stage, with symbolic lookup as a barrier,
 * so that loads of the thread pointer and &errno can be pure/const and
 * thereby hoistable. */

void __dls2b(size_t* sp, size_t* auxv)
{
	/* Setup early thread pointer in builtin_tls for ldso/libc itself to
	 * use during dynamic linking. If possible it will also serve as the
	 * thread pointer at runtime. */
//	search_vec(auxv, &__hwcap, AT_HWCAP);
//	libc.auxv = auxv;
//	libc.tls_size = sizeof builtin_tls;
//	libc.tls_align = tls_align;
//	if (__init_tp(__copy_tls((void *)builtin_tls)) < 0) {
//		a_crash();
//	}

//	struct symdef dls3_def = find_sym(&ldso, "__dls3", 0);
//	if (DL_FDPIC) ((stage3_func)&ldso.funcdescs[dls3_def.sym-ldso.syms])(sp, auxv);
//	else ((stage3_func)laddr(&ldso, dls3_def.sym->st_value))(sp, auxv);


	/* well, we dont need it at present, just next step */
	struct symdef dls3_def = find_sym(&ldso, "__dls3", 0);
	((stage3_func)laddr(&ldso, dls3_def.sym->st_value))(sp, auxv);
}

static void load_direct_deps(struct dso* p)
{
	size_t i, cnt=0;

	if(p->deps) {
		return;
	}
	/* For head, all preloads are direct pseudo-dependencies.
	 * Count and include them now to avoid realloc later. */
	if(p==head)
		for(struct dso* q=p->next; q; q=q->next) {
			cnt++;
		}
	for(i=0; p->dynv[i]; i+=2)
		if(p->dynv[i] == DT_NEEDED) {
			cnt++;
		}
	/* Use builtin buffer for apps with no external deps, to
	 * preserve property of no runtime failure paths. */
	p->deps = (p==head && cnt<2) ? builtin_deps :
	          calloc(cnt+1, sizeof *p->deps);
	if(!p->deps) {
		printf("\n!!!Error!!! loading dependencies for %s\n", p->name);
//		if (runtime) longjmp(*rtld_fail, 1);
	}
	cnt=0;
	if(p==head)
		for(struct dso* q=p->next; q; q=q->next) {
			p->deps[cnt++] = q;
		}
	for(i=0; p->dynv[i]; i+=2) {
		if(p->dynv[i] != DT_NEEDED) {
			continue;
		}
		struct dso* dep = load_library(p->strings + p->dynv[i+1], p);
		if(!dep) {
			printf("\n!!!Error!!! loading shared library %s: %m (needed by %s)\n",
			       p->strings + p->dynv[i+1], p->name);
//			if (runtime) longjmp(*rtld_fail, 1);
			continue;
		}
		p->deps[cnt++] = dep;
	}
	p->deps[cnt] = 0;
	p->ndeps_direct = cnt;
}

static void load_deps(struct dso* p)
{
	if(p->deps) {
		return;
	}
	for(; p; p=p->next) {
		load_direct_deps(p);
	}
}

static void add_syms(struct dso* p)
{
	if(!p->syms_next && syms_tail != p) {
		syms_tail->syms_next = p;
		syms_tail = p;
	}
}

static void dl_debug_state(void)
{
}
weak_alias(dl_debug_state, _dl_debug_state);

enum { RT_CONSISTENT, RT_ADD, RT_DELETE } r_state;

/* Stage 3 of the dynamic linker is called with the dynamic linker/libc
 * fully functional. Its job is to load (if not already loaded) and
 * process dependencies and relocations for the main application and
 * transfer control to its entry point. */
void __dls3(size_t* sp, size_t* auxv)
{
	static struct dso app, vdso;
	size_t aux[AUX_CNT];
	size_t i;
	char* env_preload=0;
	char* replace_argv0=0;
	size_t vdso_base;
	int argc = *sp;
	char** argv = (void*)(sp+1);
	char** argv_orig = argv;
	char** envp = argv+argc+1;

	decode_vec(auxv, aux, AUX_CNT);

	/* If the main program was already loaded by the kernel,
	 * AT_PHDR will point to some location other than the dynamic
	 * linker's program headers. */
	/* aux[AT_PHDR] is main-program program-header addr */
	if(aux[AT_PHDR] != (size_t)ldso.phdr) {  /* this is app program */
		size_t interp_off = 0;
		size_t tls_image = 0;
		/* Find load address of the main program, via AT_PHDR vs PT_PHDR. */
		Phdr* phdr = app.phdr = (void*)aux[AT_PHDR];
		app.phnum = aux[AT_PHNUM];
		app.phentsize = aux[AT_PHENT];
		for(i=aux[AT_PHNUM]; i; i--, phdr=(void*)((char*)phdr + aux[AT_PHENT])) {
			if(phdr->p_type == PT_PHDR) {
				app.base = (void*)(aux[AT_PHDR] - phdr->p_vaddr);
			}
			else if(phdr->p_type == PT_INTERP) {
				interp_off = (size_t)phdr->p_vaddr;
			}
			else if(phdr->p_type == PT_TLS) {
//				tls_image = phdr->p_vaddr; /* yes, we dont deal them now */
//				app.tls.len = phdr->p_filesz;
//				app.tls.size = phdr->p_memsz;
//				app.tls.align = phdr->p_align;
			}
		}
//        if (app.tls.size) app.tls.image = laddr(&app, tls_image);
		if(interp_off) {
			ldso.name = laddr(&app, interp_off);
		}
		if((aux[0] & (1UL<<AT_EXECFN))
		   && strncmp((char*)aux[AT_EXECFN], "/proc/", 6)) {
			app.name = (char*)aux[AT_EXECFN];
		}
		else {
			app.name = argv[0];    /* prog arg0 arg1 ... */
		}
		kernel_mapped_dso(&app);
	}
	else { /* this is ld itself */
		int fd;
		char* ldname = argv[0];
		size_t l = strlen(ldname);
		if(l >= 3 && !strcmp(ldname+l-3, "ldd")) {
			ldd_mode = 1;
		}
		argv++;
		while(argv[0] && argv[0][0]=='-' && argv[0][1]=='-') {
			char* opt = argv[0]+2;
			*argv++ = (void*)-1;
			if(!*opt) {
				break;
			}
			else if(!memcmp(opt, "list", 5)) {
				ldd_mode = 1;
			}
			else if(!memcmp(opt, "library-path", 12)) {
				if(opt[12]=='=') {
					env_path = opt+13;
				}
				else if(opt[12]) {
					*argv = 0;
				}
				else if(*argv) {
					env_path = *argv++;
				}
			}
			else if(!memcmp(opt, "preload", 7)) {
				if(opt[7]=='=') {
					env_preload = opt+8;
				}
				else if(opt[7]) {
					*argv = 0;
				}
				else if(*argv) {
					env_preload = *argv++;
				}
			}
			else if(!memcmp(opt, "argv0", 5)) {
				if(opt[5]=='=') {
					replace_argv0 = opt+6;
				}
				else if(opt[5]) {
					*argv = 0;
				}
				else if(*argv) {
					replace_argv0 = *argv++;
				}
			}
			else {
				argv[0] = 0;
			}
		}

		argv[-1] = (void*)(argc - (argv-argv_orig));
		if(!argv[0]) {
//			dprintf(2, "musl libc (" LDSO_ARCH ")\n"
//				"Version %s\n"
//				"Dynamic Program Loader\n"
//				"Usage: %s [options] [--] pathname%s\n",
//				__libc_version, ldname,
//				ldd_mode ? "" : " [args]");
			printf("\n!!!Error!!! musl libc (" LDSO_ARCH ")\n"
			       "Version %s\n"
			       "Dynamic Program Loader\n"
			       "Usage: %s [options] [--] pathname%s\n",
			       __libc_version, ldname,
			       ldd_mode ? "" : " [args]");

			_exit(1);
		}
		fd = open(argv[0], O_RDONLY); /* such as: ldd /bin/ls */
		if(fd < 0) {
			printf("\n!!!Error!!! %s: cannot load %s\n", ldname, argv[0]);
			_exit(1);
		}
		Ehdr* ehdr = map_library(fd, &app);
		if(!ehdr) {
			printf("\n!!!Error!!! %s: %s: Not a valid dynamic program\n", ldname, argv[0]);
			_exit(1);
		}
		close(fd);
		ldso.name = ldname;
		app.name = argv[0];
		aux[AT_ENTRY] = (size_t)laddr(&app, ehdr->e_entry);
		/* Find the name that would have been used for the dynamic
		 * linker had ldd not taken its place. */
		if(ldd_mode) {
			for(i=0; i<app.phnum; i++) {
				if(app.phdr[i].p_type == PT_INTERP) {
					ldso.name = laddr(&app, app.phdr[i].p_vaddr);
				}
			}
			printf("\n\t%s (%p)\n", ldso.name, ldso.base);
		}
	}

//    if (app.tls.size) {
//        libc.tls_head = tls_tail = &app.tls;
//        app.tls_id = tls_cnt = 1;
//#ifdef TLS_ABOVE_TP
//        app.tls.offset = GAP_ABOVE_TP;
//        app.tls.offset += (-GAP_ABOVE_TP + (uintptr_t)app.tls.image)
//            & (app.tls.align-1);
//        tls_offset = app.tls.offset + app.tls.size;
//#else
//        tls_offset = app.tls.offset = app.tls.size
//            + ( -((uintptr_t)app.tls.image + app.tls.size)
//            & (app.tls.align-1) );
//#endif
//        tls_align = MAXP2(tls_align, app.tls.align);
//    }
	decode_dyn(&app);

	/* Initial dso chain consists only of the app. */
	head = tail = syms_tail = &app;

	/* Donate unused parts of app and library mapping to malloc */
//	reclaim_gaps(&app);
//	reclaim_gaps(&ldso);

	/* Load preload/needed libraries, add symbols to global namespace. */
	ldso.deps = (struct dso**)no_deps;
	if(env_preload) {
		load_preload(env_preload);
	}
	load_deps(&app);
	for(struct dso* p=head; p; p=p->next) {
		add_syms(p);
	}

	/* Attach to vdso, if provided by the kernel, last so that it does
	 * not become part of the global namespace.  */
	if(search_vec(auxv, &vdso_base, AT_SYSINFO_EHDR) && vdso_base) {
		Ehdr* ehdr = (void*)vdso_base;
		Phdr* phdr = vdso.phdr = (void*)(vdso_base + ehdr->e_phoff);
		vdso.phnum = ehdr->e_phnum;
		vdso.phentsize = ehdr->e_phentsize;
		for(i=ehdr->e_phnum; i; i--, phdr=(void*)((char*)phdr + ehdr->e_phentsize)) {
			if(phdr->p_type == PT_DYNAMIC) {
				vdso.dynv = (void*)(vdso_base + phdr->p_offset);
			}
			if(phdr->p_type == PT_LOAD) {
				vdso.base = (void*)(vdso_base - phdr->p_vaddr + phdr->p_offset);
			}
		}
		vdso.name = "";
		vdso.shortname = "linux-gate.so.1";
		vdso.relocated = 1;
		vdso.deps = (struct dso**)no_deps;
		decode_dyn(&vdso);
		vdso.prev = tail;
		tail->next = &vdso;
		tail = &vdso;
	}

	for(i=0; app.dynv[i]; i+=2) {
		if(!DT_DEBUG_INDIRECT && app.dynv[i]==DT_DEBUG) {
			app.dynv[i+1] = (size_t)&debug;
		}
		if(DT_DEBUG_INDIRECT && app.dynv[i]==DT_DEBUG_INDIRECT) {
			size_t* ptr = (size_t*) app.dynv[i+1];
			*ptr = (size_t)&debug;
		}
	}

	/* This must be done before final relocations, since it calls
	 * malloc, which may be provided by the application. Calling any
	 * application code prior to the jump to its entry point is not
	 * valid in our model and does not work with FDPIC, where there
	 * are additional relocation-like fixups that only the entry point
	 * code can see to perform. */
	main_ctor_queue = queue_ctors(&app);

	/* Initial TLS must also be allocated before final relocations
	 * might result in calloc being a call to application code. */
//	update_tls_size();
//	void *initial_tls = builtin_tls;
//	if (libc.tls_size > sizeof builtin_tls || tls_align > MIN_TLS_ALIGN) {
//		initial_tls = calloc(libc.tls_size, 1);
//		if (!initial_tls) {
//			dprintf(2, "%s: Error getting %zu bytes thread-local storage: %m\n",
//				argv[0], libc.tls_size);
//			_exit(127);
//		}
//	}
//	static_tls_cnt = tls_cnt;

	/* The main program must be relocated LAST since it may contain
	 * copy relocations which depend on libraries' relocations. */
	reloc_all(app.next);
	reloc_all(&app);

#if 0
	/* Actual copying to new TLS needs to happen after relocations,
	 * since the TLS images might have contained relocated addresses. */
	if(initial_tls != builtin_tls) {
		if(__init_tp(__copy_tls(initial_tls)) < 0) {
			a_crash();
		}
	}
	else {
		size_t tmp_tls_size = libc.tls_size;
		pthread_t self = __pthread_self();
		/* Temporarily set the tls size to the full size of
		 * builtin_tls so that __copy_tls will use the same layout
		 * as it did for before. Then check, just to be safe. */
		libc.tls_size = sizeof builtin_tls;
		if(__copy_tls((void*)builtin_tls) != self) {
			a_crash();
		}
		libc.tls_size = tmp_tls_size;
	}
#endif

	if(ldso_fail) {
		_exit(127);
	}
	if(ldd_mode) {
		_exit(0);
	}

	/* Determine if malloc was interposed by a replacement implementation
	 * so that calloc and the memalign family can harden against the
	 * possibility of incomplete replacement. */
//	if (find_sym(head, "malloc", 1).dso != &ldso)
//		__malloc_replaced = 1;
//	if (find_sym(head, "aligned_alloc", 1).dso != &ldso)
//		__aligned_alloc_replaced = 1;

	/* Switch to runtime mode: any further failures in the dynamic
	 * linker are a reportable failure rather than a fatal startup
	 * error. */
//	runtime = 1;

	debug.ver = 1;
	debug.bp = dl_debug_state;
	debug.head = head;
	debug.base = ldso.base;
	debug.state = RT_CONSISTENT;
	_dl_debug_state();

	if(replace_argv0) {
		argv[0] = replace_argv0;
	}

//	errno = 0;

	CRTJMP((void*)aux[AT_ENTRY], argv-1);
	for(;;);
}

