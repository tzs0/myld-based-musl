#include "myld.h"
#include "elf.h"

#define START "_myld_start"

//void non_static_func(void)
//{
//	printf("i am %s\n", __func__);
//}

//static void static_func(void)
//{
//	printf("i am %s\n", __func__);
//}

extern uint8_t mod0_var;
size_t non_static_var = 1;
static size_t static_var = 2;

__asm__(
    ".text \n"
    ".global " START " \n"
    START ": \n"
    "	xor %rbp,%rbp \n"
    "	mov %rsp,%rdi \n"
    ".weak _DYNAMIC \n"
    ".hidden _DYNAMIC \n"
    "	lea _DYNAMIC(%rip),%rsi \n"
    "	andq $-16,%rsp \n"
    "	call " START "_c \n"
);

hidden void _myld_start_c(size_t* sp, size_t* dynv)
{
//	printf("hello world!\n");
//	printf("non_static_var:%d\n", non_static_var);
//	printf("static_var:%d\n", static_var);

	size_t i, aux[AUX_CNT], dyn[DYN_CNT];
	size_t* rel, rel_size, base;

	int argc = *sp;
	char** argv = (void*)(sp+1);
	for(i=argc+1; argv[i]; i++);  /* 跳过环境变量 */
	size_t* auxv = (void*)(argv+i+1);  /* 跳过环境变量后面的\0 */

	for(i=0; i<AUX_CNT; i++) {
		aux[i] = 0;
	}
	for(i=0; auxv[i]; i+=2)
		if(auxv[i]<AUX_CNT) {
			aux[auxv[i]] = auxv[i+1];
		}

	for(i=0; i<DYN_CNT; i++) {
		dyn[i] = 0;
	}
	for(i=0; dynv[i]; i+=2)
		if(dynv[i]<DYN_CNT) {
			dyn[dynv[i]] = dynv[i+1];
		}

	/* If the dynamic linker is invoked as a command, its load
	 * address is not available in the aux vector. Instead, compute
	 * the load address as the difference between &_DYNAMIC and the
	 * virtual address in the PT_DYNAMIC program header. */
	base = aux[AT_BASE];
	if(!base) {
		size_t phnum = aux[AT_PHNUM];
		size_t phentsize = aux[AT_PHENT];
		Phdr* ph = (void*)aux[AT_PHDR];
		for(i=phnum; i--; ph = (void*)((char*)ph + phentsize)) {
			if(ph->p_type == PT_DYNAMIC) {
				base = (size_t)dynv - ph->p_vaddr;
				break;
			}
		}
	}

	/*rel = (void *)(base+dyn[DT_REL]);
	rel_size = dyn[DT_RELSZ];
	for (; rel_size; rel+=2, rel_size-=2*sizeof(size_t)) {
	    if (!IS_RELATIVE(rel[1], 0)) continue;
	    size_t *rel_addr = (void *)(base + rel[0]);
	    *rel_addr += base;
	}

	rel = (void *)(base+dyn[DT_RELA]);
	rel_size = dyn[DT_RELASZ];
	for (; rel_size; rel+=3, rel_size-=3*sizeof(size_t)) {
	    if (!IS_RELATIVE(rel[1], 0)) continue;
	    size_t *rel_addr = (void *)(base + rel[0]);
	    *rel_addr = base + rel[2];
	}*/

	/* can access below vars? --no*/
//    mod0_var = 2;
//    static_var = 5;
//    non_static_var = 6;



	stage2_func dls2;
	GETFUNCSYM(&dls2, __dls2);
	dls2((void*)base, sp);



//	static_func();
//	non_static_func();

}
