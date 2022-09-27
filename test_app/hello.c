#include "libfunc.h"

extern void _exit(int status);
extern int printf(const char* fmt, ...);


static int test_var = 2;

int main()
{
	printf("hello, world!\n");
	
	int a;
	int b;

	a = 1;
	b = a+test_var;
	printf("test_var:%d a:%d b:%d\n", test_var, a, b);

	_exit(0);

	return 0;
}
