#include <windows.h>
#include <wininet.h>
#include <stdio.h>

// Instruct the MSVC linker to link the necessary libraries
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

void PerformFileOperations(char* outFilePath) {
    printf("[*] Starting File System Operations...\n");
    char tempPath[MAX_PATH];
    
    // Get the user's Temp directory
    GetTempPathA(MAX_PATH, tempPath);
    snprintf(outFilePath, MAX_PATH, "%sharmless_test_log.txt", tempPath);

    // Create a new file
    HANDLE hFile = CreateFileA(
        outFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        const char* data = "Hello! This is a harmless file system test.\n";
        DWORD bytesWritten;
        WriteFile(hFile, data, strlen(data), &bytesWritten, NULL);
        CloseHandle(hFile);
        printf("[+] Successfully wrote to %s\n", outFilePath);
    } else {
        printf("[-] Failed to create file.\n");
    }
}

void PerformRegistryOperations() {
    printf("\n[*] Starting Registry Operations...\n");
    HKEY hKey;
    const char* regPath = "Software\\HarmlessTestApp";
    
    // Create or open a harmless key in the Current User hive
    LSTATUS status = RegCreateKeyExA(
        HKEY_CURRENT_USER, regPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL
    );

    if (status == ERROR_SUCCESS) {
        const char* valueData = "Harmless registry modification successful.";
        RegSetValueExA(hKey, "TestValue", 0, REG_SZ, (const BYTE*)valueData, strlen(valueData) + 1);
        RegCloseKey(hKey);
        printf("[+] Successfully wrote to HKCU\\%s\n", regPath);
    } else {
        printf("[-] Failed to write to registry.\n");
    }
}

void PerformNetworkOperations() {
    printf("\n[*] Starting Network Operations...\n");
    
    // Initialize WinINet
    HINTERNET hInternet = InternetOpenA("HarmlessTestClient/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet) {
        // Open a connection to example.com (safe IANA domain)
        HINTERNET hUrl = InternetOpenUrlA(
            hInternet, "http://www.example.com", NULL, 0, INTERNET_FLAG_RELOAD, 0
        );

        if (hUrl) {
            char buffer[101];
            DWORD bytesRead;
            
            // Read the first 100 bytes of the HTML response
            if (InternetReadFile(hUrl, buffer, 100, &bytesRead) && bytesRead > 0) {
                buffer[bytesRead] = '\0'; // Null-terminate
                printf("[+] Successfully fetched %lu bytes from example.com\n", bytesRead);
                printf("    Snippet: %s...\n", buffer);
            }
            InternetCloseHandle(hUrl);
        } else {
             printf("[-] Failed to open URL.\n");
        }
        InternetCloseHandle(hInternet);
    } else {
        printf("[-] Failed to initialize network API.\n");
    }
}

void PerformProcessOperations(const char* targetFile) {
    printf("\n[*] Starting Process Spawning Operations...\n");
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Construct the command line: notepad.exe C:\Temp\harmless_test_log.txt
    char cmdLine[MAX_PATH + 50];
    snprintf(cmdLine, sizeof(cmdLine), "notepad.exe \"%s\"", targetFile);

    // Spawn the process
    if (CreateProcessA(
        NULL,           // Application name (NULL means use command line)
        cmdLine,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi             // Pointer to PROCESS_INFORMATION structure
    )) {
        printf("[+] Successfully spawned Notepad with PID: %lu\n", pi.dwProcessId);
        
        // Close handles to allow the child process to run independently
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] Failed to spawn process. Error code: %lu\n", GetLastError());
    }
}

int main() {
    printf("=== Harmless OS Interactions Test ===\n\n");
    
    char createdFilePath[MAX_PATH];
    
    PerformFileOperations(createdFilePath);
    PerformRegistryOperations();
    PerformNetworkOperations();
    PerformProcessOperations(createdFilePath);
    
    printf("\n=== Execution Complete ===\n");
    return 0;
}