#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>

#pragma comment(lib, "Ws2_32.lib")

void PrintError(const std::string& msg) {
    std::cerr << "[-] " << msg << " Error code: " << GetLastError() << std::endl;
}

// ---------------------------------------------------------
// 1. Process & Memory Activity Test
// ---------------------------------------------------------
DWORD WINAPI DummyThread(LPVOID lpParam) {
    std::cout << "[*] Thread running, performing dummy computation..." << std::endl;
    volatile int compute = 0;
    for (int i = 0; i < 1000000; ++i) { compute += i; }
    return 0;
}

void TestProcessActivity() {
    std::cout << "\n=== Starting Process & Memory Test ===" << std::endl;
    
    // Heap Allocation
    HANDLE hHeap = GetProcessHeap();
    LPVOID memory = HeapAlloc(hHeap, 0, 1024 * 1024); // 1MB
    if (memory) {
        std::cout << "[+] Allocated 1MB on heap." << std::endl;
        HeapFree(hHeap, 0, memory);
        std::cout << "[+] Freed heap memory." << std::endl;
    }

    // Thread Creation
    HANDLE hThread = CreateThread(NULL, 0, DummyThread, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        std::cout << "[+] Thread execution completed and synchronized." << std::endl;
        CloseHandle(hThread);
    }
}

// ---------------------------------------------------------
// 2. Network Activity Test
// ---------------------------------------------------------
void TestNetworkActivity() {
    std::cout << "\n=== Starting Network Activity Test ===" << std::endl;
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        PrintError("WSAStartup failed.");
        return;
    }

    SOCKET connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connectSocket == INVALID_SOCKET) {
        PrintError("Socket creation failed.");
        WSACleanup();
        return;
    }

    sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_port = htons(8080); // Harmless port
    inet_pton(AF_INET, "127.0.0.1", &clientService.sin_addr);

    std::cout << "[*] Attempting connection to 127.0.0.1:8080..." << std::endl;
    if (connect(connectSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        std::cout << "[-] Connection failed (expected if no listener is active on 8080). Moving on." << std::endl;
    } else {
        std::cout << "[+] Connected successfully." << std::endl;
        const char* sendbuf = "Sandbox Network Test";
        send(connectSocket, sendbuf, (int)strlen(sendbuf), 0);
        std::cout << "[+] Sent harmless payload." << std::endl;
    }

    closesocket(connectSocket);
    WSACleanup();
}

// ---------------------------------------------------------
// 3. File System Activity Test
// ---------------------------------------------------------
void TestFileSystemActivity() {
    std::wcout << L"\n=== Starting File System Activity Test ===" << std::endl;
    std::wstring dirName = L"C:\\Temp\\SandboxTestDir";
    std::wstring fileName = dirName + L"\\test_data.txt";
    
    CreateDirectoryW(L"C:\\Temp", NULL); // Ensure C:\Temp exists
    if (!CreateDirectoryW(dirName.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        PrintError("Failed to create directory.");
        return;
    }

    HANDLE hFile = CreateFileW(fileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        std::wcout << L"[+] Created file: " << fileName << std::endl;
        DWORD bytesWritten;
        const char* data = "Test Data";
        WriteFile(hFile, data, (DWORD)strlen(data), &bytesWritten, NULL);
        CloseHandle(hFile);
        
        DeleteFileW(fileName.c_str());
        std::wcout << L"[+] Deleted file." << std::endl;
    }
    
    RemoveDirectoryW(dirName.c_str());
    std::wcout << L"[+] Removed directory." << std::endl;
}

// ---------------------------------------------------------
// 4. Registry Activity Test
// ---------------------------------------------------------
void TestRegistryActivity() {
    std::cout << "\n=== Starting Registry Activity Test ===" << std::endl;
    HKEY hKey;
    LPCWSTR subKey = L"Software\\TestSandbox";
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        std::cout << "[+] Created Registry Key: HKCU\\Software\\TestSandbox" << std::endl;
        
        const wchar_t* valueData = L"TelemetryTest";
        RegSetValueExW(hKey, L"TestValue", 0, REG_SZ, (const BYTE*)valueData, (wcslen(valueData) + 1) * sizeof(wchar_t));
        std::cout << "[+] Wrote REG_SZ value." << std::endl;
        
        RegDeleteValueW(hKey, L"TestValue");
        RegCloseKey(hKey);
        
        RegDeleteKeyW(HKEY_CURRENT_USER, subKey);
        std::cout << "[+] Cleaned up Registry Key." << std::endl;
    } else {
        PrintError("Failed to create registry key.");
    }
}

// ---------------------------------------------------------
// 5. DLL Loading Test
// ---------------------------------------------------------
void TestDLLActivity() {
    std::cout << "\n=== Starting DLL Loading Test ===" << std::endl;
    
    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    if (hUser32) {
        std::cout << "[+] Successfully loaded user32.dll" << std::endl;
        
        FARPROC msgBoxAddr = GetProcAddress(hUser32, "MessageBoxW");
        if (msgBoxAddr) {
            std::cout << "[+] Successfully resolved address for MessageBoxW." << std::endl;
        } else {
            PrintError("Failed to resolve MessageBoxW.");
        }
        
        FreeLibrary(hUser32);
        std::cout << "[+] Freed user32.dll" << std::endl;
    } else {
        PrintError("Failed to load user32.dll");
    }
}

// ---------------------------------------------------------
// Main Execution
// ---------------------------------------------------------
int main() {
    std::cout << "Starting Combined Sandbox Validation Tool...\n" << std::endl;
    
    TestProcessActivity();
    Sleep(1000); // ETW/Sysmon validation: Sleeping between actions
    
    TestNetworkActivity();
    Sleep(1000);
    
    TestFileSystemActivity();
    Sleep(1000);
    
    TestRegistryActivity();
    Sleep(1000);
    
    TestDLLActivity();
    
    std::cout << "\n[*] All validation tests completed." << std::endl;
    return 0;
}
