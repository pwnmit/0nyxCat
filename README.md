# Win32 Process Memory Extraction and Diagnostic Tool

A comprehensive C++ demonstration showing how Windows System APIs interact with process tokens, privileges, and debugging libraries. This project is designed for system administrators, security researchers, and developers looking to understand low-level Windows internals, process monitoring, and crash-dump generation.

---

## 🛠️ Technical Architecture & Workflow

The application operates as a command-line tool that performs a sequential 5-stage workflow to safely inspect and capture a target process's state:
[Start] ──> Check Local Privileges ──> Locate Target PID ──> Elevate Token (SeDebugPrivilege) ──> Open Process ──> Generate Dump (.dump) ──> [End]

### 1. Privilege Verification (`isElevatedProcess`)
Before attempting any high-privilege operations, the program inspects its own security context. It uses `OpenProcessToken` combined with `GetTokenInformation` under the `TokenElevation` information class to determine if the executable is running with full administrative rights.

### 2. Dynamic Process Resolution (`GetProcessIDByName`)
Instead of requiring a manually entered PID, the tool uses the **Toolhelp32 API** (`CreateToolhelp32Snapshot`). It takes a snapshot of the active execution space, iterates through the system's process tree using `Process32First` and `Process32Next`, and dynamically resolves the required executable name (e.g., `lsass.exe`) to its current active Process ID.

### 3. Token Adjustment (`setPrivilege`)
Interacting with protected system-level architecture requires explicit debugging permissions. The code targets the process access token, uses `LookupPrivilegeValueW` to fetch the locally unique identifier (LUID) for **`SeDebugPrivilege`**, and applies it via `AdjustTokenPrivileges`.

### 4. Memory Mapping & Dumping (`MiniDumpWriteDump`)
Once permissions are acquired, the program calls `OpenProcess` with `PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION` flags. It then interfaces with `dbghelp.dll` via the `MiniDumpWriteDump` API to generate a user-mode minidump file (`lsass.dump`) with specific memory flags (`MiniDumpWithFullMemoryInfo`), matching standard Windows error-reporting structures.

---

## 🚀 Getting Started

### Prerequisites
* **Operating System:** Windows 10 / 11 or Windows Server.
* **Compiler:** Any standard C++ compiler supporting Win32 development (MinGW-w64, MSVC, or Clang).
* **SDK:** Windows Header Files (`windows.h`, `dbghelp.h`, `tlhelp32.h`).

### Compilation Instructions

#### Using MinGW-w64 / GCC:
Open your terminal or command prompt and link the required `dbghelp` library during compilation:
```bash
g++ onyxcat.cpp -o lsassdump.exe -static -ldbghelp
