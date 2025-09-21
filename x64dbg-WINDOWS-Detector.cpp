#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <cstdlib>   

// --------------------------- Environment helpers ---------------------------
std::string safe_getenv(const char* name)
{
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, name) == 0 && buf != nullptr) {
        std::string val(buf);
        free(buf);
        return val;
    }
    return {};
}   

// Helper to safely print a wide (UTF-16) string to Windows console.
void PrintWide(const std::wstring& s)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == nullptr) {
        // fallback to narrow output
        std::wcout << s << std::endl;
        return;
    }
    DWORD written = 0;
    WriteConsoleW(hOut, s.c_str(), static_cast<DWORD>(s.size()), &written, nullptr);
    // write a newline
    const wchar_t nl = L'\n';
    WriteConsoleW(hOut, &nl, 1, &written, nullptr);
}

bool anti_debug_env_enabled()
{
    std::string v = safe_getenv("ANTI_DEBUG");
    if (v.empty()) return true; // default: enabled
    if (v == "0" || _stricmp(v.c_str(), "false") == 0 || _stricmp(v.c_str(), "no") == 0)
        return false;
    return true;
}

bool anti_debug_force_enabled()
{
    std::string v = safe_getenv("ANTI_DEBUG_FORCE");
    if (v.empty()) return false;
    if (v == "1" || _stricmp(v.c_str(), "true") == 0) return true;
    return false;
}

// --------------------------- VEH breakpoint ---------------------------
volatile LONG g_veh_seen_bp = 0;
PVOID g_veh_handle = nullptr;

LONG CALLBACK MyVeh(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo && ExceptionInfo->ExceptionRecord &&
        ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        InterlockedExchange(&g_veh_seen_bp, 1);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool veh_breakpoint_test()
{
    g_veh_handle = AddVectoredExceptionHandler(1, MyVeh);
    if (!g_veh_handle) return false;
    InterlockedExchange(&g_veh_seen_bp, 0);

    __try { __debugbreak(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    bool saw = (InterlockedCompareExchange(&g_veh_seen_bp, 0, 0) != 0);
    RemoveVectoredExceptionHandler(g_veh_handle);
    g_veh_handle = nullptr;
    return saw;
}

// --------------------------- PEB check ---------------------------
bool check_peb_being_debugged()
{
#ifdef _M_X64
    PBYTE pPEB = (PBYTE)__readgsqword(0x60);
#else
    PBYTE pPEB = (PBYTE)__readfsdword(0x30);
#endif
    if (!pPEB) return false;
    return (*(pPEB + 2) != 0);
}

// --------------------------- NtQueryInformationProcess / ProcessDebugPort ---------------------------
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool ntdll_function_looks_orig(LPCSTR funcName)
{
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return false;
    void* p = (void*)GetProcAddress(hNt, funcName);
    if (!p) return false;

    unsigned char buf[8] = { 0 };
    __try { memcpy(buf, p, sizeof(buf)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

#ifdef _M_X64
    if (buf[0] == 0x4C && buf[1] == 0x8B && buf[2] == 0xD1) return true;
    if (buf[0] == 0xE9 || (buf[0] == 0xFF && buf[1] == 0x25)) return false;
    return false;
#else
    if (buf[0] == 0xE9) return false;
    return true;
#endif
}

bool check_nt_query_information_process_hooked() { return !ntdll_function_looks_orig("NtQueryInformationProcess"); }

bool check_process_debug_port_via_nt()
{
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return false;
    auto NtQIP = (NtQueryInformationProcess_t)GetProcAddress(hNt, "NtQueryInformationProcess");
    if (!NtQIP) return false;

    ULONG debugPort = 0;
    NTSTATUS st = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), nullptr);
    return (st == 0 && debugPort != 0);
}

// --------------------------- Hardware breakpoints ---------------------------
bool any_thread_has_hw_breakpoints()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    DWORD myPid = GetCurrentProcessId();
    bool detected = false;

    if (!Thread32First(snap, &te)) {
        CloseHandle(snap);
        return false;
    }

    do {
        if (te.th32OwnerProcessID != myPid) continue;
        if (te.th32ThreadID == GetCurrentThreadId()) continue; // skip current thread

        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
        if (!hThread) continue;

        DWORD suspendCount = SuspendThread(hThread);
        if (suspendCount == (DWORD)-1) { CloseHandle(hThread); continue; }

        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;

        if (GetThreadContext(hThread, &ctx))
        {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
                detected = true;
        }

        ResumeThread(hThread);
        CloseHandle(hThread);
        if (detected) break;

    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    return detected;
}

// --------------------------- Software breakpoint detection ---------------------------
bool check_software_breakpoint(void* address)
{
    unsigned char byte = 0;
    SIZE_T read = 0;
    if (ReadProcessMemory(GetCurrentProcess(), address, &byte, 1, &read) && read == 1)
        return (byte == 0xCC);
    return false;
}

// Example critical addresses (expand as needed)
void* critical_addresses[] = {
    reinterpret_cast<void*>(&IsDebuggerPresent),
    reinterpret_cast<void*>(&veh_breakpoint_test)
};

// --------------------------- Main detector ---------------------------
int main()
{
    std::cout << "X64dbg Multi-layer debugger detection demo (with HW/SW breakpoints)\n\n";

    bool anyDetected = false;

    // Basic checks
    bool api_dbg = IsDebuggerPresent() != 0;
    bool peb_dbg = check_peb_being_debugged();
    bool veh_dbg = veh_breakpoint_test();
    bool ntdll_hooked = check_nt_query_information_process_hooked();
    bool dbgport = check_process_debug_port_via_nt();
    bool hw_bp = any_thread_has_hw_breakpoints();

    std::cout << "IsDebuggerPresent(): " << (api_dbg ? "YES" : "no") << "\n";
    std::cout << "PEB BeingDebugged:    " << (peb_dbg ? "YES" : "no") << "\n";
    std::cout << "VEH breakpoint seen:  " << (veh_dbg ? "YES" : "no") << "\n";
    std::cout << "NtQueryInformationProcess hooked: " << (ntdll_hooked ? "YES" : "no") << "\n";
    std::cout << "ProcessDebugPort != 0: " << (dbgport ? "YES" : "no") << "\n";
    std::cout << "Hardware breakpoints: " << (hw_bp ? "YES" : "no") << "\n";

    anyDetected |= api_dbg | peb_dbg | !veh_dbg | ntdll_hooked | dbgport | hw_bp;

    // Software breakpoints
    for (void* addr : critical_addresses)
    {
        if (check_software_breakpoint(addr))
        {
            std::cout << "Software breakpoint detected at address: " << addr << "\n";
            anyDetected = true;
        }
    }

    std::cout << "\nFinal result: " << (anyDetected ? "Debugger detected!" : "No debugger detected") << "\n";

    std::wstring secretA = L"1";
    std::wstring secretB = L"3";
    std::wstring secretC = L"3";
    std::wstring secretD = L"7";

    std::wstring legitimateCopyA = L"L";
    std::wstring legitimateCopyB = L"e";
    std::wstring legitimateCopyC = L"g";
    std::wstring legitimateCopyD = L"i";
    std::wstring legitimateCopyE = L"t";
    std::wstring legitimateCopyF = L"i";
    std::wstring legitimateCopyG = L"m";
    std::wstring legitimateCopyH = L"a";
    std::wstring legitimateCopyI = L"t";
    std::wstring legitimateCopyJ = L"e";
    std::wstring legitimateCopyK = L" ";
    std::wstring legitimateCopyL = L"C";
    std::wstring legitimateCopyM = L"o";
    std::wstring legitimateCopyN = L"p";
    std::wstring legitimateCopyO = L"y";
    std::wstring illlegitimateCopyA = L"I";
    std::wstring illlegitimateCopyB = L"l";
    std::wstring illlegitimateCopyC = L"l";
    std::wstring illlegitimateCopyD = L"e";
    std::wstring illlegitimateCopyE = L"g";
    std::wstring illlegitimateCopyF = L"i";
    std::wstring illlegitimateCopyG = L"t";
    std::wstring illlegitimateCopyH = L"i";
    std::wstring illlegitimateCopyI = L"m";
    std::wstring illlegitimateCopyJ = L"a";
    std::wstring illlegitimateCopyK = L"t";
    std::wstring illlegitimateCopyL = L"e";
    std::wstring illlegitimateCopyM = L" ";
    std::wstring illlegitimateCopyN = L"C";
    std::wstring illlegitimateCopyO = L"o";
    std::wstring illlegitimateCopyP = L"p";
    std::wstring illlegitimateCopyQ = L"y";

    if (!anyDetected)
    {
        std::wstring inputSecret;
        std::wcout << L"Enter your secret key: ";
        std::getline(std::wcin, inputSecret);

        if (inputSecret == secretA + secretB + secretC + secretD)
        {
            PrintWide(legitimateCopyA + legitimateCopyB + legitimateCopyC + legitimateCopyD + legitimateCopyE +
                legitimateCopyF + legitimateCopyG + legitimateCopyH + legitimateCopyI + legitimateCopyJ + legitimateCopyK +
                legitimateCopyL + legitimateCopyM + legitimateCopyN + legitimateCopyO);
        }
        else {
            PrintWide(illlegitimateCopyA + illlegitimateCopyB + illlegitimateCopyC + illlegitimateCopyD + illlegitimateCopyE +
                illlegitimateCopyF + illlegitimateCopyG + illlegitimateCopyH + illlegitimateCopyI + illlegitimateCopyJ + illlegitimateCopyK +
                illlegitimateCopyL + illlegitimateCopyM + illlegitimateCopyN + illlegitimateCopyO + illlegitimateCopyP + illlegitimateCopyQ);
        }
    }
    else {
        if (!secretA.empty()) {
            SecureZeroMemory(&secretA[0], secretA.size() * sizeof(wchar_t));
            secretA.clear();
            secretA.shrink_to_fit();
        }
        if (!secretB.empty()) {
            SecureZeroMemory(&secretB[0], secretB.size() * sizeof(wchar_t));
            secretB.clear();
            secretB.shrink_to_fit();
        }
        if (!secretC.empty()) {
            SecureZeroMemory(&secretC[0], secretC.size() * sizeof(wchar_t));
            secretC.clear();
            secretC.shrink_to_fit();
        }
        if (!secretD.empty()) {
            SecureZeroMemory(&secretD[0], secretD.size() * sizeof(wchar_t));
            secretD.clear();
            secretD.shrink_to_fit();
        }

        PrintWide(illlegitimateCopyA + illlegitimateCopyB + illlegitimateCopyC + illlegitimateCopyD + illlegitimateCopyE +
            illlegitimateCopyF + illlegitimateCopyG + illlegitimateCopyH + illlegitimateCopyI + illlegitimateCopyJ + illlegitimateCopyK +
            illlegitimateCopyL + illlegitimateCopyM + illlegitimateCopyN + illlegitimateCopyO + illlegitimateCopyP + illlegitimateCopyQ);

        ExitProcess(1);
    }

    if (!secretA.empty()) {
        SecureZeroMemory(&secretA[0], secretA.size() * sizeof(wchar_t));
        secretA.clear();
        secretA.shrink_to_fit();
    }
    if (!secretB.empty()) {
        SecureZeroMemory(&secretB[0], secretB.size() * sizeof(wchar_t));
        secretB.clear();
        secretB.shrink_to_fit();
    }
    if (!secretC.empty()) {
        SecureZeroMemory(&secretC[0], secretC.size() * sizeof(wchar_t));
        secretC.clear();
        secretC.shrink_to_fit();
    }
    if (!secretD.empty()) {
        SecureZeroMemory(&secretD[0], secretD.size() * sizeof(wchar_t));
        secretD.clear();
        secretD.shrink_to_fit();
    }

    std::cin.get();

    return anyDetected ? 1 : 0;
}