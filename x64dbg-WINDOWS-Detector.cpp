#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <cstdlib>        
#include <io.h>      // _setmode
#include <fcntl.h>   // _O_U16TEXT

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

// Helper to safely print a wide (UTF-16) string to Windows console.
void PrintWideNoNewLine(const std::wstring& s)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == nullptr) {
        // fallback to narrow output
        std::wcout << s << std::endl;
        return;
    }
    DWORD written = 0;
    WriteConsoleW(hOut, s.c_str(), static_cast<DWORD>(s.size()), &written, nullptr);
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

bool constant_time_equal_split(const std::wstring& input,
    const std::wstring& a,
    const std::wstring& b,
    const std::wstring& c,
    const std::wstring& d)
{
    std::wstring::size_type totalLen = a.size() + b.size() + c.size() + d.size();
    if (input.size() != totalLen) return false;

    volatile unsigned diff = 0;
    size_t pos = 0;

    for (wchar_t ch : a) diff |= input[pos++] ^ ch;
    for (wchar_t ch : b) diff |= input[pos++] ^ ch;
    for (wchar_t ch : c) diff |= input[pos++] ^ ch;
    for (wchar_t ch : d) diff |= input[pos++] ^ ch;

    return diff == 0;
}

bool lock_string(std::wstring& s)
{
    if (s.empty()) return false;
    return VirtualLock(&s[0], s.size() * sizeof(wchar_t)) != 0;
}

void unlock_and_zero_string(std::wstring& s)
{
    if (s.empty()) return;
    SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t));
    VirtualUnlock(&s[0], s.size() * sizeof(wchar_t));
    s.clear();
    s.shrink_to_fit();
}

class ObfuscatedSecret {
private:
    std::vector<wchar_t> encoded_;
    wchar_t xorKey_;

public:
    ObfuscatedSecret(const std::wstring& secret, wchar_t key = 0xAA)
        : xorKey_(key)
    {
        encoded_.reserve(secret.size());
        for (auto c : secret)
            encoded_.push_back(c ^ xorKey_);
        if (!encoded_.empty())
            VirtualLock(encoded_.data(), encoded_.size() * sizeof(wchar_t));
    }

    ~ObfuscatedSecret() { secure_zero(); }

    bool check(const std::wstring& input) const
    {
        if (input.size() != encoded_.size()) return false;
        volatile unsigned diff = 0;
        for (size_t i = 0; i < input.size(); ++i)
            diff |= (encoded_[i] ^ xorKey_) ^ input[i];
        return diff == 0;
    }

    void secure_zero()
    {
        if (!encoded_.empty()) {
            SecureZeroMemory(encoded_.data(), encoded_.size() * sizeof(wchar_t));
            VirtualUnlock(encoded_.data(), encoded_.size() * sizeof(wchar_t));
            encoded_.clear();
        }
    }
};

std::wstring decode_string(const wchar_t* obf, size_t len, wchar_t key)
{
    std::wstring out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i)
        out.push_back(obf[i] ^ key);
    return out;
}

// --------------------------- Main detector ---------------------------
int wmain()
{                   // enable UTF-16 I/O on Windows console for wcin/wcout/WriteConsoleW
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);

    PrintWide(L"X64dbg Multi-layer debugger detection demo (with HW/SW breakpoints)\n");

    bool debuggerDetected = false;

    debuggerDetected |= (IsDebuggerPresent() != 0);
    debuggerDetected |= check_peb_being_debugged();
    debuggerDetected |= !veh_breakpoint_test();
    debuggerDetected |= check_nt_query_information_process_hooked();
    debuggerDetected |= check_process_debug_port_via_nt();
    debuggerDetected |= any_thread_has_hw_breakpoints();

    for (void* addr : critical_addresses)
    {
        if (check_software_breakpoint(addr))
        {
            debuggerDetected = true;
        }
    }

    constexpr wchar_t key = 0xAA;

    wchar_t secret_obf[] = { 0x31 ^ key, 0x33 ^ key, 0x33 ^ key, 0x37 ^ key };
    wchar_t legit_obf[] = {
        L'L' ^ key,L'e' ^ key,L'g' ^ key,L'i' ^ key,L't' ^ key,L'i' ^ key,L'm' ^ key,L'a' ^ key,L't' ^ key,L'e' ^ key,
        L' ' ^ key,L'C' ^ key,L'o' ^ key,L'p' ^ key,L'y' ^ key
    };
    wchar_t illegit_obf[] = {
        L'I' ^ key,L'l' ^ key,L'l' ^ key,L'e' ^ key,L'g' ^ key,L'i' ^ key,L't' ^ key,L'i' ^ key,L'm' ^ key,L'a' ^ key,L't' ^ key,L'e' ^ key,
        L' ' ^ key,L'C' ^ key,L'o' ^ key,L'p' ^ key,L'y' ^ key
    };
    wchar_t prompt_obf[] = {
        L'E' ^ key,L'n' ^ key,L't' ^ key,L'e' ^ key,L'r' ^ key,L' ' ^ key,L'y' ^ key,L'o' ^ key,L'u' ^ key,L'r' ^ key,
        L' ' ^ key,L's' ^ key,L'e' ^ key,L'c' ^ key,L'r' ^ key,L'e' ^ key,L't' ^ key,L' ' ^ key,L'k' ^ key,L'e' ^ key,L'y' ^ key,L':' ^ key,L' ' ^ key
    };

    std::wstring secret = decode_string(secret_obf, 4, key);
    std::wstring legitMsg = decode_string(legit_obf, 15, key);
    std::wstring illegitMsg = decode_string(illegit_obf, 17, key);
    std::wstring promptMsg = decode_string(prompt_obf, 23, key);

    if (!lock_string(secret))
    {
        unlock_and_zero_string(secret);
        unlock_and_zero_string(legitMsg);
        unlock_and_zero_string(illegitMsg);
        unlock_and_zero_string(promptMsg);
        PrintWide(L"Failed to lock memory, exiting.\n");
        ExitProcess(1);
    }

    if (debuggerDetected)
    {
        unlock_and_zero_string(secret);
        unlock_and_zero_string(legitMsg);
        PrintWide(illegitMsg);
        unlock_and_zero_string(illegitMsg);
        unlock_and_zero_string(promptMsg);

        ExitProcess(1);
    }

    PrintWide(promptMsg);

    std::wstring inputSecret;
    std::getline(std::wcin, inputSecret);

    // Recheck for debugger after input
    debuggerDetected |= (IsDebuggerPresent() != 0);
    debuggerDetected |= check_peb_being_debugged();
    debuggerDetected |= !veh_breakpoint_test();
    debuggerDetected |= check_nt_query_information_process_hooked();
    debuggerDetected |= check_process_debug_port_via_nt();
    debuggerDetected |= any_thread_has_hw_breakpoints();       

    if (debuggerDetected)
    {
        unlock_and_zero_string(secret);
        unlock_and_zero_string(legitMsg);
        PrintWide(illegitMsg);
        unlock_and_zero_string(illegitMsg);
        unlock_and_zero_string(promptMsg);

        ExitProcess(1);
    }

    if (constant_time_equal_split(inputSecret, secret.substr(0, 1), secret.substr(1, 1),
        secret.substr(2, 1), secret.substr(3, 1)))
    {
        unlock_and_zero_string(secret);
        PrintWide(legitMsg);
    }
    else
    {
        unlock_and_zero_string(secret);
        PrintWide(illegitMsg);
    }

    // Zero messages before exit
    unlock_and_zero_string(legitMsg);
    unlock_and_zero_string(illegitMsg);
    unlock_and_zero_string(promptMsg);

    PrintWide(L"Press Enter to exit...");
    std::wstring dummy;
    std::getline(std::wcin, dummy);

    return debuggerDetected ? 1 : 0;
}