#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <winternl.h>
#include <Windows.h>
#include <Wincrypt.h>

// --------------------------- Anti-debug helpers ---------------------------

// VEH breakpoint
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

// PEB check
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

// NtQueryInformationProcess / ProcessDebugPort
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

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

// Hardware breakpoints
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
        if (te.th32ThreadID == GetCurrentThreadId()) continue;

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

// Software breakpoints
bool check_software_breakpoint(void* address)
{
    unsigned char byte = 0;
    SIZE_T read = 0;
    if (ReadProcessMemory(GetCurrentProcess(), address, &byte, 1, &read) && read == 1)
        return (byte == 0xCC);
    return false;
}

// Critical addresses to check for SW breakpoints
void* critical_addresses[] = {
    reinterpret_cast<void*>(&IsDebuggerPresent),
    reinterpret_cast<void*>(&veh_breakpoint_test)
};

std::string xor_string(const std::string& s, char key) {
    std::string r = s;
    for (auto& c : r) c ^= key; // decode at runtime
    return r;
}

std::vector<std::string> secret_fragments = {
    xor_string("U29tZV9z", 0x5A),
    xor_string("ZWNyZXRf", 0x5A),
    xor_string("cGFydF8x", 0x5A)
};

// --------------------------- Base64 split comparison ----------------
bool constant_time_compare(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

// ------------------- Fixed secret key (split + XOR) -------------------
struct Fragment { std::string data; char key; };

std::string reconstruct_secret() {
    std::string s;
    for (auto& frag : secret_fragments) s += xor_string(frag, 0x5A);
    return s;
}

void print_fragments(const std::vector<std::pair<std::string, char>>& frags) {
    for (auto& p : frags)
        std::cout << xor_string(p.first, p.second);
    std::cout << std::endl;
}

std::string base64_encode(const std::string& in) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// --------------------------- Main ----------------
int main()
{
    // Lock console for UTF-8 input/output
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

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
            debuggerDetected = true;
    }

    char xor_key = 0x55;

    std::vector<std::pair<std::string, char>> prompt_fragments = {
        {"\x1F",0x5A},{"\x35",0x5B},{"\x28",0x5C},{"\x38",0x5D},{"\x2C",0x5E},{"\x7F",0x5F},
        {"\x13",0x60},{"\x04",0x61},{"\x01",0x62},{"\x11",0x63},{"\x01",0x64},{"\x11",0x65},{"\x46",0x66},
        {"\x0C",0x67},{"\x0D",0x68},{"\x10",0x69},{"\x50",0x6A},{"\x4B",0x6B}
    };

    // Access message: "Access granted.\n"
    std::vector<std::pair<std::string, char>> access_fragments = {
        {"\x2D",0x6C},{"\x0E",0x6D},{"\x0D",0x6E},{"\x0A",0x6F},{"\x03",0x70},{"\x02",0x71},{"\x52",0x72},
        {"\x14",0x73},{"\x06",0x74},{"\x14",0x75},{"\x18",0x76},{"\x03",0x77},{"\x1D",0x78},{"\x1D",0x79},
        {"\x54",0x7A},{"\x71",0x7B}
    };

    // Fail message: "Illegitimate copy.\n"
    std::vector<std::pair<std::string, char>> fail_fragments = {
        {"\x6A",0x23}, // I
        {"\x2D",0x41}, // l
        {"\x7E",0x12}, // l
        {"\x30",0x55}, // e
        {"\x54",0x33}, // g
        {"\x25",0x44}, // a
        {"\x4D",0x21}, // l
        {"\x0A",0x2A}, // ' '
        {"\x3C",0x5F}, // c
        {"\x54",0x3B}, // o
        {"\x3D",0x4D}, // p
        {"\x15",0x6C}, // y
        {"\x0C",0x22}  // .
     };

    // Exit message: "Press Enter to exit..."
    std::vector<std::pair<std::string, char>> exit_fragments = {
        {"\xDF",0x8F},{"\xE2",0x90},{"\xF4",0x91},{"\xE1",0x92},{"\xE0",0x93},{"\xB4",0x94},
        {"\xD0",0x95},{"\xF8",0x96},{"\xE3",0x97},{"\xFD",0x98},{"\xEB",0x99},{"\xBA",0x9A},
        {"\xEF",0x9B},{"\xF3",0x9C},{"\xBD",0x9D},{"\xFB",0x9E},{"\xE7",0x9F},{"\xC9",0xA0},
        {"\xD5",0xA1},{"\x8C",0xA2},{"\x8C",0xA2},{"\x8C",0xA2}
    };

    if (debuggerDetected)
    {
        print_fragments(fail_fragments);
        ExitProcess(1);
    }

    print_fragments(prompt_fragments);
    std::string input;
    std::getline(std::cin, input);
    std::string input_b64 = base64_encode(input);

    // Recheck debugger after input
    debuggerDetected |= (IsDebuggerPresent() != 0);
    debuggerDetected |= check_peb_being_debugged();
    debuggerDetected |= !veh_breakpoint_test();
    debuggerDetected |= check_nt_query_information_process_hooked();
    debuggerDetected |= check_process_debug_port_via_nt();
    debuggerDetected |= any_thread_has_hw_breakpoints();

    if (debuggerDetected)
    {
        print_fragments(fail_fragments);
        ExitProcess(1);
    }

    std::string secret_b64 = reconstruct_secret();

    if (constant_time_compare(input_b64, secret_b64))
    {
        print_fragments(access_fragments);
    }
    else
    {
        print_fragments(fail_fragments);
    }

    print_fragments(exit_fragments);
    std::getline(std::cin, input);

    return debuggerDetected ? 1 : 0;
}
