#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <winternl.h>
#include <Windows.h>
#include <Wincrypt.h>

volatile LONG a1 = 0;
PVOID a2 = nullptr;

LONG CALLBACK a3(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo && ExceptionInfo->ExceptionRecord &&
        ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        InterlockedExchange(&a1, 1);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool a4()
{
    a2 = AddVectoredExceptionHandler(1, a3);
    if (!a2) return false;
    InterlockedExchange(&a1, 0);

    __try { __debugbreak(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    bool saw = (InterlockedCompareExchange(&a1, 0, 0) != 0);
    RemoveVectoredExceptionHandler(a2);
    a2 = nullptr;
    return saw;
}

bool a5()
{
#ifdef _M_X64
    PBYTE pPEB = (PBYTE)__readgsqword(0x60);
#else
    PBYTE pPEB = (PBYTE)__readfsdword(0x30);
#endif
    if (!pPEB) return false;
    return (*(pPEB + 2) != 0);
}

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool a6(LPCSTR funcName)
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

bool a7() { return !a6("NtQueryInformationProcess"); }

bool a8()
{
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return false;
    auto NtQIP = (NtQueryInformationProcess_t)GetProcAddress(hNt, "NtQueryInformationProcess");
    if (!NtQIP) return false;

    ULONG debugPort = 0;
    NTSTATUS st = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), nullptr);
    return (st == 0 && debugPort != 0);
}

bool a9()
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

bool a10(void* address)
{
    unsigned char byte = 0;
    SIZE_T read = 0;
    if (ReadProcessMemory(GetCurrentProcess(), address, &byte, 1, &read) && read == 1)
        return (byte == 0xCC);
    return false;
}

void* a11[] = {
    reinterpret_cast<void*>(&IsDebuggerPresent),
    reinterpret_cast<void*>(&a4)
};

std::string a12(const std::string& s, char key) {
    std::string r = s;
    for (auto& c : r) c ^= key;
    return r;
}

std::vector<std::string> a13 = {
    a12("U29tZV9z", 0x5A),
    a12("ZWNyZXRf", 0x5A),
    a12("cGFydF8x", 0x5A)
};

bool a14(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char a15 = 0;
    for (size_t i = 0; i < a.size(); ++i) a15 |= a[i] ^ b[i];
    return a15 == 0;
}

struct a16 { std::string a17; char key; };

std::string a18() {
    std::string s;
    for (auto& a19 : a13) s += a12(a19, 0x5A);
    return s;
}

void a20(const std::vector<std::pair<std::string, char>>& a21) {
    for (auto& p : a21)
        std::cout << a12(p.first, p.second);
    std::cout << std::endl;
}

std::string a21(const std::string& in) {
    static const std::string a22 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int a23 = 0, a24 = -6;
    for (unsigned char c : in) {
        a23 = (a23 << 8) + c;
        a24 += 8;
        while (a24 >= 0) {
            out.push_back(a22[(a23 >> a24) & 0x3F]);
            a24 -= 6;
        }
    }
    if (a24 > -6) out.push_back(a22[((a23 << 8) >> (a24 + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

int a26()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    bool a25 = false;

    a25 |= (IsDebuggerPresent() != 0);
    a25 |= a5();
    a25 |= !a4();
    a25 |= a7();
    a25 |= a8();
    a25 |= a9();

    for (void* a26 : a11)
    {
        if (a10(a26))
            a25 = true;
    }

    char a27 = 0x55;

    std::vector<std::pair<std::string, char>> a28 = {
        {"\x1F",0x5A},{"\x35",0x5B},{"\x28",0x5C},{"\x38",0x5D},{"\x2C",0x5E},{"\x7F",0x5F},
        {"\x13",0x60},{"\x04",0x61},{"\x01",0x62},{"\x11",0x63},{"\x01",0x64},{"\x11",0x65},{"\x46",0x66},
        {"\x0C",0x67},{"\x0D",0x68},{"\x10",0x69},{"\x50",0x6A},{"\x4B",0x6B}
    };

    std::vector<std::pair<std::string, char>> a29 = {
        {"\x2D",0x6C},{"\x0E",0x6D},{"\x0D",0x6E},{"\x0A",0x6F},{"\x03",0x70},{"\x02",0x71},{"\x52",0x72},
        {"\x14",0x73},{"\x06",0x74},{"\x14",0x75},{"\x18",0x76},{"\x03",0x77},{"\x1D",0x78},{"\x1D",0x79},
        {"\x54",0x7A},{"\x71",0x7B}
    };

    std::vector<std::pair<std::string, char>> a30 = {
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

    std::vector<std::pair<std::string, char>> a31 = {
        {"\xDF",0x8F},{"\xE2",0x90},{"\xF4",0x91},{"\xE1",0x92},{"\xE0",0x93},{"\xB4",0x94},
        {"\xD0",0x95},{"\xF8",0x96},{"\xE3",0x97},{"\xFD",0x98},{"\xEB",0x99},{"\xBA",0x9A},
        {"\xEF",0x9B},{"\xF3",0x9C},{"\xBD",0x9D},{"\xFB",0x9E},{"\xE7",0x9F},{"\xC9",0xA0},
        {"\xD5",0xA1},{"\x8C",0xA2},{"\x8C",0xA2},{"\x8C",0xA2}
    };

    if (a25)
    {
        a20(a30);
        ExitProcess(1);
    }

    a20(a28);
    std::string a32;
    std::getline(std::cin, a32);
    std::string a33 = a21(a32);

    a25 |= (IsDebuggerPresent() != 0);
    a25 |= a5();
    a25 |= !a4();
    a25 |= a7();
    a25 |= a8();
    a25 |= a9();

    if (a25)
    {
        a20(a30);
        ExitProcess(1);
    }

    std::string a34 = a18();

    if (a14(a33, a34))
    {
        a20(a29);
    }
    else
    {
        a20(a30);
    }

    a20(a31);
    std::getline(std::cin, a32);

    return a25 ? 1 : 0;
}

int wmain() {
    return a26();
}