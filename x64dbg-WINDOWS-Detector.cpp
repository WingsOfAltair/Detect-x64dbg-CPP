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

std::string b23(const char* name)
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

void b22(const std::wstring& s)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == nullptr) {
        std::wcout << s << std::endl;
        return;
    }
    DWORD written = 0;
    WriteConsoleW(hOut, s.c_str(), static_cast<DWORD>(s.size()), &written, nullptr);
    const wchar_t nl = L'\n';
    WriteConsoleW(hOut, &nl, 1, &written, nullptr);
}

void b21(const std::wstring& s)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == nullptr) {
        std::wcout << s << std::endl;
        return;
    }
    DWORD written = 0;
    WriteConsoleW(hOut, s.c_str(), static_cast<DWORD>(s.size()), &written, nullptr);
}

bool b20()
{
    std::string v = b23("ANTI_DEBUG");
    if (v.empty()) return true;
    if (v == "0" || _stricmp(v.c_str(), "false") == 0 || _stricmp(v.c_str(), "no") == 0)
        return false;
    return true;
}

bool b19()
{
    std::string v = b23("ANTI_DEBUG_FORCE");
    if (v.empty()) return false;
    if (v == "1" || _stricmp(v.c_str(), "true") == 0) return true;
    return false;
}

volatile LONG b18 = 0;
PVOID b17 = nullptr;

LONG CALLBACK b16(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo && ExceptionInfo->ExceptionRecord &&
        ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        InterlockedExchange(&b18, 1);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool b15()
{
    b17 = AddVectoredExceptionHandler(1, b16);
    if (!b17) return false;
    InterlockedExchange(&b18, 0);

    __try { __debugbreak(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    bool saw = (InterlockedCompareExchange(&b18, 0, 0) != 0);
    RemoveVectoredExceptionHandler(b17);
    b17 = nullptr;
    return saw;
}

bool b14()
{
#ifdef _M_X64
    PBYTE pPEB = (PBYTE)__readgsqword(0x60);
#else
    PBYTE pPEB = (PBYTE)__readfsdword(0x30);
#endif
    if (!pPEB) return false;
    return (*(pPEB + 2) != 0);
}

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool b13(LPCSTR funcName)
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

bool b12() { return !b13("NtQueryInformationProcess"); }

bool b11()
{
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return false;
    auto NtQIP = (NtQueryInformationProcess_t)GetProcAddress(hNt, "NtQueryInformationProcess");
    if (!NtQIP) return false;

    ULONG debugPort = 0;
    NTSTATUS st = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), nullptr);
    return (st == 0 && debugPort != 0);
}

bool b10()
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

bool b9(void* address)
{
    unsigned char byte = 0;
    SIZE_T read = 0;
    if (ReadProcessMemory(GetCurrentProcess(), address, &byte, 1, &read) && read == 1)
        return (byte == 0xCC);
    return false;
}

void* b8[] = {
    reinterpret_cast<void*>(&IsDebuggerPresent),
    reinterpret_cast<void*>(&b15)
};

bool b7(const std::wstring& input,
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

bool b6(std::wstring& s)
{
    if (s.empty()) return false;
    return VirtualLock(&s[0], s.size() * sizeof(wchar_t)) != 0;
}

void b5(std::wstring& s)
{
    if (s.empty()) return;
    SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t));
    VirtualUnlock(&s[0], s.size() * sizeof(wchar_t));
    s.clear();
    s.shrink_to_fit();
}

class b1 {
private:
    std::vector<wchar_t> encoded_;
    wchar_t xorKey_;

public:
    b1(const std::wstring& secret, wchar_t key = 0xAA)
        : xorKey_(key)
    {
        encoded_.reserve(secret.size());
        for (auto c : secret)
            encoded_.push_back(c ^ xorKey_);
        if (!encoded_.empty())
            VirtualLock(encoded_.data(), encoded_.size() * sizeof(wchar_t));
    }

    ~b1() { b3(); }

    bool b2(const std::wstring& input) const
    {
        if (input.size() != encoded_.size()) return false;
        volatile unsigned diff = 0;
        for (size_t i = 0; i < input.size(); ++i)
            diff |= (encoded_[i] ^ xorKey_) ^ input[i];
        return diff == 0;
    }

    void b3()
    {
        if (!encoded_.empty()) {
            SecureZeroMemory(encoded_.data(), encoded_.size() * sizeof(wchar_t));
            VirtualUnlock(encoded_.data(), encoded_.size() * sizeof(wchar_t));
            encoded_.clear();
        }
    }
};

std::wstring b4(const wchar_t* obf, size_t len, wchar_t key)
{
    std::wstring out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i)
        out.push_back(obf[i] ^ key);
    return out;
}

int a1()
{
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);

    b22(L"X64dbg Multi-layer debugger detection demo (with HW/SW breakpoints)\n");

    bool b24 = false;

    b24 |= (IsDebuggerPresent() != 0);
    b24 |= b14();
    b24 |= !b15();
    b24 |= b12();
    b24 |= b11();
    b24 |= b10();

    for (void* b25 : b8)
    {
        if (b9(b25))
        {
            b24 = true;
        }
    }

    constexpr wchar_t b26 = 0xAA;

    wchar_t b27[] = { 0x31 ^ b26, 0x33 ^ b26, 0x33 ^ b26, 0x37 ^ b26 };
    wchar_t b28[] = {
        L'L' ^ b26,L'e' ^ b26,L'g' ^ b26,L'i' ^ b26,L't' ^ b26,L'i' ^ b26,L'm' ^ b26,L'a' ^ b26,L't' ^ b26,L'e' ^ b26,
        L' ' ^ b26,L'C' ^ b26,L'o' ^ b26,L'p' ^ b26,L'y' ^ b26
    };
    wchar_t b29[] = {
        L'I' ^ b26,L'l' ^ b26,L'l' ^ b26,L'e' ^ b26,L'g' ^ b26,L'i' ^ b26,L't' ^ b26,L'i' ^ b26,L'm' ^ b26,L'a' ^ b26,L't' ^ b26,L'e' ^ b26,
        L' ' ^ b26,L'C' ^ b26,L'o' ^ b26,L'p' ^ b26,L'y' ^ b26
    };
    wchar_t b30[] = {
        L'E' ^ b26,L'n' ^ b26,L't' ^ b26,L'e' ^ b26,L'r' ^ b26,L' ' ^ b26,L'y' ^ b26,L'o' ^ b26,L'u' ^ b26,L'r' ^ b26,
        L' ' ^ b26,L's' ^ b26,L'e' ^ b26,L'c' ^ b26,L'r' ^ b26,L'e' ^ b26,L't' ^ b26,L' ' ^ b26,L'k' ^ b26,L'e' ^ b26,L'y' ^ b26,L':' ^ b26,L' ' ^ b26
    };

    std::wstring b31 = b4(b27, 4, b26);
    std::wstring b32 = b4(b28, 15, b26);
    std::wstring b33 = b4(b29, 17, b26);
    std::wstring b34 = b4(b30, 23, b26);

    if (!b6(b31))
    {
        b5(b31);
        b5(b32);
        b5(b33);
        b5(b34);
        ExitProcess(1);
    }

    if (b24)
    {
        b5(b31);
        b5(b32);
        b22(b33);
        b5(b33);
        b5(b34);

        ExitProcess(1);
    }

    b22(b34);

    std::wstring b35;
    std::getline(std::wcin, b35);

    b24 |= (IsDebuggerPresent() != 0);
    b24 |= b14();
    b24 |= !b15();
    b24 |= b12();
    b24 |= b11();
    b24 |= b10();

    if (b24)
    {
        b5(b31);
        b5(b32);
        b22(b33);
        b5(b33);
        b5(b34);

        ExitProcess(1);
    }

    if (b7(b35, b31.substr(0, 1), b31.substr(1, 1),
        b31.substr(2, 1), b31.substr(3, 1)))
    {
        b5(b31);
        b22(b32);
    }
    else
    {
        b5(b31);
        b22(b33);
    }

    b5(b32);
    b5(b33);
    b5(b34);

    b22(L"Press Enter to exit...");
    std::wstring dummy;
    std::getline(std::wcin, dummy);

    return b24 ? 1 : 0;
}

int wmain() {
    return a1();
}