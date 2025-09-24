#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <io.h>
#include <fcntl.h>
#include <cassert>

static const char a1[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string a2(const unsigned char* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        unsigned int n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(a1[(n >> 18) & 0x3F]);
        out.push_back(a1[(n >> 12) & 0x3F]);
        out.push_back(a1[(n >> 6) & 0x3F]);
        out.push_back(a1[n & 0x3F]);
    }
    if (i < len) {
        unsigned int n = data[i] << 16;
        out.push_back(a1[(n >> 18) & 0x3F]);
        if (i + 1 < len) {
            n |= (data[i + 1] << 8);
            out.push_back(a1[(n >> 12) & 0x3F]);
            out.push_back(a1[(n >> 6) & 0x3F]);
            out.push_back('=');
        }
        else {
            out.push_back(a1[(n >> 12) & 0x3F]);
            out.push_back('=');
            out.push_back('=');
        }
    }
    return out;
}

std::vector<unsigned char> a3(const std::string& s) {
    int len = (int)s.size();
    if (len % 4 != 0) return {};
    auto dec = std::vector<int>(256, -1);
    for (int i = 0; i < 64; ++i) dec[(unsigned char)a1[i]] = i;
    dec['='] = 0;

    std::vector<unsigned char> out;
    out.reserve((len / 4) * 3);
    for (int i = 0; i < len; i += 4) {
        int a = dec[(unsigned char)s[i]];
        int b = dec[(unsigned char)s[i + 1]];
        int c = dec[(unsigned char)s[i + 2]];
        int d = dec[(unsigned char)s[i + 3]];
        if (a < 0 || b < 0 || c < 0 || d < 0) return {};
        unsigned int n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push_back((n >> 16) & 0xFF);
        if (s[i + 2] != '=') out.push_back((n >> 8) & 0xFF);
        if (s[i + 3] != '=') out.push_back(n & 0xFF);
    }
    return out;
}

static std::string a4(const std::wstring& ws) {
    if (ws.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out;
    out.resize(needed);
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &out[0], needed, nullptr, nullptr);
    return out;
}

static std::wstring a5(const std::string& s) {
    if (s.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out;
    out.resize(needed);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], needed);
    return out;
}

static void a6(std::string& s) {
    if (!s.empty()) {
        SecureZeroMemory(&s[0], s.size());
        s.clear();
        s.shrink_to_fit();
    }
}
static void a7(std::vector<unsigned char>& v) {
    if (!v.empty()) {
        SecureZeroMemory(v.data(), v.size());
        v.clear();
        v.shrink_to_fit();
    }
}

class a8 {
public:
    a8(const unsigned char* obf_bytes, size_t len, unsigned char xor_key)
        : xor_key_(xor_key), len_(len)
    {
        if (len_ == 0) return;
        base64_text_.resize(len_);
        for (size_t i = 0; i < len_; ++i) base64_text_[i] = static_cast<char>(obf_bytes[i] ^ xor_key_);
        if (!base64_text_.empty()) {
            VirtualLock(&base64_text_[0], base64_text_.size());
        }
    }

    ~a8() {
        a9();
    }

    const std::string& a10() const { return base64_text_; }

    std::vector<unsigned char> a11() const {
        return a3(base64_text_);
    }

    std::wstring a12() const {
        std::vector<unsigned char> bytes = a11();
        if (bytes.empty()) return {};
        std::string utf8((char*)bytes.data(), bytes.size());
        std::wstring ret = a5(utf8);
        a6(utf8);
        a7(bytes);
        return ret;
    }

    void a9() {
        if (!base64_text_.empty()) {
            SecureZeroMemory(&base64_text_[0], base64_text_.size());
            VirtualUnlock(&base64_text_[0], base64_text_.size());
            base64_text_.clear();
            base64_text_.shrink_to_fit();
        }
    }

private:
    unsigned char xor_key_;
    size_t len_;
    std::string base64_text_;
};

std::string a13(const char* name)
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

void a14(const std::wstring& s)
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

volatile LONG a16 = 0;
PVOID a17 = nullptr;

LONG CALLBACK a18(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo && ExceptionInfo->ExceptionRecord &&
        ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        InterlockedExchange(&a16, 1);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool a19()
{
    a17 = AddVectoredExceptionHandler(1, a18);
    if (!a17) return false;
    InterlockedExchange(&a16, 0);

    __try { __debugbreak(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    bool saw = (InterlockedCompareExchange(&a16, 0, 0) != 0);
    RemoveVectoredExceptionHandler(a17);
    a17 = nullptr;
    return saw;
}

bool a20()
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

bool a21(LPCSTR funcName)
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

bool a22() { return !a21("NtQueryInformationProcess"); }

bool a23()
{
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return false;
    auto NtQIP = (NtQueryInformationProcess_t)GetProcAddress(hNt, "NtQueryInformationProcess");
    if (!NtQIP) return false;

    ULONG debugPort = 0;
    NTSTATUS st = NtQIP(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), nullptr);
    return (st == 0 && debugPort != 0);
}

bool a24()
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

bool a25(void* address)
{
    unsigned char byte = 0;
    SIZE_T read = 0;
    if (ReadProcessMemory(GetCurrentProcess(), address, &byte, 1, &read) && read == 1)
        return (byte == 0xCC);
    return false;
}

static bool a26(const std::string& input_b64,
    const std::string& a, const std::string& b,
    const std::string& c, const std::string& d)
{
    size_t totalLen = a.size() + b.size() + c.size() + d.size();
    if (input_b64.size() != totalLen) return false;

    volatile unsigned diff = 0;
    size_t pos = 0;

    for (char ch : a) diff |= static_cast<unsigned char>(input_b64[pos++]) ^ static_cast<unsigned char>(ch);
    for (char ch : b) diff |= static_cast<unsigned char>(input_b64[pos++]) ^ static_cast<unsigned char>(ch);
    for (char ch : c) diff |= static_cast<unsigned char>(input_b64[pos++]) ^ static_cast<unsigned char>(ch);
    for (char ch : d) diff |= static_cast<unsigned char>(input_b64[pos++]) ^ static_cast<unsigned char>(ch);

    return diff == 0;
}

constexpr unsigned char a27 = 0xAA;
unsigned char a28[] = { static_cast<unsigned char>('M') ^ a27, static_cast<unsigned char>('T') ^ a27 };
unsigned char a29[] = { static_cast<unsigned char>('M') ^ a27, static_cast<unsigned char>('z') ^ a27 };
unsigned char a30[] = { static_cast<unsigned char>('N') ^ a27, static_cast<unsigned char>('w') ^ a27 };
unsigned char a31[] = { static_cast<unsigned char>('=') ^ a27, static_cast<unsigned char>('=') ^ a27 };

std::string a32 = "TGVnaXRpbWF0ZSBDb3B5";
std::string a33 = "SWxsZWdpdGltYXRlIENvcHk=";
std::string a34 = "RW50ZXIgeW91ciBzZWNyZXQga2V5OiA=";

int a60()
{
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);

    a14(L"X64dbg Multi-layer debugger detection demo (with HW/SW breakpoints)\n");

    bool a35 = false;

    a35 |= (IsDebuggerPresent() != 0);
    a35 |= a20();
    a35 |= !a19();
    a35 |= a22();
    a35 |= a23();
    a35 |= a24();

    void* a36[] = { reinterpret_cast<void*>(&IsDebuggerPresent),
                                   reinterpret_cast<void*>(&a19) };
    for (void* a37 : a36) {
        if (a25(a37)) a35 = true;
    }

    std::wstring a38;
    {
        std::vector<unsigned char> a39 = a3(a32); 
        std::string a40(a39.begin(), a39.end());     
        a38 = a5(a40);                     
        a7(a39);                                          
        a6(a40);
    }

    std::wstring a41;
    {
        std::vector<unsigned char> a42 = a3(a33);
        std::string a43(a42.begin(), a42.end());
        a41 = a5(a43);
        a7(a42);
        a6(a43);
    }

    if (a35) {
        a14(a41);
        
        a6(a32); a6(a33); a6(a34);
        return 1;
    }

    std::wstring a44;
    {
        std::vector<unsigned char> a45 = a3(a34);
        std::string a46(a45.begin(), a45.end());
        a44 = a5(a46);
        a7(a45);
        a6(a46);
    }

    a14(a44);

    std::wstring a47;
    std::getline(std::wcin, a47);

    a35 |= (IsDebuggerPresent() != 0);
    a35 |= a20();
    a35 |= !a19();
    a35 |= a22();
    a35 |= a23();
    a35 |= a24();

    if (a35) {
        a14(a41);
        a6(a32); a6(a33); a6(a34);
        return 1;
    }

    std::string a48 = a4(a47);
    std::string a49 = a2((const unsigned char*)a48.data(), a48.size());

    a8 a51(a28, sizeof(a28), a27);
    a8 a53(a29, sizeof(a29), a27);
    a8 a55(a30, sizeof(a30), a27);
    a8 a57(a31, sizeof(a31), a27);

    std::string a50 = a51.a10();
    std::string a52 = a53.a10();
    std::string a54 = a55.a10();
    std::string a56 = a57.a10();

    if (a35) {
        a14(a41);
        a51.a9(); a53.a9(); a55.a9(); a57.a9();
        a6(a32); a6(a33); a6(a34);
        return 1;
    }

    bool a58 = a26(a49, a50, a52, a54, a56);

    a51.a9(); a53.a9(); a55.a9(); a57.a9();
    a6(a49);
    a6(a48);
    a6(a32); a6(a33); a6(a34);

    if (a58) {
        a14(a38);
    }
    else {
        a14(a41);
    }

    a14(L"Press Enter to exit...");
    std::wstring a59;
    std::getline(std::wcin, a59);

    return a35 ? 1 : 0;
}

int wmain() {
    return a60();
}