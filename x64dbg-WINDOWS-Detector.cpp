// detector_with_obf_class.cpp
// Restores ObfuscatedSecret class for obfuscated byte arrays (base64 parts and messages).
// Compile with MSVC (x64) - uses Windows APIs.

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
#include <cassert>

// --------------------------- Utility: base64 encoder/decoder (RFC4648, no newlines) ---------------------------

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode_bytes(const unsigned char* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        unsigned int n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(b64_table[(n >> 18) & 0x3F]);
        out.push_back(b64_table[(n >> 12) & 0x3F]);
        out.push_back(b64_table[(n >> 6) & 0x3F]);
        out.push_back(b64_table[n & 0x3F]);
    }
    if (i < len) {
        unsigned int n = data[i] << 16;
        out.push_back(b64_table[(n >> 18) & 0x3F]);
        if (i + 1 < len) {
            n |= (data[i + 1] << 8);
            out.push_back(b64_table[(n >> 12) & 0x3F]);
            out.push_back(b64_table[(n >> 6) & 0x3F]);
            out.push_back('=');
        }
        else {
            out.push_back(b64_table[(n >> 12) & 0x3F]);
            out.push_back('=');
            out.push_back('=');
        }
    }
    return out;
}

// decode base64 into bytes (returns empty on invalid)
std::vector<unsigned char> base64_decode_to_bytes(const std::string& s) {
    // Quick decoder suitable for valid RFC4648 base64 (no newlines). Not extremely defensive.
    int len = (int)s.size();
    if (len % 4 != 0) return {};
    auto dec = std::vector<int>(256, -1);
    for (int i = 0; i < 64; ++i) dec[(unsigned char)b64_table[i]] = i;
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

// UTF conversion helper: wstring -> UTF-8
static std::string utf8_from_wstring(const std::wstring& ws) {
    if (ws.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out;
    out.resize(needed);
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &out[0], needed, nullptr, nullptr);
    return out;
}

// UTF conversion helper: UTF-8 -> wstring
static std::wstring wstring_from_utf8(const std::string& s) {
    if (s.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out;
    out.resize(needed);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], needed);
    return out;
}

// Secure zero for std::string / vector
static void secure_zero_string(std::string& s) {
    if (!s.empty()) {
        SecureZeroMemory(&s[0], s.size());
        s.clear();
        s.shrink_to_fit();
    }
}
static void secure_zero_vector(std::vector<unsigned char>& v) {
    if (!v.empty()) {
        SecureZeroMemory(v.data(), v.size());
        v.clear();
        v.shrink_to_fit();
    }
}

// --------------------------- ObfuscatedSecret class (for XOR-obf byte arrays) ---------------------------
class ObfuscatedSecret {
    // Stores XOR-obfuscated bytes in static data (in your binary).
    // At runtime we decode into base64_text_ (std::string), optionally lock it, then
    // provide methods to obtain the plaintext wstring (by base64-decoding to bytes
    // and converting from UTF-8).
public:
    ObfuscatedSecret(const unsigned char* obf_bytes, size_t len, unsigned char xor_key)
        : xor_key_(xor_key), len_(len)
    {
        if (len_ == 0) return;
        // decode XOR into temporary base64 text
        base64_text_.resize(len_);
        for (size_t i = 0; i < len_; ++i) base64_text_[i] = static_cast<char>(obf_bytes[i] ^ xor_key_);
        // attempt to lock the decoded base64 text in memory
        if (!base64_text_.empty()) {
            VirtualLock(&base64_text_[0], base64_text_.size());
        }
    }

    ~ObfuscatedSecret() {
        secure_clear();
    }

    // Return the base64 text (non-owning copy). Caller should not keep it long.
    const std::string& get_base64_text() const { return base64_text_; }

    // Decode into UTF-8 plaintext bytes (base64 -> bytes)
    std::vector<unsigned char> decode_base64_to_bytes() const {
        return base64_decode_to_bytes(base64_text_);
    }

    // Decode into wstring (assumes original plaintext was UTF-8)
    std::wstring reveal_wstring() const {
        std::vector<unsigned char> bytes = decode_base64_to_bytes();
        if (bytes.empty()) return {};
        std::string utf8((char*)bytes.data(), bytes.size());
        std::wstring ret = wstring_from_utf8(utf8);
        secure_zero_string(utf8);
        secure_zero_vector(bytes);
        return ret;
    }

    void secure_clear() {
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
    std::string base64_text_; // holds decoded (XORed) base64 text
};

// --------------------------- Anti-debug helpers (same as before) ---------------------------

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

void PrintWide(const std::wstring& s)
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

bool check_software_breakpoint(void* address)
{
    unsigned char byte = 0;
    SIZE_T read = 0;
    if (ReadProcessMemory(GetCurrentProcess(), address, &byte, 1, &read) && read == 1)
        return (byte == 0xCC);
    return false;
}

// --------------------------- constant-time split compare for base64 strings ---------------------------
static bool constant_time_equal_split_b64(const std::string& input_b64,
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

// --------------------------- Example obfuscated secret parts (kept as character XOR expressions) ---------------------------
// For small secret parts it's okay to show the obfuscated-by-expression approach.
// Example secret "1337" -> base64 "MTMzNw==" -> split "MT","Mz","Nw","=="
constexpr unsigned char KEY = 0xAA;
unsigned char secret_part1_obf[] = { static_cast<unsigned char>('M') ^ KEY, static_cast<unsigned char>('T') ^ KEY }; // "MT"
unsigned char secret_part2_obf[] = { static_cast<unsigned char>('M') ^ KEY, static_cast<unsigned char>('z') ^ KEY }; // "Mz"
unsigned char secret_part3_obf[] = { static_cast<unsigned char>('N') ^ KEY, static_cast<unsigned char>('w') ^ KEY }; // "Nw"
unsigned char secret_part4_obf[] = { static_cast<unsigned char>('=') ^ KEY, static_cast<unsigned char>('=') ^ KEY }; // "=="

// --------------------------- Example base64-encoded messages (these are base64 text, you can XOR-obfuscate in the binary) ----
// If you want these *obfuscated in the binary* as well, run the small generator script in the comments below and replace these with the produced unsigned char[] arrays.

std::string b64_legit = "TGVnaXRpbWF0ZSBDb3B5";
std::string b64_illegit = "SWxsZWdpdGltYXRlIENvcHk=";
std::string b64_prompt = "RW50ZXIgeW91ciBzZWNyZXQga2V5OiA=";

// ---------- If you want to embed those base64 strings XOR-obfuscated in the binary ----------
// Run this tiny helper program locally (or implement equivalent in your build script) to produce
// C initializers for obfuscated arrays (then paste the initializer into the source).
/*
#include <iostream>
#include <iomanip>
#include <string>
int main() {
    std::string s = "TGVnaXRpbWF0ZSBDb3B5"; // replace with desired base64 text
    unsigned char key = 0xAA;
    std::cout << "unsigned char my_obf[] = { ";
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char v = static_cast<unsigned char>(s[i]) ^ key;
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)v;
        if (i + 1 < s.size()) std::cout << ", ";
    }
    std::cout << " }; // len=" << std::dec << s.size() << "\\n";
    return 0;
}
*/
// After producing the initializer, replace the std::string b64_legit above with an ObfuscatedSecret using
// the produced array and ObfuscatedSecret constructor.

// --------------------------- Main ---------------------------

int wmain()
{
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

    // critical addresses check (small example)
    void* critical_addresses[] = { reinterpret_cast<void*>(&IsDebuggerPresent),
                                   reinterpret_cast<void*>(&veh_breakpoint_test) };
    for (void* addr : critical_addresses) {
        if (check_software_breakpoint(addr)) debuggerDetected = true;
    }

    // For simplicity here we use base64 literals (still not the plaintext in binary).
    // Convert them to wstring now (decode base64 -> bytes -> utf8 -> wstring)
    // --- safe decoding for legit, illegit, prompt (replace the 3 one-liners) ---

    // decode legit
    std::wstring legit_w;
    {
        std::vector<unsigned char> tmp = base64_decode_to_bytes(b64_legit); // decode once
        std::string tmp_utf8(tmp.begin(), tmp.end());                        // bytes -> utf8 string
        legit_w = wstring_from_utf8(tmp_utf8);                               // utf8 -> wstring
        secure_zero_vector(tmp);                                             // wipe tmp bytes
        secure_zero_string(tmp_utf8);                                        // wipe tmp utf8
    }

    // decode illegit
    std::wstring illegit_w;
    {
        std::vector<unsigned char> tmp = base64_decode_to_bytes(b64_illegit);
        std::string tmp_utf8(tmp.begin(), tmp.end());
        illegit_w = wstring_from_utf8(tmp_utf8);
        secure_zero_vector(tmp);
        secure_zero_string(tmp_utf8);
    }

    // If any VirtualLock/obfuscation checks required a lock, you'd handle it in ObfuscatedSecret
    // For the secret parts we want them as base64 text in memory (locked inside ObfuscatedSecret).
    // Now check VirtualLock success - we did VirtualLock inside constructor.

    // If a debugger was detected earlier, show illegit and exit
    if (debuggerDetected) {
        PrintWide(illegit_w);
        // clear everything
        secure_zero_string(b64_legit); secure_zero_string(b64_illegit); secure_zero_string(b64_prompt);
        return 1;
    }

    // decode prompt
    std::wstring prompt_w;
    {
        std::vector<unsigned char> tmp = base64_decode_to_bytes(b64_prompt);
        std::string tmp_utf8(tmp.begin(), tmp.end());
        prompt_w = wstring_from_utf8(tmp_utf8);
        secure_zero_vector(tmp);
        secure_zero_string(tmp_utf8);
    }

    // Show prompt (from decoded base64)
    PrintWide(prompt_w);

    std::wstring input;
    std::getline(std::wcin, input);

    // re-run anti-debug checks
    debuggerDetected |= (IsDebuggerPresent() != 0);
    debuggerDetected |= check_peb_being_debugged();
    debuggerDetected |= !veh_breakpoint_test();
    debuggerDetected |= check_nt_query_information_process_hooked();
    debuggerDetected |= check_process_debug_port_via_nt();
    debuggerDetected |= any_thread_has_hw_breakpoints();

    if (debuggerDetected) {
        PrintWide(illegit_w);
        secure_zero_string(b64_legit); secure_zero_string(b64_illegit); secure_zero_string(b64_prompt);
        return 1;
    }

    // base64-encode user input (convert to UTF-8 then base64)
    std::string input_utf8 = utf8_from_wstring(input);
    std::string input_b64 = base64_encode_bytes((const unsigned char*)input_utf8.data(), input_utf8.size());

    // Create ObfuscatedSecret instances for the secret parts (they decode to base64 text)
    ObfuscatedSecret p1(secret_part1_obf, sizeof(secret_part1_obf), KEY);
    ObfuscatedSecret p2(secret_part2_obf, sizeof(secret_part2_obf), KEY);
    ObfuscatedSecret p3(secret_part3_obf, sizeof(secret_part3_obf), KEY);
    ObfuscatedSecret p4(secret_part4_obf, sizeof(secret_part4_obf), KEY);

    // If you replaced message base64 strings with obfuscated arrays,
    // you'd do the same: ObfuscatedSecret legit_msg_obf(...); std::wstring legit = legit_msg_obf.reveal_wstring();

    // get base64 parts as std::string from the ObfuscatedSecret objects:
    std::string a = p1.get_base64_text();
    std::string b = p2.get_base64_text();
    std::string c = p3.get_base64_text();
    std::string d = p4.get_base64_text();

    if (debuggerDetected) {
        PrintWide(illegit_w);
        p1.secure_clear(); p2.secure_clear(); p3.secure_clear(); p4.secure_clear();
        secure_zero_string(b64_legit); secure_zero_string(b64_illegit); secure_zero_string(b64_prompt);
        return 1;
    }

    // constant-time split compare
    bool ok = constant_time_equal_split_b64(input_b64, a, b, c, d);

    // cleanup
    p1.secure_clear(); p2.secure_clear(); p3.secure_clear(); p4.secure_clear();
    secure_zero_string(input_b64);
    secure_zero_string(input_utf8);
    secure_zero_string(b64_legit); secure_zero_string(b64_illegit); secure_zero_string(b64_prompt);

    if (ok) {
        PrintWide(legit_w);
    }
    else {
        PrintWide(illegit_w);
    }

    PrintWide(L"Press Enter to exit...");
    std::wstring dummy;
    std::getline(std::wcin, dummy);

    return debuggerDetected ? 1 : 0;
}
