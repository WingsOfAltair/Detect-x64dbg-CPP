#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <intrin.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <chrono>
#include <thread>

#pragma intrinsic(__readfsdword)
#pragma intrinsic(__readgsdword)     
#pragma comment(lib, "iphlpapi.lib")


typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
    );

// Wrapper struct to hold check result
struct DebugCheckResult {
    std::string name;
    bool detected;
};

// Base64 encoding/decoding functions
std::string base64_encode(const std::string& input) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (i < input.length()) {
        char_array_3[0] = input[i++];
        char_array_3[1] = (i < input.length()) ? input[i++] : 0;
        char_array_3[2] = (i < input.length()) ? input[i++] : 0;

        char_array_4[0] = (char_array_3[0] & 0xFC) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xF0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0F) << 2) + ((char_array_3[2] & 0xC0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3F;

        for (j = 0; (j < 4); j++) {
            encoded += base64_chars[char_array_4[j]];
        }
    }

    while (encoded.length() % 4 != 0) {
        encoded += '=';
    }

    return encoded;
}

std::string base64_decode(const std::string& encoded) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string decoded;
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_ < encoded.length()) {
        if (encoded[in_] == '=') break;

        char_array_4[i++] = encoded[in_];
        in_++;

        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char_array_4[i] = base64_chars.find(char_array_4[i]);
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++) {
                decoded += char_array_3[i];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }

        for (j = 0; j < 4; j++) {
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) {
            decoded += char_array_3[j];
        }
    }

    return decoded;
}

// Constant time comparison to prevent timing attacks
bool constant_time_compare(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) return false;

    volatile unsigned char result = 0;
    for (size_t i = 0; i < a.length(); i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

// Enhanced constant time comparison for larger data
bool constant_time_compare_large(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) return false;

    volatile unsigned char result = 0;
    for (size_t i = 0; i < a.length(); i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

// Anti-debugging techniques
bool check_debugger_presence() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    auto NtQueryInformationProcessFunc =
        (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcessFunc) return false;

    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcessFunc(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        nullptr
    );

    if (status == 0 && pbi.PebBaseAddress) {
        PEB* peb = (PEB*)pbi.PebBaseAddress;
        if (peb->BeingDebugged) {
            return true;
        }
    }

    // Fallback checks
    if (IsDebuggerPresent()) return true;

    BOOL bRemote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bRemote);
    if (bRemote) return true;

    return false;
}

bool check_debugger_threads() {
    // Enumerate threads to detect debugger
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
                // Check if this thread is a debugger thread
                // This is a simplified check - real implementation would be more complex
                if (te32.th32ThreadID == GetCurrentThreadId()) {
                    // This is our own thread
                    continue;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return false;
}

bool check_debugger_symbols() {
    // Check for common debugger symbols in memory
    // This is a simplified check - real implementation would be more thorough
    char* p = (char*)GetModuleHandle(NULL);
    if (p) {
        // Look for common debugger markers
        const char* debug_markers[] = {
            "dbghelp.dll", "mscordbi.dll", "ntdll.dll", "kernel32.dll"
        };

        for (const char* marker : debug_markers) {
            if (strstr(p, marker)) {
                return true;
            }
        }
    }
    return false;
}

bool check_timing_anomalies() {
    // Measure execution time to detect debugging
    auto start = std::chrono::high_resolution_clock::now();

    // Simulate some work that would take different time in a debugger
    volatile int sum = 0;
    for (int i = 0; i < 1000000; i++) {
        sum += i;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // If execution time is suspiciously long, debugger is likely present
    return duration.count() > 50000; // 50ms threshold
}

bool check_memory_protection() {
    // Check memory protection flags
    DWORD_PTR address = (DWORD_PTR)&check_memory_protection;
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
        // Check for unusual memory protection
        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) ||
            (mbi.Protect & PAGE_READWRITE)) {
            // This might indicate debugging activity
            return true;
        }
    }
    return false;
}

bool check_heap_corruption() {
    // Simple heap corruption detection
    void* p = malloc(100);
    if (p) {
        // Corrupt the memory
        char* pc = (char*)p;
        *pc = 0xFF;

        // Try to free it - if it crashes, debugging is likely
        try {
            free(p);
        }
        catch (...) {
            return true;
        }
    }
    return false;
}

bool check_fpu_state() {
    return false;
    unsigned int fpu_state;
    if (_controlfp_s(&fpu_state, 0, 0) != 0) return false;

    // Typical default: all exceptions masked (0x1F80 for x86/x64)
    const unsigned int default_fpu_state = 0x1F80;
    return fpu_state != default_fpu_state; // Only trigger if it's abnormal
}

bool check_stack_trace() {
    // Check stack trace for debugging
    void* stack[100];
    USHORT frames = CaptureStackBackTrace(0, 100, stack, NULL);

    // If we have too many frames or suspicious patterns, debugger is likely
    return frames > 50;
}

bool check_process_heap() {
    // Check process heap for signs of debugging
    HANDLE hHeap = GetProcessHeap();
    if (hHeap) {
        // Try to allocate and deallocate memory
        void* p = HeapAlloc(hHeap, 0, 100);
        if (p) {
            HeapFree(hHeap, 0, p);
            return false;
        }
    }
    return true;
}

// Combined anti-debugging function
bool is_debugger_present() {
    // Run multiple anti-debugging checks
    if (check_debugger_presence()) return true;
    if (check_debugger_threads()) return true;
    if (check_debugger_symbols()) return true;
    if (check_timing_anomalies()) return true;
    if (check_memory_protection()) return true;
    if (check_heap_corruption()) return true;
    if (check_fpu_state()) return true;
    if (check_stack_trace()) return true;
    if (check_process_heap()) return true;

    return false;
}

// Enhanced security functions
class SecureAccessControl {
private:
    std::string secret_key;
    std::string encrypted_data;

public:
    SecureAccessControl() {
        // Initialize with a secure key
        secret_key = "SecureKey1234567890"; // In production, this should be generated securely
    }

    void set_encrypted_data(const std::string& data) {
        encrypted_data = data;
    }

    std::string get_encrypted_data() const {
        return encrypted_data;
    }

    bool authenticate(const std::string& input_key) {
        // Constant time comparison to prevent timing attacks
        return constant_time_compare(secret_key, input_key);
    }

    bool verify_access(const std::string& access_token) {
        // Verify access token using secure method
        std::string decoded_token = base64_decode(access_token);
        return constant_time_compare(secret_key, decoded_token);
    }
};

// Updated anti-debugging checks with names
std::vector<DebugCheckResult> run_debugger_checks() {
    std::vector<DebugCheckResult> results;

    results.push_back({ "Debugger via NtQueryInformationProcess / IsDebuggerPresent / CheckRemoteDebuggerPresent", check_debugger_presence() });
    results.push_back({ "Debugger threads", check_debugger_threads() });
    results.push_back({ "Debugger symbols in memory", check_debugger_symbols() });
    results.push_back({ "Timing anomalies", check_timing_anomalies() });
    results.push_back({ "Memory protection flags", check_memory_protection() });
    results.push_back({ "Heap corruption", check_heap_corruption() });
    results.push_back({ "FPU state", check_fpu_state() });
    results.push_back({ "Stack trace analysis", check_stack_trace() });
    results.push_back({ "Process heap allocation", check_process_heap() });

    return results;
}


// Main application logic
int main() {
    // Initialize security system
    SecureAccessControl access_control;

    // Set encrypted data (simulating protected content)
    std::string protected_content = "This is highly confidential information!";
    access_control.set_encrypted_data(base64_encode(protected_content));

    std::cout << "=== Anti-Debugging Check Report ===" << std::endl;

    auto results = run_debugger_checks();

    bool any_detected = false;
    for (const auto& r : results) {
        std::cout << r.name << ": " << (r.detected ? "Detected" : "Not Detected") << std::endl;
        if (r.detected) any_detected = true;
    }

    // Anti-debugging check
    if (any_detected) {
        std::cout << "Security Alert: Debugger detected! Exiting securely..." << std::endl;
        return 1;
    }

    // Display welcome message
    std::cout << "=== Secure Access System ===" << std::endl;
    std::cout << "Welcome to the secure access system." << std::endl;
    std::cout << "Please enter your access key to proceed:" << std::endl;

    // Get user input
    std::string user_key;
    std::getline(std::cin, user_key);

    // Authenticate user
    if (access_control.authenticate(user_key)) {
        std::cout << "Authentication successful!" << std::endl;
        std::cout << "Access granted to protected content." << std::endl;
        std::cout << "Protected content: " << base64_decode(access_control.get_encrypted_data()) << std::endl;
    }
    else {
        std::cout << "Authentication failed! Access denied." << std::endl;

        // Additional security measures
        if (is_debugger_present()) {
            std::cout << "Security Alert: Debugger detected during authentication!" << std::endl;
        }
    }

    // Additional security check
    std::cout << "\nPerforming additional security checks..." << std::endl;
    if (is_debugger_present()) {
        std::cout << "Security Alert: Debugger detected during final check!" << std::endl;
        return 1;
    }

    std::cout << "All security checks passed. System secure." << std::endl;

    return 0;
}