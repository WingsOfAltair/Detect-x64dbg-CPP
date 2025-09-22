Multi-Layer Debugger Detection

A C++ demo project that implements a multi-layer anti-debugging detection system for Windows. This tool combines several techniques to detect debuggers, including hardware breakpoints, software breakpoints, VEH, PEB flags, and NtQueryInformationProcess hooks.

⚠️ Intended for educational purposes. Use responsibly and only on software you own.

### Features:

## 1. Classic Debugger Checks:

  - IsDebuggerPresent()

  - PEB BeingDebugged flag

  - NtQueryInformationProcess hooks

  - ProcessDebugPort

  - VEH (Vectored Exception Handler) breakpoint detection

## 2. Hardware Breakpoint Detection:

  - Enumerates all threads

  - Reads debug registers (DR0–DR3) to detect breakpoints

  - Skips threads that cannot be safely suspended

  - Works for per-thread hardware breakpoints set by debuggers like x64dbg

## 3. Software Breakpoint Detection:

  - Checks selected critical addresses for INT3 (0xCC) instructions

  - Can be expanded to scan more addresses or modules

## 4. Environment-Based Overrides:

  - ANTI_DEBUG to disable anti-debugging for testing

  - ANTI_DEBUG_FORCE to force checks even in debug builds

## 5. Safe for Visual Studio Debugging:

  - Avoids infinite loops by skipping threads that cannot be opened

  - Does not suspend the current thread

  - Properly checks return values when enumerating threads

### Getting Started
### Requirements

  - Windows 7 or later (x86/x64)

  - Microsoft Visual Studio 2019+ (tested with MSVC)

  - C++17 compatible compiler (or higher)

### Building

  - Clone the repository
  - Open the project in Visual Studio or build via command line
  - Run the compiled executable

### Environment Variables
```
- ANTI_DEBUG	Disable anti-debugging checks (for testing)	0 = disabled, 1 or empty = enabled
- ANTI_DEBUG_FORCE	Force anti-debugging checks in debug builds	1 = force, 0 or empty = default
```

### Output Example:
```
Multi-layer debugger detection demo (with HW/SW breakpoints)

IsDebuggerPresent(): no
PEB BeingDebugged:    no
VEH breakpoint seen:  YES
NtQueryInformationProcess hooked: no
ProcessDebugPort != 0: no
Hardware breakpoints: YES
Software breakpoint detected at address: 0x7FF6F1234567

Final result: Debugger detected!
```

### To ensure static analysis tools such as IDA Pro have a hard time reading through the code, make sure to do the following:

1. Compile Without Debug Symbols

In MSVC:

Set Configuration to Release.

Set Debug Information Format to None (/DEBUG:NONE) in C/C++ → General.


In CMake:

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi- /DEBUG:NONE")

This removes .pdb files and local variable names from the binary.

Outcome: IDA will see only compiler-generated names like sub_401000 instead of wmain.



---

2. Strip Symbols / Minimize Exports

Use the linker to not export any functions:

In MSVC: Properties → Linker → Advanced → Export All Symbols → No.

Or use __declspec(dllexport) only when necessary.


Use strip.exe (for MinGW) or editbin.exe /strip (MSVC) to remove symbol tables from the executable.



---

3. Obfuscate Function and Variable Names

For internal functions:

Rename them to meaningless names, e.g., f1, f2, g123.

For classes or helpers, make them struct a { ... };.


Example:

void PrintPartsNoConcat(std::vector<std::wstring*>& parts) { ... }
// becomes
void f1(std::vector<std::wstring*>& a) { ... }



---

4. Use Inline and Static

Make helper functions static or inline so they do not appear in the export table.

static void f1(std::vector<std::wstring*>& a) { ... }



---

5. Obfuscate the Call Stack

IDA shows names in pseudocode using debug info + RTTI. You can:

Disable RTTI if not needed (/GR- in MSVC).

Avoid C++ exceptions or virtual functions that leave RTTI info.

Use anonymous namespaces for C++:

namespace { void f1() { ... } }




---

6. Optional: Use a Binary Obfuscator

Tools like Themida, VMProtect, Obsidium can rename functions, scramble control flow, and encrypt strings.

Even without debug symbols, these tools make IDA’s pseudocode almost unreadable.



---

## Recommended Combination

1. Release build without debug info.


2. Static / inline / anonymous namespaces for helpers.


3. Rename all functions/variables to meaningless short names.


4. Keep string obfuscation (XOR at runtime) as we already discussed.


5. Optionally, pack or obfuscate the binary to prevent static analysis.