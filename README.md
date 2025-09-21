Multi-Layer Debugger Detection

A C++ demo project that implements a multi-layer anti-debugging detection system for Windows. This tool combines several techniques to detect debuggers, including hardware breakpoints, software breakpoints, VEH, PEB flags, and NtQueryInformationProcess hooks.

⚠️ Intended for educational purposes. Use responsibly and only on software you own.

Features

1- Classic Debugger Checks

  A- IsDebuggerPresent()

  B- PEB BeingDebugged flag

  C- NtQueryInformationProcess hooks

  D- ProcessDebugPort

  E- VEH (Vectored Exception Handler) breakpoint detection

2- Hardware Breakpoint Detection

  A- Enumerates all threads

  B- Reads debug registers (DR0–DR3) to detect breakpoints

  C- Skips threads that cannot be safely suspended

  D- Works for per-thread hardware breakpoints set by debuggers like x64dbg

3- Software Breakpoint Detection

  A- Checks selected critical addresses for INT3 (0xCC) instructions

  B- Can be expanded to scan more addresses or modules

4- Environment-Based Overrides

  A- ANTI_DEBUG to disable anti-debugging for testing

  B- ANTI_DEBUG_FORCE to force checks even in debug builds

5- Safe for Visual Studio Debugging

  A- Avoids infinite loops by skipping threads that cannot be opened

  B- Does not suspend the current thread

  C- Properly checks return values when enumerating threads

Getting Started
Requirements

  Windows 7 or later (x86/x64)

  Microsoft Visual Studio 2019+ (tested with MSVC)

  C++17 compatible compiler (or higher)

Building

  Clone the repository
  Open the project in Visual Studio or build via command line
  Run the compiled executable

Environment Variables
Variable	Description	Values
ANTI_DEBUG	Disable anti-debugging checks (for testing)	0 = disabled, 1 or empty = enabled
ANTI_DEBUG_FORCE	Force anti-debugging checks in debug builds	1 = force, 0 or empty = default

Output Example:
Multi-layer debugger detection demo (with HW/SW breakpoints)

IsDebuggerPresent(): no
PEB BeingDebugged:    no
VEH breakpoint seen:  YES
NtQueryInformationProcess hooked: no
ProcessDebugPort != 0: no
Hardware breakpoints: YES
Software breakpoint detected at address: 0x7FF6F1234567

Final result: Debugger detected!
