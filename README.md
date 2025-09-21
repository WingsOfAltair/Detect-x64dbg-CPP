Multi-Layer Debugger Detection

A C++ demo project that implements a multi-layer anti-debugging detection system for Windows. This tool combines several techniques to detect debuggers, including hardware breakpoints, software breakpoints, VEH, PEB flags, and NtQueryInformationProcess hooks.

⚠️ Intended for educational purposes. Use responsibly and only on software you own.

Features

Classic Debugger Checks

  IsDebuggerPresent()

  PEB BeingDebugged flag

  NtQueryInformationProcess hooks

  ProcessDebugPort

  VEH (Vectored Exception Handler) breakpoint detection

Hardware Breakpoint Detection

  Enumerates all threads

  Reads debug registers (DR0–DR3) to detect breakpoints

  Skips threads that cannot be safely suspended

  Works for per-thread hardware breakpoints set by debuggers like x64dbg

Software Breakpoint Detection

  Checks selected critical addresses for INT3 (0xCC) instructions

  Can be expanded to scan more addresses or modules

Environment-Based Overrides

  ANTI_DEBUG to disable anti-debugging for testing

  ANTI_DEBUG_FORCE to force checks even in debug builds

Safe for Visual Studio Debugging

  Avoids infinite loops by skipping threads that cannot be opened

  Does not suspend the current thread

  Properly checks return values when enumerating threads

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
