export default {
  id: "pe-structure-windows-internals",
  title: "PE File Structure & Windows Internals",
  src: "Intro to Malware Analysis, Windows Internals",
  icon: "🧱",
  cards: [
    {
      title: "PE file layout, top to bottom (the part that keeps slipping)",
      span2: true,
      blocks: [
        { t: "txt", text: "The <b>Portable Executable (PE)</b> format is the container Windows uses for <code>.exe</code>, <code>.dll</code>, <code>.sys</code> (kernel modules/drivers), <code>.cpl</code> and more. It is a data structure holding what the <b>Windows loader</b> needs to map the code into memory." },
        { t: "table", head: ["Order on disk", "Piece", "What it holds"], rows: [
          ["1", "<b>DOS header</b>", "Starts with <code>MZ</code> (0x4D5A). Holds <code>e_lfanew</code>, the offset to the PE header. Legacy, but every PE has it"],
          ["2", "<b>DOS stub</b>", "Tiny program printing \"This program cannot be run in DOS mode\""],
          ["3", "<b>PE signature</b>", "<code>PE\\0\\0</code> (0x50450000), found at the <code>e_lfanew</code> offset"],
          ["4", "<b>COFF / File header</b>", "Machine type (<code>0x14c</code> = x86, <code>0x8664</code> = x64), number of sections, timestamp, characteristics (EXE vs DLL)"],
          ["5", "<b>Optional header</b>", "Entry point, image base, section alignment, subsystem, and the <b>Data Directories</b> (pointers to imports, exports, resources, relocations)"],
          ["6", "<b>Section table</b>", "One entry per section: name, virtual address/size, raw address/size, permission flags (R/W/X)"],
          ["7", "<b>Sections</b>", "The actual content: code, data, resources, import/export info (table below)"],
        ]},
        { t: "note", kind: "info", title: "memory hook", text: "<b>MZ</b> → jump via <code>e_lfanew</code> → <b>PE</b> → file header → optional header → section table → sections. Headers describe, sections contain." },
        { t: "note", kind: "warn", title: "rows 1 to 6 are general PE knowledge", text: "The module text itself only covers the section list and imports/exports. The header order above is added from the PE spec so the whole structure sits in one place." },
      ],
    },
    {
      title: "PE sections",
      span2: true,
      blocks: [
        { t: "txt", text: "The Section Table points at sections, which are the repositories for the file's real content: code, data and resources." },
        { t: "table", head: ["Section", "Name", "Holds"], rows: [
          ["<code>.text</code>", "Text", "Executable code of the program. <b>Often scrutinized for injection artifacts</b>"],
          ["<code>.data</code>", "Data", "Initialized global and static variables"],
          ["<code>.rdata</code>", "Read-only data", "Constants, string literals, read-only initialized globals/statics"],
          ["<code>.pdata</code>", "Exception info", "Function table entries used for exception handling"],
          ["<code>.bss</code>", "BSS", "Uninitialized global and static variables"],
          ["<code>.rsrc</code>", "Resources", "Images, icons, strings, version information"],
          ["<code>.idata</code>", "Imports", "Functions imported from other DLLs"],
          ["<code>.edata</code>", "Exports", "Functions this binary exposes to others"],
          ["<code>.reloc</code>", "Relocations", "Fix-ups needed if the image loads at a different base address"],
        ]},
        { t: "note", kind: "info", title: "viewing sections", text: "<b>pestudio</b> shows each section with MD5, entropy, raw vs virtual address and size, and flags such as writable/executable. On REMnux use <code>pecheck &lt;sample&gt;</code>." },
        { t: "note", kind: "warn", title: "what looks wrong", text: "A section that is both <b>writable and executable</b>, high entropy, a missing or tiny <code>.text</code>, or almost no imports all point to a packed sample (see Malware Analysis, anti-analysis card)." },
      ],
    },
    {
      title: "Imports & exports (DLL functions)",
      span2: true,
      blocks: [
        { t: "table", head: ["", "Imports", "Exports"], rows: [
          ["Meaning", "Functions the binary links to from external libraries at runtime", "Functions the binary exposes for other modules to call"],
          ["Why it matters", "Reveals what the sample can <i>do</i>: file ops, network, registry, process manipulation", "The interface other software uses to talk to the binary (typical of DLLs)"],
          ["IOC value", "Import names or an import-table hash can identify variants and related samples", "Odd export names on a DLL can flag a malicious or hijacked library"],
          ["Tool", "CFF Explorer (Import Directory), pestudio", "x64dbg Symbols tab, CFF Explorer"],
        ]},
        { t: "txt", text: "A <b>DLL</b> is a PE that is Microsoft's take on the shared library: many programs can load one copy of its functions." },
      ],
    },
    {
      title: "Process injection recognized from imports alone",
      span2: true,
      blocks: [
        { t: "txt", text: "Example from the module: <code>shell.exe</code> injects into <code>notepad.exe</code>. All four functions are imported from <code>kernel32.dll</code>, so the import table already tells the story before you run anything." },
        { t: "steps", items: [
          "<b>OpenProcess</b>: get a handle to the target process with enough access rights to touch its memory.",
          "<b>VirtualAllocEx</b>: allocate a block of memory inside the target's address space.",
          "<b>WriteProcessMemory</b>: copy the payload into that allocated block.",
          "<b>CreateRemoteThread</b>: start a thread in the target with the payload as its entry point. The code now runs as the target process.",
        ]},
        { t: "note", kind: "danger", title: "triage rule", text: "Seeing OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread together in one import table is a strong classic-injection fingerprint. One of them alone proves nothing." },
      ],
    },
    {
      title: "User mode vs kernel mode",
      span2: true,
      blocks: [
        { t: "table", head: ["", "User mode", "Kernel mode"], rows: [
          ["Runs", "Most applications and user processes", "Windows kernel, device drivers"],
          ["Access", "Limited. Must go through APIs. Processes are isolated from each other and from hardware", "Unrestricted access to hardware, resources and critical functions"],
          ["Malware here can", "Touch files, registry, network, and try to escalate privileges", "Hide itself, intercept system calls, tamper with security mechanisms"],
        ]},
      ],
    },
    {
      title: "Windows architecture components",
      span2: true,
      blocks: [
        { t: "table", head: ["Layer", "Component", "Role / examples"], rows: [
          ["User", "System support processes", "<code>winlogon.exe</code>, <code>smss.exe</code>, <code>services.exe</code>. Needed for the system but are not Windows services"],
          ["User", "Service processes", "Host services: Windows Update, Task Scheduler, Print Spooler"],
          ["User", "User applications", "32 and 64-bit programs. Call APIs, which funnel into <code>NTDLL.DLL</code>"],
          ["User", "Environment subsystems", "Win32, POSIX, OS/2 execution environments"],
          ["User", "Subsystem DLLs", "Translate documented functions to native calls: <code>kernelbase.dll</code>, <code>user32.dll</code>, <code>wininet.dll</code>, <code>advapi32.dll</code>"],
          ["Kernel", "Executive", "I/O Manager, Object Manager, Security Reference Monitor, Process Manager. Runs checks, then passes to the kernel or a driver"],
          ["Kernel", "Kernel", "Thread scheduling, interrupt/exception dispatch, multiprocessor sync"],
          ["Kernel", "Device drivers", "Let the OS talk to hardware"],
          ["Kernel", "HAL", "Hardware abstraction layer: consistent, platform-independent hardware access"],
          ["Kernel", "Win32k.sys", "Windowing and graphics (the GUI)"],
        ]},
      ],
    },
    {
      title: "Windows API call flow (ReadProcessMemory example)",
      span2: true,
      blocks: [
        { t: "steps", items: [
          "App calls <code>ReadProcessMemory</code> (documented WinAPI in <code>kernel32.dll</code>).",
          "kernel32 hands off to <code>NTDLL.DLL</code>, which maps it to the Native API <code>NtReadVirtualMemory</code>.",
          "NTDLL loads the syscall number into a register (<code>3F</code> in the module's x64dbg screenshot) and runs the <code>syscall</code> instruction. <b>This is the user to kernel transition.</b>",
          "The kernel looks the number up in the <b>SSDT</b> (System Service Descriptor Table, the syscall table), which points at <code>Nt!NtReadVirtualMemory</code>.",
          "The kernel validates parameters and access rights, reads the target's memory and copies it into the caller's buffer.",
          "Thread returns to user mode, and the app gets its data.",
        ]},
        { t: "cmd", label: "ReadProcessMemory signature (what to look for in a disassembler)", code: "BOOL ReadProcessMemory(\n  [in]  HANDLE  hProcess,             // target process handle\n  [in]  LPCVOID lpBaseAddress,        // address to read from\n  [out] LPVOID  lpBuffer,             // caller's buffer for the data\n  [in]  SIZE_T  nSize,                // bytes to read\n  [out] SIZE_T  *lpNumberOfBytesRead\n);" },
        { t: "note", kind: "info", title: "why analysts care", text: "Every WinAPI ends up in <code>NTDLL.DLL</code> as an <code>Nt*</code> call. Malware that calls <code>Nt*</code>/syscalls directly skips the kernel32 layer, which is how it dodges API hooks placed there." },
      ],
    },
    {
      title: "What a process consists of",
      span2: true,
      blocks: [
        { t: "table", head: ["Element", "Meaning"], rows: [
          ["PID", "Unique process identifier used by the OS to track it"],
          ["Virtual Address Space", "Private virtualized view of memory (code, data, stack), giving isolation"],
          ["Image file on disk", "The PE the process was started from"],
          ["Handle table", "References to system objects: files, devices, registry keys, sync objects"],
          ["Access token", "Security context: which account it runs as, privileges and access rights"],
          ["Threads", "One or more units of execution inside the process"],
        ]},
      ],
    },
  ],
};
