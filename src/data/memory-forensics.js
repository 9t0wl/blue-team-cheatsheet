export default {
  id: "memory-forensics",
  title: "Memory Forensics with Volatility 3",
  src: "Boogeyman 2 (SOC L1 Capstone)",
  icon: "🧠",
  cards: [
    {
      title: "Why RAM answers questions the disk can't",
      span2: true,
      blocks: [
        { t: "txt", text: "A memory image captures the machine mid-intrusion: decrypted payloads, full command lines, sockets that have already closed, and injected code that never touched the filesystem. When persistence is <b>fileless</b> — payload in a registry value, executed by <code>IEX</code> — a disk image can come back clean while RAM still holds the whole chain." },
        { t: "cmd", label: "basic invocation + plugin discovery", code: "vol -f memdump.raw <plugin>\nvol -f memdump.raw -h          # every available plugin\nvol -f memdump.raw windows.info  # confirm the profile/OS parsed correctly" },
        { t: "note", kind: "info", title: "expect it to be slow", text: "Each plugin re-parses the image — minutes per run is normal. Redirect output to a file the first time (<code>vol -f mem.raw windows.pstree &gt; pstree.txt</code>) and grep the file afterwards instead of re-running the plugin for every question." },
      ],
    },

    // ---------- PLUGIN MAP ----------
    {
      title: "Plugin map — which one answers which question",
      span2: true,
      blocks: [
        { t: "table", head: ["Question", "Plugin"], rows: [
          ["What ran, and what spawned it?", "<code>windows.pstree</code> (indented tree) / <code>windows.pslist</code>"],
          ["What were the full arguments?", "<code>windows.cmdline</code>"],
          ["What did it connect to?", "<code>windows.netscan</code> / <code>windows.netstat</code>"],
          ["Does a given file exist in memory?", "<code>windows.filescan</code>"],
          ["Can I recover that file?", "<code>windows.dumpfiles --virtaddr &lt;offset&gt;</code>"],
          ["What was typed at a console?", "<code>windows.consoles</code> / <code>windows.cmdscan</code>"],
          ["What's in the registry?", "<code>windows.registry.printkey --key '&lt;path&gt;'</code>"],
          ["Any injected/unbacked code?", "<code>windows.malfind</code>"],
          ["What DLLs did it load?", "<code>windows.dlllist --pid &lt;pid&gt;</code>"],
          ["Dump one process's memory", "<code>windows.memmap --dump --pid &lt;pid&gt;</code>"],
          ["Hashes / credential material?", "<code>windows.hashdump</code>, <code>windows.lsadump</code>"],
        ]},
        { t: "note", kind: "ok", title: "two ways to get a process's own image path", text: "<code>windows.cmdline --pid &lt;pid&gt;</code> is the direct route. <code>windows.dlllist --pid &lt;pid&gt;</code> also works and is a useful fallback — <b>the first entry in a process's module list is its own executable</b>, so the top row gives you the full path even when cmdline is truncated or empty." },
        { t: "note", kind: "ok", title: "a workable triage order", text: "<code>pstree</code> to find the anomaly → <code>cmdline</code> on that PID for the full invocation → <code>netscan</code> filtered to that PID for the C2 → <code>filescan</code> for the artifacts it touched → <code>dumpfiles</code> to recover them. Each step hands you the pivot value for the next." },
      ],
    },

    // ---------- PSTREE ----------
    {
      title: "Process tree — read the ancestry, not the process",
      blocks: [
        { t: "cmd", label: "tree + drop the noise", code: "vol -f memdump.raw windows.pstree.PsTree\nvol -f memdump.raw windows.pstree | grep -vE 'svchost|RuntimeBroker|SearchUI'" },
        { t: "note", kind: "danger", title: "the tell is the parent, not the child", text: "<code>wscript.exe</code> is a signed Microsoft binary and unremarkable alone. <code>WINWORD.EXE → wscript.exe</code> is an intrusion. Office and browsers should never parent a scripting host, a shell, or an unsigned binary — that edge in the tree <i>is</i> the detection." },
        { t: "txt", text: "Indentation depth = ancestry depth, so a payload chain reads straight down the page. Note the <b>CreateTime</b> column while you're there — a tight cluster of timestamps across unrelated-looking processes is one chain executing, not coincidence." },
        { t: "note", kind: "info", title: "exited processes still show", text: "Rows with a populated <b>ExitTime</b> already terminated but their structures survive in memory. A short-lived dropper that ran and quit is still visible here." },
      ],
    },

    // ---------- NETSCAN ----------
    {
      title: "Network artifacts — netscan recovers dead sockets",
      blocks: [
        { t: "cmd", label: "connections, filtered to a suspect PID", code: "vol -f memdump.raw windows.netscan | grep -i <pid>\nvol -f memdump.raw windows.netscan | grep -vE 'svchost|System|lsass|LISTENING'" },
        { t: "note", kind: "ok", title: "CLOSED rows are the point", text: "<code>netscan</code> pool-scans for connection structures still resident in memory rather than reading a live table, so it recovers sockets that <b>already tore down</b>. A beacon that finished its callback minutes before capture still appears with state <code>CLOSED</code> — a live <code>netstat</code> at that moment would have shown nothing. This is the single strongest argument for grabbing RAM before doing anything else on a suspect host." },
        { t: "note", kind: "info", title: "read it as a beacon, not a connection", text: "Many short <code>CLOSED</code> rows from one PID to one IP:port, spaced a minute or two apart, is a polling C2 — not a failed connection. Compare the timestamps: even spacing is the tell." },
        { t: "note", kind: "warn", title: "keep a benign row for contrast", text: "Note what normal looks like in the same output (e.g. <code>OUTLOOK.EXE</code> → an Azure IP on 443). Reports land better when the malicious row is shown next to the legitimate one." },
      ],
    },

    {
      title: "Output handling — make the results readable",
      blocks: [
        { t: "cmd", label: "redirect once, grep many times", code: "vol -f mem.raw windows.pstree   > pstree.txt\nvol -f mem.raw windows.netscan  > netscan.txt\nvol -f mem.raw windows.dlllist --pid <pid> > dlllist.txt\nolevba document.doc > macros.txt" },
        { t: "note", kind: "info", title: "wrapped columns are a terminal-width problem, not a tool problem", text: "Volatility's wide tables shear into unreadable offset columns in a small window. <b>Maximise the terminal before running</b>, or redirect to a file and open it in an editor — the columns realign. Losing the PID/PPID alignment is how you misread a process tree." },
        { t: "cmd", label: "page long output instead of scrollback-hunting", code: "vol -f mem.raw windows.netscan | less     # / to search, q to quit\nvol -f mem.raw windows.netscan | more" },
        { t: "note", kind: "ok", title: "keep a working notes file", text: "Paste each confirmed artifact (PID, path, URL, hash) into a scratch file as you go. Every answer in a memory investigation is the pivot value for the next query, and re-running a five-minute plugin because you lost a PID in scrollback is the most avoidable time sink there is." },
      ],
    },

    {
      title: "Dumping a single process's memory",
      blocks: [
        { t: "cmd", label: "dump, then string it", code: "vol -f mem.raw windows.memmap --dump --pid <pid>\nstrings pid.<pid>.dmp    | grep -i '<keyword>'\nstrings -el pid.<pid>.dmp | grep -i '<keyword>'" },
        { t: "note", kind: "warn", title: "a process dump can hold less than the full image", text: "Narrowing to one PID cuts noise, but the artifact you want may live in another process's memory, in pool memory, or in a since-exited process — a command line built by PowerShell and passed to <code>schtasks.exe</code> exists in <b>both</b> processes. If a targeted dump comes back thin, <b>fall back to strings across the whole image</b> rather than concluding the artifact isn't there." },
      ],
    },

    // ---------- STRINGS ----------
    {
      title: "strings on a memory image — run it twice",
      span2: true,
      blocks: [
        { t: "cmd", label: "both encodings, always", code: "strings memdump.raw    | grep -i '<keyword>'   # ASCII\nstrings -el memdump.raw | grep -i '<keyword>'   # UTF-16LE" },
        { t: "note", kind: "danger", title: "the default pass silently drops most Windows strings", text: "<code>strings</code> defaults to ASCII. Windows stores command lines, PowerShell script blocks, registry data and most UI text as <b>UTF-16LE</b>, so those are invisible without <code>-el</code> — and you get no warning, just fewer results. Skipping the second pass looks exactly like \"the artifact isn't in the dump.\"" },
        { t: "note", kind: "ok", title: "run both even when the first pass hits", text: "The two passes surface <i>different copies</i> of the same artifact from different memory structures — one may be truncated where the other is complete, and a process command line often appears in one encoding while the script block that built it appears in the other. Corroborating both is also stronger evidence than a single hit." },
        { t: "note", kind: "info", title: "greppable pivots worth trying", text: "<code>schtasks</code>, <code>powershell</code>, <code>-enc</code>, <code>IEX</code>, <code>DownloadString</code>, <code>http://</code>, <code>.ps1</code>, <code>Host Application:</code>, the C2 domain, and any filename from the process tree." },
      ],
    },

    // ---------- FILELESS PERSISTENCE ----------
    {
      title: "Fileless persistence — payload in the registry",
      span2: true,
      blocks: [
        { t: "txt", text: "A maturing pattern: the scheduled task points at <code>powershell.exe</code>, not at a binary. The actual payload is a base64 blob parked in a registry value, read and executed at runtime." },
        { t: "cmd", label: "shape of the persistence command", code: "schtasks /Create /F /SC DAILY /ST 09:00 /TN <TaskName> /TR 'powershell.exe -NonI -W hidden -c\n  \"IEX ([Text.Encoding]::UNICODE.GetString(\n     [Convert]::FromBase64String((gp HKCU:\\Software\\...\\<key> <value>).<value>)))\"'" },
        { t: "cmd", label: "go read the value it points at", code: "vol -f memdump.raw windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion'\necho '<blob>' | base64 -d | iconv -f UTF-16LE -t UTF-8" },
        { t: "table", head: ["Why it works", "What it defeats"], rows: [
          ["No payload file on disk", "File-hash sweeps, AV on-write scanning"],
          ["Task target is signed <code>powershell.exe</code>", "\"Unsigned binary in a task\" rules"],
          ["Payload survives deleting the dropper", "Remediation that only removes the EXE"],
          ["<code>-W hidden</code> / <code>-NonI</code>", "User noticing a console window"],
        ]},
        { t: "note", kind: "danger", title: "remediation trap", text: "Deleting the malicious binary and the scheduled task is <b>not</b> enough — the registry value is the payload. If it survives, re-created persistence restores access. Always chase what the task <i>reads</i>, not just what it runs." },
        { t: "note", kind: "ok", title: "detection angles", text: "Alert on <code>schtasks /Create</code> whose <code>/TR</code> contains <code>powershell</code> + <code>-enc</code>/<code>IEX</code>/<code>FromBase64String</code>; on <code>-W hidden</code> in any scheduled task; and on registry values under <code>CurrentVersion</code> holding multi-KB base64. A registry value that large is abnormal on its own." },
        { t: "note", kind: "info", title: "operators log their own success", text: "C2 frameworks frequently print a confirmation string after a module runs (\"persistence established using ... with ... trigger at ...\"). Those land in memory too, and they narrate the attack in the attacker's own words — grep for <code>persistence</code>, <code>established</code>, <code>listener</code>." },
      ],
    },

    // ---------- OFFICE / DELIVERY ----------
    {
      title: "Macro-document delivery — olevba",
      blocks: [
        { t: "cmd", label: "extract and analyse VBA", code: "olevba document.doc\nolevba --decode document.doc     # deobfuscate embedded strings\nmd5sum document.doc              # hash for threat-intel lookup" },
        { t: "note", kind: "info", title: "no mail client? read the .eml as text", text: "Don't assume the analysis box has Thunderbird — some don't. An <code>.eml</code> is plain text: open it in any editor (or <code>cat</code>/<code>less</code> it) and the <code>From</code>, <code>To</code>, <code>Subject</code>, <code>Date</code> and MIME attachment part are all right there. Save the attachment out of it (or base64-decode the part) before hashing." },
        { t: "note", kind: "info", title: "what to pull out of the macro", text: "The stage-2 URL, where it writes the download, and how it executes it. A macro that writes to <code>C:\\ProgramData\\</code> or <code>%TEMP%</code> and launches via <code>wscript.exe</code>/<code>mshta.exe</code> is the classic shape." },
        { t: "note", kind: "warn", title: "extension ≠ content", text: "A stage-2 payload downloaded as <code>update.png</code> that is actually JavaScript written to <code>update.js</code> is deliberate — image extensions survive naive egress filtering and look benign in proxy logs. Judge by what executes it, not what it's called." },
      ],
    },

    {
      title: "Outlook attachment cache",
      blocks: [
        { t: "cmd", label: "find the attachment in the dump", code: "vol -f memdump.raw windows.filescan | grep -i '<filename>'" },
        { t: "txt", text: "Outlook writes opened attachments to:" },
        { t: "cmd", code: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\<8-CHAR>\\<file>" },
        { t: "note", kind: "info", title: "the 8-character folder is random", text: "Per-profile and unguessable, which is exactly why you scan for it rather than construct the path by hand." },
        { t: "note", kind: "ok", title: "a trailing (002) is evidence", text: "Outlook appends an incrementing counter when a file of that name already exists in the cache — so <code>Resume (002).doc</code> means the attachment was opened <b>more than once</b>. That distinguishes \"previewed it briefly\" from \"opened it repeatedly,\" which changes how you interview the user." },
      ],
    },

    // ---------- WORKED EXAMPLE ----------
    {
      title: "Worked example — reconstructing an intrusion from RAM alone",
      span2: true,
      blocks: [
        { t: "steps", steps: [
          "<b>pstree</b> → <code>OUTLOOK.EXE → WINWORD.EXE → wscript.exe → updater.exe</code>. The Office-parents-a-script-host edge is the whole finding; note the PIDs and the tight CreateTime cluster.",
          "<b>olevba</b> on the attachment → macro downloads a fake <code>.png</code> and writes it as <code>C:\\ProgramData\\update.js</code>, executed by <code>wscript.exe</code>.",
          "<b>strings / cmdline</b> → the JS pulls a second binary and drops it in <code>C:\\Windows\\Tasks\\</code> — a directory that looks system-ish but is user-writable.",
          "<b>netscan</b> filtered to the implant's PID → C2 on an <code>IP:8080</code>, several <code>CLOSED</code> rows spaced minutes apart = beaconing.",
          "<b>strings -el</b> → the full <code>schtasks /Create</code> line, plus the operator's own \"persistence established\" confirmation message.",
          "<b>printkey</b> on the registry value the task reads → the actual base64 payload, decodable offline.",
          "<b>filescan</b> → the original attachment in the Outlook cache, with a <code>(002)</code> counter proving repeat opens.",
        ]},
        { t: "note", kind: "ok", title: "one image, the entire chain", text: "Delivery, execution, C2, and persistence all came out of a single memory capture — no disk image, no EDR, no PCAP. Worth remembering when scoping what to collect first on a live incident: <b>RAM before shutdown, always.</b>" },
        { t: "note", kind: "info", title: "infrastructure reuse is a real pivot", text: "Compare C2 IPs across campaigns from the same actor — cheap VPS providers get reused even when individual IPs rotate. Provider preference sits higher on the Pyramid of Pain than any single address, and beacon port habits (e.g. plain HTTP on 8080) tend to persist too." },
      ],
    },

    // ---------- SOC FOLLOW-THROUGH ----------
    {
      title: "After the analysis — what the investigation is actually for",
      span2: true,
      blocks: [
        { t: "txt", text: "A challenge room ends when the questions are answered. A real incident doesn't — every IOC recovered above is a search term for finding <b>the victims you don't know about yet</b>. This is the step that separates an analyst from someone who can run Volatility." },
        { t: "steps", steps: [
          "<b>Pivot every IOC into the SIEM/mail gateway</b> — sender address, subject line, attachment filename, file hash, stage-2 URL, C2 IP. Spear-phishing is rarely sent to one person.",
          "<b>Identify every recipient</b>, then split them: delivered-and-opened, delivered-not-opened, blocked. Each group gets different handling.",
          "<b>Purge/retract the message</b> from mailboxes that still hold it — this is time-critical and the highest-value action available, because it prevents compromises rather than investigating them.",
          "<b>Sweep endpoints</b> for the artifacts: the dropped paths, the scheduled task name, the registry value, and outbound connections to the C2 IP:port.",
          "<b>Block</b> the sender, the staging domain, and the C2 at mail gateway / proxy / firewall.",
          "<b>Then</b> remediate the known-compromised host — and remember the fileless persistence trap: the registry value is the payload.",
        ]},
        { t: "note", kind: "danger", title: "the clock is on containment, not analysis", text: "Perfect forensics delivered after five more users have opened the attachment is a worse outcome than partial findings that triggered a mail purge in the first twenty minutes. Once you have the sender, subject, and hash — enough to search on — <b>hand those off for containment and keep analysing in parallel</b>. Don't hold IOCs back waiting for a complete picture." },
        { t: "note", kind: "info", title: "hash first, because it's free", text: "<code>md5sum</code>/<code>sha256sum</code> the attachment the moment you have it and check it against threat intel. If it's a known sample, the whole chain may already be documented — minutes of reading instead of hours of reversing. (Offline lab VMs can't reach VirusTotal; the habit still belongs in the workflow.)" },
      ],
    },
  ],
};
