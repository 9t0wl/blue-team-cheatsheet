export default {
  id: "file-hash-threat-intel",
  title: "File & Hash Threat Intel",
  src: "File and Hash Threat Intel",
  icon: "🧾",
  cards: [
    {
      title: "Why hash-based lookups",
      span2: true,
      blocks: [
        { t: "txt", text: "A hash (MD5/SHA1/SHA256) is a fixed-size fingerprint of a file — one changed bit produces a completely different hash. Given an unknown binary, hashing it and searching that hash against threat-intel platforms (VirusTotal, hybrid analysis) turns a mystery file into a known quantity: prior AV verdicts, malware family, first-seen date, sandbox behavior reports — without ever having to detonate it yourself." },
        { t: "note", kind: "danger", title: "search the hash, don't upload the file", text: "Same discipline as malware analysis generally — uploading a sensitive/proprietary sample before you know what it is can leak it to a public service." },
      ],
    },
    {
      title: "VirusTotal verdict signals",
      span2: true,
      blocks: [
        { t: "table", head: ["Signal", "What it tells you"], rows: [
          ["Detection ratio (e.g. 61/70)", "how many AV vendors flag it malicious — a strong consensus is a fast confidence check"],
          ["Sandbox classifications (Zenbox, Yomi, CAPE)", "behavioral tags like MALWARE / RANSOM / EVADER, independent of static signature matching"],
          ["Malware family labels", "e.g. akira, filecryptor — links the sample to a known campaign/toolset"],
          ["First seen in the wild", "timestamp — how long this hash has been circulating, useful for triage urgency"],
        ]},
      ],
    },
    {
      title: "Reading a behavior report — worked example (Akira ransomware)",
      span2: true,
      blocks: [
        { t: "cmd", label: "destructive recovery-inhibiting command observed", code: "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject" },
        { t: "note", kind: "warn", title: "maps to MITRE T1490 — Inhibit System Recovery", text: "Deleting Volume Shadow Copies via PowerShell/WMI is a textbook ransomware pre-encryption step — removes the victim's easiest recovery path before the encryptor runs." },
        { t: "note", kind: "danger", title: "dropped ransom note", text: "akira_readme.txt — a dropped-file artifact is often faster to hunt for across an estate (EDR file-created queries) than trying to catch the encryption process itself in the act." },
        { t: "txt", text: "Other behavior observed: extensive file writes/deletes under C:\\MSOCache\\All Users\\... (staging/cleanup), PowerShell/pwsh instances performing the destructive WMI calls, and process injection into multiple Google updater executables (living-off-legitimate-process camouflage — same theme as LOLBin abuse)." },
      ],
    },
    {
      title: "MITRE ATT&CK breadth as a maturity signal",
      span2: true,
      blocks: [
        { t: "txt", text: "A single sample triggering techniques across many tactics — Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, C2, Impact — is itself a signal: broad technique footprint is typical of modern, actively-developed ransomware families rather than a narrow, single-purpose tool." },
        { t: "table", head: ["Tactic", "Example techniques seen"], rows: [
          ["Execution", "T1047 WMI, T1059 Command/Script Interpreter, T1106 Native API"],
          ["Persistence / Priv Esc", "T1176 Browser Extensions, T1547 Boot/Logon Autostart"],
          ["Defense Evasion", "T1027 Obfuscation, T1036 Masquerading, T1070 Indicator Removal, T1202 Indirect Command Execution"],
          ["Credential Access", "T1003 OS Credential Dumping"],
          ["Discovery", "T1010 App Window Discovery, T1057 Process Discovery, T1082 System Info Discovery, T1083 File/Dir Discovery"],
          ["C2", "T1090 Proxy, T1105 Ingress Tool Transfer"],
          ["Impact", "T1485 Data Destruction, T1486 Data Encrypted for Impact"],
        ]},
      ],
    },
    {
      title: "Network indicators from the sample",
      blocks: [
        { t: "txt", text: "HTTP requests to Microsoft and Sectigo certificate endpoints (environment/legitimacy checks), plus DNS resolutions to onion addresses associated with the Akira leak site — a reminder that a sample's network calls aren't all malicious on their face (cert checks look benign) but the .onion resolution is the real tell worth pivoting on." },
      ],
    },
    {
      title: "Hash-lookup triage checklist",
      blocks: [
        { t: "steps", items: [
          "Compute SHA256 (preferred — collision-resistant) of the unknown file",
          "Search the hash on VirusTotal / hybrid analysis — don't upload the file itself",
          "Check detection ratio + any named malware family",
          "Read the behavior/sandbox report for dropped files, registry changes, process tree",
          "Map observed behavior to MITRE ATT&CK tactics for a structured writeup",
          "Pivot on any dropped-file names or C2 domains for estate-wide hunting",
        ]},
      ],
    },
  ],
};
