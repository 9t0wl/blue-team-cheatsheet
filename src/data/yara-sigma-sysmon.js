export default {
  id: "yara-sigma-sysmon",
  title: "YARA, Sigma & Event Log Hunting",
  src: "HTB Academy: YARA & Sigma For SOC Analysts (CDSA Path)",
  icon: "📜",
  cards: [
    {
      title: "YARA vs Sigma in one line",
      span2: true,
      blocks: [
        { t: "table", head: ["", "YARA (The Mugshot)", "Sigma (The Security Badge Log)"], rows: [
          ["inspects", "<b>Files on disk & raw process memory</b> (what the malware <i>looks like</i>)", "<b>Log event streams</b> (what the attacker <i>does</i>)"],
          ["format", "YARA rule language (text or compiled <code>.yrc</code>)", "YAML format, converted to Splunk SPL, Elastic KQL, Sentinel, etc."],
          ["sweet spot", "Classifying malware families, unpacking shellcode, memory dumps", "SIEM detections, behavioral alerting across heterogeneous log sources"],
          ["evasion", "Packers, crypters, code obfuscation, encrypted payloads", "Log tampering, living-off-the-land without generating target events"],
        ]},
        { t: "note", kind: "info", title: "defense-in-depth workflow", text: "Static analysis and sandboxing feed YARA signatures. Dynamic behavior observed in Sysmon, EVTX, and network logs feeds Sigma rules." },
      ],
    },
    {
      title: "YARA Rule Anatomy & String Modifiers",
      span2: true,
      blocks: [
        { t: "cmd", label: "standard rule template", code: `rule APT_Implant_Detector {
    meta:
        description = "Detects in-memory and disk implants"
        author = "9t0wl / 221B Baker Street SOC"
        reference = "https://attack.mitre.org"
    strings:
        $ascii_str  = "Sandbox detected" ascii
        $wide_str   = "powershell.exe" wide nocase
        $hex_stub   = { fc e8 8? 00 00 00 60 }       // wildcards: 8? or ??
        $hex_jump   = { 64 8b [0-4] 30 }             // jumps: [0-4] bytes
        $xor_str    = "http://malicious.c2" xor
    condition:
        uint16(0) == 0x5a4d and                      // MZ header (Windows PE)
        uint16(uint32(0x3c)) == 0x4550 and           // PE pointer verification
        filesize < 5MB and
        (2 of ($ascii*, $wide*) or $hex_stub)
}` },
        { t: "table", head: ["Modifier", "Meaning", "When to Use"], rows: [
          ["<code>ascii</code>", "Standard 1-byte ASCII characters", "Default string matching"],
          ["<code>wide</code>", "2-byte UTF-16LE characters", "Crucial for Windows filenames, Registry paths, and PowerShell strings"],
          ["<code>nocase</code>", "Case-insensitive matching", "Handles randomized capitalization (e.g., <code>pOwErShElL</code>)"],
          ["<code>fullword</code>", "Matches only delimited by non-alphanumeric chars", "Prevents false positives on substrings (e.g., matching <code>cat</code> inside <code>catalog</code>)"],
          ["<code>xor</code>", "Searches all 255 single-byte XOR keys", "Catches obfuscated strings and simple XORed C2 beacon domains"],
          ["<code>hex ?? / 8?</code>", "Byte & nibble wildcards", "Accommodates dynamic offsets and variable registers in shellcode"],
        ]},
      ],
    },
    {
      title: "Advanced YARA Modules: PE Internals & Entropy (math)",
      span2: true,
      blocks: [
        { t: "cmd", label: "high-entropy resource & imphash hunting (wiper / packer)", code: `import "pe"
import "math"

rule Suspicious_Packed_File_Wiper {
    meta:
        description = "Detects packed payloads, wipers, and stolen imphash"
    strings:
        $dos_stub = "This program cannot be run in DOS mode."
    condition:
        uint16(0) == 0x5A4D and filesize < 1MB and
        pe.number_of_sections > 4 and
        pe.number_of_signatures == 0 and             // Unsigned binary
        (pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9" or
         for any i in (0..pe.number_of_resources - 1): (
             math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.8
         ))
}` },
        { t: "table", head: ["Function / Property", "Forensic Value"], rows: [
          ["<code>pe.imphash()</code>", "Import Hash: tracks malware variants sharing identical API import tables even when code is scrambled"],
          ["<code>math.entropy(offset, len) > 7.8</code>", "Detects encrypted, compressed, or packed payloads in PE resources (Shamoon, Stonedrill)"],
          ["<code>pe.number_of_signatures == 0</code>", "Ensures the file is unsigned, filtering out signed Microsoft and third-party binaries"],
          ["<code>pe.entry_point == ...</code>", "Validates whether the execution entry point points to suspicious or non-standard sections"],
        ]},
      ],
    },
    {
      title: "Live Windows Process & Memory Forensics with YARA",
      span2: true,
      blocks: [
        { t: "cmd", label: "PowerShell live process sweep across all running PIDs", code: `# Scan every running process PID with a YARA rule
Get-Process | ForEach-Object { 
    $pid_num = $_.Id
    & "yara64.exe" "C:\\Rules\\yara\\meterpreter_shellcode.yar" $pid_num 2>$null
}` },
        { t: "cmd", label: "Volatility 3 / 2.6 yarascan on raw memory dumps (.raw / .vmem)", code: `# Offline memory dump inspection with PID & process attribution
vol.py -f /path/to/memory.raw yarascan -U "delete shadows"

# Output reveals the owning process directly:
# Rule: r1
# Owner: Process @WanaDecryptor@ Pid 3200
# 0x00420fe4: delete shadows /all /quiet & bcdedit ...` },
        { t: "cmd", label: "SilkETW real-time detection (attaching YARA to ETW event streams)", code: `# Inspect PowerShell script blocks in real time
.\\SilkETW.exe -t user -pn Microsoft-Windows-PowerShell -ot file -p ./etw_ps.json -l verbose -y C:\\Rules\\yara -yo Matches

# Inspect DNS queries for C2 domain resolution & killswitch domains
.\\SilkETW.exe -t user -pn Microsoft-Windows-DNS-Client -ot file -p ./etw_dns.json -l verbose -y C:\\Rules\\yara -yo Matches` },
      ],
    },
    {
      title: "Sigma Rule Architecture & Anatomy",
      span2: true,
      blocks: [
        { t: "cmd", label: "complete sigma rule template", code: `title: Suspicious svchost.exe Process Creation
id: fa34b441-961a-42fa-a100-ecc28c886725
status: experimental
description: Detects svchost.exe spawned from non-system paths or unusual parents
references:
    - https://attack.mitre.org/techniques/T1036/005/
author: 9t0wl / 221B Baker Street SOC
date: 2026-10-16
tags:
    - attack.defense_evasion
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_proc:
        Image|endswith: '\\svchost.exe'
    selection_susp_path:
        Image|contains:
            - '\\AppData\\Local\\Temp\\'
            - '\\Users\\Public\\'
            - '\\PerfLogs\\'
    filter_legit_parent:
        ParentImage|endswith: '\\services.exe'
    condition: selection_proc and selection_susp_path and not filter_legit_parent
falsepositives:
    - Rare third-party installers
level: high` },
        { t: "table", head: ["Section", "Requirement", "Job / Logic"], rows: [
          ["<code>title</code>", "Required", "Short descriptive name of the alert (max 256 chars)"],
          ["<code>logsource</code>", "Required", "<b>Where</b> to search: <code>category</code> (process_creation), <code>product</code> (windows), <code>service</code> (sysmon, security)"],
          ["<code>detection</code>", "Required", "Search-identifiers (lists, maps) + boolean <code>condition</code>"],
          ["<code>status</code>", "Optional", "Maturity: <code>experimental</code> (lab only), <code>test</code> (few systems), <code>stable</code> (production ready)"],
          ["<code>level</code>", "Optional", "Severity: <code>informational</code>, <code>low</code>, <code>medium</code>, <code>high</code>, <code>critical</code>"],
        ]},
      ],
    },
    {
      title: "Sigma Detection Logic: Modifiers, Lists (OR) vs Maps (AND)",
      span2: true,
      blocks: [
        { t: "table", head: ["Structure", "YAML Syntax", "Boolean Logic", "Example"], rows: [
          ["<b>List</b>", "Bulleted with dashes (<code>-</code>)", "<b>OR</b>", "<code>Image|endswith:</code><br><code>  - 'cmd.exe'</code><br><code>  - 'powershell.exe'</code>"],
          ["<b>Map (Dict)</b>", "Key-Value pairs at same indent", "<b>AND</b>", "<code>Image|endswith: '\\wmic.exe'</code><br><code>CommandLine|contains: ' /node:'</code>"],
          ["<code>\|contains</code>", "Wildcards both sides (<code>*val*</code>)", "Substring", "<code>CommandLine\|contains: 'mimikatz'</code>"],
          ["<code>\|endswith</code>", "Wildcard at start (<code>*val</code>)", "Suffix", "<code>Image\|endswith: '\\mshta.exe'</code>"],
          ["<code>\|startswith</code>", "Wildcard at end (<code>val*</code>)", "Prefix", "<code>ParentImage\|startswith: 'C:\\Windows\\Temp\\'</code>"],
          ["<code>\|re</code>", "Regular expression pattern", "Regex", "<code>CommandLine\|re: '.{1000,}'</code> (long commands)"],
          ["<code>\|all</code>", "Forces list to require all items", "<b>AND</b>", "<code>CommandLine\|contains\|all: ['downloadstring', 'http']</code>"],
          ["<b>Aggregation</b>", "Piped into condition", "Threshold", "<code>condition: selection \| count(TargetUserName) by Workstation > 3</code>"],
        ]},
      ],
    },
    {
      title: "Hunting EVTX with Chainsaw (Multi-Threaded Sigma Engine)",
      span2: true,
      blocks: [
        { t: "txt", text: "<b>Chainsaw</b> is a standalone Rust CLI tool that concurrently sweeps raw Windows EVTX logs against Sigma rule packs using multi-threading, without needing a running SIEM." },
        { t: "cmd", label: "core syntax", code: `# Hunt through EVTX logs using a Sigma rule or folder of rules
.\\chainsaw.exe hunt C:\\Events\\ -s C:\\Rules\\sigma\\ --mapping .\\mappings\\sigma-event-logs-all-new.yml

# Output to structured JSON for analysis pipelines
.\\chainsaw.exe hunt C:\\Events\\lab_events.evtx -s C:\\Rules\\sigma\\ --mapping .\\mappings\\sigma-event-logs-all-new.yml --json -o results.json

# Fast keyword search
.\\chainsaw.exe search mimikatz -i C:\\Events\\` },
        { t: "table", head: ["Field / Parameter", "Role in Triage"], rows: [
          ["<code>hunt</code>", "Core execution mode: compiles and executes Sigma rules against EVTX files"],
          ["<code>-s &lt;path&gt;</code>", "Path to a specific <code>.yml</code> rule or directory of rules"],
          ["<code>--mapping &lt;path&gt;</code>", "<b>The Rosetta Stone:</b> maps Sigma field names (e.g. <code>NewProcessName</code>) to Windows Event XML fields. If omitted or outdated, detections will return 0!"],
          ["<code>--full</code>", "Prints unclipped command lines, scripts, and complete payloads in terminal"],
        ]},
        { t: "note", kind: "ok", title: "key chainsaw detections from the field", text: "<b>Defender Exclusions:</b> <code>posh_ps_win_defender_exclusions_added.yml</code> on Event 4104 catches <code>Set-MpPreference -ExclusionPath</code>.<br><b>Shadow Copy Wiping:</b> <code>posh_ps_susp_win32_shadowcopy.yml</code> catches ransomware running <code>Get-WmiObject Win32_Shadowcopy \| ForEach-Object {$_.Delete();}</code>." },
      ],
    },
    {
      title: "Sigma to Splunk SPL Translation (sigmac & pySigma)",
      span2: true,
      blocks: [
        { t: "cmd", label: "translating sigma rules into Splunk SPL queries", code: `# Convert Sigma YAML to Splunk SPL using sigmac / pySigma
cd C:\\Tools\\sigma-0.21\\tools
python sigmac -t splunk C:\\Rules\\sigma\\file_event_win_app_dropping_archive.yml -c .\\config\\splunk-windows.yml

# pySigma (modern syntax)
sigma convert -t splunk -p sysmon ./rules/detection_rule.yml` },
        { t: "table", head: ["Technique", "Sigma Rule Focus", "Generated Splunk SPL Pattern"], rows: [
          ["<b>LSASS MiniDump</b> (Living-off-the-Land)", "<code>comsvcs.dll</code> called via <code>rundll32.exe</code> (Sysmon 10)", "<code>(TargetImage=\"*\\\\lsass.exe\" SourceImage=\"*\\\\rundll32.exe\" CallTrace=\"*comsvcs.dll*\")</code>"],
          ["<b>Process Injection</b> (Hollowing / Stager)", "<code>notepad.exe</code> spawning CLI / PowerShell (Sysmon 1)", "<code>(ParentImage=\"*\\\\notepad.exe\" (Image=\"*\\\\powershell.exe\" OR Image=\"*\\\\cmd.exe\"))</code>"],
          ["<b>SharpHound AD Exfil</b>", "Office/tool process dropping <code>.zip</code> or <code>.rar</code> (Sysmon 11)", "<code>(Image=\"*\\\\sharphound.exe\" (TargetFilename=\"*.zip\" OR TargetFilename=\"*.rar\"))</code>"],
          ["<b>Failed NTLM Logins</b>", "Rapid-fire credential testing (Security 4776)", "<code>EventCode=4776 Status=\"0xc0000064\" \| stats count by Workstation \| where count > 3</code>"],
        ]},
        { t: "note", kind: "info", title: "time range tip in splunk", text: "When verifying newly translated Sigma rules in Splunk Web, always remember to set the time range dropdown to <b>All time</b> so historical event logs are included." },
      ],
    },
    {
      title: "Sysmon Telemetry: Key Event IDs Behind Rules",
      span2: true,
      blocks: [
        { t: "table", head: ["Event ID", "Category", "Critical Fields to Hunt"], rows: [
          ["<b>1</b>", "Process Create", "<code>Image</code>, <code>CommandLine</code>, <code>ParentImage</code>, <code>ParentCommandLine</code>, <code>IntegrityLevel</code>, <code>User</code>"],
          ["<b>3</b>", "Network Connect", "<code>SourceIp</code>, <code>DestinationIp</code>, <code>DestinationPort</code>, <code>Image</code> (catches C2 beacons)"],
          ["<b>7</b>", "Image Loaded", "<code>ImageLoaded</code>, <code>Signed</code>, <code>SignatureStatus</code> (catches malicious DLL sideloading)"],
          ["<b>8</b>", "CreateRemoteThread", "<code>SourceImage</code>, <code>TargetImage</code>, <code>StartAddress</code> (catches classic process injection)"],
          ["<b>10</b>", "Process Access", "<code>SourceImage</code>, <code>TargetImage</code>, <code>GrantedAccess</code> (<code>0x1010</code>, <code>0x1410</code>, <code>0x1fffff</code> for LSASS dumping)"],
          ["<b>11</b>", "File Create", "<code>TargetFilename</code>, <code>Image</code> (catches ransomware dropping payloads & BloodHound zips)"],
          ["<b>12 / 13 / 14</b>", "Registry Event", "<code>TargetObject</code>, <code>Details</code> (catches Run-key persistence, UAC bypasses)"],
          ["<b>22</b>", "DNS Query", "<code>QueryName</code>, <code>QueryResults</code> (catches DNS tunneling and DGA domains)"],
          ["<b>4104</b>", "PowerShell ScriptBlock", "<code>ScriptBlockText</code>, <code>ScriptBlockId</code> (catches deobfuscated in-memory execution)"],
        ]},
      ],
    },
  ],
};
