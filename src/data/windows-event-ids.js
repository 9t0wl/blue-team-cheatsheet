export default {
  id: "windows-event-ids",
  title: "Windows Event IDs & Logging",
  src: "Windows Logging for SOC (Module 9, growing)",
  icon: "🪟",
  cards: [
    {
      title: "Log sources — what covers what",
      span2: true,
      blocks: [
        { t: "txt", text: "Windows telemetry for a SOC comes from two layers that don't overlap: the built-in <b>Security Log</b> (always present, no install needed) and <b>Sysmon</b> (Sysinternals add-on, has to be deployed/configured, far more granular). Treat them as complementary, not redundant." },
        { t: "table", head: ["Source", "Covers", "Install?"], rows: [
          ["Security Log", "authentication (logon/logoff), user management (account/group/privilege changes)", "built-in"],
          ["Sysmon", "process creation, file modification, network connections, image/DLL loads, DNS queries", "Sysinternals, config-driven"],
        ]},
        { t: "note", kind: "warn", title: "living reference", text: "This section covers <b>Windows Logging for SOC</b> only so far — Sysmon Event ID 1 (process creation) plus the Security Log's auth/user-mgmt categories. Specific numeric Event IDs for logon types, process creation, user/group changes, and the rest of the Sysmon ID range (3, 7, 11, 22, etc.) get filled in as <b>Windows Threat Detection 1–3</b> are completed — cards below are scaffolded with room to grow." },
      ],
    },
    {
      title: "Security Log — Authentication",
      blocks: [
        { t: "txt", text: "SOC analysts use these events to spot suspicious logins: failed logins, unusual login times, unexpected account usage. Specific Event IDs (4624 successful logon, 4625 failed logon, logon type breakdown, etc.) — <b>TODO: fill in from Windows Threat Detection 1</b>." },
      ],
    },
    {
      title: "Security Log — User Management",
      blocks: [
        { t: "txt", text: "Covers account creation/deletion and privilege/group changes — the events that catch unauthorized account manipulation (e.g. an attacker creating a persistence account or adding themselves to Domain Admins). Specific Event IDs (4720 user created, 4728/4732 added to group, 4732/4756 added to privileged group, etc.) — <b>TODO: fill in from Windows Threat Detection 1</b>." },
      ],
    },
    {
      title: "Sysmon — Process Creation (Event ID 1)",
      blocks: [
        { t: "txt", text: "Sysmon logs every new process: image path, command line, parent process, hashes, user. Useful for spotting malware execution or unusual tool launches — but it only sees the <b>launch</b>, not what happens inside a long-running interactive process." },
        { t: "note", kind: "danger", title: "the PowerShell blind spot", text: "Sysmon Event ID 1 logs that <code>powershell.exe</code> launched — it does <b>not</b> capture commands typed inside the resulting interactive session. An attacker can run dozens of malicious commands (discovery, credential harvesting, malware download, process injection) inside one logged launch with <b>zero additional process-level logs</b> for any of it. This is exactly the gap tools like Empire / PowerSploit-era tradecraft have historically exploited — knowing the defender-side blind spot explains why so much offensive PowerShell assumes it won't get caught by process monitoring alone." },
      ],
    },
    {
      title: "Sysmon — Files & Network (rest of the ID range)",
      blocks: [
        { t: "txt", text: "Sysmon also logs file modifications and network connections, useful for spotting data exfiltration, suspicious downloads, or lateral movement. Specific Event IDs (3 network connection, 7 image loaded, 11 file create, 22 DNS query, etc.) — <b>TODO: fill in from Windows Threat Detection 1–3</b> as those rooms are completed." },
      ],
    },
    {
      title: "PowerShell history file — working around the blind spot",
      span2: true,
      blocks: [
        { t: "cmd", label: "path (per-user)", code: "C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt" },
        { t: "txt", text: "PSReadLine (the module providing PowerShell's command-line editing) writes every submitted command to this file the instant Enter is pressed. Not a log in the Event Viewer sense — a plain text file, one command per line." },
        { t: "table", head: ["Property", "Detail"], rows: [
          ["Scope", "per-user — each account has its own history file"],
          ["Persistence", "survives reboots unless manually deleted"],
          ["Good for", "system discovery, credential harvesting, malware download commands"],
          ["Does NOT capture", "command output, or the contents of a script that was invoked (only the invocation line, e.g. .\\payload.ps1)"],
          ["Coverage gap", "only populated for interactive console sessions — a scheduled task running a .ps1 directly leaves nothing here"],
        ]},
        { t: "note", kind: "warn", title: "not a substitute for real logging", text: "An attacker who knows about this file can delete it. Treat it as one useful artifact among several during an investigation, not a substitute for <b>PowerShell Script Block Logging (Event ID 4104)</b> or <b>Module Logging</b> — the actual enterprise-grade fix for this blind spot, not covered in this room but worth flagging as the next thing to learn." },
      ],
    },
  ],
};
