export default {
  id: "windows-persistence-c2",
  title: "C2, Persistence & Impact",
  src: "Windows Threat Detection 3",
  icon: "🔗",
  cards: [
    {
      title: "Command & Control — when it's needed, how it's staged",
      span2: true,
      blocks: [
        { t: "txt", text: "C2 isn't always required — an attacker on a live RDP session can just type commands directly. That access dies the moment the session closes, which is why most actors stand up a durable C2 channel immediately after breaching, even from an interactive foothold." },
        { t: "table", head: ["Staging pattern", "How it works"], rows: [
          ["Direct connect-back", "the phishing attachment itself establishes the C2 channel on execution (e.g. a Cobalt Strike beacon appearing live in the operator console)"],
          ["Staged/dropped C2", "the attachment downloads a second, separate payload, hides it somewhere innocuous (e.g. %AppData%\\Roaming\\update.exe), and runs that as an independent process"],
        ]},
        { t: "note", kind: "info", title: "why staging matters operationally", text: "If the victim or AV deletes the original attachment, the attack survives — the real C2 process is a separate file never associated with the original email. Seen in real ransomware cases and APT29 phishing campaigns." },
        { t: "note", kind: "info", title: "detecting it", text: "Sysmon Event ID 22 (DNS query) surfaces the C2 domain itself — an unfamiliar/odd-looking domain is the first tell, which then correlates to the process actually making that query." },
      ],
    },
    {
      title: "Persistence — backdoor user accounts",
      span2: true,
      blocks: [
        { t: "txt", text: "Extends an RDP-style breach: plant an account that survives a password rotation on the original one. Creating the account alone isn't enough — it also has to be added to a privileged group (Administrators / Remote Desktop Users) before it's useful." },
        { t: "table", head: ["ID", "Description"], rows: [
          ["4720", "user account created"],
          ["4732", "member added to a security-enabled local group"],
          ["4724", "attempt to reset an account's password (covers skip-creation variant — reuse an old/dormant account instead)"],
        ]},
        { t: "note", kind: "warn", title: "don't rely on suspicious-sounding names", text: "Attackers pick boring names on purpose (lab example: an account called \"support\") specifically to blend into legit IT/helpdesk accounts. Investigate context instead: who created the account, source IP/time of the creator's login, and what else happened in that creator's session." },
      ],
    },
    {
      title: "Persistence — services & scheduled tasks",
      blocks: [
        { t: "txt", text: "Needed when there's no login path to reuse (phishing/USB access instead of RDP) — the attacker needs a process that survives reboot on its own." },
        { t: "cmd", label: "service", code: "sc create <name> binpath= <malware.exe> start= auto" },
        { t: "cmd", label: "scheduled task", code: "schtasks /create /tn <taskname> /tr <malware.exe> /sc onstart" },
        { t: "table", head: ["Method", "Sysmon", "Security/System log", "Suspicious parent"], rows: [
          ["Service", "ID 1 (sc.exe create)", "4697 (service installed) / 7045", "services.exe (sometimes via svchost.exe)"],
          ["Scheduled task", "ID 1 (schtasks.exe /create)", "4698 (scheduled task created)", "svchost.exe -k netsvcs (Task Scheduler host)"],
        ]},
        { t: "note", kind: "info", title: "why scheduled tasks are the attacker favorite", text: "Easier to configure and hide than a full service, same reboot-survival payoff — the go-to for real APTs (APT28, Fin7). Both techniques favor boring, plausible names (\"Data Protection Service\", \"Amazon Sync\") — the name isn't the signal, the parent process and path are." },
      ],
    },
    {
      title: "Persistence — run keys & startup folder",
      blocks: [
        { t: "txt", text: "Per-user tier — fires on logon instead of boot, needs no admin rights at all. Useful when the attacker's foothold is a regular, non-admin account." },
        { t: "cmd", label: "startup folder (per-user)", code: "%AppData%\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" },
        { t: "cmd", label: "run key", code: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { t: "table", head: ["Method", "Sysmon ID"], rows: [
          ["File dropped in startup folder", "11 (FileCreate)"],
          ["Registry value added to Run key", "13 (RegistryEvent — value set)"],
        ]},
        { t: "note", kind: "warn", title: "same explorer.exe-parent ambiguity as GUI Discovery", text: "Both fire under explorer.exe as the parent once they execute — identical to a user manually launching something at logon. The folder should normally be empty and the Run key rarely touched, so any new entry is worth scrutiny regardless of how boring its name looks." },
      ],
    },
    {
      title: "Persistence — COM/CLSID hijacking via a shell object (T1546.015)",
      src: "HTB Sherlock: ReliableThreat",
      span2: true,
      blocks: [
        { t: "txt", text: "Every desktop shell object (Recycle Bin, This PC, Control Panel, etc.) is backed by a COM CLSID registered under <code>HKCU\\Software\\Classes\\CLSID\\&lt;GUID&gt;</code>. Writing a <code>\\shell\\open\\command</code> value under that CLSID hijacks the verb Explorer fires when the user interacts with the object — for the Recycle Bin specifically, that's <b>every double-click on the desktop icon</b>. No admin/elevation required, it's entirely HKCU, and the \"legitimate component\" being abused is something the user touches constantly without a second thought." },
        { t: "cmd", label: "the Recycle Bin's CLSID — worth memorizing, it recurs", code: "HKCU\\Software\\Classes\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\shell\\open\\command" },
        { t: "note", kind: "info", title: "how a compiled dropper tool reveals its own registry writes", text: "A small persistence-setting binary (compiled with `RegCreateKeyExA`/`RegSetValueExA` imports) will usually keep its target CLSID/key path as a single ASCII string literal, even when other content is obfuscated. `strings sample.exe | grep -i software` surfaces the exact key it's built to write — evidence of intent, straight from the binary's own imports and constant pool, no dynamic analysis required." },
        { t: "note", kind: "danger", title: "the point-in-time trap — a live-state search can be correct and still find nothing", text: "If the persistence-writing tool is dropped and executed <i>after</i> the memory image was captured, a live registry search (Volatility, a mounted hive) will correctly show the key as absent, even when you've checked the exact right CLSID. The write genuinely doesn't exist yet in that snapshot. When a well-reasoned live-state search comes back clean, check whether the evidence source captures the right moment before concluding the technique wasn't used — a dropped tool's own static strings/imports can prove intent even when its effects never made it into the specific snapshot you're holding. Cross-referencing evidence sources captured at different times (here: a memory dump vs. a separately-timestamped disk image) is how this gap gets caught." },
        { t: "note", kind: "ok", title: "detection angle", text: "Baseline <code>HKCU\\Software\\Classes\\CLSID\\*\\shell</code> for well-known system object GUIDs (Recycle Bin, My Computer, Control Panel) — these should almost never have custom `shell\\open\\command` overrides on a normal endpoint. Any value present at all is worth investigating." },
      ],
    },

    {
      title: "Impact & why persistence matters",
      span2: true,
      blocks: [
        { t: "table", head: ["Reason to persist", "Real-world example"], rows: [
          ["Add host to a botnet", "Kraken — combines crypto-miner, data-stealer, and C2 in one bot"],
          ["Spy (state-sponsored)", "Volt Typhoon — undetected in US critical infrastructure for nearly a year"],
          ["Beachhead into the wider network", "actors spent 29 days breaching a full network from one compromised host"],
        ]},
        { t: "note", kind: "danger", title: "ransomware = the biggest threat to corporate Windows networks", text: "Not just a cost — it can halt the entire business (cited case: McLaren Hospitals, 743,000 patients affected; ransom notes auto-printed on every office printer)." },
        { t: "note", kind: "info", title: "the meta-lesson tying WTD 1→2→3 together", text: "Every complex, multi-week AD/ransomware attack starts from one simple breach. Full chain: Initial Access → Execution → Persistence (account manipulation, service/task creation) → Credential Access → Discovery → Collection → Command and Control → Exfiltration → Impact. Best point to detect and stop it: as early as possible — ideally right at Initial Access." },
      ],
    },
  ],
};
