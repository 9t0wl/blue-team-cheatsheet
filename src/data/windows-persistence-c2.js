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
