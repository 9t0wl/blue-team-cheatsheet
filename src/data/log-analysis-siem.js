export default {
  id: "log-analysis-siem",
  title: "Log Analysis with SIEM — Ready-Made SPL",
  src: "Log Analysis with SIEM (Module 13)",
  icon: "🔍",
  cards: [
    {
      title: "Why SIEM, and how logs are grouped",
      span2: true,
      blocks: [
        { t: "table", head: ["Benefit", "What it means in practice"], rows: [
          ["Centralization", "every source (network devices, cloud, identity providers) lands in one searchable place — no pivoting between separate consoles"],
          ["Correlation", "linking otherwise-isolated events — an IDS alert with just a source IP gets enriched by pivoting to identity/system/network logs until you know who, what, and which tools"],
          ["Historical lookback", "an unusual login-location alert only means something once you've checked whether that user has ever logged in from there before"],
        ]},
        { t: "table", head: ["Tier", "Sources", "Catches"], rows: [
          ["Host-based", "workstations, servers (web/SQL/DNS)", "auth/brute force, account manipulation, process execution, object access, policy changes"],
          ["Network-based", "firewalls, IDS/IPS, VPN, proxy, DNS, routers", "suspicious external connections to unusual ports, port scanning"],
          ["Web-based", "web server logs, WAF, CDN, load balancer, API gateway", "web shell exploitation, SQLi attempts"],
        ]},
        { t: "note", kind: "info", title: "time zones & normalization", text: "See the <b>Query Language Gotchas</b> section for the full time-zone-display and log-normalization pitfalls — both apply to every query on this card, not just Splunk." },
      ],
    },
    {
      title: "Windows — Sysmon (process exec + network conn)",
      span2: true,
      blocks: [
        { t: "cmd", label: "malicious process execution — encoded PowerShell (EventCode 1)", code: "index=winenv EventCode=1 *powershell* AND *EncodedCommand*\n| table _time ComputerName ParentUser ParentImage ParentCommandLine Image CommandLine" },
        { t: "cmd", label: "network connections from a specific host (EventCode 3)", code: "index=winenv EventCode=3 ComputerName=WINHOST05\n| table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol" },
        { t: "note", kind: "info", title: "the two-alert pattern", text: "Process exec and network connection are separate Sysmon event codes — a single infection often surfaces as two correlated alerts minutes apart (dropper spawns PowerShell → payload calls out to C2), not one. See the <b>Windows Event IDs & Logging</b> section for the full numeric ID reference." },
      ],
    },
    {
      title: "Windows — Security & System logs (account + service persistence)",
      span2: true,
      blocks: [
        { t: "cmd", label: "user account creation/enable (4720/4722) — backdoor account persistence", code: "index=winenv EventCode=4720 OR EventCode=4722\n| table _time EventCode ComputerName Subject_Account_Name Target_Account_Name New_Account_Account_Name Keywords" },
        { t: "cmd", label: "service install + start/stop (7045/7036) — service-based persistence/privesc", code: "index=winenv EventCode=7045 OR EventCode=7036 ComputerName=WINHOST05\n| table _time EventCode ComputerName Service_Name Service_Account Service_File_Name Message" },
        { t: "note", kind: "warn", title: "watch the account tier jump", text: "Worked example: attacker's foothold account (<code>ted-admin</code>) creates a backdoor user, then minutes later a malicious service launches a Temp-directory executable as <b>SYSTEM</b> — the service is the privesc step from the original foothold to SYSTEM." },
      ],
    },
    {
      title: "Linux — auth.log (SSH brute force + su/sudo privesc)",
      span2: true,
      blocks: [
        { t: "cmd", label: "successful vs failed SSH logins for a specific user", code: "index=linux source=\"auth.log\" *ubuntu* process=sshd\n| search \"Accepted password\" OR \"Failed password\"" },
        { t: "cmd", label: "su/sudo activity, chronological", code: "index=linux source=\"auth.log\" *su*\n| sort + _time" },
        { t: "note", kind: "info", title: "reading the su/sudo three-line signature", text: "<code>sudo: ... COMMAND=/usr/bin/su</code> → <code>session opened for user root</code> → <code>su[...]: (to root) root on pts/N</code> is a successful root escalation. auth.log alone can't say <i>how</i> the attacker got there (stolen creds vs. exploit) — that needs a different source layered in." },
      ],
    },
    {
      title: "Linux — syslog (cron-based persistence)",
      span2: true,
      blocks: [
        { t: "cmd", label: "cron entries running scripting interpreters / netcat", code: "index=linux sourcetype=syslog (\"CRON\" OR \"cron\")\n| search (\"python\" OR \"perl\" OR \"ruby\" OR \".sh\" OR \"bash\" OR \"nc\")" },
        { t: "note", kind: "warn", title: "what this caught in the worked example", text: "A <code>/tmp</code> shell script cron'd every 5 minutes (world-writable, non-suspicious-looking location — classic persistence spot) <i>and</i> a raw Perl reverse-shell one-liner (<code>socket()</code>/<code>connect()</code>/<code>exec(\"/bin/sh -i\")</code>) calling home on the same schedule." },
      ],
    },
    {
      title: "Web — brute force, web shell, DDoS (access logs)",
      span2: true,
      blocks: [
        { t: "cmd", label: "brute force — repeated POSTs to a login page (>25 in 5 min)", code: "index=* method=POST uri_path=\"/wp-login.php\"\n| bin _time span=5m\n| stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time\n| where count > 25\n| table referer_domain clientip UserAgent uri_path count status" },
        { t: "cmd", label: "possible web shell — script/exe requests, status 200, >2 in a window", code: "index=*\n| search status=200 AND uri_path IN(*.php, *.phtm, *.asp, *.aspx, *.jsp, *.exe) AND (method=POST AND method=GET)\n| stats values(status) as status values(useragent) as UserAgent values(method) as method values(uri) as uri values(clientip) as clientip count by referer_domain\n| where count > 2\n| table referer_domain count method status clientip UserAgent uri" },
        { t: "cmd", label: "DDoS — 503s with a huge request count in a short window", code: "index=* status=503\n| bin _time span=10m\n| stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time\n| where count > 100000\n| table _time referer_domain clientip UserAgent uri_path count status" },
        { t: "note", kind: "info", title: "concept detail lives elsewhere", text: "These are ready-made query templates for this room's worked scenarios (Hydra-flagged wp-login brute force, a misspelled <code>505.php</code> web shell, a 1.5M-request DDoS burst). For the deeper attack-pattern breakdown see <b>Detecting Web Attacks</b>, <b>Detecting Web Shells</b>, and <b>Detecting Web DoS/DDoS</b>." },
      ],
    },
    {
      title: "The reusable investigation shape",
      blocks: [
        { t: "steps", items: [
          "Start from the alert's known facts (host, port, user) — don't start from a memorized query.",
          "Run a broad index-scoped search first (e.g. <code>index=task4</code>) to confirm data exists before narrowing.",
          "Sift the <b>Interesting Fields</b> panel for what's actually present in <i>this</i> dataset — field names/availability vary by source.",
          "Build the narrow query from there; the templates above are starting points, not one-size-fits-all.",
        ]},
        { t: "note", kind: "warn", title: "pivot chains compound", text: "Worked practice scenarios chained multiple pivots: a suspicious network connection → the process that made it → its hash → other events referencing that hash → the scheduled task it created for persistence. Each answer usually points at the next field to pivot on." },
      ],
    },
  ],
};
