export default {
  id: "linux-logging",
  title: "Linux Logging & Auditd",
  src: "Linux Logging for SOC",
  icon: "🐧",
  cards: [
    {
      title: "The Windows → Linux mental shift",
      span2: true,
      blocks: [
        { t: "txt", text: "Windows structures telemetry around event IDs and the Event Log service. Linux has no equivalent structured event-ID system by default — nearly everything lands as <b>plain text in /var/log</b>, readable with any text editor. Tradeoff: format is far less consistent — hundreds of distros customize logging slightly, so a log's exact shape (or existence) can differ system to system." },
        { t: "table", head: ["Command", "Use"], rows: [
          ["grep 'pattern' file", "filter to matching lines"],
          ["grep -v 'pattern' file", "exclude matching lines (e.g. strip noisy cron spam)"],
          ["head / tail file", "first / last N lines"],
          ["more / less file", "page through gradually (q to quit)"],
        ]},
      ],
    },
    {
      title: "auth.log / secure — one file, four use cases",
      span2: true,
      blocks: [
        { t: "table", head: ["Distro family", "Path"], rows: [
          ["Debian/Ubuntu", "/var/log/auth.log"],
          ["RHEL-based", "/var/log/secure"],
        ]},
        { t: "table", head: ["Use case", "grep target"], rows: [
          ["Login/logout", "\"session opened\" / \"session closed\""],
          ["SSH auth", "\"Accepted password\" / \"Accepted publickey\" (success), \"Failed password\" (failure)"],
          ["Privilege escalation", "sudo / su usage"],
          ["User management", "useradd, group changes, passwd"],
        ]},
        { t: "note", kind: "info", title: "the rough Windows equivalent", text: "This single file covers what Windows splits across 4624/4625/4720/4732/4724 — one text stream instead of separate event IDs." },
      ],
    },
    {
      title: "Other common system logs",
      blocks: [
        { t: "table", head: ["Log", "Covers"], rows: [
          ["/var/log/syslog (or /var/log/messages)", "general aggregated stream — kernel messages, network changes, service/cron runs"],
          ["/var/log/dpkg.log (Debian) or dnf.log/yum.log (RHEL)", "package manager install/update history — spot unauthorized installs"],
          ["App-specific (nginx/Apache access, DB, mail)", "same \"check the specific app's own log\" principle as web shell detection"],
        ]},
      ],
    },
    {
      title: "Bash history — unreliable for SOC, three evasion tricks",
      blocks: [
        { t: "cmd", label: "path", code: "~/.bash_history" },
        { t: "table", head: ["Evasion method", "How"], rows: [
          ["Leading space", "prefixing a command with a space suppresses it from history (documented bash feature)"],
          ["Script execution", "paste commands into a script and run the script instead of typing interactively"],
          ["Alternate shell", "switch to sh instead of bash — different history mechanism entirely"],
        ]},
        { t: "note", kind: "warn", title: "structural gap, not just evasion", text: "Bash history can't capture non-interactive execution at all — cron jobs, web-triggered commands. Direct Linux analogue of the Windows ConsoleHost_history.txt PowerShell caveat: useful corroborating artifact, never a primary detection source." },
      ],
    },
    {
      title: "auditd — Linux's answer to Sysmon",
      span2: true,
      blocks: [
        { t: "txt", text: "None of the text logs above capture process creation, file changes, or network activity by default — the same gap Windows has without Sysmon. auditd fills it by monitoring <b>system calls</b> (300+, e.g. execve to run a program) — the low-level interface every user action funnels through to reach the kernel. Hard to bypass by design." },
        { t: "cmd", label: "rules live in", code: "/etc/audit/rules.d/" },
        { t: "cmd", label: "search by rule key (readable output)", code: "ausearch -i -k proc_wget" },
        { t: "note", kind: "warn", title: "same noise-management principle as everywhere else", text: "Auditing every syscall system-wide produces gigabytes/day of unusable noise. Build targeted rule sets around high-risk binaries/paths instead of auditing everything." },
      ],
    },
    {
      title: "Reading a multi-line audit event",
      span2: true,
      blocks: [
        { t: "table", head: ["Line type", "Captures"], rows: [
          ["PROCTITLE", "the full command line as run"],
          ["CWD", "working directory at execution time"],
          ["SYSCALL — pid/ppid", "parent-child correlation (same idea as Sysmon ProcessId/ParentProcessId)"],
          ["SYSCALL — auid", "account originally used to log in — stable across sudo/su"],
          ["SYSCALL — uid", "account the command actually ran as — differs from auid after a privilege switch"],
          ["SYSCALL — tty", "session identifier, useful on shared boxes"],
          ["SYSCALL — exe", "absolute path of the executed binary"],
          ["key", "the rule tag that matched, for fast filtering"],
        ]},
        { t: "note", kind: "info", title: "auid vs uid is the standout detail", text: "auid = who originally authenticated, uid = who this command is running as right now. The two diverging is itself a signal — e.g. auid=ubuntu, uid=root means the ubuntu account escalated via sudo/su to run this specific command." },
      ],
    },
    {
      title: "Alternatives to auditd",
      blocks: [
        { t: "table", head: ["Tool", "Best for"], rows: [
          ["Sysmon for Linux", "XML output — natural fit if already using Windows Sysmon"],
          ["Falco", "containerized / cloud-native workloads"],
          ["osquery", "SQL-like queries against live system state"],
          ["EDRs", "commercial endpoint platforms"],
        ]},
        { t: "note", kind: "info", title: "all hook the same thing", text: "Every alternative still fundamentally monitors system calls under the hood — once auditd's model clicks, each of these is a variation on the same theme, not a from-scratch concept." },
      ],
    },
  ],
};
