export default {
  id: "elastic-alert-triage-playbook",
  title: "Alert Triage Playbook — Kibana/Elastic",
  src: "Alert Triage With Elastic",
  icon: "🔍",
  cards: [
    {
      title: "The scenario — one attack, five stacked alerts",
      span2: true,
      blocks: [
        { t: "txt", text: "Unlike the Splunk room's three separate scenarios, this room strings 5 SOC dashboard alerts for one client (\"SomeCorp\") into a single continuous timeline — a web exploit that pivots to a full Windows compromise. Each alert queried below builds on the timestamp confirmed by the previous one." },
        { t: "table", head: ["Alert", "Severity", "Time"], rows: [
          ["Web Requests Indicating File Upload", "High", "04:38"],
          ["GET Requests to ASPX File with Query Parameters", "High", "04:45"],
          ["Administrator Access Outside of Business Hours", "High", "05:11"],
          ["New User Account Created", "Critical", "05:13"],
          ["Unusual Command-Line Behavior: Privilege Changes", "Critical", "05:13"],
        ]},
      ],
    },
    {
      title: "Web — ProxyLogon exploitation attempt",
      span2: true,
      blocks: [
        { t: "cmd", label: "scope to the attacker IP + POST requests", code: "_index:weblogs and client.ip:203.0.113.55 and http.request.method:POST" },
        { t: "note", kind: "danger", title: "worked example", text: "3 automated POST requests (User-Agent <code>python-requests</code>, not a browser) to <code>/ecp/proxyLogon.ecp</code> — the URL path alone names a known Exchange vulnerability (ProxyLogon). Add <code>client.ip</code>, <code>user.agent</code>, <code>http.request.method</code>, <code>url.path</code>, and <code>http.response.status_code</code> as columns to read it as a table." },
      ],
    },
    {
      title: "Web — confirming the web shell (errorEE.aspx)",
      span2: true,
      blocks: [
        { t: "cmd", label: "GET requests to the suspected shell, sorted oldest-first", code: "_index:weblogs and client.ip:203.0.113.55 and http.request.method:GET and errorEE.aspx" },
        { t: "note", kind: "warn", title: "the tell: a cmd= query parameter", text: "A <code>cmd=</code> parameter on a GET request is a hallmark of web shell activity — attackers append the command to execute directly to the URL (e.g. <code>cmd=whoami</code>). Worked example showed URL-encoded discovery commands running one after another in <code>url.path</code>: <code>cmd=whoami</code>, <code>cmd=whoami%20%2Fpriv</code>, and further group-enumeration variants — readable directly off the request line with no need to decode a body." },
        { t: "note", kind: "info", text: "Same shape as the Splunk room's <code>b374k.php</code> scenario — a query-parameter-driven web shell instead of a POST-body one, but the investigative move (confirm exploitation → sort chronologically → read the commands straight off the request) is identical." },
      ],
    },
    {
      title: "Windows — confirming the logon (EventCode 4624)",
      span2: true,
      blocks: [
        { t: "cmd", label: "logon events for this host/user from the alert time forward", code: "@timestamp >= \"2025-07-20T05:11:22\" and winlog.event_id:4624 and host.name:winserv2019.some.corp and winlog.event_data.TargetUserName:Administrator" },
        { t: "table", head: ["Field", "What it confirms"], rows: [
          ["winlog.event_data.TargetUserName", "which account logged in"],
          ["winlog.logon.type", "how — RemoteInteractive in this case, i.e. RDP"],
          ["winlog.event_data.IpAddress", "source IP — matched the same 203.0.113.55 from the web alerts, tying the web exploit and the Windows logon into one actor"],
        ]},
        { t: "note", kind: "danger", title: "this alone isn't proof of malice", text: "A logon at an odd hour from a matching IP is strong correlation, but not conclusive by itself — the room's own framing: \"perhaps the Administrator started work early today.\" Confirming a logon is step one, not the verdict." },
      ],
    },
    {
      title: "Windows — Sysmon process creation for the same account",
      span2: true,
      blocks: [
        { t: "cmd", label: "what did the Administrator's logon actually spawn?", code: "@timestamp >= \"2025-07-20T05:11:22\" and winlog.event_id:1 and user.name:Administrator" },
        { t: "table", head: ["Field", "Use"], rows: [
          ["user.name", "who launched the process"],
          ["process.parent.name", "the executable that spawned it"],
          ["process.command_line", "the full command"],
        ]},
        { t: "note", kind: "info", text: "Worked example initially showed normal Windows session-initialization noise (svchost/services.exe chains) — not yet malicious on its own. The point: correlating logon + immediate process activity builds context, but the verdict comes from what happens next." },
      ],
    },
    {
      title: "Windows — new backdoor account (User Account Management)",
      span2: true,
      blocks: [
        { t: "cmd", label: "filter by human-readable task category, not a memorized event ID", code: "@timestamp >= \"2025-07-20T05:13:10.000\" and winlog.channel:Security and winlog.task:\"User Account Management\"" },
        { t: "note", kind: "warn", title: "worked example", text: "Surfaced a new account (<code>svc_backup</code> — a service-account-sounding name, deliberately unremarkable) created and enabled right after the Administrator logon. Add <code>winlog.event_id</code>, <code>winlog.task</code>, and <code>message</code> as columns, sort oldest-first to see creation before enablement." },
      ],
    },
    {
      title: "Windows — privilege escalation via cmd.exe, correlated with 4732",
      span2: true,
      blocks: [
        { t: "cmd", label: "commands launched by cmd.exe under the Administrator account", code: "@timestamp >= \"2025-07-20T05:13:15\" and process.parent.name:cmd.exe and user.name:Administrator" },
        { t: "note", kind: "danger", title: "worked example", text: "<code>net localgroup \"Remote Desktop Users\" &lt;backdoor_account&gt; /add</code>, then further <code>net localgroup ... /add</code> commands adding the same account to additional sensitive groups (Server Operators, Administrators) — classic post-compromise privilege escalation via built-in group membership rather than a exploit." },
        { t: "cmd", label: "correlate Sysmon 1 + Security 4732 (Security Group Management) in one query", code: "@timestamp >= \"2025-07-20T05:13:15\" and (winlog.event_id:4732 or process.parent.name:cmd.exe)" },
        { t: "note", kind: "info", text: "Two structurally different event types (a Sysmon process-creation event and a Windows Security group-management event) land in one time-ordered table — confirms the <code>net localgroup</code> command line and its corresponding Security-log consequence side by side." },
      ],
    },
    {
      title: "Windows — PowerShell Script Block Logging closes the Sysmon blind spot",
      span2: true,
      blocks: [
        { t: "cmd", label: "plaintext commands run inside a PowerShell session", code: "@timestamp >= \"2025-07-20T05:13:15\" and event.module:powershell and event.code:4104\n// add powershell.file.script_block_text as a column, sort oldest-first" },
        { t: "note", kind: "danger", title: "why this event code specifically matters", text: "Sysmon Event ID 1 only logs that <code>powershell.exe</code> launched — it does not capture what ran inside the resulting interactive session (see the Windows Event IDs card's \"PowerShell blind spot\" note). Event Code 4104 is the actual enterprise-grade fix: <code>whoami</code> and <code>whoami /priv</code> — classic discovery commands — appeared here in full plaintext, something Sysmon alone would have completely missed." },
      ],
    },
    {
      title: "No alert generated — hunting a legitimate-but-abusable tool",
      span2: true,
      blocks: [
        { t: "cmd", label: "check what else the compromised account touched, alert or not", code: "process.name: \"Rar.exe\"" },
        { t: "note", kind: "warn", title: "not every malicious action trips an alert", text: "Rar.exe is legitimate, always-present compression software — no rule fired on it. The backdoor account used it to build a password-protected archive of sensitive (finance-related) data shortly after the group-membership changes — classic exfil-staging behavior. Same LOLBin logic as the certutil/PowerShell material: the tool itself is benign, the account/timing/target-file combination is what makes it worth escalating. Caught only by deliberately asking \"what else did this account do\" instead of stopping once the alert queue was empty." },
      ],
    },
    {
      title: "The full reconstructed timeline",
      blocks: [
        { t: "steps", items: [
          "ProxyLogon exploitation attempt against the web app (04:38)",
          "Web shell confirmed via errorEE.aspx?cmd= (04:45)",
          "RDP logon as Administrator from the same source IP, outside business hours (05:11)",
          "Backdoor account (svc_backup) created (05:13)",
          "Backdoor account added to Remote Desktop Users / Server Operators / Administrators via cmd.exe, correlated to Security 4732 (05:13)",
          "PowerShell discovery commands (whoami, whoami /priv) captured via Script Block Logging (05:13-05:16)",
          "Rar.exe used to stage a password-protected archive for exfil — no alert, found by deliberate hunting",
        ]},
        { t: "note", kind: "info", text: "See also the Kibana / KQL — Query Language Reference section for the general syntax these queries build on, and the Splunk-equivalent Alert Triage Playbook for the SPL version of the same investigative shape." },
      ],
    },
  ],
};
