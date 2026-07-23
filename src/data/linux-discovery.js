export default {
  id: "linux-discovery",
  title: "Linux Discovery Detection",
  src: "Linux Threat Detection 2",
  icon: "🔍",
  cards: [
    {
      title: "PID/PPID climbing — a PPID is just another process's PID",
      span2: true,
      blocks: [
        { t: "txt", text: "Every process has a PID (its own ID) and a PPID (the PID of whatever spawned it). There is no separate 'PPID search' — you feed the PPID value into the exact same PID lookup you'd use for any process, to climb one level up the tree." },
        { t: "cmd", label: "find the suspicious event", code: "ausearch -i -x whoami" },
        { t: "cmd", label: "look up its ppid AS a pid — reveals the parent (often a script)", code: "ausearch -i --pid <ppid>" },
        { t: "cmd", label: "reverse direction — list everything a process spawned", code: "ausearch -i --ppid <pid>" },
        { t: "note", kind: "info", title: "climbing to the root", text: "Repeat the --pid lookup upward (each hop's ppid becomes the next lookup's pid) until you hit something recognizable — a login shell, PID 1 (systemd), or a suspicious script sitting in /tmp/~. Same technique as the Windows ProcessId/ParentProcessId pivot, just ausearch instead of Sysmon." },
      ],
    },
    {
      title: "Detecting is easy — interpreting intent is the hard part",
      span2: true,
      blocks: [
        { t: "txt", text: "auditd/ausearch make discovery commands trivial to log. The real challenge is judging attacker vs. legitimate service vs. IT admin from context, since attackers mostly reuse completely normal admin commands." },
        { t: "table", head: ["Observation", "Verdict"], rows: [
          ["Web server process suddenly runs whoami", "red flag — web apps don't need to know their own identity"],
          ["IT admin runs find/grep hunting for secrets", "suspicious regardless of role"],
          ["Monitoring tool periodically pings the LAN", "normal, expected behavior"],
        ]},
        { t: "note", kind: "warn", title: "whoami is a near-universal attacker tell", text: "Legitimate users/apps rarely need to ask who they are — but it's often the first command run right after a breach. Strong candidate for its own standalone detection rule." },
      ],
    },
    {
      title: "Specialized discovery — three attacker goals",
      span2: true,
      blocks: [
        { t: "table", head: ["Goal", "Typical commands"], rows: [
          ["Credential / secret theft", "history | grep pass · find / -name .env · find /home -name id_rsa"],
          ["Crypto-mining suitability", "cat /proc/cpuinfo · lscpu · free -m · top / htop"],
          ["Internal network scan for more victims", "ping / nc sweep loop, e.g. for i in 192.168.1.1-254"],
        ]},
        { t: "note", kind: "info", title: "combined objectives", text: "Some malware chains all three goals in one session — CPU/RAM checks appearing in the first few commands of a session is itself a strong signal it's a cryptominer, since little other malware needs that info." },
      ],
    },
    {
      title: "Ingress tool transfer — detection gap on attacker-initiated pulls",
      span2: true,
      blocks: [
        { t: "table", head: ["Method", "Log footprint"], rows: [
          ["wget / curl", "normal auditd process-creation event, full command line visible in proctitle"],
          ["Victim-initiated scp/sftp", "auditd process-creation event for the scp/sftp command"],
          ["Attacker-initiated scp/sftp (pulls FROM victim)", "no transfer command in the victim's auditd logs at all — the only artifact is a new SSH login in auth.log"],
        ]},
        { t: "note", kind: "danger", title: "widen detection beyond grepping for scp", text: "When the attacker connects TO the victim and pulls files themselves, correlate a new SSH login with new files appearing rather than expecting a command in the process logs." },
        { t: "note", kind: "info", title: "other signals worth layering in", text: "Network traffic to a known-bad IP/domain (VirusTotal-flagged, randomly-generated-looking domains, or abusable-but-legit hosts like raw GitHub); new files landing in /tmp or /var/tmp with suspicious or random-looking names." },
      ],
    },
    {
      title: "Case study — Dota3 cryptominer, full infection chain",
      span2: true,
      blocks: [
        { t: "steps", items: [
          "Botnet brute-forces SSH — targets root, top-10 weak passwords",
          "On success: automated discovery burst (/proc/cpuinfo etc. in the first 3 commands — a strong cryptominer signal)",
          "Persistence via credential lockout: changes the breached user's password AND replaces authorized_keys with the attacker's own key — locks out both the owner and competing botnets",
          "Stages a malware archive (dota3.tar.gz) via SCP into a hidden, boring-sounding folder under /tmp (mimics legitimate software naming)",
          "Launches two binaries with nohup (survives SSH session close): tsm — internal SSH scanner hunting more victims — and the XMRig/kinsing crypto miner",
        ]},
        { t: "note", kind: "warn", title: "nohup in a command line is itself a detection tell", text: "Legitimate interactive admin work rarely needs a process to outlive its own SSH session." },
      ],
    },
  ],
};
