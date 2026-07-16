export default {
  id: "pyramid",
  title: "Detection Frameworks — Pyramid of Pain",
  src: "Cyber Defence Frameworks",
  icon: "🔺",
  cards: [
    {
      title: "The pyramid (bottom = cheap for attacker to change)",
      span2: true,
      blocks: [
        { t: "table", head: ["Tier", "Indicator", "Pain to attacker", "Blue-team tool"], rows: [
          ["1 (bottom)", "Hash values", "Trivial (one bit flip)", "Hash blocklist / EDR"],
          ["2", "IP addresses", "Easy (rent new VPS)", "Firewall rule manager"],
          ["3", "Domain names", "Moderate (register/rehost)", "DNS rule manager / sinkhole"],
          ["4", "Host artifacts", "Annoying (recompile)", "Sigma rule (Sysmon)"],
          ["5", "Network artifacts", "Annoying (UA/URI/beacon)", "Sigma / IDS signature"],
          ["6 (top)", "TTPs", "Painful (change behaviour)", "Behavioral detection"],
        ]},
        { t: "note", kind: "info", title: "behavioral > IOC", text: "Match the <b>shape</b> of a beacon (fixed size + fixed interval), not a specific C2 IP — generalizes past infra changes a static block never catches. Detection rules should map to a MITRE <b>tactic</b> (e.g. TA0011 Command &amp; Control), not just an IOC." },
        { t: "note", kind: "warn", title: "signal vs noise", text: "Sandbox reports mix in 1–2 benign entries (decoy Microsoft IPs, explorer.exe/notepad.exe noise). Filter by correlating PID/process ownership or behavioral regularity — don't trust every row." },
      ],
    },
  ],
};
