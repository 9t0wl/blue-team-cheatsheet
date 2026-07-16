export default {
  id: "log-pivot",
  title: "Incident Investigation — CLI Log Pivoting",
  src: "Network Security Essentials",
  icon: "🧬",
  cards: [
    {
      title: "The one pattern that does everything",
      desc: "Swap the IOC and field position; the skeleton never changes.",
      span2: true,
      blocks: [
        { t: "cmd", label: "core pivot pattern", code: "grep <IOC> <logfile> | cut -d<delim> -f<field> | sort | uniq -c | sort -nr" },
        { t: "note", kind: "info", text: "Once this clicks, an unfamiliar log format stops being a blocker — the skill transfers across VPN, SMTP, firewall, and IDS schemas unchanged." },
      ],
    },
    {
      title: "Kill-chain pivot order",
      blocks: [
        { t: "steps", items: [
          "<b>Recon:</b> count BLOCK sources — <code>grep \"BLOCK\" fw.log | cut -d' ' -f5 | cut -d: -f1 | sort -nr | uniq -c</code>. Top offender = scanning IP.",
          "<b>Initial access:</b> <code>grep FAIL vpn_auth.log | cut -d' ' -f3 | sort | uniq -c | sort -nr</code> → brute-forced source; grep it back for the <code>assigned_ip=</code> on the first SUCCESS = attacker foothold.",
          "<b>Lateral movement:</b> grep foothold IP for ALLOW on 22/445/3389; IDS alert text names the technique.",
          "<b>C2 beaconing:</b> <code>grep \"C2\" ids_alerts.log</code> → src (internal beacon) vs dst (external handler).",
          "<b>Exfiltration:</b> <code>grep -i exfil ids_alerts.log</code> or <code>grep \"HTTP POST Large\"</code> — src should match the beacon host.",
        ]},
      ],
    },
  ],
};
