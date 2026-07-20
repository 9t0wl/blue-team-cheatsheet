export default {
  id: "snort-ids",
  title: "IDS/IPS Fundamentals & Snort",
  src: "IDS Fundamentals, Snort",
  icon: "🛡️",
  cards: [
    {
      title: "IDS vs IPS — passive vs active",
      blocks: [
        { t: "txt", text: "Same underlying job (spot malicious traffic), different response posture. <b>IDS</b> = detect + alert only, never touches the packet. <b>IPS</b> = detect + automatically block/terminate. Snort is <b>one engine</b> that can run as either — the difference is which mode/flags you launch it with, not a different product." },
        { t: "table", head: ["System", "Scope", "Active?"], rows: [
          ["NIDS", "entire subnet", "no — alerts only"],
          ["HIDS", "single endpoint", "no — alerts only"],
          ["NIPS", "entire subnet", "yes — blocks inline"],
          ["HIPS", "single endpoint", "yes — blocks inline"],
          ["WIPS", "wireless network", "yes — rogue AP / deauth detection"],
          ["NBA", "subnet, behavior-based", "baselines normal traffic first"],
        ]},
        { t: "note", kind: "info", title: "why NBA is the odd one out", text: "Everything else above is signature/rule-driven. NBA baselines what \"normal\" looks like first, then flags deviation — which is what makes it viable against <b>zero-days</b> with no existing signature. Tradeoff: an attacker active <i>during</i> the training window gets learned in as normal." },
      ],
    },
    {
      title: "Detection techniques",
      blocks: [
        { t: "note", kind: "info", title: "signature-based", text: "Matches known patterns/IOCs. Fast and precise, but blind to anything novel. This is what most of Snort's default ruleset does." },
        { t: "note", kind: "warn", title: "behavior-based", text: "Compares live traffic against a learned baseline. Catches novel attacks; costs false positives whenever legitimate behavior shifts." },
        { t: "note", kind: "warn", title: "policy-based", text: "Flags anything that violates a defined policy, regardless of whether it's inherently malicious — e.g. alerting on <i>any</i> Telnet use because policy forbids it, not because Telnet itself is an attack pattern." },
      ],
    },
    {
      title: "Snort's four operating modes",
      span2: true,
      blocks: [
        { t: "table", head: ["Mode", "Flags", "What it does"], rows: [
          ["Sniffer", "-v / -d / -e / -X", "Live packet display, no ruleset — like tcpdump. Visibility, not detection."],
          ["Packet Logger", "-dev -l . / -K ASCII", "Captures traffic to disk (binary/pcap or ASCII). Still no ruleset — capture only."],
          ["IDS/IPS", "-c snort.conf", "The real detection engine — matches traffic against the loaded ruleset, alerts per -A mode."],
          ["PCAP Investigation", "-r file.pcap / --pcap-list / --pcap-show", "Replays a saved capture through the ruleset offline — threat hunting / forensics."],
        ]},
        { t: "note", kind: "danger", title: "IPS/inline is opt-in", text: "Loading a ruleset with <code>-c</code> runs Snort as an <b>IDS by default</b> (alert only). Actual blocking requires explicitly launching <b>inline mode</b> with <code>-Q --daq af_packet -i eth0:eth1</code> and two NICs. Same rules, different execution flag — this is the concrete answer to \"how does one engine do both IDS and IPS.\"" },
        { t: "note", kind: "info", title: "PCAP mode = retroactive detection", text: "Replay last week's capture against <b>today's</b> updated ruleset to catch something that had no signature yet when it first happened. Detection capability improves over time even for already-passed traffic, as long as it was captured — same idea as the Pyramid of Pain's \"indicators improve\" logic." },
      ],
    },
    {
      title: "Rule structure",
      blocks: [
        { t: "cmd", label: "anatomy", code: "action protocol src_ip src_port direction dst_ip dst_port (options)" },
        { t: "txt", text: "The 4-tuple (protocol/src/dst/port) is pure network-layer filtering — same shape as a firewall ACL. What makes it IDS-grade is the <code>(options)</code> block: <b>general</b> (msg/sid/rev bookkeeping), <b>payload</b> (content matching inside the packet body — a stateless firewall can't do this), <b>non-payload</b> (flags:S, sameip, id:&lt;n&gt; — protocol-metadata conditions beyond simple 4-tuple filtering)." },
        { t: "table", head: ["Action", "Behavior"], rows: [
          ["alert", "generate alert + log — pure IDS behavior"],
          ["log", "log only, no alert"],
          ["drop", "block + log silently (inline mode only)"],
          ["reject", "block + log + actively tear down session (RST/unreachable)"],
        ]},
        { t: "note", kind: "warn", title: "drop/reject need inline mode", text: "In passive IDS mode <code>drop</code> and <code>reject</code> still just log — there's no physical position in the traffic path to actually block from. They only have teeth in IPS/inline mode." },
      ],
    },
    {
      title: "Example rules",
      blocks: [
        { t: "cmd", label: "alert on all ICMP (bidirectional)", code: "alert icmp any any <> any any (msg:\"ICMP Detected\"; sid:1000001; rev:1;)" },
        { t: "cmd", label: "alert on TCP SYN flag", code: "alert tcp any any <> any any (msg:\"SYN Flag Detected\"; flags:S; sid:1000002; rev:1;)" },
        { t: "cmd", label: "alert on TCP PSH+ACK flags", code: "alert tcp any any <> any any (msg:\"PSH-ACK Flag Detected\"; flags:PA; sid:1000003; rev:1;)" },
        { t: "cmd", label: "alert when src IP == dst IP", code: "alert ip any any -> any any (msg:\"Same Src/Dst IP\"; sameip; sid:1000004; rev:1;)" },
        { t: "cmd", label: "filter by IP ID field", code: "alert icmp any any <> any any (msg:\"IP ID Match\"; id:35369; sid:1000005; rev:1;)" },
      ],
    },
    {
      title: "Commands quick reference",
      span2: true,
      blocks: [
        { t: "table", head: ["Flag", "Purpose"], rows: [
          ["-V", "version info"],
          ["-c", "specify config file"],
          ["-T", "test config (validate without running live)"],
          ["-v / -d / -e / -X", "verbose / dump payload / link-layer headers / full hex dump"],
          ["-i", "specify network interface"],
          ["-l", "log to directory (. = current)"],
          ["-K ASCII", "log in ASCII format instead of binary"],
          ["-r", "read a pcap/log file"],
          ["-n", "process N packets then stop"],
          ["-N", "disable logging"],
          ["-D", "daemon/background mode"],
          ["-A", "alert mode: console / cmg / fast / full / none"],
          ["-Q", "inline IPS mode"],
        ]},
        { t: "cmd", label: "test config before deploying", code: "sudo snort -c /etc/snort/snort.conf -T" },
        { t: "cmd", label: "sniffer mode, verbose + payload dump", code: "sudo snort -dev -i eth0" },
        { t: "cmd", label: "packet logger, ASCII format", code: "sudo snort -dev -K ASCII -l ." },
        { t: "cmd", label: "IDS/IPS mode, alert to console", code: "sudo snort -c /etc/snort/snort.conf -A console" },
        { t: "cmd", label: "IPS inline mode (2 interfaces)", code: "sudo snort -c /etc/snort/snort.conf -Q --daq af_packet -i eth0:eth1" },
        { t: "cmd", label: "PCAP investigation, multiple files + show which triggered", code: "sudo snort -c /etc/snort/snort.conf --pcap-list=\"file1.pcap file2.pcap\" --pcap-show" },
        { t: "cmd", label: "run against local rules only, no full config", code: "sudo snort -r file.pcap --rules local.rules -A full -l ." },
      ],
    },
    {
      title: "Config & rule management",
      blocks: [
        { t: "table", head: ["File", "Path"], rows: [
          ["Main config", "/etc/snort/snort.conf"],
          ["Local rules", "/etc/snort/rules/local.rules"],
          ["Default log dir", "/var/log/snort/"],
        ]},
        { t: "note", kind: "info", title: "why comment out, never delete", text: "Deleting a rule silently makes it impossible to reconstruct <i>why</i> a detection gap exists later, during an incident postmortem. Commenting preserves the rule's rationale/history for the next analyst — same instinct as not force-pushing over git history." },
        { t: "note", kind: "warn", title: "always bump rev", text: "Any time a rule is modified, increment its <code>rev</code> number. <code>sid</code> stays constant (it's the rule's identity); <code>rev</code> tracks its version." },
        { t: "note", kind: "danger", title: "-T before every deploy", text: "Snort's equivalent of <code>terraform plan</code> / <code>nginx -t</code> — validates syntax without loading the ruleset live, catching a malformed rule before it either crashes the running IDS or silently fails to load and leaves you blind to whatever that rule was supposed to catch." },
      ],
    },
  ],
};
