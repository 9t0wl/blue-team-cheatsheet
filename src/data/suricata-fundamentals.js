export default {
  id: "suricata-fundamentals",
  title: "Suricata: Operation, Logs and File Extraction",
  src: "HTB Academy: Working With IDS/IPS",
  icon: "🦉",
  cards: [
    {
      title: "Four operating modes",
      span2: true,
      blocks: [
        { t: "table", head: ["Mode", "What it does", "Can it block?"], rows: [
          ["<b>IDS</b>", "passive, watches a copy of traffic, alerts only. No latency, no protection", "no"],
          ["<b>IPS</b>", "inline, traffic must pass through Suricata. Needs <code>drop</code> rules. Risk: false positives block legitimate traffic, and it adds latency", "yes"],
          ["<b>IDPS</b>", "passive monitoring plus a TCP RST to kill a session. Low-latency middle ground", "kills sessions via RST"],
          ["<b>NSM</b>", "logging only, no alerting logic. Huge volume, great for retrospective IR", "no"],
        ]},
        { t: "note", kind: "info", title: "the guard-in-a-mailroom picture", text: "<b>Rules</b> are the guard's watchlist. IDS = writes down what looks wrong. IPS = stands in the doorway and refuses the package. IDPS = watches but can shout stop. NSM = no watchlist, writes down every package." },
      ],
    },
    {
      title: "Inputs and the flags you use",
      span2: true,
      blocks: [
        { t: "table", head: ["Input", "Command", "Notes"], rows: [
          ["Offline pcap", "<code>suricata -r file.pcap</code>", "post-mortem analysis and the safe place to test rules"],
          ["Live LibPCAP", "<code>suricata --pcap=ens160</code>", "slow, no load balancing"],
          ["Live AF_PACKET", "<code>suricata -i ens160</code>", "best default on Linux, multi-threaded"],
          ["Inline NFQ", "<code>sudo iptables -I FORWARD -j NFQUEUE</code> then <code>sudo suricata -q 0</code>", "inline IPS, needs <code>drop</code> rules to block"],
        ]},
        { t: "table", head: ["Flag", "Purpose"], rows: [
          ["<code>-r &lt;pcap&gt;</code>", "read a pcap (offline mode)"],
          ["<code>-k none</code>", "skip checksum validation. Needed for pcaps with bad or offloaded checksums, otherwise packets get ignored and you see no alerts"],
          ["<code>-l &lt;dir&gt;</code>", "write logs to another directory (<code>-l .</code> = current dir, the dot is required)"],
          ["<code>-c &lt;yaml&gt;</code> / <code>-T</code>", "config file / test the config and exit"],
          ["<code>-S &lt;rules&gt;</code>", "load only that rule file (great for isolating one rule)"],
          ["<code>-vv</code>", "verbose startup, shows rules loaded or failed"],
          ["<code>-q 0</code>", "inline NFQ queue 0"],
        ]},
        { t: "cmd", label: "standard offline test run", code: "sudo suricata -r pcaps/suspicious.pcap -k none -l ." },
        { t: "cmd", label: "validate before deploying (must end with \"successfully loaded\")", code: "sudo suricata -T -c /etc/suricata/suricata.yaml" },
      ],
    },
    {
      title: "Config essentials (suricata.yaml)",
      blocks: [
        { t: "table", head: ["Setting", "Meaning"], rows: [
          ["<code>vars: address-groups:</code>", "<code>HOME_NET</code>, <code>EXTERNAL_NET</code> (defaults to <code>!$HOME_NET</code>), <code>HTTP_SERVERS</code>, <code>DNS_SERVERS</code>. Be specific for accuracy and speed"],
          ["<code>rule-files:</code>", "where custom rules get registered (for example <code>/home/htb-student/local.rules</code>)"],
          ["commented <code>#alert</code> lines", "not loaded, usually superseded or obsolete"],
          ["rule directories", "<code>/etc/suricata/rules/</code>, downloaded rules land in <code>/var/lib/suricata/rules/suricata.rules</code>"],
          ["<code>outputs: http-log</code>", "set <code>enabled: yes</code> to get a separate <code>http.log</code>"],
        ]},
        { t: "note", kind: "warn", title: "custom rules do nothing until registered", text: "A rule in <code>local.rules</code> that is not under <code>rule-files:</code> never loads, and a stray character in a rule silently loads 0 rules. Check <code>suricata.log</code> or run <code>-vv</code> for \"1 rules successfully loaded, 0 rules failed\"." },
      ],
    },
    {
      title: "Outputs: what each file is",
      span2: true,
      blocks: [
        { t: "table", head: ["File (default <code>/var/log/suricata/</code>, root only)", "What it is"], rows: [
          ["<code>eve.json</code>", "everything as JSON, one object per line: alert, http, dns, tls, ssh, smtp, flow, netflow, drop, stats. The recommended output"],
          ["<code>fast.log</code>", "alerts only, one human-readable line each"],
          ["<code>stats.log</code>", "engine counters, for debugging deployments"],
          ["<code>suricata.log</code>", "engine messages (rule load errors)"],
          ["<code>http.log</code>", "only if <code>http-log</code> is enabled in the yaml"],
        ]},
        { t: "cmd", label: "fast.log alert line anatomy", code: "timestamp [**] [gid:sid:rev] message [**] [Classification: x] [Priority: n] {PROTO} src:port -> dst:port" },
        { t: "note", kind: "danger", title: "fast.log and eve.json APPEND", text: "Alerts from your previous test stay in the file and make a rule that no longer fires look like it still works. <b>Delete logs between runs</b>: <code>rm -f fast.log eve.json stats.log suricata.log</code>." },
        { t: "note", kind: "info", title: "pcap time vs replay time", text: "Reading a pcap offline stamps events with the pcap's own packet times. Replaying it live (tcpreplay) stamps \"now\". Same traffic, two different timestamps." },
      ],
    },
    {
      title: "eve.json with jq",
      span2: true,
      blocks: [
        { t: "cmd", label: "only alerts", code: "cat /var/log/suricata/eve.json | jq -c 'select(.event_type == \"alert\")'" },
        { t: "cmd", label: "first DNS event, pretty printed (swap dns for http, tls, ssh, flow ...)", code: "cat eve.json | jq -c 'select(.event_type == \"dns\")' | head -1 | jq ." },
        { t: "cmd", label: "TLS JA3 fingerprints per connection", code: "jq -c 'select(.event_type==\"tls\") | .tls.ja3' eve.json" },
        { t: "note", kind: "info", title: "-c keeps head, grep, wc working", text: "<code>-c</code> prints one compact object per line, so Unix tools still work. Pipe through a final <code>jq .</code> only when you want it pretty." },
        { t: "table", head: ["Field", "Why you care"], rows: [
          ["<code>flow_id</code>", "the <b>case number</b>: one ID shared by the alert, dns, http, tls and flow events of one conversation. Pivot on it to tie a DNS lookup to the HTTP download"],
          ["<code>pcap_cnt</code>", "ties an alert back to the exact packet number in Wireshark"],
          ["<code>action</code>", "<code>allowed</code> means IDS mode, it alerted but did not block"],
        ]},
        { t: "note", kind: "ok", title: "worked example", text: "A known-bad DNS lookup alert (<code>adv.epostoday.uk</code>) and, on the same host, one TCP connection carrying three HTTP transactions: <code>GET /app.php</code>, a self-referred <code>GET /app.php</code> returning ~600 KB, then <code>/favicon.ico</code>. A large self-referred response right after a bad lookup is a likely payload download." },
      ],
    },
    {
      title: "File extraction (file-store)",
      blocks: [
        { t: "txt", text: "Extraction is not automatic. You need <b>both</b> halves:" },
        { t: "cmd", label: "1. suricata.yaml", code: "file-store:\n  version: 2\n  enabled: yes\n  force-filestore: yes" },
        { t: "cmd", label: "2. a rule saying what to store", code: "alert http any any -> any any (msg:\"FILE store all\"; filestore; sid:2; rev:1;)" },
        { t: "txt", text: "Files land in <code>filestore/</code> named by their <b>SHA256</b>, inside a subfolder of the first two hex characters. The filename is already the hash to search in VirusTotal. Check the magic bytes with <code>xxd file | head</code>: <code>4d5a</code> (MZ) is a Windows PE." },
      ],
    },
    {
      title: "Rule updates and live reload",
      blocks: [
        { t: "table", head: ["Task", "Command"], rows: [
          ["live reload with no gap in inspection", "set <code>detect-engine: - reload: true</code>, then <code>sudo kill -usr2 $(pidof suricata)</code>"],
          ["pull rules (ET Open default)", "<code>sudo suricata-update</code>, writes <code>/var/lib/suricata/rules/suricata.rules</code> and runs <code>suricata -T</code>"],
          ["list providers", "<code>suricata-update list-sources</code> (et/open, et/pro, oisf/trafficid, sslbl/ja3-fingerprints, ...)"],
          ["enable one", "<code>suricata-update enable-source et/open</code>, then <code>suricata-update</code> again"],
          ["test rules on a live sensor", "<code>sudo tcpreplay -i ens160 pcaps/suspicious.pcap</code> in a second session"],
        ]},
        { t: "note", kind: "info", title: "internet needed", text: "<code>suricata-update</code> downloads rules, so it cannot be replayed on an offline lab target." },
      ],
    },
  ],
};
