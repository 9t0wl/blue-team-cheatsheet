export default {
  id: "ids-rule-writing",
  title: "IDS Rule Writing: Suricata and Snort 3",
  src: "HTB Academy: Working With IDS/IPS (rule development)",
  icon: "✍️",
  cards: [
    {
      title: "A rule is one sentence",
      span2: true,
      blocks: [
        { t: "txt", text: "\"<b>When</b> [action] <b>you see</b> [protocol] traffic from [here] to [there], <b>and</b> it contains [these bytes or this pattern], <b>tell me</b> [message].\" Header = which traffic to even look at (cheap). Options = what it must contain (all options must match, it is an AND). Every rule costs CPU, so the craft is narrow enough to avoid false positives and cheap enough to run fast." },
        { t: "cmd", label: "anatomy", code: `alert  http  $HOME_NET any  ->  $EXTERNAL_NET any  ( msg:"..."; flow:established,to_server; content:"..."; sid:1; rev:1; )
action proto  from      port    dir   to            port    options` },
        { t: "table", head: ["Part", "Notes"], rows: [
          ["action", "<code>alert</code>, <code>log</code>, <code>pass</code> (ignore), <code>drop</code> (IPS only), <code>reject</code> (RST)"],
          ["protocol", "<code>tcp udp icmp ip</code> or app layer: <code>http tls smb dns</code>"],
          ["direction", "<code>-&gt;</code> one way, <code>&lt;&gt;</code> both ways"],
          ["<code>sid</code> / <code>rev</code>", "unique ID and version. <b>Bump rev on every edit.</b> Never load the same sid from two files"],
        ]},
      ],
    },
    {
      title: "Keywords you keep looking up",
      span2: true,
      blocks: [
        { t: "table", head: ["Keyword", "Meaning"], rows: [
          ["<code>msg</code>", "alert text. Put malware family and behavior here"],
          ["<code>flow</code>", "session state and direction, e.g. <code>flow:established,to_server</code>. Always include <code>established</code>"],
          ["<code>content</code>", "literal bytes. Hex goes between pipes: <code>|3a 20|</code> = <code>: </code>, <code>|0d 0a|</code> = CRLF, <code>|2f|</code> = <code>/</code>"],
          ["sticky buffer", "limits where a content is searched (<code>http.uri</code>, <code>http_header</code>, <code>http_client_body</code>, <code>http.cookie</code>, <code>tls</code> fields). Faster and fewer false positives"],
          ["<code>nocase</code>", "ignore case so <code>User-agent</code> does not dodge the rule"],
          ["<code>offset</code> / <code>depth</code>", "position in the <b>payload</b>, measured from its start"],
          ["<code>distance</code> / <code>within</code>", "position relative to the <b>previous match</b>"],
          ["<code>dsize</code>", "payload size of the packet (TCP segment length, not total packet)"],
          ["<code>pcre</code>", "Perl regex. Never rely on pcre alone (slow), pair it with a fast content"],
          ["<code>fast_pattern</code>", "which content the engine pre-filters on first"],
          ["<code>detection_filter</code>", "alert only after N hits in T seconds: <code>track by_src, count 4, seconds 10</code>"],
          ["<code>byte_test</code>", "compare a number at a byte position (e.g. length &gt; 13)"],
          ["<code>ja3.hash</code> / <code>tls</code>", "match a TLS client fingerprint (see the encrypted traffic card)"],
        ]},
        { t: "note", kind: "info", title: "detection styles", text: "<b>Signature</b> (specific strings, precise on known threats, blind to new ones), <b>behavior or anomaly</b> (sizes, intervals, volume, odd ports, more false positives), <b>stateful protocol analysis</b> (flag impossible state transitions)." },
      ],
    },
    {
      title: "offset, depth, distance, within",
      span2: true,
      blocks: [
        { t: "cmd", label: "example", code: `content:"GET"; offset:0; depth:4; content:"/admin"; distance:10; within:80;
# "GET" in the first 4 bytes, then "/admin" starting 10 to 90 bytes after GET ended` },
        { t: "note", kind: "warn", title: "depth counts from the offset, not byte 0", text: "A content of length <b>L</b> found at position <b>P</b> only matches if <code>offset &lt;= P</code> and <code>P + L &lt;= offset + depth</code>. When L equals depth, min offset equals max offset equals P." },
        { t: "note", kind: "ok", title: "worked example: EternalBlue sid 2024217", text: "SMB over TCP has a 4-byte NetBIOS session header, so <code>|ff|SMB...</code> starts at byte <b>4</b>. The shipped <code>offset:9</code> starts the window after the content so it never alerted. The content was 30 bytes with <code>depth:30</code>, so only <b>offset 4</b> alerts (3 alerts, matching <code>threshold count 3</code>)." },
        { t: "cmd", label: "find the boundary by testing a range on a throwaway copy (-S loads only that rule file)", code: `grep 'sid:2024217' local.rules | sed 's/^#\\s*//' > /tmp/ms17.rules
for o in $(seq 0 12); do
  mkdir -p /tmp/t$o
  sed "s/offset:9;/offset:$o;/" /tmp/ms17.rules > /tmp/t$o/r.rules
  sudo suricata -r pcaps/eternalblue.pcap -S /tmp/t$o/r.rules -l /tmp/t$o -k none >/dev/null 2>&1
  echo "offset $o: $(grep -c 2024217 /tmp/t$o/fast.log 2>/dev/null) alerts"
done` },
        { t: "note", kind: "info", title: "reusable technique", text: "When unsure which parameter makes a rule fire, test a range on a copy and read the boundary off the results, then explain it with the formula so it sticks." },
      ],
    },
    {
      title: "C2 and malware rule examples (what each one keys on)",
      span2: true,
      blocks: [
        { t: "table", head: ["Target (pcap)", "Technique", "Key bits", "Weakness"], rows: [
          ["PowerShell Empire", "signature + regex", "GET to <code>login/process.php</code>, <code>admin/get.php</code> or <code>news.php</code>; base64 <code>session=</code> cookie; User-Agent <code>Mozilla/5.0 (Windows NT 6.1</code>; headers must NOT include Referer, Cache or Accept", "profile is malleable, URI and UA are easy to change"],
          ["Covenant (content)", "signature + threshold", "<code>&lt;title&gt;Hello World!&lt;/title&gt;</code> in the response body, <code>detection_filter</code> 4 hits per 10 s per source", "unscoped TCP content match, inefficient"],
          ["Covenant (analytics)", "behavior", "<code>dsize:312</code>, 3 hits per 10 s per source: the beacon's fixed payload size", "breaks if the C2 profile changes"],
          ["Sliver (HTTP)", "regex", "POST plus a URI pcre shaped like directory + <code>login/index/...php?x=value</code>; <code>Set-Cookie</code> with a 32-char alnum value", "leans on pcre"],
          ["Ursnif", "static string + absent headers", "URL <code>/images/...</code> with <code>_2F</code> and <code>_2B</code>, old <code>MSIE 8.0</code> User-Agent, no Accept, Cookie or Referer", "no sticky buffers, so inefficient"],
          ["Cerber", "size, pattern and repetition", "UDP, <code>dsize:9</code>, content <code>hi</code> at depth 2, pcre <code>[a-f0-9]{7}</code>, <code>detection_filter</code>. Sweep of check-ins (511 alerts in the lab)", "one packet shape"],
          ["Patchwork HTTP", "structured HTTP fields", "POST, URI <code>.php?profile=</code>, body starting <code>ddager=</code> then <code>&amp;r1=</code>, no Accept or Referer. 257 beacons", "profile changes"],
          ["Patchwork TLS", "certificate field", "OID <code>55 04 03</code> (commonName) followed by the 8-char CN <code>toigetgf</code>", "needs TLS 1.2 or older, cert in the clear"],
        ]},
        { t: "note", kind: "info", title: "absent headers as a detection idea", text: "Malware crafts minimal requests. Real browsers send Accept, Referer and Cookie, so their <b>absence</b> is a signal (<code>content:!\"Accept\"</code>)." },
        { t: "note", kind: "warn", title: "attacker mirror", text: "Every detail a rule matches is something a malleable C2 profile can change. Read each rule as \"what did the operator leave default\"." },
      ],
    },
    {
      title: "Encrypted traffic: certificates and JA3",
      span2: true,
      blocks: [
        { t: "txt", text: "When the payload is encrypted the <b>envelope</b> is still readable. Two things are visible before encryption starts: the server's <b>certificate</b> (TLS 1.2 and older), and the client's handshake <b>accent</b>, the <b>JA3</b> fingerprint." },
        { t: "table", head: ["Item", "Meaning"], rows: [
          ["<b>JA3</b>", "MD5 of the TLS <b>client</b> hello: <code>TLSVersion,Ciphers,Extensions,EllipticCurves,PointFormats</code>. Fingerprints the <i>software</i>, not the IP or domain"],
          ["<b>JA3S</b>", "same idea for the server's reply"],
          ["<code>ja3.hash</code>", "Suricata sticky buffer holding the JA3 MD5"],
          ["certificate OIDs", "country <code>55 04 06</code>, locality <code>55 04 07</code>, organization <code>55 04 0a</code>, common name <code>55 04 03</code>"],
          ["abuse.ch SSL blacklist", "public list of certificates and JA3 values tied to malware C2"],
        ]},
        { t: "cmd", label: "JA3 rule (Sliver)", code: `alert tls any any -> any any (msg:"Sliver C2 SSL"; ja3.hash; content:"473cd7cb9faa642487833865d516e578"; sid:1002; rev:1;)` },
        { t: "cmd", label: "get the hash from a pcap", code: "ja3 -a --json pcaps/sliverenc.pcap      # read ja3_digest (the MD5)" },
        { t: "note", kind: "ok", title: "picking the implant hash (Trickbot lab)", text: "Two digests appeared: one to Google (the browser, ignore) and <code>72a589da586844d7f0818ce684948eea</code> to <code>45.138.72.155:443</code>, repeated at spaced intervals. <b>Separate digests by destination and repetition</b>: the one talking repeatedly to one unfamiliar IP is the implant." },
        { t: "note", kind: "warn", title: "limits", text: "JA3 fingerprints a TLS stack, so legitimate software on the same library shares the hash. Attackers change or randomize it (one reason JA4 exists). Certificate rules need TLS 1.2 or older, because TLS 1.3 encrypts the certificate. Pair with destination and frequency before alerting." },
      ],
    },
    {
      title: "Snort 3 vs Suricata: what is different",
      span2: true,
      blocks: [
        { t: "table", head: ["Thing", "Snort 3", "Suricata"], rows: [
          ["config", "<code>snort.lua</code> (Lua)", "<code>suricata.yaml</code> (YAML)"],
          ["content modifiers", "comma, space: <code>content:\"/images/\", depth 12;</code>", "semicolon options: <code>content:\"/images/\"; depth:12;</code>"],
          ["HTTP buffers", "sticky buffer <b>before</b> the content: <code>http_header; content:!\"Accept\";</code>", "old style (after) or <code>http.uri; content:</code> (before)"],
          ["load rules", "<code>-R local.rules</code>, <code>--rule-path dir</code>, or <code>ips</code> include in <code>snort.lua</code>", "<code>rule-files:</code> in the yaml, <code>-S</code>/<code>-s</code>"],
          ["alert output", "only if you pass <code>-A</code> (<code>cmg</code>, <code>alert_fast</code>, <code>alert_json</code>, <code>u2</code>, <code>csv</code>)", "<code>fast.log</code> and <code>eve.json</code> written automatically"],
          ["at exit", "prints a big statistics report (read the <code>detection</code> block)", "<code>stats.log</code> file"],
        ]},
        { t: "cmd", label: "Snort 3 lab run, count alerts for one sid", code: "sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R local.rules -r pcaps/wannamine.pcap -A alert_fast | grep -c '\\[1:1000001:'" },
        { t: "table", head: ["Snort 3 command", "Purpose"], rows: [
          ["<code>snort --help-modules</code> / <code>--help-config &lt;module&gt;</code>", "list modules, show a module's settings"],
          ["<code>snort --list-plugins | grep logger</code>", "list output types"],
          ["<code>snort -c snort.lua</code>", "validate config (\"successfully validated the configuration (with 0 warnings)\")"],
          ["<code>-A cmg</code>", "= <code>-A fast -d -e</code>: one-line alert, headers and payload dump"],
          ["<code>snort --help-module http_header</code>", "see a buffer's options"],
        ]},
        { t: "note", kind: "warn", title: "the sticky buffer lesson (Log4Shell)", text: "The same rule on the same pcap went from 0 alerts to alerts by only adding <code>http_header;</code> before <code>content</code>, because the payload is in the User-Agent header. Point <code>content</code> at the right buffer. (LDAP callback was on <b>port 53</b>, a port often allowed through egress filtering.)" },
        { t: "note", kind: "danger", title: "duplicate-sid trap", text: "A backup copy of the rules file in the loaded directory, or <code>-R</code> pointed at it, makes Snort report <code>duplicate rules: 1</code> and the broken copy can win, so alerts vanish. Move backups out (<code>mv local.rules.bak /tmp/</code>). Confirm a rule loaded by the <b>total rules loaded</b> count going up." },
      ],
    },
    {
      title: "Network signatures from the skills assessments",
      span2: true,
      blocks: [
        { t: "table", head: ["Attack", "What it looks like on the wire", "Rule idea"], rows: [
          ["<b>WMIExec</b> (Impacket wmiexec)", "DCOM/RPC (port 135, then a dynamic high port). To start a process the client calls the WMI <code>Win32_Process</code> class's <b><code>Create</code></b> method, after setting up <code>Win32_ProcessStartup</code>", "the shipped rule matched <code>Win32_ProcessStartup</code> plus <code>powershell</code> (context). Adding <code>content:\"Create\";</code> moves it to the <b>action</b>. Host side: <code>WmiPrvSE.exe</code> spawning the command"],
          ["<b>Overpass-the-Hash</b>", "an AS-REQ whose pre-auth encrypted timestamp uses etype <b>RC4-HMAC</b> where the environment normally uses AES (an encryption-type downgrade)", "match etype byte <code>17</code> (hex). Etypes: <code>0x17</code> = 23 = RC4, <code>0x12</code> = 18 = AES256, <code>0x11</code> = 17 = AES128. The trap is reading the hex <code>17</code> as decimal. Host-side twin: Event 4768 with encryption type <code>0x17</code>"],
        ]},
        { t: "note", kind: "warn", title: "tune for legacy", text: "Old clients and some service accounts legitimately use RC4. High signal, not proof. Best where RC4 is rare or disabled." },
      ],
    },
    {
      title: "Rule debugging checklist",
      blocks: [
        { t: "steps", items: [
          "Rules often ship <b>commented out</b> (<code>#</code>). Uncomment only the one you are testing.",
          "Clear old logs before each run (<code>fast.log</code> and <code>eve.json</code> append).",
          "Validate: <code>suricata -T</code> or <code>snort -c ... </code>. A stray character means \"0 rules loaded\", check <code>-vv</code> output.",
          "Baseline first (does it alert as shipped?), edit one thing, rerun, compare the count.",
          "Add <code>-k none</code> if a pcap gives no alerts and checksums look bad.",
          "Never load two files defining the same sid. Keep backups outside the rule directory.",
          "Test a range on a throwaway copy with <code>-S</code> to find a boundary.",
          "Check the version: Suricata 4.0.0 in the text, 6.0.13 in one lab, Snort 3.1.64.0. Keywords differ between versions.",
        ]},
      ],
    },
  ],
};
