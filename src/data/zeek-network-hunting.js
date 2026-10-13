export default {
  id: "zeek-network-hunting",
  title: "Zeek: Network Logs and Hunting Patterns",
  src: "HTB Academy: Working With IDS/IPS (Zeek)",
  icon: "🔎",
  cards: [
    {
      title: "Zeek is a stenographer, not a guard",
      span2: true,
      blocks: [
        { t: "txt", text: "Suricata and Snort shout when a rule matches. <b>Zeek writes detailed minutes of every conversation</b> (connections, DNS, HTTP, files, TLS) as structured logs. Detection comes from reading those logs and from Zeek scripts that react to events. It is passive, works on live traffic or a pcap, and never blocks." },
        { t: "table", head: ["", "Suricata / Snort", "Zeek"], rows: [
          ["core idea", "match packets against signatures, alert", "record structured activity, analyze with scripts and queries"],
          ["what you read", "alerts", "many logs, plus notices"],
          ["strength", "known threats, blocking in IPS mode", "visibility, hunting, anomalies, retrospective investigation"],
          ["detection logic", "rules", "scripts (more flexible, more effort)"],
          ["blocking", "possible (IPS)", "no, passive only"],
        ]},
        { t: "note", kind: "info", title: "complementary", text: "A common SOC pattern is an IDS for known-bad alerts plus Zeek logs for context and hunting. Architecture: packets, then the <b>event engine</b> (parses protocols, emits policy-neutral events), then the <b>script interpreter</b> (your policy), then logs, notices or actions. Protocol analysis works <b>regardless of port</b>." },
      ],
    },
    {
      title: "Running Zeek on a pcap and reading logs",
      span2: true,
      blocks: [
        { t: "cmd", label: "run on a pcap (logs land in the CURRENT directory, use a clean one per pcap)", code: "mkdir -p ~/case1 && cd ~/case1\n/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/file.pcap" },
        { t: "txt", text: "<code>-r</code> reads the pcap. <code>-C</code> ignores checksum validation (same idea as Suricata's <code>-k none</code>). Logs from different runs overwrite or mix, so one directory per pcap." },
        { t: "cmd", label: "pick columns with zeek-cut", code: "cat http.log | zeek-cut host uri user_agent\ncat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p" },
        { t: "cmd", label: "rotated live logs are gzip in dated folders", code: "zcat 2026-10-06/conn.*.log.gz | zeek-cut ...\nzgrep 45.33.32.156 2026-10-06/*.gz" },
        { t: "cmd", label: "read field names from #fields instead of counting columns", code: "paste <(grep '^#fields' x509.log | tr '\\t' '\\n' | tail -n +2) <(grep -i 'my *company' x509.log | head -1 | tr '\\t' '\\n')" },
      ],
    },
    {
      title: "Which log answers which question",
      span2: true,
      blocks: [
        { t: "table", head: ["Log", "Answers"], rows: [
          ["<code>conn.log</code>", "the backbone: who talked to whom, when, how much, how long"],
          ["<code>dns.log</code>", "queries and answers"],
          ["<code>http.log</code>", "requests and responses: <code>host</code>, <code>uri</code>, <code>referrer</code>, <code>user_agent</code>, <code>status_code</code>"],
          ["<code>files.log</code>", "file objects extracted from any protocol, large transfers"],
          ["<code>ssl.log</code> / <code>x509.log</code>", "TLS connections, and the <b>certificates</b> seen in handshakes (parsed even though traffic is encrypted)"],
          ["<code>smb_files.log</code> / <code>smb_mapping.log</code>", "SMB file open/delete (e.g. <code>PSEXESVC.exe</code> to <code>ADMIN$</code>) and share connections (<code>ADMIN$</code>, <code>IPC$</code>)"],
          ["<code>dce_rpc.log</code>", "RPC calls: endpoint and operation (service control, spooler functions)"],
          ["<code>ntlm.log</code> / <code>kerberos.log</code>", "how someone authenticated"],
          ["<code>weird.log</code> / <code>reporter.log</code>", "protocol oddities / Zeek's own errors (usually harmless)"],
        ]},
        { t: "table", head: ["conn.log field", "Meaning"], rows: [
          ["<code>uid</code>", "connection ID, joins records across logs (Zeek's <code>flow_id</code>)"],
          ["<code>id.orig_h/p</code>, <code>id.resp_h/p</code>", "client and server address and port"],
          ["<code>orig_bytes</code> / <code>resp_bytes</code>", "payload sent by client / server. <code>-</code> means no value"],
          ["<code>conn_state</code>", "<code>SF</code> normal finish, <code>S0</code> SYN seen, no reply (scan)"],
          ["<code>history</code>", "flag sequence, e.g. <code>ShADadfF</code>"],
        ]},
      ],
    },
    {
      title: "Hunt: beaconing",
      span2: true,
      blocks: [
        { t: "txt", text: "<b>Same destination, regular timing, near-identical sizes, many short connections with a new source port each time.</b> Empire's default beacon is every 5 seconds with a little jitter (PowerShell Empire pcap: <code>192.168.56.14</code> to <code>51.15.197.127:80</code>, gaps of about 5 s, <code>resp_bytes</code> 399, duration about 0.1 s)." },
        { t: "cmd", label: "gap in seconds between connections to each host (a steady value is the beacon)", code: "cat conn.log | zeek-cut ts id.resp_h | awk '{print $1-p, $2; p=$1}'" },
        { t: "note", kind: "info", title: "two views of one attack", text: "The same Empire traffic was caught by a <b>content rule</b> (cookie, User-Agent) in Suricata and by <b>timing and size</b> here." },
      ],
    },
    {
      title: "Hunt: exfiltration (DNS and TLS)",
      span2: true,
      blocks: [
        { t: "txt", text: "<b>DNS exfil:</b> hundreds of unique subdomains under <b>one</b> domain (<code>456c54f2.blue.letsgohunt.online</code>) with hex labels and an incrementing counter (<code>...0346c53ab</code>, <code>1346c53ab</code>, ...). The data rides in the query, so the answers are junk (<code>0.0.0.0</code>). Legitimate use rarely touches dozens of unique subdomains of one domain." },
        { t: "cmd", label: "list names, then count queries per parent domain (exfil domain floats to the top)", code: "cat dns.log | zeek-cut query | cut -d . -f1-7\ncat dns.log | zeek-cut query | awk -F. '{print $(NF-1)\".\"$NF}' | sort | uniq -c | sort -rn | head" },
        { t: "txt", text: "<b>TLS exfil:</b> you cannot read the payload but you can count bytes. Large one-directional volume to one destination is the signal (one pair sent about 270 MB, the other 0)." },
        { t: "cmd", label: "bytes sent per host pair, biggest first", code: "cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes | sort | grep -v -e '^$' | grep -v '-' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10" },
        { t: "table", head: ["Pipeline part", "Purpose"], rows: [
          ["<code>zeek-cut id.orig_h id.resp_h orig_bytes</code>", "client, server, bytes the client sent"],
          ["<code>grep -v -e '^$'</code> / <code>grep -v '-'</code>", "drop empty lines and Zeek's <code>-</code> placeholder (caveat: drops any line containing a hyphen)"],
          ["<code>datamash -g 1,2 sum 3</code>", "group by source and destination, sum bytes. SPL equivalent: <code>stats sum(orig_bytes) by src,dst</code>"],
          ["<code>sort -k 3 -rn | head -10</code>", "top 10 by the sum"],
        ]},
        { t: "note", kind: "warn", title: "a number alone does not say malicious", text: "A per-destination sum can be tiny (REvil/Kaseya lab: only 2311 bytes to <code>178.23.155.240</code>, small check-ins) or huge. Direction matters: <code>orig_bytes</code> is what the <i>originator</i> sent, so confirm the victim opened the connection." },
        { t: "cmd", label: "sum bytes sent to one IP", code: "cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes | awk '$2==\"178.23.155.240\" {s+=$3} END {print s}'" },
      ],
    },
    {
      title: "Hunt: lateral movement and privilege escalation in network logs",
      span2: true,
      blocks: [
        { t: "table", head: ["Attack", "What the logs show"], rows: [
          ["<b>PsExec</b>", "<code>smb_files.log</code>: <code>PSEXESVC.exe</code> written to <code>\\\\dc1\\ADMIN$</code> (<code>SMB::FILE_OPEN</code>, ~145 KB), later <code>SMB::FILE_DELETE</code>. <code>smb_mapping.log</code>: <code>ADMIN$</code> and <code>IPC$</code>. <code>dce_rpc.log</code> over <code>\\pipe\\ntsvcs</code> (<code>svcctl</code>): <code>OpenSCManagerW</code>, <code>CreateServiceWOW64W</code>, <code>StartServiceW</code>, <code>ControlService</code>, <code>DeleteService</code>, after <code>epmapper ept_map</code> on port 135"],
          ["<b>PrintNightmare</b> (CVE-2021-34527)", "<code>dce_rpc.log</code> shows <code>spoolss RpcEnumPrinterDrivers</code> (recon) then <code>RpcAddPrinterDriverEx</code> (install a driver, the exploit call). <code>ntlm.log</code> and <code>kerberos.log</code> show how the attacker authenticated (valid credentials needed)"],
        ]},
        { t: "cmd", label: "summarize RPC operations per host pair", code: "cat dce_rpc.log | zeek-cut id.orig_h id.resp_h endpoint operation | sort | uniq -c | sort -rn" },
        { t: "note", kind: "info", title: "host-side twins", text: "PsExec on the host: Event 7045 (service install) and 5145 (share access). WMIExec: <code>WmiPrvSE.exe</code> spawning the command." },
      ],
    },
    {
      title: "Hunt: suspicious certificates (x509.log)",
      span2: true,
      blocks: [
        { t: "txt", text: "Self-signed or throwaway certs carry lazy default values. Look for <b>generic or default names</b>, <b>subject equal to issuer</b> and a one-year validity. Gootkit (delivered by the Neutrino exploit kit) used <code>CN=localhost,OU=IT,O=MyCompany Ltd.,L=York,ST=Yorks,C=GB</code> in both subject and issuer, valid 2016-06-14 to 2017-06-14." },
        { t: "cmd", label: "unique subject/issuer pairs", code: "cat x509.log | zeek-cut certificate.subject certificate.issuer | sort | uniq -c" },
        { t: "note", kind: "warn", title: "course text vs reality", text: "The lab text called \"My Company Ltd.\" the Common Name. In the data it is the <b>Organization</b> (<code>O=</code>) and the CN is <code>localhost</code>. The field to read is <code>certificate.subject</code> (the issuer also holds it because the cert is self-signed). Always read the actual values." },
        { t: "note", kind: "info", title: "typical lazy defaults", text: "<code>localhost</code>, <code>MyCompany Ltd.</code>, <code>Internet Widgits Pty Ltd</code>. Pair with JA3 and destination reputation before alerting." },
      ],
    },
  ],
};
