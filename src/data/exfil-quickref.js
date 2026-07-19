export default {
  id: "exfil-quickref",
  title: "Data Exfiltration — Quick Reference by Category",
  src: "Data Exfiltration Detection",
  icon: "📤",
  cards: [
    {
      title: "How this page is organized",
      span2: true,
      blocks: [
        { t: "txt", text: "Pure lookup table, grouped by tool first (Splunk vs Wireshark), then by protocol within Wireshark. No narrative — jump straight to the card you need. Deeper walkthroughs (worked examples, false-positive traps) live in the <b>Tunnelling</b>, <b>FTP</b>, and <b>HTTP</b> sections above." },
      ],
    },

    // ---------- SPLUNK ----------
    {
      title: "Splunk — cross-protocol hunting queries",
      span2: true,
      blocks: [
        { t: "cmd", label: "baseline — pull the sourcetype", code: "index=data_exfil sourcetype=DNS_logs\nindex=data_exfil sourcetype=http_logs\nindex=data_exfil sourcetype=ftp_logs" },
        { t: "cmd", label: "volume pivot — who's talking the most", code: "index=data_exfil sourcetype=DNS_logs | stats count by src_ip\nindex=data_exfil sourcetype=DNS_logs | stats count by query | sort -count" },
        { t: "cmd", label: "length pivot — abnormally long query/URI", code: "index=data_exfil sourcetype=DNS_logs | where len(query) > 30" },
        { t: "cmd", label: "HTTP — isolate POST + size stats by domain", code: "index=data_exfil sourcetype=http_logs method=POST\n| stats count avg(bytes_sent) max(bytes_sent) min(bytes_sent) by domain | sort -count" },
        { t: "cmd", label: "HTTP — large-payload shortlist", code: "index=data_exfil sourcetype=http_logs method=POST bytes_sent > 600\n| table _time src_ip uri domain dst_ip bytes_sent | sort -bytes_sent" },
        { t: "cmd", label: "FTP logs — large transfers + rare commands", code: "index=data_exfil sourcetype=ftp_logs (command=STOR OR command=RETR)\n| stats count sum(bytes) by src_ip dest_ip file | sort -sum(bytes)" },
        { t: "note", kind: "info", title: "the pattern behind every row above", text: "Same shape as the CLI log-pivot skeleton in the <b>Incident Investigation</b> section: <code>stats count by &lt;field&gt;</code> to find the outlier host/domain, then <code>where len(x) &gt; N</code> or a <code>bytes &gt; N</code> filter to isolate the payload-carrying entries." },
      ],
    },

    // ---------- WIRESHARK: DNS ----------
    {
      title: "Wireshark — DNS exfil filters",
      blocks: [
        { t: "table", head: ["Filter", "Shows"], rows: [
          ["dns", "All DNS traffic"],
          ["dns.flags.response == 0", "Queries only (no response) — exfil-by-query pattern"],
          ["dns && frame.len > 70", "Long queries — suspicious subdomain encoding"],
          ["dns.qry.name.len > 40 and !mdns", "Query-name length threshold, past most legit long domains"],
          ["dns && dns.qry.name contains \"domain\"", "Pin down one suspected parent domain"],
          ["dns.flags.rcode == 3", "NXDOMAIN responses — exfil-by-query often never expects an answer"],
        ]},
        { t: "note", kind: "warn", title: "reliable method: pivot by parent domain, not raw length", text: "Group by the last two labels and count — a tunnel shows one registrable domain with a huge spread of unique subdomains. Full walkthrough + tshark one-liner in the Tunnelling section." },
      ],
    },

    // ---------- WIRESHARK: FTP ----------
    {
      title: "Wireshark — FTP exfil filters",
      blocks: [
        { t: "table", head: ["Filter", "Shows"], rows: [
          ["ftp || ftp-data", "FTP control + data channel traffic"],
          ["ftp.request.command == \"USER\" || ftp.request.command == \"PASS\"", "Cleartext login attempts"],
          ["ftp contains \"STOR\"", "Uploads — data leaving via FTP"],
          ["ftp contains \"RETR\"", "Downloads — staged data being pulled"],
          ["ftp contains \"csv\"", "Filter by suspicious file extension (swap csv/pdf/txt/xlsx)"],
          ["ftp && frame.len > 90", "Large payload transfers"],
        ]},
        { t: "txt", text: "Right-click → Follow → TCP Stream on a STOR/RETR packet to view the actual file content or filename in cleartext." },
      ],
    },

    // ---------- WIRESHARK: HTTP ----------
    {
      title: "Wireshark — HTTP exfil filters",
      blocks: [
        { t: "table", head: ["Filter", "Shows"], rows: [
          ["http", "All HTTP traffic"],
          ["http.request.method == \"POST\"", "POST requests — bulk upload vector"],
          ["http.request.method == \"POST\" and frame.len > 500", "Large POST bodies (first pass)"],
          ["http.request.method == \"POST\" and frame.len > 750", "Large POST bodies (narrower, cuts more noise)"],
          ["http.request.uri matches \"[A-Za-z0-9+/=]{40,}\"", "Base64-looking blob stuffed into the URI/query string"],
          ["http.request.line contains \"X-Data\"", "Custom header used as a covert data field"],
        ]},
        { t: "txt", text: "Right-click → Follow → HTTP Stream to view the request body / exfiltrated file content directly." },
      ],
    },

    // ---------- WIRESHARK: ICMP ----------
    {
      title: "Wireshark — ICMP exfil filters",
      blocks: [
        { t: "table", head: ["Filter", "Shows"], rows: [
          ["icmp", "All ICMP traffic"],
          ["icmp.type == 8", "Echo requests (pings) only"],
          ["icmp.type == 8 and frame.len > 100", "Oversized ping payload — normal ping ≈ 74 bytes total"],
          ["icmp && data.len > 64", "Payload field itself over the typical filler size"],
          ["icmp.type == 13 || icmp.type == 14", "Timestamp request/reply — rare, often abused for covert channels"],
        ]},
        { t: "note", kind: "info", text: "Also watch for regular timing (beaconing) between the same src/dst pair — a real ping burst is short; a tunnel is a sustained, evenly-spaced stream." },
      ],
    },

    // ---------- WIRESHARK: SMB (bonus, not in the room) ----------
    {
      title: "Wireshark — SMB exfil filters",
      desc: "Not covered in the THM room — added since internal file shares are a common staging/exfil point before data leaves over DNS/HTTP/FTP.",
      blocks: [
        { t: "table", head: ["Filter", "Shows"], rows: [
          ["smb || smb2", "All SMB traffic (v1 and v2/v3)"],
          ["smb2.cmd == 5", "Tree Connect — share being mounted"],
          ["smb2.cmd == 8 && smb2.flags.response == 0", "Read requests — data being pulled off a share"],
          ["smb2.cmd == 9 && smb2.flags.response == 0", "Write requests — data being pushed onto a share (staging)"],
          ["smb2.filename contains \".zip\" || smb2.filename contains \".rar\"", "Archive staging — attacker bundling files before moving them out"],
          ["smb2.filename matches \"(?i)passw|secret|confidential\"", "Filenames matching sensitive-data keywords"],
        ]},
        { t: "note", kind: "warn", title: "why SMB matters for exfil hunts", text: "SMB itself rarely leaves the network, but it's the classic <b>staging</b> step — an attacker copies/archives sensitive files onto a reachable share, then moves them out over DNS/HTTP/ICMP/FTP. A burst of unusual SMB Writes/Reads right before a spike in one of those other protocols is a strong combined indicator." },
      ],
    },

    // ---------- WIRESHARK: HTTPS/TLS (bonus) ----------
    {
      title: "Wireshark — HTTPS/TLS exfil filters",
      desc: "Payload is encrypted — detection shifts to metadata (SNI, cert, size, timing).",
      blocks: [
        { t: "table", head: ["Filter", "Shows"], rows: [
          ["tls.handshake.extensions_server_name contains \"keyword\"", "SNI hostname — the one plaintext field in the TLS handshake"],
          ["tls.handshake.type == 1", "Client Hello — inventory every distinct destination host"],
          ["tls && frame.len > 1000", "Large encrypted application-data frames"],
          ["tls.handshake.extensions_server_name and ip.addr == x.x.x.x", "Map a suspicious IP back to the hostname it claimed"],
        ]},
        { t: "note", kind: "danger", title: "SNI is the pivot, not payload", text: "You can't read inside TLS application data without key material, but the <b>Client Hello SNI</b> field travels in cleartext and tells you exactly which hostname the connection is destined for — check it against your domain reputation/baseline the same way you'd check an HTTP <code>Host</code> header." },
      ],
    },

    // ---------- CROSS-PROTOCOL CHEAT TABLE ----------
    {
      title: "Frame-length thresholds — quick lookup",
      span2: true,
      blocks: [
        { t: "table", head: ["Protocol", "Normal size", "Suspicious size", "Filter"], rows: [
          ["DNS query", "< 70 bytes", "> 70 bytes", "dns && frame.len > 70"],
          ["FTP", "varies", "> 90 bytes", "ftp && frame.len > 90"],
          ["HTTP POST", "< 500 bytes", "> 750 bytes", "http.request.method == \"POST\" and frame.len > 750"],
          ["ICMP echo", "~74 bytes total", "> 100 bytes", "icmp.type == 8 and frame.len > 100"],
          ["TLS app data", "varies", "> 1000 bytes, repeated", "tls && frame.len > 1000"],
        ]},
        { t: "note", kind: "info", text: "Thresholds are starting points, not hard rules — always compare against this network's own baseline before calling something anomalous." },
      ],
    },
  ],
};
