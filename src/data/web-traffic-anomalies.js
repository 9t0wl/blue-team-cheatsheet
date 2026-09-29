export default {
  id: "web-traffic-anomalies",
  title: "Wireshark — HTTP Fuzzing, Header Abuse, XSS & TLS Renegotiation",
  src: "Wireshark: Intermediate Network Traffic Analysis",
  icon: "🌐",
  cards: [
    {
      title: "Directory / parameter fuzzing",
      blocks: [
        { t: "txt", text: "Attackers fire a wordlist of guessed paths and read the status codes. Tell: <b>one host, very fast, mostly 404</b>. A 403 or 200 among the 404s means the wordlist found something." },
        { t: "cmd", label: "requests only (hides server replies, good for counting)", code: "http.request.method" },
        { t: "cmd", label: "one host's web traffic", code: "http.request and ((ip.src_host == <ip>) or (ip.dst_host == <ip>))" },
        { t: "cmd", label: "same evidence in the Apache access log", code: "awk '$1 == \"<ip>\"' access.log\nawk '$9 == 404 {print $1}' access.log | sort | uniq -c | sort -rn" },
        { t: "note", kind: "warn", title: "evasion", text: "Staggering requests over time or spreading across many source IPs beats per-IP thresholds. Correlate by behavior: same wordlist order, same user-agent, same timing." },
        { t: "note", kind: "info", title: "fingerprints", text: "An ancient user agent (<code>Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)</code>) plus junk probes like <code>/randomfile1</code> and <code>/frand2</code> resemble dirb defaults. Parameter fuzzing (sequential IDs, IDOR hunting) looks like <code>id=1,2,3...</code> with errors on the missing ones." },
      ],
    },
    {
      title: "Host header abuse",
      blocks: [
        { t: "txt", text: "The <code>Host:</code> header selects the virtual host. Attackers set it to <code>127.0.0.1</code>, <code>localhost</code> or <code>admin</code> to reach internal vhosts, often through Burp." },
        { t: "cmd", label: "every request whose Host is not the real server", code: "http.request and (!(http.host == \"<server-ip-or-domain>\"))" },
        { t: "note", kind: "ok", text: "Fix: correct virtualhost config (no catch-all exposing internal sites) and a patched server." },
      ],
    },
    {
      title: "400s, CRLF injection & request smuggling",
      span2: true,
      blocks: [
        { t: "cmd", label: "bad-request responses (a cluster from one client is the lead)", code: "http.response.code == 400" },
        { t: "txt", text: "<code>%0d%0a</code> is URL-encoded CR+LF. Hidden in a parameter that a server pastes into a proxied request, it splits one request into two; the second reaches an internal service (for example <code>/uploads/cmd2.php</code> with <code>Host: 127.0.0.1:8080</code>)." },
        { t: "cmd", label: "the vulnerable Apache pattern (user input in a proxied URL)", code: "RewriteRule \"^/categories/(.*)\" \"http://192.168.10.100:8080/categories.php?id=$1\" [P]" },
        { t: "note", kind: "danger", title: "CVE-2023-25690", text: "Apache 2.4.0 through 2.4.55 with mod_proxy RewriteRule or ProxyPassMatch that puts user input into the proxied URL. Fixed in 2.4.56. Success looks like a <b>200</b> on the smuggled second request; 400s are usually rejections." },
        { t: "note", kind: "info", title: "read the banner", text: "In the course capture the 400 bodies said <code>Apache/2.4.57</code>, newer than the vulnerable range, so the 7 responses were most likely a patched server rejecting the attempts." },
      ],
    },
    {
      title: "XSS cookie exfiltration on the wire",
      blocks: [
        { t: "txt", text: "Stored XSS makes visitors' browsers run attacker JavaScript that reads <code>document.cookie</code> and sends it out. From the network it is <b>many user machines sending token-bearing GETs to one unknown host</b>, often on an odd port." },
        { t: "cmd", label: "look for the parameter and pivot to the unknown host", code: "http.request.uri contains \"cookie=\"" },
        { t: "note", kind: "warn", text: "Sloppy payloads leave artifacts (for example a doubled <code>cookie=?cookie=</code>). The listener often answers 404 because it only needs the request to arrive. Follow HTTP Stream to see it." },
        { t: "note", kind: "ok", title: "prevention", text: "Sanitize and encode user input, never interpret it as code, set <code>HttpOnly</code> on session cookies, and add a Content-Security-Policy. PHP one-liners planted through input (<code>system($_GET['cmd'])</code>) mean input is executed server-side." },
      ],
    },
    {
      title: "TLS renegotiation abuse",
      blocks: [
        { t: "txt", text: "Handshake messages stay visible even though data is encrypted. Renegotiation attacks re-run the expensive handshake repeatedly, mainly to exhaust the server." },
        { t: "cmd", label: "handshake records only", code: "tls.record.content_type == 22" },
        { t: "cmd", label: "Client Hello only", code: "tls.handshake.type == 1" },
        { t: "note", kind: "danger", title: "tells", text: "Many Client Hellos from one client in a very short window, and a Client Hello arriving after the handshake already completed. (Older Wireshark uses <code>ssl.*</code> names; still accepted as aliases.)" },
        { t: "note", kind: "info", title: "caveat", text: "A real TLS 1.2 renegotiation happens inside the encrypted session, so it would not show in the clear; TLS 1.3 removed it. Fix: disable client-initiated renegotiation, rate-limit handshakes, use TLS 1.3." },
      ],
    },
  ],
};
