export default {
  id: "detecting-web-attacks",
  title: "Detecting Web Attacks",
  src: "Detecting Web Attacks",
  icon: "🕸️",
  cards: [
    {
      title: "Client-side vs server-side — where the exploit actually runs",
      blocks: [
        { t: "table", head: ["Class", "Runs where", "Examples"], rows: [
          ["Client-side", "inside the victim's browser", "XSS, CSRF, clickjacking"],
          ["Server-side", "on the app/server/backend", "brute force, SQL injection, command injection"],
        ]},
        { t: "note", kind: "danger", title: "the SOC visibility gap", text: "Server logs and network captures only see what crosses the wire. A client-side attack (e.g. a hidden iframe stealing cookies in the background) can execute <b>entirely inside the browser sandbox</b> without generating an anomalous request — the traffic looks like a normal page load because, from the server's view, it is. Detection generally needs <b>browser-side controls or EDR</b>, not SOC log/network tooling — a structural blind spot, not a missing filter." },
        { t: "note", kind: "info", title: "why server-side is more catchable", text: "Every request a server processes leaves a trail — in access/error logs and on the wire. Server-side attacks are detectable <i>if you know where to look</i>, which is the rest of this room." },
      ],
    },
    {
      title: "Access log fields — what an anomaly in each signals",
      span2: true,
      blocks: [
        { t: "table", head: ["Field", "Suspicious pattern"], rows: [
          ["Client IP", "known-malicious or geographically unexpected"],
          ["Timestamp", "unusual hours, or many requests in a short burst"],
          ["Status code", "repeated 404s → directory/endpoint fuzzing"],
          ["Response size", "significantly smaller/larger than the page's normal baseline"],
          ["Referer", "doesn't fit the site's normal navigation flow"],
          ["User-Agent", "outdated browser strings, or tool signatures — sqlmap, wpscan, ffuf, hydra"],
        ]},
        { t: "note", kind: "warn", title: "log limitations", text: "Access logs record <i>that</i> a request happened (method, path, status) but generally <b>don't capture POST body content</b> — a login POST shows as <code>POST /login.php 302</code> with no visible credentials. GET query strings are usually logged; POST bodies usually aren't. This is exactly why network captures matter as a second source — Wireshark's Follow HTTP Stream reconstructs the full body." },
      ],
    },
    {
      title: "The canonical attack sequence — fuzz → brute force → SQLi",
      span2: true,
      blocks: [
        { t: "steps", items: [
          "<b>Directory/form fuzzing</b> (tool: <code>ffuf</code>) — burst of requests to many paths, mostly 404s, occasional 200s marking real endpoints found. Tell: high volume, low path reuse, tool-identifiable User-Agent.",
          "<b>Brute force</b> (tool: <code>hydra</code>) — repeated POSTs to the discovered login form, same path, varying credentials, until one POST returns <code>302 Found</code> instead of a failure code. <b>The redirect is the successful-login tell</b> — the app is sending the browser on to an authenticated page.",
          "<b>SQL injection</b> — once authenticated, a GET/POST to a form (e.g. <code>change_username.php</code>) carries a payload in the query string, e.g. <code>' OR 1=1 --</code>. If the log captures the full query string, the payload is visible in plaintext — no need to guess.",
        ]},
        { t: "note", kind: "info", title: "URL-decoding payloads", text: "SQLi payloads in a log line are often URL-encoded (%20, %27, %3D). CyberChef's <b>Magic</b> recipe auto-detects the encoding and picks URL Decode without needing to identify it manually first." },
      ],
    },
    {
      title: "Confirming the same sequence in Wireshark",
      blocks: [
        { t: "cmd", label: "isolate HTTP traffic", code: "http" },
        { t: "cmd", label: "narrow to the target host + suspicious UA", code: "ip.dst == 10.10.20.200 && http.user_agent" },
        { t: "steps", items: [
          "Find the brute-force POST sequence to the login form; the one with <b>302 Found</b> is the successful attempt.",
          "Right-click that packet → <b>Follow → HTTP Stream</b> to see the actual username/password submitted — not visible in access logs.",
          "Find the SQLi request (query string carries the payload); Follow HTTP Stream shows the <b>dumped table data</b> in the reassembled response body.",
        ]},
        { t: "note", kind: "info", title: "network capture > logs, with a catch", text: "Full headers, complete POST bodies, cookies, uploaded/downloaded files — genuinely more verbose than server logs. Blind spot: anything encrypted without the TLS keys (HTTPS/SSH). Unencrypted DB protocols (e.g. MySQL) can even be inspected directly in Wireshark, showing the query and the returned result set." },
      ],
    },
    {
      title: "Web Application Firewall (WAF) rule types",
      span2: true,
      blocks: [
        { t: "table", head: ["Rule type", "Description", "Example"], rows: [
          ["Block known patterns", "known malicious payloads/signatures", "block user agent containing \"sqlmap\""],
          ["Deny malicious sources", "IP reputation, threat intel, geoblocking", "block IPs from a recent botnet campaign"],
          ["Custom rules", "app-specific allow/deny logic", "allow only GET/POST to /login"],
          ["Rate limiting", "cap request frequency per IP", "limit login attempts to 5/min/IP — blunts brute force"],
        ]},
        { t: "cmd", label: "rule syntax pattern", code: "IF user_agent CONTAINS \"sqlmap\" THEN block" },
        { t: "note", kind: "warn", title: "challenge-response as a middle tier", text: "WAFs don't have to hard-block — a CAPTCHA challenge distinguishes bot traffic from a real human without outright blocking a possible false positive. Relevant given <b>~37% of global web traffic is bot traffic</b> — naive hard-blocking risks real collateral damage." },
        { t: "note", kind: "info", title: "threat intel feeds > static rules", text: "Modern WAFs (e.g. Cloudflare) lean on continuously-updated malicious-IP lists sourced from botnets, VPN/anonymizer abuse, and malware C2 — rules update automatically for new CVEs and known APT infrastructure, rather than an analyst hand-maintaining every blocklist entry." },
      ],
    },
  ],
};
