export default {
  id: "ftp-analysis",
  title: "Wireshark — Cleartext Protocol Analysis: FTP",
  src: "Wireshark: Traffic Analysis",
  icon: "📂",
  cards: [
    {
      title: "Why FTP is a liability",
      blocks: [
        { t: "txt", text: "FTP optimizes for simplicity, not security — <b>everything is cleartext</b>: commands, arguments, and file contents. In an unsecured environment that opens the door to MITM, credential theft, phishing, malware planting, and data exfiltration." },
        { t: "cmd", label: "global", code: "ftp" },
      ],
    },
    {
      title: "Response code series — read the FIRST digit",
      span2: true,
      blocks: [
        { t: "table", head: ["Series", "Category", "Key codes"], rows: [
          ["1xx", "Information / request in progress", "211 System status · 212 Directory status · 213 File status"],
          ["2xx", "Connection messages", "220 Service ready · 227 Passive mode · 228 Long passive · 229 Extended passive"],
          ["3xx", "Authentication messages", "230 Login OK · 231 Logout · 331 Valid username · 430 Invalid user/pass · 530 No login/invalid password"],
        ]},
        { t: "note", kind: "info", text: "Same shape as HTTP status codes — first digit = category, exact code = specific meaning. <code>200</code> generically means \"command successful.\"" },
        { t: "cmd", label: "system status (1xx example)", code: "ftp.response.code == 211" },
        { t: "cmd", label: "entering passive mode (2xx example)", code: "ftp.response.code == 227" },
        { t: "cmd", label: "successful login (3xx example)", code: "ftp.response.code == 230" },
      ],
    },
    {
      title: "FTP commands — credentials ride in cleartext",
      blocks: [
        { t: "table", head: ["Command", "Meaning"], rows: [
          ["USER", "Username"], ["PASS", "Password"], ["CWD", "Change working directory"], ["LIST", "Directory listing"],
        ]},
        { t: "cmd", label: "username submitted", code: "ftp.request.command == \"USER\"" },
        { t: "cmd", label: "password submitted", code: "ftp.request.command == \"PASS\"" },
        { t: "cmd", label: "hunt a specific password value", code: "ftp.request.arg == \"password\"" },
        { t: "note", kind: "danger", text: "Because FTP auth is fully cleartext, a passive sniffer sees every <code>USER</code>/<code>PASS</code> pair directly — no MITM required, unlike the HTTP form-credential case." },
        { t: "note", kind: "ok", title: "Tools → Credentials WORKS here (unlike HTML forms)", text: "FTP is one of the protocols Wireshark's built-in <code>Tools → Credentials</code> harvester natively supports (alongside HTTP Basic Auth, IMAP, POP, SMTP) — it'll auto-list every <code>USER</code>/<code>PASS</code> pair with packet numbers, no manual filtering needed. Contrast with the ARP/MITM section, where the same tool came up completely <b>empty</b> against an HTML form login — that protocol isn't one of its supported types. Always check what the tool actually covers before trusting an empty result as \"no creds here.\"" },
        { t: "note", kind: "warn", title: "empty password submitted", text: "A <code>PASS</code> command with no argument (blank right after <code>PASS</code>) followed by <code>530 Login incorrect</code> is a literal empty-password attempt — visible directly in a <b>Follow TCP Stream</b> view of that session." },
      ],
    },
    {
      title: "Brute-force & password-spray signals",
      span2: true,
      blocks: [
        { t: "note", kind: "warn", title: "brute-force = many attempts, one username", text: "Same target account hit repeatedly with different passwords." },
        { t: "cmd", label: "all failed logins (530)", code: "ftp.response.code == 530" },
        { t: "cmd", label: "failed logins for one target username", code: "(ftp.response.code == 530) and (ftp.response.arg contains \"username\")" },
        { t: "note", kind: "warn", title: "password spray = one password, many usernames", text: "Inverse pattern — same static password tried across a set of accounts to dodge per-account lockout thresholds." },
        { t: "cmd", label: "one static password tried across accounts", code: "(ftp.request.command == \"PASS\") and (ftp.request.arg == \"password\")" },
        { t: "note", kind: "info", title: "telling the two apart", text: "Brute-force: filter on the <b>response</b> (530) + a fixed <b>username</b>. Password spray: filter on the <b>request</b> (PASS command) + a fixed <b>password</b> value. Same failure mode, opposite pivot axis — mirrors the credential-hunting lesson from the ARP/MITM section (filter the field that defines the pattern, not just the protocol)." },
      ],
    },
  ],
};
