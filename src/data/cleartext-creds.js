export default {
  id: "cleartext-creds",
  title: "Bonus — Hunting Cleartext Credentials (Tools → Credentials)",
  src: "Wireshark: Traffic Analysis (room capstone)",
  icon: "🔑",
  cards: [
    {
      title: "Why this exists — packets hide the pattern, a list reveals it",
      span2: true,
      blocks: [
        { t: "txt", text: "Wireshark is not an IDS — it surfaces suggestions via Expert Info, but doesn't decide for you. Cleartext credential hunting is a good example of why: at the packet level, a brute-force attempt and a user who fat-fingered their password twice look almost identical. The fix isn't a smarter filter — it's viewing every credential entry as a <b>list</b> instead of scattered across individual packets, which is exactly what this feature does." },
        { t: "cmd", label: "menu path", code: "Tools → Credentials" },
        { t: "note", kind: "danger", title: "version + protocol gate", text: "Requires <b>Wireshark v3.1+</b>. Only works for dissectors specifically programmed to extract cleartext credentials: <b>FTP, HTTP, IMAP, POP, SMTP</b>. For HTTP, that means <b>Basic Auth</b> headers specifically — <b>not</b> arbitrary HTML form logins (confirmed empirically in the ARP/MITM section: this tool came up completely empty against a vulnweb form-based login, because forms aren't one of its structured, known credential fields)." },
        { t: "note", kind: "warn", title: "don't fully rely on it", text: "Because coverage is limited to those five protocols, treat this as a fast triage step, not a guarantee of completeness. A protocol outside that list (or an HTML form on HTTP) can carry cleartext credentials this tool will never show — hunt those manually (e.g. <code>urlencoded-form.key == pass</code>, covered in the ARP/MITM section)." },
      ],
    },
    {
      title: "Reading the Credentials window",
      blocks: [
        { t: "table", head: ["Column", "Meaning"], rows: [
          ["Packet No.", "The packet containing the PASSWORD — click it to jump straight there"],
          ["Protocol", "Which dissector extracted it (FTP/HTTP/IMAP/POP/SMTP)"],
          ["Username", "The account name — clickable, jumps to the packet containing the username"],
          ["Additional Info", "Tells you the packet number the USERNAME appeared in (since USER/PASS are separate packets in FTP, and analogous separate messages in other protocols)"],
        ]},
        { t: "note", kind: "info", title: "two different packet numbers, one row", text: "The row's own \"Packet No.\" is where the <b>password</b> landed; \"Additional Info\" points at the <b>earlier</b> packet where the <b>username</b> was submitted. They're rarely the same packet — don't assume the row number covers both halves of the login." },
      ],
    },
    {
      title: "Worked example — Bonus-exercise.pcap",
      span2: true,
      blocks: [
        { t: "txt", text: "Credentials list showed a clear pattern: repeated <code>admin</code> attempts across packets 41→126, then a shift to <code>administrator</code> from 170 onward, then one lone HTTP credential later. That username progression — same target service, escalating/rotating usernames over dozens of packets — is a brute-force/enumeration signal, not coincidence." },
        { t: "cmd", label: "confirm via Follow TCP Stream", code: "220 FTP Service\nUSER administrator\n331 Password required for administrator.\nPASS\n530 Login incorrect." },
        { t: "note", kind: "ok", title: "spotting an empty password", text: "A bare <code>PASS</code> line with nothing after it, followed by <code>530 Login incorrect</code>, is a literal empty-password submission — easiest to confirm by reading the full exchange in <b>Follow → TCP Stream</b> rather than parsing individual PASS packets." },
      ],
    },
  ],
};
