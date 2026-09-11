export default {
  id: "zeek-zui-triage",
  title: "Zeek Log Triage with Zui (Zed)",
  src: "HTB Sherlock: Trojan",
  icon: "🦓",
  cards: [
    {
      title: "What Zui actually is",
      span2: true,
      blocks: [
        { t: "txt", text: "Zui (formerly Brim) is a GUI over the <b>Zed</b> query language and a local Zed lake. Drop a pcap in and it runs Zeek against it automatically, producing the standard log set — <code>conn</code>, <code>http</code>, <code>dns</code>, <code>files</code>, <code>ssl</code> — all queryable from one place instead of digging through raw <code>.log</code> files by hand." },
        { t: "table", head: ["Log (_path)", "What it answers"], rows: [
          ["conn", "every connection tuple — who talked to whom, when, how much data, how long"],
          ["http", "HTTP <b>requests</b> — method, host, URI. Confirms a request happened, not that a file was transferred"],
          ["dns", "resolutions — what domain resolved to what IP, when"],
          ["files", "actual <b>file objects</b> Zeek's file-analysis framework extracted from any protocol — mime type, size, a real filename only if the server sent <code>Content-Disposition</code>"],
          ["ssl", "TLS handshake metadata — SNI, cert subject/issuer, JA3 if enabled"],
        ]},
        { t: "note", kind: "warn", title: "http.log ≠ files.log", text: "<code>http.log</code>'s <code>uri</code> field is only the <b>request target</b> (<code>/default/puk.php</code>). <code>files.log</code>'s <code>filename</code> field only populates from an actual <code>Content-Disposition</code> header in the response — a completely different transaction can carry the real payload name. Don't assume both logs answer \"what file was downloaded\" the same way; check both when a task/investigation asks for a downloaded file's name." },
      ],
    },
    {
      title: "Beacon/C2 hunting — dedup by count",
      span2: true,
      blocks: [
        { t: "cmd", label: "collapse repeated beacon hits down to unique URL/IP pairs, with hit counts", code: "_path==\"http\" and (id.resp_h==45.12.253.75 or id.resp_h==45.12.253.72) | count() by id.resp_h, uri | sort id.resp_h" },
        { t: "note", kind: "info", title: "why count() by", text: "A persistent beacon can fire dozens of times in a small capture — scrolling raw rows hides the pattern. Grouping by destination + URI turns 150+ noisy rows into a handful of unique endpoints, each annotated with how many times it fired. Even, tight-interval counts (e.g. every 4-5 seconds) are the beaconing tell itself." },
        { t: "cmd", label: "find the earliest activity in a capture (pools default to newest-first)", code: "_path==\"http\" | cut ts, id.orig_h, id.resp_h, host, uri, method, resp_mime_types | sort ts" },
        { t: "note", kind: "ok", title: "named file transfers only", text: "Skip the noise and jump straight to responses that actually carried a named file object:" },
        { t: "cmd", code: "_path==\"files\" and filename!=null | cut ts, filename, mime_type, seen_bytes, total_bytes, source" },
      ],
    },
    {
      title: "Type-strict fields — the silent-zero-rows trap",
      span2: true,
      blocks: [
        { t: "note", kind: "danger", title: "id.resp_h / id.orig_h are a native ip type", text: "Zed is strictly typed. Comparing an <code>ip</code>-typed field against a <b>quoted string</b> literal never matches — <b>and produces no error</b>, just a silently empty result that looks exactly like \"my filter is wrong.\"" },
        { t: "cmd", label: "wrong — silently returns nothing", code: "id.resp_h==\"45.12.253.75\"" },
        { t: "cmd", label: "correct — unquoted IP literal", code: "id.resp_h==45.12.253.75" },
        { t: "note", kind: "info", text: "Same failure shape as an unscoped Splunk search or a misnormalized SIEM field (see Query Language Gotchas) — always suspect a type/schema mismatch before assuming the data genuinely isn't there." },
      ],
    },
  ],
};
