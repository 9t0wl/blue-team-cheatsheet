export default {
  id: "https-decrypt",
  title: "Wireshark — Decrypting HTTPS Traffic",
  src: "Wireshark: Traffic Analysis",
  icon: "🔓",
  cards: [
    {
      title: "Why HTTPS traffic looks different",
      blocks: [
        { t: "txt", text: "HTTPS wraps HTTP in TLS. Without the session keys, Wireshark can see the TCP/TLS record structure but <b>not</b> the URL, headers, or body — packets show up color-coded as encrypted TLS records, and Info just shows handshake/Application-Data labels instead of real content." },
        { t: "cmd", label: "core filters", code: "http.request        # all HTTP requests\ntls                  # global TLS search\ntls.handshake.type == 1   # Client Hello\ntls.handshake.type == 2   # Server Hello\nssdp                 # local service discovery — usually noise, filter it OUT" },
        { t: "note", kind: "info", title: "SSDP shows up as pre-handshake noise", text: "Simple Service Discovery Protocol (<code>M-SEARCH</code>) is local network device discovery, unrelated to the TLS session you're investigating. It clutters the early packets in a capture — exclude it with <code>!(ssdp)</code> when hunting handshakes." },
      ],
    },
    {
      title: "TLS handshake — Client/Server Hello, and the SNI leak",
      span2: true,
      blocks: [
        { t: "txt", text: "TLS has its own handshake, conceptually parallel to the TCP three-way handshake. The first two steps are <b>Client Hello</b> and <b>Server Hello</b> — useful even with zero decryption, because they reveal which IPs/domains are involved." },
        { t: "cmd", label: "Client Hello (who's initiating TLS to where)", code: "(http.request or tls.handshake.type == 1) and !(ssdp)" },
        { t: "cmd", label: "Server Hello (the response side)", code: "(http.request or tls.handshake.type == 2) and !(ssdp)" },
        { t: "note", kind: "danger", title: "SNI is NOT encrypted (the big free win)", text: "The <b>Server Name Indication</b> field in Client Hello — which tells the server which hostname the client wants — travels in <b>plaintext</b>, even over TLS 1.3. That means you can read <code>Client Hello (SNI=accounts.google.com)</code> directly off the wire, with zero keys, and enumerate every domain a host contacted just by filtering Client Hellos. You only need the key log file to see the actual <b>data exchanged</b>, not <b>who it was exchanged with</b>." },
        { t: "note", kind: "warn", title: "handshake shape you'll see in the packet list", text: "SSDP noise → TCP SYN/SYN-ACK → DNS resolution → TLS <b>Client Hello</b> (SNI visible) → <b>Server Hello, Change Cipher Spec</b> → encrypted <b>Application Data</b> streams." },
      ],
    },
    {
      title: "SSL/TLS key log files — the constraint that matters",
      span2: true,
      blocks: [
        { t: "note", kind: "danger", title: "you cannot retroactively decrypt", text: "Key pairs are generated <b>per session, at connection time</b>, inside the browser. If you didn't have key logging turned on <b>while the traffic was being captured</b>, there is no way to conjure the keys afterward — unlike every filter technique in this room, this one requires advance setup, not just cleverness after the fact." },
        { t: "txt", text: "To capture keys: set the <code>SSLKEYLOGFILE</code> environment variable to a file path <b>before</b> launching the browser (Chrome and Firefox both support this). The browser then appends each session's key material to that file as you browse — that file is your decryption key log." },
        { t: "note", kind: "info", title: "operational takeaway for a SOC", text: "This is exactly why enterprises rely on <b>TLS-terminating proxies / decrypting firewalls</b> at the perimeter rather than hoping an endpoint dumped its keys — you can't bolt key logging onto traffic you already captured blind." },
      ],
    },
    {
      title: "Applying the key log file in Wireshark",
      blocks: [
        { t: "steps", items: [
          "<b>Right-click</b> a TLS packet → Protocol Preferences → TLS → set the key log filename, <b>or</b>",
          "<code>Edit → Preferences → Protocols → TLS</code> → set <b>(Pre)-Master-Secret log filename</b> → Browse to your <code>SSLKEYLOGFILE</code> → OK.",
          "Wireshark re-processes the capture immediately — encrypted <code>Application Data</code> rows start showing real protocol detail (HTTP/HTTP2) instead of opaque TLS records.",
        ]},
        { t: "note", kind: "ok", title: "new views that appear post-decryption", text: "The bytes pane gains extra tabs beyond the raw <b>Frame</b>: <b>Decrypted TLS</b>, <b>Decompressed Header</b>, <b>Reassembled TCP</b>, <b>Reassembled SSL</b> — each shows the data at a different stage of un-wrapping." },
      ],
    },
    {
      title: "What decryption reveals — HTTP/2 framing",
      desc: "Real structure visible once the key log file is applied.",
      span2: true,
      blocks: [
        { t: "txt", text: "Modern HTTPS is frequently <b>HTTP/2</b> underneath — binary-framed, multiplexed streams rather than plaintext request lines. Post-decryption, Wireshark parses these frame types directly:" },
        { t: "table", head: ["Frame type", "Meaning"], rows: [
          ["HEADERS[N]", "Request/response headers for stream N — e.g. GET /async/newtab_promos"],
          ["DATA[N]", "Body payload for stream N"],
          ["SETTINGS", "Connection-level HTTP/2 config negotiation"],
          ["WINDOW_UPDATE", "Flow-control credit — how much more data may be sent"],
          ["PING", "Keepalive / RTT measurement"],
        ]},
        { t: "note", kind: "info", text: "Before decryption, all of this is invisible — the frame just reads <code>Application Data</code>. After decryption, the exact same bytes resolve into a full HTTP/2 stream: which resource was requested, what came back, and the connection's live flow-control state." },
      ],
    },
  ],
};
