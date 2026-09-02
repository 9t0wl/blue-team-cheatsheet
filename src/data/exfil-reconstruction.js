export default {
  id: "exfil-reconstruction",
  title: "Exfil Reconstruction & Payload Recovery",
  src: "Boogeyman 1 (SOC L1 Capstone)",
  icon: "🧩",
  cards: [
    {
      title: "Detection ends where reconstruction begins",
      span2: true,
      blocks: [
        { t: "txt", text: "The <b>Tunnelling</b> and <b>Data Exfiltration</b> sections above answer <i>\"is data leaving?\"</i>. This section answers the next question the IR lead actually asks: <b>\"what exactly left, and can you show me the contents?\"</b> Same PCAP, different job — you're rebuilding the original file byte-for-byte out of the carrier protocol." },
        { t: "steps", steps: [
          "Identify the carrier (DNS query names, HTTP POST bodies, ICMP payloads) and the C2 IP.",
          "Isolate <b>only</b> the packets carrying payload — this filtering step is where reconstruction usually fails.",
          "Strip the carrier framing so you're left with a single unbroken encoded string.",
          "Reverse the encoding layers in the right order (hex → binary, base64 → text, decimal → ASCII).",
          "Open the recovered artifact with its native tool to prove impact.",
        ]},
      ],
    },

    // ---------- THE DNS → FILE ONE-LINER ----------
    {
      title: "Rebuild a file out of DNS exfil queries",
      span2: true,
      blocks: [
        { t: "txt", text: "The attacker hexes a file, splits it into fixed-width chunks, and sends each chunk as a subdomain label in an <code>nslookup</code> query. Every chunk is sitting in the PCAP in order — the whole file is recoverable." },
        { t: "cmd", label: "full chain — PCAP to opened file", code: "tshark -r capture.pcapng -Y \"ip.dst==<C2_IP> and dns\" -T fields -e dns.qry.name \\\n  | grep -E '[A-F0-9]+.<domain>.xyz$' \\\n  | cut -d '.' -f1 \\\n  | tr -d '\\n' \\\n  | xxd -p -r > recovered.kdbx" },
        { t: "table", head: ["Stage", "Does what"], rows: [
          ["tshark -Y \"ip.dst==C2 and dns\"", "Only queries heading to the attacker's nameserver"],
          ["-T fields -e dns.qry.name", "Strip packet framing, print the query name alone"],
          ["grep -E '...xyz$'", "Keep only the clean query — <b>the $ anchor is the whole trick</b>"],
          ["cut -d '.' -f1", "Take the first label = the hex chunk"],
          ["tr -d '\\n'", "Join every chunk into one continuous hex string"],
          ["xxd -p -r", "Reverse plain hex back to raw binary"],
        ]},
      ],
    },

    {
      title: "The gotcha that breaks this: resolver search-domain suffixes",
      span2: true,
      blocks: [
        { t: "note", kind: "danger", title: "every chunk appears 3+ times, and dedup is the wrong fix", text: "A Windows host with DNS search domains configured retries each failed lookup with each suffix appended. One chunk therefore shows up as several distinct query names:" },
        { t: "cmd", label: "raw dns.qry.name output — same chunk, three rows", code: "03D9A29A...714350BE58.bpakcaging.xyz.eu-west-1.ec2-utilities.amazonaws.com\n03D9A29A...714350BE58.bpakcaging.xyz.eu-west-1.compute.internal\n03D9A29A...714350BE58.bpakcaging.xyz" },
        { t: "note", kind: "warn", title: "why the obvious fixes fail", text: "Concatenating everything triples the file (KeePass reports <code>Unknown header ID / file header is corrupted</code>). A regex like <code>-oE '[A-Fa-f0-9]{40,}'</code> doesn't help — it still matches the leading hex on all three rows. Deduplicating with a <code>seen</code> set <i>also</i> silently corrupts the file if the payload legitimately repeats a chunk." },
        { t: "note", kind: "ok", title: "the correct fix", text: "Anchor the grep with <code>$</code> so only the bare, un-suffixed query survives. That keeps exactly one row per chunk <b>and</b> preserves capture order for free — no dedup, no sorting, no timestamp juggling." },
        { t: "note", kind: "info", title: "also drop the backslash-escaped dots", text: "<code>'[A-F0-9]+\\.domain\\.xyz$'</code> was too strict in practice; the unescaped <code>'[A-F0-9]+.domain.xyz$'</code> matched. The <code>.</code> as any-char is harmless here because the anchor already pins the tail." },
        { t: "cmd", label: "sanity-check before you celebrate", code: "ls -lh recovered.kdbx\nfile recovered.kdbx        # should name the real format, not 'data'\nxxd recovered.kdbx | head  # KDBX magic = 03 D9 A2 9A" },
      ],
    },

    // ---------- ENCODING LAYERS ----------
    {
      title: "Encoding layers — know which one you're looking at",
      span2: true,
      blocks: [
        { t: "table", head: ["Looks like", "Encoding", "Reverse it with"], rows: [
          ["<code>03D9A29A67FB4BB5...</code> (0-9 A-F only)", "Hex", "<code>xxd -p -r</code> / CyberChef <i>From Hex</i>"],
          ["<code>92 105 100 61 56...</code> (space-separated ints &lt;256)", "Decimal ASCII", "CyberChef <i>From Decimal</i> / Python <code>chr()</code>"],
          ["<code>SQBFAFgAIAAoAG4A...</code> (mixed case, <code>=</code> padding)", "Base64", "<code>base64 -d</code>"],
          ["Base64 that decodes to text with <code>NUL</code> between letters", "Base64 + UTF-16LE", "<code>base64 -d | iconv -f UTF-16LE -t UTF-8</code>"],
        ]},
        { t: "note", kind: "danger", title: "PowerShell -enc is always UTF-16LE", text: "A plain <code>base64 -d</code> on a <code>powershell -enc</code> blob gives you <code>I.E.X. .(.n.e.w.-.o.b.j.e.c.t.</code> — readable but full of null bytes, and it breaks any downstream grep. Always pipe through <code>iconv -f UTF-16LE -t UTF-8</code>, or pick <b>Decode text → UTF-16LE (1200)</b> in CyberChef." },
        { t: "note", kind: "warn", title: "font ambiguity in recovered credentials", text: "A recovered password rendered in a proportional/UI font can't distinguish <code>1</code> / <code>l</code> / <code>I</code> or <code>0</code> / <code>O</code>. Decode to raw bytes and read the numeric codes instead of trusting the glyph — <code>108</code> is lowercase <code>l</code>, <code>49</code> is the digit <code>1</code>. Chasing the wrong glyph looks exactly like a wrong password." },
      ],
    },

    // ---------- HTTP C2 OUTPUT ----------
    {
      title: "Recovering command output from an HTTP C2 channel",
      blocks: [
        { t: "txt", text: "A polling beacon splits its traffic across two endpoints on the same host. Follow the pair and you get the attacker's console, both sides." },
        { t: "table", head: ["Request", "Carries"], rows: [
          ["<code>GET /&lt;task-id&gt;</code>", "The tasking — the command the operator queued"],
          ["<code>POST /&lt;output-id&gt;</code>", "The result — stdout of that command, often encoded"],
        ]},
        { t: "cmd", label: "list every stream to the C2, then follow one", code: "tshark -r capture.pcapng -Y \"ip.addr==<C2_IP> and tcp\" -T fields -e tcp.stream | sort -un\ntshark -r capture.pcapng -q -z follow,tcp,ascii,<N>" },
        { t: "note", kind: "ok", title: "the command and its output are adjacent streams", text: "Find the stream holding the <code>GET</code> that shows the command, then read the <b>next</b> stream number — that's almost always the matching <code>POST</code> with the output. Cheaper than grepping the whole capture." },
        { t: "note", kind: "info", title: "split headers from body", text: "<code>follow,tcp,ascii</code> hands you headers <i>and</i> body. Cut on the first blank line (<code>\\r\\n\\r\\n</code>) before decoding, or the header text pollutes your decode." },
      ],
    },

    {
      title: "Wireshark route (when you'd rather click)",
      blocks: [
        { t: "steps", steps: [
          "Filter on a known artifact name — e.g. <code>frame contains \"sq3.exe\"</code>.",
          "Right-click the hit → <b>Follow → HTTP Stream</b> to read the tasking.",
          "Bump the <b>Stream</b> spinner by one to land on the matching output POST.",
          "Select the encoded body, copy, and paste into CyberChef to decode.",
        ]},
        { t: "note", kind: "info", text: "Useful when you're still orienting. Once you know which streams matter, the tshark one-liners above are faster and reproducible in a report." },
      ],
    },

    // ---------- POWERSHELL LOG PARSING ----------
    {
      title: "Parsing PowerShell logs with jq",
      span2: true,
      blocks: [
        { t: "txt", text: "EVTX converted to JSON (via <code>evtx2json</code>) makes the whole attack chain greppable. The field carrying executed code is <code>ScriptBlockText</code>." },
        { t: "cmd", label: "beautify / orient", code: "cat powershell.json | jq ." },
        { t: "cmd", label: "chronological command timeline — the money query", code: "cat powershell.json | jq -r 'select(.ScriptBlockText) | .ScriptBlockText' | sort -u" },
        { t: "cmd", label: "sort by timestamp, print two fields", code: "cat powershell.json | jq -r '. | \"\\(.EventTime) \\(.ScriptBlockText)\"' | sort" },
        { t: "cmd", label: "hunt a specific tool or path", code: "cat powershell.json | jq -r '.ScriptBlockText' | grep -iE 'sq3|\\.kdbx|nslookup|invoke-webrequest'" },
        { t: "cmd", label: "pull the encoded payloads only", code: "grep -oE '\\-[eE]nc(odedCommand)? +[A-Za-z0-9+/=]{40,}' powershell.json | awk '{print $2}' | sort -u" },
        { t: "note", kind: "warn", title: "anchor base64 regexes to the flag", text: "A bare <code>[A-Za-z0-9+/=]{60,}</code> hunt across the log matches URL fragments, GUIDs and hashes, and you'll waste time decoding garbage. Anchor on <code>-enc</code>/<code>-EncodedCommand</code> so you only pull real payloads." },
        { t: "note", kind: "info", title: "reassemble relative paths from cd", text: "Logged commands often use paths relative to a working directory set earlier. Track the <code>cd</code> / <code>Set-Location</code> calls and prefix them back on before reporting a full path." },
        { t: "note", kind: "danger", title: "the file may be JSONL, not JSON", text: "<code>json.load()</code> failing with <code>Extra data: line 2 column 1</code> means one object per line, not one array. Iterate lines with <code>json.loads(line)</code>, or just use <code>jq</code>, which handles both."},
      ],
    },

    // ---------- CREDENTIAL STORES ----------
    {
      title: "Credential stores worth checking on a compromised host",
      span2: true,
      blocks: [
        { t: "table", head: ["Store", "Path / artifact", "Why attackers hit it"], rows: [
          ["Microsoft Sticky Notes", "<code>%LOCALAPPDATA%\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite</code>", "Plain SQLite, <b>no encryption</b> — users paste passwords into it"],
          ["KeePass", "<code>*.kdbx</code>", "One master password unlocks every stored credential"],
          ["Browser profiles", "<code>Login Data</code> (SQLite)", "Saved logins, DPAPI-protected but local-decryptable"],
          ["Credential Manager", "<code>%APPDATA%\\Microsoft\\Credentials</code>", "Cached domain / RDP creds"],
        ]},
        { t: "cmd", label: "query Sticky Notes directly", code: "sqlite3 plum.sqlite \"SELECT * FROM NOTE LIMIT 100;\"" },
        { t: "note", kind: "danger", title: "the chain that makes this bite", text: "Sticky Notes is unencrypted, so a note holding a KeePass master password converts a hardened vault into a single-hop compromise. Attacker reads plum.sqlite → gets the master password → exfiltrates the .kdbx → opens every credential offline. <b>Both halves are needed, and both are recoverable from the PCAP.</b>" },
        { t: "note", kind: "ok", title: "detection angle", text: "Alert on any non-<code>StickyNotes.exe</code> process opening <code>plum.sqlite</code>, and on portable SQLite binaries (<code>sq3.exe</code>, <code>sqlite3.exe</code>) written into user-writable dirs like <code>\\Music\\</code> or <code>\\Public\\</code>." },
        { t: "note", kind: "danger", title: "scoping a vault breach: read the custom fields, not the columns", text: "KeePass entries carry arbitrary <b>custom string fields</b> that never appear as columns in the entry list — the list shows Title / User Name / Password / URL / Notes and nothing else. A single \"Company Card\" entry can hold <code>Account Number</code>, <code>CVV</code>, <code>Expiration Date</code> and the issuing org in custom fields while its Password column shows only <code>••••••••</code>. Open <b>Entry → Edit → Advanced</b> (or read the status-bar summary line for the selected entry) before writing the impact assessment, or you will materially undercount what was stolen." },
      ],
    },

    // ---------- LNK ----------
    {
      title: "LNK attachments — the phishing delivery step",
      blocks: [
        { t: "cmd", label: "dump the shortcut's metadata", code: "lnkparse Invoice_20230113.lnk\nlnkparse Invoice_20230113.lnk > parsed.txt   # then grep it" },
        { t: "table", head: ["Field", "What it gives you"], rows: [
          ["Command line arguments", "The embedded payload — usually the encoded PowerShell"],
          ["Relative path / icon", "What it masquerades as (<code>powershell.exe</code> wearing a PDF icon)"],
          ["Machine ID / MAC / droid", "Build-host artifacts — pivot across campaigns"],
        ]},
        { t: "note", kind: "warn", title: "grep case-sensitively at your peril", text: "The field is <code>Command line arguments</code> — one capital. A lowercase grep for <code>command</code> returns nothing and it looks like the field is absent." },
        { t: "note", kind: "danger", title: "password-protected archive + password in the email body", text: "A classic pairing: the password defeats gateway AV scanning of the archive, but including it in the same message is itself a high-fidelity phishing indicator. Alert on it." },
      ],
    },

    // ---------- WORKED EXAMPLE ----------
    {
      title: "Worked example — the Boogeyman 1 chain end to end",
      span2: true,
      blocks: [
        { t: "steps", steps: [
          "<b>Delivery</b> — phishing mail from a lookalike domain, password-protected ZIP, password in the body.",
          "<b>Execution</b> — LNK runs <code>powershell -enc</code>; decoded (UTF-16LE) it's an <code>IEX (New-Object Net.WebClient).DownloadString()</code> stager.",
          "<b>C2</b> — beacon polls the staging host on :8080, <code>GET</code> for tasking / <code>POST</code> for output.",
          "<b>Discovery</b> — Seatbelt pulled from the file-hosting subdomain and run for host enumeration.",
          "<b>Credential access</b> — <code>sq3.exe</code> dropped to a user-writable dir, queries <code>plum.sqlite</code>; a Sticky Note holds the KeePass master password.",
          "<b>Collection</b> — the <code>.kdbx</code> is read from the user's Documents folder.",
          "<b>Exfiltration</b> — file hexed, chunked, and pushed out chunk-by-chunk as <code>nslookup</code> queries to the attacker's nameserver.",
        ]},
        { t: "note", kind: "info", title: "two subdomains, two jobs", text: "Splitting <code>files.</code> (Python <code>http.server</code> staging) from <code>cdn.</code> (the C2 listener) is deliberate — it keeps tool downloads out of the beacon channel and survives one of the two being blocked. When you find one malicious subdomain, always enumerate its siblings." },
        { t: "note", kind: "ok", title: "what makes the whole chain reconstructable", text: "Nothing here was encrypted in transit — hex and base64 are <i>encoding</i>, not encryption. Full packet capture plus PowerShell script-block logging is enough to replay the intrusion and recover the stolen artifact." },
      ],
    },

    // ---------- DETECTION SUMMARY ----------
    {
      title: "Detections this chain hands you for free",
      span2: true,
      blocks: [
        { t: "table", head: ["Signal", "Rule shape"], rows: [
          ["Sustained NXDOMAIN burst to one parent domain", "Count unique subdomains per registrable domain per host, per hour"],
          ["<code>nslookup</code> in a loop from a user session", "Process creation: nslookup with a non-interactive parent (PowerShell), high frequency"],
          ["Hex-only DNS labels &gt; 40 chars", "<code>dns.qry.name.len &gt; 40</code> + label matches <code>^[A-F0-9]+$</code>"],
          ["<code>powershell -enc</code> from an Office/Explorer parent", "Process ancestry + <code>-enc</code>/<code>-EncodedCommand</code> in cmdline"],
          ["Portable SQLite binary in a user dir", "File create: <code>sq3.exe</code>/<code>sqlite3.exe</code> under <code>\\Users\\*\\(Music|Public|Downloads)\\</code>"],
          ["<code>plum.sqlite</code> opened by a foreign process", "File access where image != StickyNotes.exe"],
          ["<code>.kdbx</code> read followed by outbound DNS spike", "Correlate file-read on vault extensions with egress volume in the next N minutes"],
        ]},
        { t: "note", kind: "danger", title: "the control that actually stops it", text: "Egress DNS restricted to approved internal resolvers. Every step above still succeeds on the host — but a chunked-DNS channel to an attacker-controlled nameserver dies at the network edge, and the exfil never completes." },
      ],
    },
  ],
};
