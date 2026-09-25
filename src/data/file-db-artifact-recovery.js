export default {
  id: "file-db-artifact-recovery",
  title: "Structured File & Artifact Recovery (InnoDB, MFT, RDP Logon Pairs, Timestomping)",
  src: "Jinkies + Detroit Becomes Human (HTB Sherlocks, CDSA Prep Track)",
  icon: "🗃️",
  cards: [
    {
      title: "Counting rows in a raw .ibd (InnoDB) dump — strings lies in both directions at once",
      span2: true,
      blocks: [
        { t: "txt", text: "A MySQL/MariaDB <code>.ibd</code> tablespace file often has plaintext row data readable directly via <code>strings</code>, but counting real rows by grepping that output is unreliable two different ways simultaneously." },
        { t: "table", head: ["Naive method", "Failure mode"], rows: [
          ["<code>strings f | grep -c '@domain.com'</code> (narrow pattern)", "<b>Undercounts</b> — some records get fragmented across InnoDB page boundaries (checksum/pointer bytes interrupt the printable run), so that row's string never fully matches the pattern"],
          ["<code>strings f | wc -l</code> (raw line count)", "<b>Overcounts</b> — inflated by repeated structural noise: <code>infimum</code>/<code>supremum</code> page-boundary pseudo-records appear once per leaf page, plus B-tree page-directory key duplicates"],
        ]},
        { t: "note", kind: "ok", title: "the authoritative fix — parse the actual page headers", text: "InnoDB pages are (almost always) a fixed <b>16384 bytes</b>. Per page, big-endian offsets: <b>24-25</b> = page type (<code>0x45BF</code>/17855 = INDEX), <b>54-55</b> = <code>PAGE_N_RECS</code> (record count on that page), <b>64-65</b> = <code>PAGE_LEVEL</code> (0 = leaf/real rows, &gt;0 = internal/root page holding only child-pointer entries, not data). Sum <code>PAGE_N_RECS</code> across <b>leaf pages only</b> — a root/internal page's \"records\" are B-tree navigation pointers, not user rows." },
        { t: "note", kind: "warn", title: "cheap sanity check before reaching for page parsing", text: "Compare <code>strings f | wc -l</code> against <code>strings f | grep -c '&lt;pattern&gt;'</code>. If they disagree wildly, one direction is inflated by repetition and the other deflated by fragmentation — that gap itself is the signal something needs the authoritative (page-header) method, not a third guess at a better regex." },
      ],
    },
    {
      title: "RDP + NLA logs two separate 4624 events, one second apart, different Logon Types",
      span2: true,
      blocks: [
        { t: "table", head: ["Logon Type", "Name", "What it actually means here"], rows: [
          ["2", "Interactive", "The NLA pre-authentication handshake — processed locally by LSASS <i>before</i> the network session exists, so <code>IpAddress</code>/<code>RemoteHost</code> shows loopback (<code>127.0.0.1</code>/<code>::1</code>) even though the real connection is remote"],
          ["10", "RemoteInteractive", "The fully established RDP session, logged ~1 second later — <b>this</b> event carries the attacker's genuine source IP"],
        ]},
        { t: "note", kind: "danger", title: "the trap", text: "Stopping at the bare Type 2 event either misreads it as local console access, or loses the real attacker IP entirely by never checking for the Type 10 that follows. Pattern to recognize: Type 2 (loopback) immediately followed by Type 10 (real IP), same account/host, ~1 second apart = one NLA-enabled RDP connection, not two separate logons." },
        { t: "note", kind: "info", title: "expected noise at the same timestamp", text: "Every interactive session (Type 2 or 10) auto-spawns companion <code>UMFD-N</code> (Font Driver Host) and <code>DWM-N</code> (Desktop Window Manager) logons at the identical second — rendering-session plumbing, not separate activity. Expect a burst of 3-4 <code>4624</code> events sharing one timestamp per real logon." },
        { t: "note", kind: "warn", title: "machine-account filter trap", text: "A host named e.g. <code>VELMAD100</code> has a machine account <code>VELMAD100$</code> — a naive <code>TargetUserName contains &lt;username&gt;</code> filter can match the hostname-derived machine account and pull in a wall of routine Type 5 (Service) boot noise instead of the real user's logon. Use an <b>exact match</b> on the username." },
      ],
    },
    {
      title: "Recovering a file KAPE never collected — NTFS resident attributes inside the MFT",
      span2: true,
      blocks: [
        { t: "txt", text: "Targeted triage tools (KAPE and similar) collect designated forensic artifact types, not arbitrary user files. A <code>.lnk</code> shortcut pointing at something interesting doesn't mean the target file's content survived collection — <b>unless it's small enough to be NTFS-resident.</b>" },
        { t: "note", kind: "ok", title: "the concept", text: "Files small enough (roughly under ~700-900 bytes, depending on the record's other attribute overhead) get their <code>$DATA</code> stored <b>directly inside their own MFT record</b> instead of on separate disk clusters (a \"resident\" attribute). Since <code>$MFT</code> is a core artifact collected wholesale regardless, the file's actual content can survive even though the file itself was never individually pulled." },
        { t: "steps", items: [
          "Get the file's <b>Entry Number</b> from MFT metadata (via MFTECmd output, LNK metadata correlation, or similar).",
          "MFT records are (almost always) a fixed <b>1024 bytes</b> each — the target record starts at byte offset <code>EntryNumber &times; 1024</code> inside the raw <code>$MFT</code> file.",
          "Read that 1024-byte range directly and decode as ASCII (replace non-printables) — no dedicated hex editor required.",
        ]},
        { t: "cmd", label: "PowerShell — direct byte-offset read against $MFT", code: "$mftPath = \"C:\\path\\to\\`$MFT\"\n$offset = <EntryNumber> * 1024\n$fs = [System.IO.File]::OpenRead($mftPath)\n$fs.Seek($offset, 'Begin') | Out-Null\n$buffer = New-Object byte[] 1024\n$fs.Read($buffer, 0, 1024) | Out-Null\n$fs.Close()\n[System.Text.Encoding]::ASCII.GetString($buffer) -replace '[^\\x20-\\x7E]', '.'" },
        { t: "note", kind: "warn", title: "the `$` in `$MFT` needs escaping in PowerShell", text: "Double-quoted strings interpolate <code>$MFT</code> as a variable reference and silently resolve to empty. Use a backtick (<code>`$MFT</code>) or single-quote the path segment." },
        { t: "note", kind: "info", title: "no $MFT in the collection, or the file is too big to be resident?", text: "This trick has two hard limits: it needs <code>$MFT</code> to have been collected, and it only works for files small enough to be resident. When either fails, the other place a missing file's <b>text</b> commonly survives is the Windows Search index — see <b>Windows Search Index Recovery (Windows.edb / ESE)</b>. Two different answers to the same question: \"the file wasn't collected, can I still read it?\"" },
      ],
    },
    {
      title: "MFTECmd --de <Entry>-<Sequence> — the tool-assisted way to dump one MFT record",
      span2: true,
      blocks: [
        { t: "txt", text: "Same resident-data concept as above, but instead of hand-rolling a byte-offset read, MFTECmd's <code>--de</code> flag dumps a single record's full attribute breakdown (parsed, not raw hex) directly to console — the every-day tool for this rather than a one-off script." },
        { t: "cmd", label: "Dump one record by Entry-Sequence", code: "MFTECmd.exe -f \"<triage>\\C\\`$MFT\" --de <EntryNumber>-<SequenceNumber>" },
        { t: "table", head: ["Attribute printed", "What it gives you"], rows: [
          ["<b>$STANDARD_INFO (0x10)</b>", "The fakeable timestamps — compare against 0x30 below for timestomping"],
          ["<b>$FILE_NAME (0x30)</b>", "Real timestamps + <code>Parent Entry-seq #</code>, a direct pointer to the parent directory's own MFT record"],
          ["<b>$DATA</b>", "If <code>Resident: True</code>, the actual file bytes as hex + ASCII, right there in the dump"],
        ]},
        { t: "note", kind: "ok", title: "the record header's Offset: field answers \"hex offset on the filesystem\" tasks directly", text: "The very first line of output (<code>Entry-seq #: 0x..., <b>Offset: 0x3E90C00</b></code>) is the literal byte offset of that FILE record <i>within the <code>$MFT</code> file itself</i>. A CTF-style \"what's the hex offset of this file\" question is usually just asking for this value, no raw disk math required." },
        { t: "note", kind: "warn", title: "-m is NOT the flag for this", text: "<code>-m</code> is for resolving <code>$J</code> (USN Journal) parent paths against a companion <code>$MFT</code> — a different use case entirely. Use <code>--de</code> to dump one record's own details." },
      ],
    },
    {
      title: "Timestomping detection: compare 0x10 vs 0x30, don't trust either one alone",
      span2: true,
      blocks: [
        { t: "txt", text: "Every file's <code>$STANDARD_INFORMATION</code> (0x10) and <code>$FILE_NAME</code> (0x30) attributes each carry their own set of four timestamps. Under normal operation they roughly agree. A mismatch, especially on Created, is one of the cheapest, most reliable timestomping signals available." },
        { t: "table", head: ["Attribute", "Who can trivially change it", "Where it's stored"], rows: [
          ["0x10 ($STANDARD_INFORMATION)", "Any process with normal file access — what Explorer/`dir` shows, and what timestomping tools like SetMace target", "Inside the file's own MFT record"],
          ["0x30 ($FILE_NAME)", "Only updated by the OS on create/rename/move — much harder to convincingly fake", "In the <i>parent directory's</i> index entry for the file"],
        ]},
        { t: "note", kind: "danger", title: "trust 0x30, and corroborate independently", text: "If 0x10 says January and 0x30 says March, the file was almost certainly timestomped and the true creation time is the 0x30 value. Corroborate it a third way when possible — an event log entry, a paired process's own timestamp, or third-party file metadata (e.g. a public sandbox report's \"Last Saved\" field) — agreement across independent sources is what turns a suspicion into a confirmed finding worth writing up." },
      ],
    },
    {
      title: "RBCmd (Recycle Bin) — console output silently converts to local time, CSV doesn't",
      blocks: [
        { t: "txt", text: "RBCmd parses a Recycle Bin <code>$I</code> metadata file (deleted-on timestamp, original path, size) from its paired <code>$R</code> content file. Straightforward — except for one silent gotcha in how it displays time." },
        { t: "cmd", label: "Parse one $I file", code: "RBCmd.exe -f \"<Recycle.Bin>\\<SID>\\$I<random>\" --csv \"<out>\" --csvf RecycleBin.csv" },
        { t: "note", kind: "danger", title: "console text ≠ CSV value", text: "Console output showed <code>2024-03-18 21:34:16</code> for a deletion; the CSV for the <i>same record</i> showed <code>2024-03-19 04:34:16</code> — a 7-hour gap. The console print silently converts to the analysis machine's local timezone; the CSV preserves true UTC. Always pull the timestamp from the structured CSV output, never trust the human-readable console text for anything timezone-sensitive." },
      ],
    },
    {
      title: "Blocked locally? Search a distinctive leaked filename before brute-forcing the blocker",
      blocks: [
        { t: "txt", text: "A password-protected archive doesn't always need its password recovered. If an internal filename leaks (a tool's own error message when it fails to extract, an install log, a registry Install Source path), and that filename is distinctive enough, search it directly before spending time on local password-recovery artifacts." },
        { t: "note", kind: "ok", title: "why this works", text: "Public sandboxes (ANY.RUN, Hybrid-Analysis, MalwareBazaar) index submitted samples by filename and hash. Even a sample from a custom/bespoke training scenario can turn out to have a public report already, complete with every hash pre-computed and file metadata that can independently corroborate other findings (e.g. a matching backdated timestamp)." },
        { t: "note", kind: "warn", title: "VirusTotal won't help with an encrypted archive", text: "VT can't open a password-protected archive any more than you can — it'll only confirm \"this is an encrypted RAR/ZIP\". The win here comes from the sample having been <i>previously extracted and analyzed by someone else</i>, not from VT's own static scan of the still-locked container." },
      ],
    },
  ],
};
