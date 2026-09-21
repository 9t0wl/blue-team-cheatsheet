export default {
  id: "file-db-artifact-recovery",
  title: "Structured File & Artifact Recovery (InnoDB, MFT, RDP Logon Pairs)",
  src: "Jinkies (HTB Sherlock, CDSA Prep Track)",
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
  ],
};
