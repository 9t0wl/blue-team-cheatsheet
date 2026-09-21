export default {
  id: "windows-search-index-recovery",
  title: "Windows Search Index Recovery (Windows.edb / ESE)",
  src: "Windows host forensics, KAPE triage casework",
  icon: "🔎",
  cards: [
    {
      title: "Windows Search indexes file CONTENT, not just filenames",
      span2: true,
      blocks: [
        { t: "txt", text: "For file types it understands, the Windows indexer <b>opens the file, extracts its text, and stores a preview</b> in a property called <code>System.Search.AutoSummary</code> inside <code>Windows.edb</code>. That preview is a copy, stored independently of the file itself." },
        { t: "note", kind: "ok", title: "why this matters in DFIR", text: "Delete the file, wipe the folder, or never collect it in the first place, and the indexed text is <b>still in the database</b> until the indexer re-crawls and notices. <code>Windows.edb</code> is effectively a content archive hiding inside a search feature, and it is routinely overlooked." },
        { t: "table", head: ["Path", "What it is"], rows: [
          ["<code>C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb</code>", "The index itself (ESE database). Windows 11 may instead use <code>Windows.db</code>, SQLite"],
          ["<code>edb.jtx</code>, <code>edb0000*.jtx</code>", "ESE transaction logs — committed data not yet written into the .edb"],
          ["<code>edb.jcp</code>", "Checkpoint file, tells recovery where to resume"],
          ["<code>GatherLogs\\SystemIndex\\*.gthr</code>, <code>*.Crwl</code>", "Crawler staging logs (mostly filenames, rarely useful for content)"],
        ]},
        { t: "note", kind: "info", title: "content indexing is filter-dependent", text: "Plaintext formats (<code>.txt</code>, <code>.csv</code>, <code>.log</code>) and Office documents are content-indexed out of the box. PDFs need an installed iFilter. If a file type has no filter, only its <i>properties</i> (path, size, timestamps) get indexed, not its text." },
      ],
    },
    {
      title: "Three stacked obstacles, each producing a convincing false negative",
      span2: true,
      blocks: [
        { t: "txt", text: "Reading <code>AutoSummary</code> is not one problem, it is three. Each one independently returns \"nothing found\" in a way that looks like proof the data is absent." },
        { t: "table", head: ["#", "Obstacle", "How it lies to you"], rows: [
          ["1", "<b>Database is dirty</b> — captured live, so recent writes sit in <code>.jtx</code> transaction logs rather than the .edb", "Parsers either refuse to open it or silently return a stale view missing the most recent (often most relevant) records"],
          ["2", "<b>The field is LZ77-compressed</b> (UTF-16 literals plus back-reference tokens)", "<code>strings</code> and <code>grep</code> return <b>file paths only, never document text</b> — paths are stored as plain fields, content is not. Both ASCII and UTF-16LE come back empty"],
          ["3", "<b>ESE keeps large fields in a separate long-value tree</b>, not inline in the row", "<code>esedbexport</code> does not reliably export long-values, so <code>AutoSummary</code> renders as an <b>empty column</b> — which reads exactly like \"this document has no indexed content\""],
        ]},
        { t: "note", kind: "danger", title: "the meta-lesson, and the expensive one", text: "A tool returning nothing is only meaningful <b>if that tool is capable of finding the thing</b>. Obstacle 3 is evidence of absence that is really absence of capability. Before accepting a negative result, ask what the tool silently excludes, and confirm with a <b>second implementation</b> before concluding the data is gone." },
        { t: "note", kind: "warn", title: "same trap, different costume", text: "<code>strings</code> silently excludes UTF-16 unless you pass <code>-el</code>. <code>esedbexport</code> silently excludes ESE long-values. Both fail quietly rather than erroring, which is what makes them dangerous." },
      ],
    },
    {
      title: "Step 1 — replay the transaction logs with esentutl",
      blocks: [
        { t: "txt", text: "Same concept as replaying <code>SYSTEM.LOG1</code>/<code>LOG2</code> into a registry hive, just a different database engine. <code>esentutl</code> ships with Windows but is not on <code>PATH</code>." },
        { t: "note", kind: "warn", title: "copy to scratch first", text: "Triage tools mark collected files <b>read-only</b>, and <code>esentutl</code> writes in place. Copy the whole search folder somewhere writable and clear the read-only attribute, or recovery fails with <code>JET_errAccessDenied</code> partway through. Never run this against your only copy of the evidence." },
        { t: "cmd", label: "PowerShell — stage a writable copy", code: "$src = \"<triage>\\C\\ProgramData\\Microsoft\\search\\data\\applications\\windows\"\n$dst = \"<case>\\edb_recover\"\nNew-Item -ItemType Directory -Force $dst\nCopy-Item \"$src\\*\" $dst -Force\nGet-ChildItem $dst -File -Recurse | ForEach-Object { $_.IsReadOnly = $false }" },
        { t: "cmd", label: "Recover (run elevated, from inside $dst)", code: "C:\\Windows\\System32\\esentutl.exe /r edb /l . /s . /d ." },
        { t: "note", kind: "danger", title: "/d . is mandatory and non-obvious", text: "Without <code>/d .</code> recovery aborts with <code>JET_errAttachedDatabaseMismatch</code>, because the logs still reference the database's <b>original absolute path</b> on the source machine. <code>/r edb</code> sets the log base name, <code>/l</code> the log directory, <code>/s</code> the checkpoint directory, <code>/d</code> the database directory." },
        { t: "note", kind: "info", title: "last resort", text: "If soft recovery still refuses, <code>esentutl /p Windows.edb</code> force-repairs. It discards unrecoverable data, so only do it on a copy and note it in your report." },
      ],
    },
    {
      title: "Step 2 — parse it with a tool that can actually read the field",
      blocks: [
        { t: "table", head: ["Tool", "Verdict"], rows: [
          ["<b>SIDR</b> (Search Index DB Reporter)", "<b>Works.</b> Handles both <code>Windows.edb</code> (ESE) and <code>Windows.db</code> (SQLite). Decodes <code>AutoSummary</code> properly. Repo is <code>strozfriedberg/sidr</code>, release asset is a bare <code>sidr.exe</code>"],
          ["<b>WinSearchDBAnalyzer</b>", "Good GUI, but can fail hard on some compression variants — seen returning a parse error on <i>every</i> record on both the original and recovered database. A systemic parser mismatch, not corrupt data"],
          ["<b>esedbexport</b> (libesedb)", "Useful for enumerating paths and dumping tables, but <b>cannot be trusted for content</b> — skips long-values silently"],
        ]},
        { t: "cmd", label: "SIDR — takes a DIRECTORY, scans recursively", code: "curl -sL -o sidr.exe https://github.com/strozfriedberg/sidr/releases/latest/download/sidr.exe\n\n# point at the folder containing Windows.edb, not the file itself\n./sidr.exe -f json --outdir out \"<case>\\edb_recover\"" },
        { t: "note", kind: "ok", title: "output", text: "Three reports named after the hostname pulled from the database itself: <code>&lt;HOST&gt;_File_Report</code>, <code>&lt;HOST&gt;_Internet_History_Report</code>, <code>&lt;HOST&gt;_Activity_History_Report</code>. The File Report carries <code>System_ItemPathDisplay</code>, timestamps, owner, and the decoded <code>System_Search_AutoSummary</code>." },
        { t: "note", kind: "warn", title: "gotcha", text: "It is <code>strozfriedberg/sidr</code>, not <code>microsoft/sidr</code>, and there is no package on crates.io — grab the prebuilt release binary." },
      ],
    },
    {
      title: "Bonus — enumerate files that no longer exist (no decompression needed)",
      span2: true,
      blocks: [
        { t: "txt", text: "Even without decoding content, the index reconstructs <b>what was on the system</b>. Paths are stored as plain fields, so <code>esedbexport</code> handles this fine. Excellent for proving a file existed, finding documents a triage tool never collected, or recovering the directory layout of removable media that has since been unplugged." },
        { t: "cmd", label: "Dump every ESE table to text", code: "sudo apt install -y libesedb-utils\nesedbexport -t /tmp/out Windows.edb\nls /tmp/out.export/" },
        { t: "cmd", label: "List everything the indexer saw for a user, or on a drive", code: "# tr is required — the export is tab-separated and long paths get visually truncated otherwise\ntr '\\t' '\\n' < /tmp/out.export/SystemIndex_PropertyStore.11 | grep -aE \"^C:..Users..<user>\" | sort -u\n\n# removable media that is long gone\ntr '\\t' '\\n' < /tmp/out.export/SystemIndex_PropertyStore.11 | grep -aE \"^E:\" | sort -u\n\n# the directory tree the crawler walked\ncat /tmp/out.export/SystemIndex_GthrPth.7" },
        { t: "table", head: ["Table", "Contents"], rows: [
          ["<code>SystemIndex_PropertyStore</code>", "The main record store: paths, sizes, timestamps, owner, MIME type, and (compressed) AutoSummary"],
          ["<code>SystemIndex_GthrPth</code>", "Scope/path tree the crawler indexed — parent/child directory structure"],
          ["<code>SystemIndex_Gthr</code>", "Crawl log with filenames and gather timestamps"],
          ["<code>SystemIndex_1_DATA_*</code>", "The inverted word index — compressed posting lists, not readable text"],
        ]},
        { t: "note", kind: "info", title: "other ESE databases use the same workflow", text: "<code>SRUDB.dat</code> (SRUM), <code>NTDS.dit</code> (Active Directory), <code>ActivitiesCache.db</code>, and Exchange stores are all ESE. <code>esentutl</code> recovery and <code>esedbexport</code> apply to all of them — learn the workflow once, reuse it everywhere." },
      ],
    },
  ],
};
