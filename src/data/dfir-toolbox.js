export default {
  id: "dfir-toolbox",
  title: "DFIR Toolbox — Which Tool for Which Artifact",
  src: "Personal DFIR Workflow",
  icon: "🧰",
  cards: [
    {
      title: "The rule: artifact type decides the tool, not \"is this a Windows box\"",
      desc: "First question on a new case isn't which OS — it's what kind of file did I just get handed. A memory dump and a registry hive come off the same machine but need completely different tools, and a tool built for one has zero capability on the other.",
      span2: true,
      blocks: [
        { t: "table", head: ["Artifact", "Go-to tool", "Notes"], rows: [
          ["Memory dump", "<b>Volatility 3</b>", "<code>.mem</code> / <code>.raw</code> / <code>.vmem</code> — the one type nothing else here touches at all"],
          ["Windows Event Logs", "<b>EvtxECmd</b> → <b>Timeline Explorer</b>", "<code>.evtx</code>. Structural parser — add Chainsaw/Hayabusa on top for Sigma-style detection scoring"],
          ["Registry hives", "<b>RECmd</b>", "<code>NTUSER.DAT</code>, <code>SYSTEM</code>, <code>SAM</code>, <code>SOFTWARE</code>"],
          ["MFT", "<b>MFTECmd</b>", "<code>$MFT</code>"],
          ["Prefetch", "<b>PECmd</b>", "<code>.pf</code>. Prefetch has no full-path field — recover it from the <b>Files Loaded</b> column"],
          ["Shellbags", "<b>SBECmd</b>", "Output is tree-ordered (<code>BagMRU</code>), not chronological — pipe into <code>dfirtable.py</code> to read it as a timeline"],
          ["Amcache", "<b>AmcacheParser</b>", "Evidence of execution"],
          ["SRUM", "<b>SrumECmd</b>", "Resource usage, per-app network totals"],
        ]},
      ],
    },
    {
      title: "Two more layers on top of raw parsing",
      span2: true,
      blocks: [
        { t: "table", head: ["Output shape", "Tool", "What it adds"], rows: [
          ["Delimited / CSV", "<code>dfirtable.py</code>", "Sortable HTML table, live regex filter, multi-source chronological merge. For RegRipper output, Zimmerman CSVs, anything wide or tree-ordered"],
          ["JSON exports", "<code>json_to_html.py</code>", "Flattens nested JSON to dot-notation columns, merges field names differing only in case. Wazuh alert dumps, etc."],
          ["Volatility CSV", "<code>vol-triage.html</code>", "Auto-detects process/network/registry tables, click-a-PID cross-referencing, LOLBin + repeat-C2-IP + masquerade flagging"],
        ]},
        { t: "note", kind: "ok", title: "same instinct, different domain", text: "Chainsaw/Hayabusa add detection logic on top of EvtxECmd's parsing; these three do the same job for their own artifact types — a second pass that turns raw structured output into something you can actually triage instead of scroll through." },
      ],
    },
    {
      title: "Prefetch — three different \"when did it run\" answers",
      span2: true,
      blocks: [
        { t: "txt", text: "A <code>.pf</code> file carries timestamps in two separate places, and they don't always agree." },
        { t: "table", head: ["Source", "What it tells you", "Authority"], rows: [
          ["<code>.pf</code> file's own filesystem Created date", "when the .pf inode first appeared on the volume — usually ≈ first execution", "Approximation — a step removed from the actual event"],
          ["<code>.pf</code> file's own filesystem Modified date", "usually ≈ most recent execution (Prefetch rewrites the same file every run)", "Approximation"],
          ["PECmd's parsed <b>internal run-time array</b> (up to 8 stored timestamps + a Run Count header)", "written directly by the Prefetcher subsystem into the file's own binary structure at execution time", "<b>Authoritative</b> — this is the actual execution-tracking data, not a side effect of it"],
        ]},
        { t: "note", kind: "warn", title: "the discrepancy is real, not noise", text: "Seen a 10-second gap between a <code>.pf</code>'s filesystem Created timestamp and PECmd's internal 'first run' timestamp on the same file. When a task/investigation needs precision on first/last execution, prefer the parsed internal array over raw filesystem metadata — run <code>PECmd -f &lt;file&gt; --csv &lt;dir&gt;</code> and read <b>Run count</b> / <b>Last run</b> / <b>Other run times</b> from its console output or CSV, don't eyeball Explorer's file properties." },
        { t: "note", kind: "info", title: "Run Count vs. the stored timestamps", text: "Run Count keeps incrementing indefinitely; the stored run-time array is capped (8 slots on Windows 10-era Prefetch). Past 8 executions, Run Count and the visible timestamp list will disagree — Run Count is still correct for \"how many total,\" the array only shows the most recent 8." },
      ],
    },

    {
      title: "Which machine actually runs it",
      span2: true,
      blocks: [
        { t: "table", head: ["Work", "Where it runs", "Why"], rows: [
          ["Artifact parsing", "Daily-driver Windows box", "EVTX, registry, MFT, prefetch, shellbags, amcache, SRUM — already-extracted structured data, not executable code, so no meaningful compromise risk"],
          ["Memory analysis", "Kali / Linux analysis VM", "Volatility3's ecosystem is Linux-native; matches where the tooling already lives"],
          ["Malware detonation", "Isolated, network-segmented VM", "The one category that can compromise the analysis host itself if it isn't isolated"],
        ]},
        { t: "note", kind: "danger", title: "don't conflate parsing with detonation", text: "Opening a <code>.evtx</code> in EvtxECmd or reading a registry hive in RECmd is safe practice on a normal analysis box. Running a suspicious binary — even \"just to see what it does\" — is a different risk category and belongs on an isolated box, full stop." },
      ],
    },
    {
      title: "Starting checklist on a fresh case",
      span2: true,
      blocks: [
        { t: "steps", items: [
          "Identify what you were handed — memory image, disk image, EVTX export, hive, PCAP, or some mix.",
          "Route each artifact to its tool from the table above — don't reach for one tool to cover everything.",
          "Get to CSV/structured output as fast as possible, then load it into <code>dfirtable.py</code>, <code>json_to_html.py</code>, or <code>vol-triage.html</code> rather than reading raw terminal scrollback.",
          "Cross-reference across artifact types once each is parsed — a PID from <code>windows.pstree</code>, a service name from an EVTX 7045, and a Prefetch execution all pointing at the same binary is far stronger than any one alone.",
        ]},
      ],
    },
  ],
};
