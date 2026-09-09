export default {
  id: "dfir-toolbox",
  title: "DFIR Toolbox — Which Tool for Which Artifact",
  src: "Personal DFIR Workflow",
  icon: "🧰",
  cards: [
    {
      title: "The rule: artifact type decides the tool, not \"is this a Windows box\"",
      span2: true,
      blocks: [
        { t: "txt", text: "New investigation, first question isn't <i>which OS</i> — it's <b>what kind of file did I just get handed</b>. A memory dump and a registry hive both come off the same Windows machine but need completely different tools, and a tool built for one has zero capability on the other. Use this table as the entry point on any new case before touching anything." },
        { t: "table", head: ["Artifact", "Tool", "Notes"], rows: [
          ["Memory dump (<code>.mem</code>/<code>.raw</code>/<code>.vmem</code>)", "<b>Volatility 3</b> (<code>vol -f dump.raw &lt;plugin&gt;</code>)", "The one artifact type nothing else here can touch at all"],
          ["<code>.evtx</code> (Windows Event Logs)", "<b>EvtxECmd</b> → CSV, then <b>Timeline Explorer</b>", "Structural parser — pair with Chainsaw/Hayabusa for Sigma-style detection scoring on top"],
          ["Registry hives (<code>NTUSER.DAT</code>, <code>SYSTEM</code>, <code>SAM</code>, <code>SOFTWARE</code>)", "<b>RECmd</b>", "Zimmerman Tools"],
          ["MFT (<code>$MFT</code>)", "<b>MFTECmd</b>", ""],
          ["Prefetch (<code>.pf</code>)", "<b>PECmd</b>", "Prefetch itself has no full-path field — recover it from the <b>Files Loaded</b> column instead"],
          ["Shellbags", "<b>SBECmd</b>", "Output is tree-ordered (<code>BagMRU</code>), not chronological — pipe into <code>dfirtable.py</code> to read it as a timeline"],
          ["Amcache", "<b>AmcacheParser</b>", ""],
          ["SRUM", "<b>SrumECmd</b>", ""],
        ]},
      ],
    },
    {
      title: "Two more layers on top of raw parsing",
      blocks: [
        { t: "table", head: ["Output shape", "Tool", "What it adds"], rows: [
          ["Any wide/tree-ordered delimited output (RegRipper, Zimmerman CSVs)", "<code>dfirtable.py</code>", "Sortable HTML table, live regex filter, multi-source chronological merge"],
          ["JSON exports (Wazuh alert dumps, etc.)", "<code>json_to_html.py</code>", "Flattens nested JSON to columns, merges case-differing field names"],
          ["Volatility 3 <code>-r csv</code> output specifically", "<code>vol-triage.html</code>", "Auto-detects process/network/registry rows, click-a-PID cross-referencing, LOLBin + repeat-C2-IP flagging"],
        ]},
        { t: "note", kind: "ok", title: "same instinct, different domain", text: "Chainsaw/Hayabusa add detection logic on top of EvtxECmd's parsing; these three do the same job for their own artifact types — a second pass that turns raw structured output into something you can actually triage instead of scroll through." },
      ],
    },
    {
      title: "Which machine actually runs it",
      blocks: [
        { t: "table", head: ["Risk category", "Where it runs", "Why"], rows: [
          ["Artifact <i>parsing</i> — EVTX, registry, MFT, prefetch, shellbags, amcache, SRUM", "Daily-driver Windows box", "Already-extracted structured data, not executable code — no meaningful compromise risk"],
          ["Memory analysis — Volatility", "Kali/Linux analysis VM", "Python/Volatility3 ecosystem is Linux-native; matches where the tooling already lives"],
          ["Malware <i>detonation</i> — actually running a sample", "Isolated VM, network-segmented", "The one category that can compromise the analysis host itself if not isolated"],
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
