export default {
  id: "ntfs-timeline-forensics",
  title: "NTFS Timeline Forensics — MFT, USN Journal & ADS",
  src: "HTB Sherlock: Streamer",
  icon: "🗂️",
  cards: [
    {
      title: "$MFT resident data — small files survive their own deletion",
      desc: "NTFS stores a file's content directly inside its own MFT record's $DATA attribute when the file is small enough (roughly under a few hundred bytes, no separate data-cluster allocation needed). That content can outlive the file itself, right up until the MFT slot gets reused.",
      span2: true,
      blocks: [
        { t: "txt", text: "Bulk MFT CSV exports sometimes leave the resident-data columns blank even when the data is present — don't take that as proof the content is gone. Pull the specific record directly instead:" },
        { t: "cmd", code: 'MFTECmd.exe -f "...\\$MFT" --de <EntryNumber>-<SequenceNumber>' },
        { t: "note", kind: "ok", title: "worked example", text: "A 54-byte note flagged via a Jump List LNK's cached <b>Target MFT Entry Number</b> wasn't in the collected evidence at all (targeted triage collections don't grab arbitrary user documents) — but the single-record dump mode printed its full resident <code>$DATA</code> as plain ASCII straight to console, recovering the deleted content with no separate carving step." },
      ],
    },
    {
      title: "$STANDARD_INFORMATION (0x10) vs $FILE_NAME (0x30) — two separate timestamp sets, don't grab the first plausible column",
      span2: true,
      blocks: [
        { t: "table", head: ["Attribute", "What it tracks", "Behavior across a rename"], rows: [
          ["$STANDARD_INFORMATION (0x10)", "General file metadata (Created/Modified/Accessed/Record-Changed)", "<b>Survives a rename</b> — Created stays the original creation moment"],
          ["$FILE_NAME (0x30)", "The filename attribute itself, has its own Created/Modified timestamps", "Gets restamped when the name changes — but its own \"Created\" isn't reliably the exact rename moment either"],
        ]},
        { t: "note", kind: "warn", title: "verify against the USN Journal before submitting", text: "Grabbing whichever timestamp column looks plausible for \"when was this renamed\" is a real trap — a submission using $FILE_NAME's own timestamp was rejected on a real case, then corrected against the USN Journal's ground-truth <code>RenameNewName</code> event, which also independently matched the file's own <b>Last Record Change (0x10)</b> timestamp. Two independent sources agreeing is the actual confirmation, not one plausible-looking column." },
      ],
    },
    {
      title: "MFT entry + sequence number is stable across a rename — trace a cached LNK target forward to its current name",
      span2: true,
      blocks: [
        { t: "txt", text: "A file's MFT entry number and sequence number don't change on a plain rename — only a <b>delete + slot-reuse by a new, unrelated file</b> bumps the sequence number. LNK files (via LECmd) cache the <b>Target MFT Entry Number</b> and <b>Target MFT Sequence Number</b> of whatever they pointed at when created or last updated." },
        { t: "steps", items: [
          "Pull the cached entry/sequence off an old LNK pointing at the file's original name.",
          "Look that exact entry+sequence up in a fresh $MFT parse.",
          "If the sequence number still matches, whatever name/path sits there now is what the file was most recently renamed to — same file lineage, not a coincidence.",
        ]},
        { t: "note", kind: "info", title: "sanity-check with file size", text: "If the current record's size doesn't match what you'd expect (e.g. a multi-hundred-MB installer suddenly showing a few hundred bytes), don't assume the lookup is wrong — it can mean the file's content was truncated/overwritten <i>after</i> the rename (e.g. dropper cleanup post-extraction). Check the Last Record Change timestamp against your known timeline before concluding the entry/sequence match was a false positive." },
      ],
    },
    {
      title: "USN Journal ($Extend\\$J) — ground truth for create/rename/delete events, and what MFTECmd can't parse",
      span2: true,
      blocks: [
        { t: "txt", text: "The USN Journal is NTFS's own transaction log of every create/rename/delete as it happens, each with an explicit reason code and timestamp — the definitive source when static $MFT snapshots disagree with each other on timing." },
        { t: "cmd", code: 'MFTECmd.exe -f "...\\$Extend\\$J" --csv <out>' },
        { t: "table", head: ["Reason code", "What it means"], rows: [
          ["RenameOldName / RenameNewName", "Paired entries at the same timestamp — the literal old and new filenames"],
          ["FileCreate", "New file/directory created"],
          ["FileDelete", "File/directory removed"],
        ]},
        { t: "note", kind: "danger", title: "MFTECmd does NOT parse raw $LogFile", text: "MFTECmd handles $MFT, $Boot, $SDS, and $J (USN Journal) — it explicitly does <b>not</b> support raw $LogFile. Reaching for $LogFile ground-truth data needs a different, more specialized tool; don't burn time feeding it to MFTECmd expecting it to work." },
      ],
    },
    {
      title: "Zone.Identifier ADS (Mark of the Web) — download provenance that survives cleared browser history",
      span2: true,
      blocks: [
        { t: "txt", text: "Windows tags anything downloaded via a browser with a hidden <code>:Zone.Identifier</code> Alternate Data Stream on the file itself — separate from, and independent of, whatever the browser's own history database records. MFTECmd decodes it automatically into a <b>Zone Id Contents</b> column when parsing $MFT." },
        { t: "cmd", label: "sample :Zone.Identifier ADS content", code: "[ZoneTransfer]\nZoneId=3\nReferrerUrl=http://example.com/page/\nHostUrl=http://example.com/download/file.zip" },
        { t: "table", head: ["ZoneId", "Meaning"], rows: [
          ["0", "Local machine"],
          ["1", "Local intranet"],
          ["2", "Trusted sites"],
          ["3", "Internet zone — confirms a genuine internet download"],
          ["4", "Restricted sites"],
        ]},
        { t: "note", kind: "ok", title: "the trail that survives", text: "On a real case, browser SQLite history came back completely clean (cleared, or the entry never wrote), but the downloaded file's own $MFT record still carried its Zone.Identifier ADS with the full <b>HostUrl</b> — recovering the exact download URL from a filesystem-level artifact the malware/user never thought to (or couldn't) touch." },
      ],
    },
  ],
};
