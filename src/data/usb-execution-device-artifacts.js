export default {
  id: "usb-execution-device-artifacts",
  title: "USB, Execution & Device-Access Artifacts (Registry + SRUM)",
  src: "Windows host forensics, KAPE triage casework",
  icon: "🔌",
  cards: [
    {
      title: "USB device history — SYSTEM hive, and the &0 suffix that fails your answer",
      span2: true,
      blocks: [
        { t: "txt", text: "Removable storage history lives in the <b>SYSTEM</b> hive under <code>ControlSet00X\\Enum\\USBSTOR</code> (and <code>Enum\\USB</code>). The per-device connect/disconnect timestamps are buried in a nested <code>Properties</code> subkey keyed by GUID <code>{83da6326-97a6-4088-9453-a1923f573b29}</code>." },
        { t: "note", kind: "ok", title: "do not hand-walk those GUID keys", text: "Load the SYSTEM hive in <b>Registry Explorer</b> and use its bookmarked <b>USB Devices</b> / <b>USBSTOR</b> view. It parses the property GUIDs automatically and gives you serial, manufacturer, product, device name, and first/last connected/removed in one table. Accept the transaction-log replay prompt when it appears." },
        { t: "table", head: ["Field", "Meaning"], rows: [
          ["<code>Installed</code> / <code>First Installed</code>", "First time this specific device (by serial) was ever seen on this host"],
          ["<code>Last Connected</code> / <code>Last Removed</code>", "Most recent plug and unplug"],
          ["Serial Number", "The device's hardware serial, taken from the registry subkey name"],
          ["Device Desc / Friendly Name", "Generic driver-supplied text (e.g. \"Lexar USB Flash Drive USB Device\"), <b>not</b> a custom label"],
        ]},
        { t: "note", kind: "danger", title: "the &0 suffix", text: "Serials often end <code>&amp;0</code> in the raw registry key (Windows appends it when a device does not present a genuinely unique serial). Summarised parser views frequently <b>strip it</b>. If a serial from a parsed table gets rejected, go read the <b>literal subkey name</b> under <code>USBSTOR\\Disk&amp;Ven_X&amp;Prod_Y&amp;Rev_Z\\</code> and use that verbatim." },
        { t: "note", kind: "info", title: "corroborate the drive letter", text: "<code>SYSTEM\\MountedDevices</code> maps <code>\\DosDevices\\E:</code> to the device, which confirms which letter the media was mounted as. Useful for validating an execution path that starts with a removable drive letter." },
      ],
    },
    {
      title: "Volume labels — when EMDMgmt doesn't exist, try VolumeInfoCache",
      blocks: [
        { t: "txt", text: "The generic <code>FriendlyName</code> is the driver's description, not whatever someone actually named the volume. A deliberately-applied label (asset tag, project name) lives elsewhere." },
        { t: "table", head: ["Location", "Hive", "Note"], rows: [
          ["<code>Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt</code>", "SOFTWARE", "Classic answer. <b>Only created if Windows ever evaluated the device for ReadyBoost</b> — frequently absent"],
          ["<code>Microsoft\\Windows Search\\VolumeInfoCache\\&lt;letter&gt;</code>", "SOFTWARE", "<b>The reliable fallback.</b> Windows Search caches <code>VolumeLabel</code> and <code>DriveType</code> when it indexes the media"],
        ]},
        { t: "note", kind: "ok", title: "why this is worth remembering", text: "<code>VolumeInfoCache</code> is keyed by drive letter and survives independently of the USBSTOR entries. When <code>EMDMgmt</code> is missing (common), this is usually where the human-assigned label still is." },
      ],
    },
    {
      title: "Execution evidence — UserAssist gives the real path, Shimcache gives a fragment",
      span2: true,
      blocks: [
        { t: "table", head: ["Artifact", "Location", "What it actually proves"], rows: [
          ["<b>UserAssist</b>", "NTUSER.DAT — <code>Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist</code>", "<b>GUI-launched</b> programs, with the genuine <b>absolute path</b>, a run counter, and a real last-executed timestamp"],
          ["<b>Shimcache</b> (AppCompatCache)", "SYSTEM hive — <code>Control\\Session Manager\\AppCompatCache</code>", "Executables the OS has <b>seen</b>, regardless of launch method. Timestamp is the file's <b>last-modified</b> time, not an execution time"],
        ]},
        { t: "note", kind: "danger", title: "do not manufacture an absolute path from context", text: "Shimcache entries can surface with the path concatenated against other cache metadata, leaving you only a <b>relative fragment</b> like <code>update package\\app.exe</code>. Stitching that onto a working directory you learned from a LNK file is a <b>guess</b>, not evidence — and it will be wrong if the binary ran from removable media. Go find an artifact that stores the absolute path." },
        { t: "note", kind: "warn", title: "UserAssist values are ROT13-encoded", text: "EZ Tools decodes them into a <code>Program Name</code> column automatically and shows the raw form alongside, so you can verify. Worth eyeballing the decode: <code>R:</code>→<code>E:</code>, <code>hcqngr.rkr</code>→<code>update.exe</code>." },
        { t: "note", kind: "info", title: "two different timestamps, both correct", text: "Shimcache's timestamp (file last-modified, i.e. when the binary was built or copied) and UserAssist's last-executed will differ, often by hours. That gap is a useful signal about staging versus detonation, not a contradiction." },
        { t: "cmd", label: "EZ Tools", code: "AppCompatCacheParser.exe -f <SYSTEM> --csv <out> --csvf shimcache.csv\n\n# batch name is BatchExampleUserAssist.reb — list BatchExamples\\*.reb rather than guessing\nRECmd.exe -f <NTUSER.DAT> --bn \"BatchExamples\\BatchExampleUserAssist.reb\" --csv <out> --csvf userassist.csv" },
        { t: "note", kind: "warn", title: "substring collisions will bite you", text: "Filtering execution artifacts for something like <code>update.exe</code> happily matches <code>microsoftedgeupdate.exe</code>. Always check the <b>full path</b>, not the match." },
      ],
    },
    {
      title: "Microphone & webcam access times — Capability Access Manager (HKCU, not HKLM)",
      span2: true,
      blocks: [
        { t: "txt", text: "Windows records <b>which application used the microphone or camera, and exactly when</b>. This is the artifact that answers \"when did the implant switch on the mic\" and it is rarely taught." },
        { t: "table", head: ["Hive", "Path", "What's there"], rows: [
          ["<b>SOFTWARE</b> (HKLM)", "<code>...\\CapabilityAccessManager\\ConsentStore\\{microphone,webcam}</code>", "Machine-wide <b>policy only</b> — a single <code>Value: Allow</code>. <b>Zero subkeys, no history.</b> This is the dead end"],
          ["<b>NTUSER.DAT</b> (HKCU)", "<code>Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{microphone,webcam}\\NonPackaged\\</code>", "<b>The actual usage history</b>, per application, with timestamps"],
        ]},
        { t: "note", kind: "danger", title: "the trap", text: "Checking the SOFTWARE hive first is the natural move and it returns <code>0 subkeys</code>, which looks like \"no recorded usage.\" The per-app history is in the <b>user's own NTUSER.DAT</b>. Store apps go under <code>ConsentStore\\&lt;device&gt;\\</code> directly, desktop binaries under the <code>NonPackaged</code> subkey." },
        { t: "note", kind: "ok", title: "the subkey name is the executable path", text: "Backslashes are replaced with <code>#</code>, e.g. <code>E:#folder#app.exe</code>. That independently corroborates where a binary ran from — useful cross-check against UserAssist." },
        { t: "table", head: ["Value", "Meaning"], rows: [
          ["<code>LastUsedTimeStart</code>", "When that app began using the device (FILETIME, REG_QWORD)"],
          ["<code>LastUsedTimeStop</code>", "When it stopped. <code>0</code> means still in use at capture time"],
        ]},
        { t: "note", kind: "info", title: "converting FILETIME, and duration", text: "FILETIME counts 100-nanosecond intervals since 1601-01-01. Session duration in seconds = <code>(Stop - Start) / 10,000,000</code>. Keep the raw values in your notes; rounding versus truncating matters when someone asks for a whole-second answer." },
        { t: "cmd", label: "PowerShell — FILETIME to UTC", code: "[DateTime]::FromFileTimeUtc(134316274881131799)" },
      ],
    },
    {
      title: "How much data left the box — SRUM network accounting, no PCAP required",
      blocks: [
        { t: "txt", text: "<b>SRUM</b> (System Resource Usage Monitor, <code>C:\\Windows\\System32\\SRU\\SRUDB.dat</code>) keeps <b>per-application network byte counters</b> bucketed by time. With no packet capture, no proxy logs and no firewall data, this is often the only way to quantify exfiltration volume." },
        { t: "cmd", label: "SrumECmd — pass the SOFTWARE hive to resolve app/network references", code: "SrumECmd.exe -f <SRUDB.dat> -r <SOFTWARE hive> --csv <out>" },
        { t: "table", head: ["Output table", "Use"], rows: [
          ["<code>*_NetworkUsages_*</code>", "<b>The one you want.</b> Per-app <code>BytesSent</code> / <code>BytesReceived</code> with timestamps and SID"],
          ["<code>*_NetworkConnections_*</code>", "Connection windows per app — no byte counts"],
          ["<code>*_AppResourceUseInfo_*</code>", "CPU/IO per app; useful for corroborating an activity window"],
          ["<code>*_AppTimelineProvider_*</code>", "Foreground/duration data — can bracket how long a process ran"],
        ]},
        { t: "note", kind: "warn", title: "SRUM buckets by hour", text: "A long-running process produces <b>multiple rows</b>. Sum <code>BytesSent</code> across all of them for that executable, do not read a single row as the total." },
        { t: "note", kind: "info", title: "decimal vs binary megabytes", text: "\"Decimal megabytes\" means <b>÷ 1,000,000</b>. Binary (MiB) is ÷ 1,048,576. If a figure is being checked against an expected value, this is a common source of a near-miss answer." },
        { t: "note", kind: "ok", title: "device paths, not drive letters", text: "SRUM records executables as <code>\\device\\harddiskvolumeN\\...</code>. Correlate N back to a drive letter via <code>MountedDevices</code> or the USBSTOR/volume evidence rather than assuming <code>C:</code>." },
      ],
    },
  ],
};
