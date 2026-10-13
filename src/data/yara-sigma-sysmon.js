export default {
  id: "yara-sigma-sysmon",
  title: "YARA, Sigma and Sysmon Detections",
  src: "HTB Academy: Introduction To Malware Analysis (detection rules)",
  icon: "📜",
  cards: [
    {
      title: "YARA vs Sigma in one line",
      span2: true,
      blocks: [
        { t: "table", head: ["", "YARA", "Sigma"], rows: [
          ["matches", "<b>files, processes in memory</b> by content (what the file <i>looks like</i>)", "<b>log events</b> by behavior (what it <i>does</i>)"],
          ["format", "YARA rule language", "YAML, converted to Splunk, Elastic, Sentinel and others"],
          ["good for", "classifying samples and families even when the filename changes", "SIEM detections, one rule shared across platforms"],
        ]},
        { t: "note", kind: "info", title: "analysis feeds rules", text: "Analysis works out how one burglar operates, a rule is the wanted poster. Strings, imports and IOCs from static work become YARA. Behavior seen in Procmon, Wireshark and Sysmon becomes Sigma and network rules." },
      ],
    },
    {
      title: "YARA anatomy",
      span2: true,
      blocks: [
        { t: "cmd", label: "smallest useful rule", code: `rule Shell_Sandbox_Detection {
    strings:
        $sandbox_string = "Sandbox detected"
    condition:
        $sandbox_string
}` },
        { t: "table", head: ["Block", "Job"], rows: [
          ["<code>meta:</code>", "description, author, reference, date, sample hash (labels, not matching)"],
          ["<code>strings:</code>", "the patterns: <code>$name = \"text\"</code> (ascii, wide, nocase, fullword), hex, or regex"],
          ["<code>condition:</code>", "the logic: which strings, how many, plus file checks"],
        ]},
        { t: "cmd", label: "scan syntax: yara <rules file> <file or directory>", code: "yara /home/htb-student/yarGen-0.23.4/yargen_rules.yar /home/htb-student/Samples/MalwareAnalysis/\n# prints:  <rule name> <matching file>" },
      ],
    },
    {
      title: "yarGen: generate a first draft, then tune it",
      span2: true,
      blocks: [
        { t: "txt", text: "yarGen extracts strings from a sample and <b>removes strings seen in a large goodware database</b>, so the rule keys on what is unusual. The output is a starting point, <b>not a finished rule</b>." },
        { t: "cmd", label: "workflow", code: "mkdir Test && cp shell.exe Test/            # ONLY the sample(s) you want a rule for\ncd ~/yarGen-0.23.4\nsudo python3 yarGen.py -m /home/htb-student/Samples/MalwareAnalysis/Test/\ncat yargen_rules.yar" },
        { t: "cmd", label: "the generated condition (shell.exe)", code: `condition:
   uint16(0) == 0x5a4d and filesize < 60KB and
   1 of ($x*) and 4 of them` },
        { t: "table", head: ["Piece", "Reads as"], rows: [
          ["<code>uint16(0) == 0x5a4d</code>", "first two bytes are <code>MZ</code> (little-endian 0x5a4d): a Windows executable"],
          ["<code>filesize &lt; 60KB</code>", "small file, keeps big legitimate files out"],
          ["<code>1 of ($x*)</code>", "at least one of the very distinctive <code>$x</code> strings"],
          ["<code>4 of them</code>", "at least four of all strings match"],
        ]},
        { t: "note", kind: "ok", title: "why several clues", text: "One common word can appear in a harmless file. Four unusual strings together almost never do." },
        { t: "note", kind: "warn", title: "hand-tune the draft", text: "Drop weak strings yarGen kept (<code>connect</code>, <code>socket</code>, \"Goodware String - occured 429 times\", compiler noise like pseudo-relocation messages). Make <code>$x</code> the strongest IOCs (domain, URL, user agent, IP). Add the shellcode stub as hex (<code>fc 48 83 e4 f0 e8 c0 00 00 00 41 51 41 50 52 51</code>) and keep the MZ check." },
        { t: "cmd", label: "good strings to key on for shell.exe (from analysis)", code: `$x1 = "ms-windows-update.com" ascii
$s2 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
$s3 = "Windows-Update/7.6.7600.256" ascii
$s4 = "45.33.32.156" ascii
$s5 = "/k ping 127.0.0.1 -n 5" ascii
$s6 = "AQAPRQVH1" ascii` },
      ],
    },
    {
      title: "Sigma skeleton (and two fixes to the course example)",
      span2: true,
      blocks: [
        { t: "table", head: ["Field", "Job"], rows: [
          ["<code>title</code>, <code>status</code>, <code>description</code>", "name, maturity (experimental), what it finds"],
          ["<code>logsource</code>", "<b>which log</b> to search (category, product, service)"],
          ["<code>detection</code>", "<code>selection</code> = field/value tests, <code>condition</code> = how they combine"],
          ["<code>level</code>", "severity: informational, low, medium, high, critical"],
          ["<code>falsepositives</code>", "harmless activity that could trigger it"],
        ]},
        { t: "cmd", label: "corrected: file drop of svchost.exe in a user's Temp folder", code: `title: Suspicious svchost.exe Dropped In User Temp
status: experimental
description: A process created svchost.exe in a user Temp folder (real svchost lives in System32)
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '\\AppData\\Local\\Temp\\svchost.exe'
    condition: selection
falsepositives:
    - Legitimate installers extracting files to Temp
level: high` },
        { t: "note", kind: "warn", title: "what was off in the course example", text: "1) It used <code>category: process_creation</code> with <code>TargetFilename</code>, which is a <b>file creation</b> field (Sysmon Event 11, category <code>file_event</code>). Process creation fields are <code>Image</code>, <code>CommandLine</code>, <code>ParentImage</code>. 2) The pattern had doubled backslashes inside a single-quoted string, which is probably unnecessary. Verify against the Sigma spec when you convert." },
      ],
    },
    {
      title: "Sysmon events: the log source behind the rules",
      span2: true,
      blocks: [
        { t: "table", head: ["Event ID", "Meaning", "What shell.exe produced"], rows: [
          ["<b>1</b> Process create", "a process started", "<code>Image: ...\\AppData\\Local\\Temp\\svchost.exe</code>, <code>CommandLine</code> with a wallet-looking argument, <code>ParentImage: ...\\Downloads\\shell.exe</code>, <code>IntegrityLevel: Medium</code>"],
          ["<b>3</b> Network connection", "a process connected out", "<code>shell.exe</code> TCP to the INetSim host on 80, and a second connect to <code>45.33.32.156:31337</code>"],
          ["<b>10</b> Process access", "one process opened another", "<code>SourceImage: shell.exe</code>, <code>TargetImage: ...\\notepad.exe</code>, <code>GrantedAccess: 0x1F3FFF</code> (broad: write memory, create thread). <b>Not configured on the module's Windows targets</b>"],
          ["<b>11</b> File create", "a file was written", "<code>shell.exe</code> created <code>C:\\Users\\LabUser\\AppData\\Local\\Temp\\svchost.exe</code>"],
          ["<b>13</b> Registry value set", "a registry value was written", "the <code>...\\CurrentVersion\\Run</code> value <code>WindowsUpdater</code>"],
        ]},
      ],
    },
    {
      title: "Detection ideas from the module (behavior to log to rule)",
      span2: true,
      blocks: [
        { t: "table", head: ["Behavior", "Where it shows", "Idea"], rows: [
          ["<code>svchost.exe</code> in a user Temp folder", "Sysmon 1 and 11", "<code>Image</code> or <code>TargetFilename</code> ends with <code>\\AppData\\Local\\Temp\\svchost.exe</code>. The real one is in <code>System32</code>"],
          ["wrong parent for <code>svchost.exe</code>", "Sysmon 1", "<code>ParentImage</code> is not <code>services.exe</code>"],
          ["remote process injection", "Sysmon 10", "user-folder program opens <code>notepad.exe</code> with a broad <code>GrantedAccess</code> such as <code>0x1F3FFF</code> or <code>0x1FFFFF</code>"],
          ["LSASS dumping", "Sysmon 10 and 11", "<code>TargetImage</code> is <code>lsass.exe</code> from an unexpected source; a <code>.dmp</code> created outside crash-dump locations; <code>dbghelp.dll</code> loaded by a non-debugger. Hardening: RunAsPPL, Credential Guard"],
          ["Run-key persistence", "Sysmon 13", "value written under <code>...\\CurrentVersion\\Run</code> by a user-folder process"],
          ["fixed user agent", "proxy, Suricata, Zeek <code>http.log</code>", "prefix <code>Windows-Update/7.6.7600.256</code> or an old <code>MSIE 8.0</code> UA with the hostname appended"],
          ["PE downloaded over HTTP", "network IDS", "response body starts <code>MZ</code> and contains <code>This program cannot be run in DOS mode</code>"],
          ["DNS and connect anomalies", "DNS logs, Sysmon 3", "long random-looking <code>.com</code> lookups; connections to port <code>31337</code>"],
          ["Bitcoin-wallet-style argument", "Sysmon 1 <code>CommandLine</code>", "a long base58 string passed to a program run from Temp"],
        ]},
        { t: "note", kind: "info", title: "good rules combine independent clues", text: "A single indicator is easy to dodge or to false-positive. Combine file location, parent, behavior and network evidence." },
      ],
    },
  ],
};
