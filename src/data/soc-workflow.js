export default {
  id: "soc-workflow",
  title: "SOC Workflow & Reporting",
  src: "SOC Simulator",
  icon: "🎯",
  cards: [
    {
      title: "Five Ws report template",
      blocks: [
        { t: "table", head: ["W", "Capture"], rows: [
          ["Who", "Sender/recipient + spoofing status (SPF/DKIM)"],
          ["What", "Attack vector + payload"],
          ["When", "Delivery / detection time"],
          ["Where", "Mailbox / system affected"],
          ["Why", "Attacker motive / social-engineering angle"],
        ]},
        { t: "note", kind: "danger", title: "grading gotcha", text: "Graders check each W is <b>visibly, explicitly</b> labeled in every report — don't let \"obvious\" ones (affected mailbox/asset) collapse into implied text, even when it feels repetitive." },
      ],
    },
    {
      title: "TP/FP vs escalation — two separate decisions",
      blocks: [
        { t: "note", kind: "info", text: "<b>TP/FP judges the artifact, not the outcome.</b> A phishing email with zero evidence of a click is still a True Positive if the email itself is malicious — \"no click found\" is a finding, not grounds for FP." },
        { t: "note", kind: "warn", text: "<b>Escalation is driven by realized risk.</b> All alerts can be TP but only some escalate — e.g. when the malicious connection was <b>allowed through</b> rather than blocked, creating real exposure." },
        { t: "txt", text: "<b>Correlate across alerts</b> (shared URL/IP + close timestamps). <b>Reason around missing telemetry</b> — make a risk-based call and document the gap, don't hunt a log source that doesn't exist." },
      ],
    },
    {
      title: "Command-line signature false positives — read what actually matched",
      span2: true,
      blocks: [
        { t: "note", kind: "info", title: "the first question on any AV/EDR alert", text: "Not \"what was detected\" but <b>\"what object did it match against?\"</b> Defender's <b>Affected items</b> field (equivalents: CrowdStrike's Triggering Process, SentinelOne's Threat Indicators) tells you whether the hit was a <b>file on disk</b> or a <b>process command line</b>. Those are completely different findings and they triage differently." },
        { t: "table", head: ["Matched object", "What it actually means", "Triage weight"], rows: [
          ["File / binary hash", "Something known-bad is written to disk. Real, regardless of whether it ran.", "High — confirm hash, check execution evidence"],
          ["Process command line", "A <i>string</i> in an argument matched a signature. The process may have done nothing at all.", "Low-to-medium — read the full command line before assuming anything"],
          ["Memory / in-process (AMSI)", "Content was scanned at runtime, e.g. a script block about to execute.", "High — this is execution, not just text"],
        ]},
        { t: "note", kind: "danger", title: "worked example — a markdown file set off a Mimikatz signature", text: "Writing DFIR study notes containing the line <code>Offensive mirror: Mimikatz sekurlsa::logonpasswords</code> via a shell heredoc fired <code>HackTool:Win32/Mimikatz.I</code> at <b>High</b> severity, and Defender terminated the shell. The heredoc passed the entire file contents as an <b>argument to bash.exe</b>, so credential-dumping syntax appeared verbatim in a process command line — exactly what the signature matches on. Zero malicious behaviour; notes <i>about</i> detecting an attack tripped the detection for that tool." },
        { t: "note", kind: "warn", title: "why the same text is fine sitting on disk", text: "The identical string in the saved <code>.md</code> file didn't alert. Command lines are separately and heavily instrumented on Windows (Sysmon EID 1, Security 4688, EDR process telemetry) precisely because argument content is such high-signal evidence — which cuts both ways. Anything routed <i>through</i> a command line gets inspected; the same bytes written by direct file I/O usually don't." },
        { t: "steps", items: [
          "Read the Affected items / triggering-process field before anything else — file or command line?",
          "Read the <b>full</b> command line, not the truncated preview. The matched substring is often incidental to what the process was doing.",
          "Ask what the process legitimately does. A text editor, shell, or note-taking tool writing security content is a different story from a LOLBin fetching a remote payload.",
          "Check for execution evidence: child processes, network connections, file writes. A signature match with no behaviour behind it is a string, not an intrusion.",
          "Classify FP and document the matched string — the same benign trigger will recur, and the note saves the next analyst the round trip.",
        ]},
        { t: "note", kind: "warn", title: "resist the reflex to add an exclusion", text: "A <b>path</b> exclusion won't even fix a command-line match — the detection is against the process, not the target file. Silencing it needs a <b>process</b> exclusion (e.g. all of <code>bash.exe</code>), which blinds the EDR to everything a shell does on that host. Almost never the right trade. Fix the workflow that puts sensitive strings on command lines instead. Genuine exception: a dedicated analysis VM handling live samples, memory dumps or KAPE collections — but that belongs on an isolated box, not a daily driver." },
        { t: "note", kind: "info", title: "the interview answer", text: "\"Tell me about a false positive you investigated\" is a standard SOC question, and this is a clean one: High-severity HackTool alert → checked the matched object → command-line string, not a file → no execution, no child process, no network → benign security documentation → closed FP with the trigger documented. It shows you read the <i>evidence</i> rather than the severity label." },
      ],
    },
  ],
};
