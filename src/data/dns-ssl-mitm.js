export default {
  id: "dns-ssl-mitm",
  title: "DNS Spoofing & SSL Stripping — Chained MITM",
  src: "Man-in-the-Middle Detection",
  icon: "🔓",
  cards: [
    {
      title: "The three-stage chain",
      desc: "ARP spoofing positions the attacker; DNS spoofing redirects the victim; SSL stripping harvests plaintext. Each stage is a precondition for the next — not independent alternatives.",
      span2: true,
      blocks: [
        { t: "table", head: ["Stage", "Goal", "Key evidence"], rows: [
          ["1 · ARP spoofing", "Get victim traffic routing through the attacker", "Duplicate MAC claiming the gateway IP — see the ARP/MITM section above"],
          ["2 · DNS spoofing", "Redirect victim's domain lookup to the attacker's IP", "Multiple conflicting DNS responses for one query"],
          ["3 · SSL stripping", "Downgrade HTTPS→HTTP so credentials are readable", "Plaintext POST body with a password field on a domain that normally runs TLS"],
        ]},
        { t: "note", kind: "info", title: "why this order, not arbitrary", text: "You can't DNS-spoof someone whose traffic doesn't route through you (needs positioning first). You can't strip TLS on a connection unless the victim's already been redirected to a server you control (needs the DNS spoof first). Positioning → redirection → harvesting is the general template for any multi-stage MITM." },
      ],
    },
    {
      title: "DNS spoofing — detection filters",
      blocks: [
        { t: "cmd", label: "all DNS (start here)", code: "dns" },
        { t: "cmd", label: "baseline — replies confirmed from the real resolver", code: "dns.flags.response == 1 && ip.src == 8.8.8.8" },
        { t: "cmd", label: "all responses regardless of source (scan for an odd source IP)", code: "dns.flags.response == 1" },
        { t: "cmd", label: "scope to one domain of interest", code: "dns && dns.qry.name == \"corp-login.acme-corp.local\"" },
        { t: "cmd", label: "payoff — replies for that domain from anything but the real resolver", code: "dns.flags.response == 1 && ip.src != 8.8.8.8 && dns.qry.name == \"corp-login.acme-corp.local\"" },
        { t: "note", kind: "danger", title: "the reusable pivot shape", text: "Baseline the legit source → widen to see everyone answering → flip to <code>!=</code> and re-narrow, isolating exactly the traffic that shouldn't exist. Same skeleton as the ARP gateway pivot above, just DNS fields instead of ARP fields." },
      ],
    },
    {
      title: "DNS spoofing — indicators to hunt",
      blocks: [
        { t: "table", head: ["Indicator", "Why it matters"], rows: [
          ["Multiple responses for one query", "Legit resolver + forged responder both answer — single most reliable tell"],
          ["Response from an unexpected source IP", "Doesn't match any configured resolver"],
          ["Suspiciously short TTL (1–30s)", "Attacker wants the poisoned entry to expire fast so they can re-assert it"],
          ["Unsolicited response", "A reply with no matching prior request — DNS's version of gratuitous ARP"],
        ]},
      ],
    },
    {
      title: "SSL stripping — how it actually works",
      blocks: [
        { t: "txt", text: "The attacker keeps the <b>attacker↔real-server</b> leg on genuine HTTPS, while relaying plain <b>HTTP</b> to the victim. The victim's browser never even attempts a TLS handshake for that connection — no cert to inspect, often just a missing padlock / <code>http://</code> in the address bar that most users don't check." },
        { t: "note", kind: "warn", title: "why no filter can prove absence directly", text: "You can't easily filter Wireshark for \"a handshake that didn't happen.\" The proof is indirect: confirm the domain <i>normally</i> runs TLS, then show a plaintext HTTP conversation exists between victim and attacker for that same domain." },
      ],
    },
    {
      title: "SSL stripping — detection filters",
      span2: true,
      blocks: [
        { t: "cmd", label: "all TLS/SSL traffic (both terms — SSL is deprecated but some fields still dissect under the old name)", code: "tls || ssl" },
        { t: "cmd", label: "confirm the domain normally negotiates TLS (Client Hello, via SNI)", code: "tls.handshake.type == 1 && tls.handshake.extensions_server_name == \"corp-login.acme-corp.local\"" },
        { t: "cmd", label: "confirm the attacker's IP is the one that spoofed DNS for this domain", code: "dns.flags.response == 1 && ip.src == <attacker-ip> && dns.qry.name == \"corp-login.acme-corp.local\"" },
        { t: "cmd", label: "payoff — plaintext HTTP between victim and attacker (where HTTPS should be)", code: "http && ip.src == <victim-ip> && ip.dst == <attacker-ip>" },
        { t: "txt", text: "Right-click → Follow → HTTP Stream on the POST to view the credential fields in cleartext." },
        { t: "note", kind: "info", title: "exclusion vs inclusion filters", text: "Early in an investigation, filter by <b>exclusion</b> (<code>!= known-good</code>) because the suspect is still unknown. Once an IOC is confirmed (the attacker's IP), later filters key on it by <b>inclusion</b> (<code>== known-bad</code>) since it's now a fact, not a hypothesis. Same IP, different filter role depending on investigation stage." },
      ],
    },
    {
      title: "SSL stripping — indicators to hunt",
      blocks: [
        { t: "table", head: ["Indicator", "What to look for"], rows: [
          ["Initial request vs. response mismatch", "Request targets HTTPS (443), subsequent packets shift to HTTP (80) for the same domain"],
          ["Redirect / link rewriting", "301/302 redirects that persistently point an HTTPS request at an HTTP resource"],
          ["Certificate errors", "Failed handshake or self-signed cert, if the attacker used a more direct proxy technique"],
        ]},
      ],
    },
  ],
};
