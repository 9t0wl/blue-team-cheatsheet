export default {
  id: "arp-mitm",
  title: "Wireshark — ARP Poisoning & MITM Detection",
  src: "Wireshark: Traffic Analysis",
  icon: "🕵️",
  cards: [
    {
      title: "ARP in a nutshell — why it's abusable",
      blocks: [
        { t: "txt", text: "ARP (Address Resolution Protocol) maps an <b>IP → MAC</b> on the local segment so hosts can actually frame packets to each other." },
        { t: "table", head: ["Property", "Consequence"], rows: [
          ["Local network only", "Attack must be on the same L2 segment"],
          ["Not routable", "Doesn't cross the router — contained to the LAN"],
          ["No authentication", "Hosts trust ANY reply and update their cache"],
          ["Stateless", "A reply is accepted even with no matching request (gratuitous ARP)"],
        ]},
        { t: "note", kind: "info", title: "the core weakness", text: "No auth + stateless = a host will overwrite its ARP cache from an <b>unsolicited</b> reply. That's the entire basis of ARP poisoning — claim to be the gateway and traffic flows through you." },
        { t: "txt", text: "Common packet types: <b>request/response</b>, <b>announcement</b>, and <b>gratuitous</b> (unsolicited \"I am IP x at MAC y\")." },
      ],
    },
    {
      title: "Detection filters",
      span2: true,
      blocks: [
        { t: "cmd", label: "all ARP (start here)", code: "arp" },
        { t: "cmd", label: "requests (opcode 1) / replies (opcode 2)", code: "arp.opcode == 1\narp.opcode == 2" },
        { t: "cmd", label: "ARP scanning — dest MAC all-zeros (asking 'who has this IP?')", code: "arp.dst.hw_mac == 00:00:00:00:00:00" },
        { t: "cmd", label: "possible poisoning — duplicate IP detected", code: "arp.duplicate-address-detected or arp.duplicate-address-frame" },
        { t: "cmd", label: "flooding from one MAC (fill in the suspect)", code: "((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == <target-mac>)" },
        { t: "table", head: ["Filter", "Hunts for"], rows: [
          ["arp.opcode == 1", "ARP requests"],
          ["arp.opcode == 2", "ARP responses"],
          ["arp.dst.hw_mac == 00:00:00:00:00:00", "ARP scanning"],
          ["arp.duplicate-address-detected", "Possible ARP poisoning"],
          ["arp.opcode==1 &amp;&amp; arp.src.hw_mac==&lt;mac&gt;", "Possible ARP flooding from one host"],
        ]},
      ],
    },
    {
      title: "The three tells",
      blocks: [
        { t: "note", kind: "danger", title: "1 · spoofing (the conflict)", text: "<b>Two different MAC addresses claim the same IP.</b> The classic poison. Especially damning when the contested IP is the <b>gateway</b> — attacker is inserting itself as the router." },
        { t: "note", kind: "warn", title: "2 · gateway impersonation", text: "One MAC owns its <b>real</b> IP <i>and</i> also claims the <b>gateway</b> IP. That single MAC now answers as two hosts." },
        { t: "note", kind: "warn", title: "3 · flooding / scanning", text: "One MAC crafts <b>many ARP requests across a range of IPs</b> in a short window — mapping the segment and/or poisoning caches en masse." },
      ],
    },
    {
      title: "Investigation workflow",
      blocks: [
        { t: "steps", items: [
          "Filter <code>arp</code> and look for a <b>duplicate IP → MAC</b> (two MACs, one IP). Wireshark's <b>Expert Info</b> flags it — but only the <b>second</b> occurrence, so YOU decide which is legit.",
          "Note the suspect MAC: does it own a real IP <i>and</i> claim the gateway? Take structured notes (MAC ↔ IP) as you go.",
          "Check for <b>flooding</b>: same source MAC, opcode 1, hitting a range of IPs.",
          "Pivot to another protocol (e.g. HTTP). At the <b>IP layer everything looks normal</b> — that's the trap.",
          "Add <b>MAC address columns</b> to the packet list. If the suspect MAC is the <b>destination of the victim's traffic</b>, the traffic is being forwarded through it → <b>MITM confirmed</b>.",
          "Summarise as Attacker / Gateway / Victim, each pinned to a MAC ↔ IP pair.",
        ]},
      ],
    },
    {
      title: "Confirming MITM at the MAC layer",
      blocks: [
        { t: "note", kind: "info", title: "why add MAC columns", text: "IP addresses look correct end-to-end during a MITM — the attacker forwards packets so routing still works. The evidence is one layer down: every frame for the victim's IP has the <b>attacker's MAC</b> as its L2 destination." },
        { t: "note", kind: "danger", title: "expert-info gotcha", text: "Wireshark's duplicate-address warning shows only the <b>second</b> occurrence of the conflict. Identifying which of the two MACs is the impostor is the analyst's job — knowing the real network layout (which MAC is really the gateway) is what breaks the tie." },
      ],
    },
  ],
};
