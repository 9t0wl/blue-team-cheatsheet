export default {
  id: "ip-tcp-layer-attacks",
  title: "Wireshark — IP & TCP Layer Attacks",
  src: "Wireshark: Intermediate Network Traffic Analysis",
  icon: "🧩",
  cards: [
    {
      title: "The common thread",
      span2: true,
      blocks: [
        { t: "txt", text: "IP and TCP have almost no built-in identity or integrity checking. Each attack below abuses a header field that the destination trusts more than a security control in the middle does. <b>The control that inspects fragments or packets in isolation is the one that gets fooled.</b>" },
        { t: "note", kind: "ok", title: "the fix pattern", text: "Make the middle device behave like the destination host: reassemble fragments before inspecting, drop implausible TTLs, validate RST, and watch who really owns each address." },
      ],
    },
    {
      title: "Fragmentation (nmap -f)",
      blocks: [
        { t: "txt", text: "Big packets are split at the MTU; the <b>Fragment Offset</b> lets the destination reassemble. Attackers force tiny fragments so an IDS or firewall that does not reassemble never sees the whole scan. <code>nmap -f</code> = 8-byte fragments, <code>-f -f</code> = 16, <code>--mtu N</code> = custom (multiple of 8)." },
        { t: "cmd", label: "fragments that have more coming (also the first of each datagram)", code: "ip.flags.mf == 1" },
        { t: "cmd", label: "catch the final fragment too", code: "ip.flags.mf == 1 or ip.frag_offset > 0" },
        { t: "note", kind: "info", title: "proof in the packet", text: "Info column shows <code>Fragmented IP protocol (proto=TCP 6, off=0, ID=...)</code>. Data of exactly 8 bytes per fragment is the <code>-f</code> default. The real target still reassembles and answers normally." },
        { t: "note", kind: "warn", title: "fragmentation is not DoS avoidance", text: "Two separate abuses: evasion (this) versus the old ping-of-death (reassembles to more than 65535 bytes and crashes a host). Different goals, same field." },
        { t: "note", kind: "info", text: "Wireshark reassembly toggle: Edit, Preferences, Protocols, IPv4, Reassemble fragmented IPv4 datagrams." },
      ],
    },
    {
      title: "Low TTL",
      blocks: [
        { t: "txt", text: "Each router decrements TTL; at 0 the packet is dropped and an ICMP Time Exceeded goes back. Attackers set tiny TTLs to expire before a filtering device, or to map hop distance (same mechanism as traceroute)." },
        { t: "table", head: ["OS default start TTL", "Value"], rows: [
          ["Linux / macOS / BSD", "64"],
          ["Windows", "128"],
          ["Network gear (often)", "255"],
        ]},
        { t: "cmd", label: "abnormally low TTL on real traffic (tune the threshold to your hop distance)", code: "ip.ttl < 10" },
        { t: "note", kind: "info", text: "Wireshark itself flags it in Expert Info: <code>Time To Live only 3</code>. A TTL of 1 to 5 on a normal SYN or connection is crafted. Fix: discard packets whose TTL is implausibly low for your topology." },
      ],
    },
    {
      title: "Source / destination spoofing",
      span2: true,
      blocks: [
        { t: "note", kind: "info", title: "baseline rule", text: "Inbound packets should not claim a source from your own subnet; outbound packets must carry a source from your subnet. Violations mean crafted packets or a compromised inside host." },
        { t: "table", head: ["Attack", "Mechanism", "Tell"], rows: [
          ["Decoy scan (nmap -D)", "Real scan mixed with fake source addresses", "Only the REAL source ever receives the useful RST or SYN-ACK answers"],
          ["Random source flood", "Many spoofed sources to one port", "One dest port, sequential base source ports, identical length fields"],
          ["Inverse random (ICMP)", "Target replies out to many random addresses", "One host sending replies to a spread of unrelated IPs"],
          ["Smurf", "Spoofed victim address pings live hosts; they reply to the victim", "Echo REPLIES with no matching request at the victim"],
          ["LAND", "Source IP = destination IP", "Self-addressed SYNs, incrementing source ports, exhausts port space"],
        ]},
        { t: "cmd", label: "LAND attack", code: "ip.src == ip.dst" },
        { t: "cmd", label: "Smurf: replies landing on the suspected victim", code: "icmp.type == 0 and ip.dst == <victim>" },
        { t: "cmd", label: "then count distinct senders", code: "Statistics > Endpoints > IPv4, tick Limit to display filter" },
        { t: "note", kind: "danger", title: "verify, do not assume", text: "The course Smurf capture had a single reflector, not a swarm. Freezing the destination MAC or filtering requests (type 8) answers the wrong question: attacking hosts in a Smurf are the REPLY senders." },
      ],
    },
    {
      title: "RST injection",
      blocks: [
        { t: "txt", text: "Attacker forges a packet that appears to come from a connection's peer, RST flag set, port in use. The victim tears the connection down (DoS or forced reconnect)." },
        { t: "cmd", label: "RSTs aimed at one port", code: "tcp.flags.reset == 1 and tcp.dstport == 80" },
        { t: "note", kind: "danger", title: "the MAC tell", text: "The device list says <code>192.168.10.4</code> is <code>aa:aa:aa:aa:aa:aa</code> but the RSTs come from another MAC. IP is forged, hardware address is not. If the MAC is also spoofed, fall back to ARP-poisoning tells." },
      ],
    },
    {
      title: "TCP hijacking",
      span2: true,
      blocks: [
        { t: "txt", text: "Sequence numbers are the only real authentication of a TCP segment. Sniff the session, compute the next sequence (last seq + payload length), inject data with the victim's source IP, and <b>block the victim's ACKs</b> so the endpoints cannot resync. Almost always paired with ARP poisoning." },
        { t: "steps", items: [
          "<b>Watch</b> an existing session (Telnet is the classic: plaintext, no integrity).",
          "<b>Predict</b> the next sequence number by arithmetic.",
          "<b>Inject</b> PSH,ACK with attacker data; the server accepts it as the real user.",
          "<b>Silence</b> the real client by dropping its ACKs; it and the server desync (ACK storm, retransmissions).",
        ]},
        { t: "cmd", label: "the retransmission fallout", code: "tcp.analysis.retransmission or tcp.analysis.duplicate_ack" },
        { t: "note", kind: "info", title: "reading a Telnet capture", text: "One character per packet and the server echoes each back, so use Follow TCP Stream and the direction dropdown (client to server only) to read what was typed. The shell prompt (<code>user@host:~$</code>) shows the account." },
        { t: "note", kind: "ok", title: "defenses", text: "SSH or TLS instead of Telnet (injection fails the integrity check), randomized initial sequence numbers, strict RST validation (RFC 5961), Dynamic ARP Inspection and port security." },
      ],
    },
  ],
};
