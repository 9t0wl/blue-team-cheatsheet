export default {
  id: "nmap-detection",
  title: "Wireshark — Nmap Scan Detection & TCP Flags",
  src: "Wireshark: Traffic Analysis",
  icon: "📡",
  cards: [
    {
      title: "TCP flags are a bitmask",
      desc: "Why the decimal values look random — they're sums of set bits.",
      span2: true,
      blocks: [
        { t: "table", head: ["Flag", "Bit value", "Meaning"], rows: [
          ["FIN", "1", "Gracefully close connection"],
          ["SYN", "2", "Start / synchronize a connection"],
          ["RST", "4", "Abort / reject connection"],
          ["PSH", "8", "Push buffered data to app now"],
          ["ACK", "16", "Acknowledging received data"],
          ["URG", "32", "Urgent pointer set"],
        ]},
        { t: "note", kind: "info", title: "the trick", text: "A packet's <code>tcp.flags</code> value is the <b>sum</b> of whichever bits are set. <code>18</code> = SYN(2)+ACK(16). <code>20</code> = RST(4)+ACK(16). Reconstruct any value instead of memorizing." },
        { t: "table", head: ["Match style", "Example", "Matches"], rows: [
          ["Exact value", "tcp.flags == 2", "ONLY that exact bit set — every other flag 0 (strict)"],
          ["Single bit", "tcp.flags.syn == 1", "That bit set — don't care about the rest (loose)"],
        ]},
        { t: "note", kind: "warn", text: "For scan-hunting the <b>loose</b> form is usually what you want — you're isolating a behaviour, not one exact packet shape. Field name for RST is <code>tcp.flags.reset</code> (not <code>.rst</code>)." },
      ],
    },
    {
      title: "TCP Connect scan  (nmap -sT)",
      blocks: [
        { t: "note", kind: "info", text: "<b>Completes</b> the full 3-way handshake. Default for <b>non-privileged</b> users. Window usually <b>&gt; 1024</b> — finished handshake expects real data." },
        { t: "cmd", label: "detection filter", code: "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024" },
      ],
    },
    {
      title: "TCP SYN scan  (nmap -sS)  — half-open / stealth",
      blocks: [
        { t: "note", kind: "info", text: "Does <b>NOT</b> finish the handshake — replies with RST instead of ACK. Requires <b>root</b>. Window usually <b>≤ 1024</b> — connection never finished, no data window needed." },
        { t: "cmd", label: "detection filter", code: "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024" },
        { t: "note", kind: "warn", title: "the -sT vs -sS tell", text: "Both are bare SYN packets. The <b>only</b> distinguishing signal is <b>window size</b>: <code>&gt; 1024</code> (connect) vs <code>&le; 1024</code> (stealth)." },
      ],
    },
    {
      title: "UDP scan  (nmap -sU)",
      blocks: [
        { t: "note", kind: "info", text: "No handshake. <b>Open port</b> → usually silent. <b>Closed port</b> → ICMP error Type 3 / Code 3 (destination unreachable, port unreachable). You detect UDP scans by the ICMP errors closed ports throw back." },
        { t: "cmd", label: "detection filter", code: "icmp.type==3 and icmp.code==3" },
        { t: "note", kind: "warn", title: "ICMP encapsulation", text: "An ICMP error carries a <b>copy of the original request</b> as encapsulated data. Expand the ICMP section in packet details to see which probe triggered it (source IP/port)." },
      ],
    },
    {
      title: "ICMP type/code quick ref",
      blocks: [
        { t: "table", head: ["Type", "Code", "Meaning"], rows: [
          ["3", "3", "Dest unreachable — PORT unreachable (closed UDP)"],
          ["3", "0", "Dest unreachable — Net unreachable"],
          ["3", "1", "Dest unreachable — Host unreachable"],
          ["8", "0", "Echo request (ping)"],
          ["0", "0", "Echo reply (ping response)"],
        ]},
      ],
    },
  ],
};
