export default {
  id: "wireshark-filters",
  title: "Wireshark — Core & Advanced Filters",
  src: "Wireshark: Packet Operations",
  icon: "🦈",
  cards: [
    {
      title: "Protocol filters by OSI layer",
      blocks: [
        { t: "table", head: ["Filter", "Shows"], rows: [
          ["ip", "All IP packets"],
          ["ip.addr == 10.10.10.5", "To OR from that IP (direction-agnostic)"],
          ["ip.addr == 10.10.10.0/24", "Anything involving that subnet"],
          ["ip.src == x / ip.dst == x", "Directional (from / to)"],
          ["tcp.port == 80 / udp.port == 53", "Transport port, either direction"],
          ["tcp.srcport / tcp.dstport", "Directional transport port"],
          ["http / dns", "All app-layer packets of that protocol"],
          ["http.request.method == \"GET\"", "HTTP GET requests"],
          ["http.response.code == 200", "HTTP response code 200"],
        ]},
        { t: "note", kind: "info", title: "key distinction", text: "<code>ip.addr</code> ignores direction; <code>ip.src</code>/<code>ip.dst</code> are directional. Same logic for <code>tcp.port</code> vs <code>tcp.srcport</code>/<code>tcp.dstport</code>." },
      ],
    },
    {
      title: "DNS query/response DUPLICATION trap",
      desc: "The classic doubled-count bug.",
      blocks: [
        { t: "note", kind: "warn", title: "meta-rule", text: "When a Wireshark count comes out ~<b>double</b> what you expect → suspect <b>query/response duplication</b> first, not protocol noise." },
        { t: "txt", text: "<code>dns.qry.type == 1</code> matches A-record packets in <b>both directions</b> — a DNS response echoes the original question, so <code>dns.qry.type</code> exists in the query AND the response. Add a direction filter:" },
        { t: "cmd", label: "queries only", code: "dns.qry.type == 1 && dns.flags.response == 0" },
        { t: "cmd", label: "responses only", code: "dns.qry.type == 1 && dns.flags.response == 1" },
        { t: "note", kind: "danger", title: "why !llmnr does NOT fix it", text: "<code>!llmnr</code> filters by <b>protocol</b> (LLMNR is a separate DNS-like protocol). The extra packets are DNS <b>responses</b>, not LLMNR — direction is the problem, not protocol contamination. A direction filter halves it; protocol exclusion can't." },
        { t: "table", head: ["#", "Record", "Purpose"], rows: [["1", "A", "IPv4 address"], ["28", "AAAA", "IPv6 address"], ["15", "MX", "Mail server"], ["5", "CNAME", "Alias / canonical"]] },
      ],
    },
    {
      title: "string() + matches regex operator",
      blocks: [
        { t: "note", kind: "info", text: "<code>matches</code> is Wireshark's regex operator but works on <b>text only</b>. Integer fields (<code>ip.ttl</code>) must be converted with <code>string()</code> first." },
        { t: "cmd", label: "even TTL (last digit even)", code: "string(ip.ttl) matches \"[02468]$\"" },
        { t: "cmd", label: "odd TTL", code: "string(ip.ttl) matches \"[13579]$\"" },
        { t: "txt", text: "<code>[02468]</code> = char class, <code>$</code> = end anchor → \"last digit is even.\" Parity is decided by the final digit, hence the end anchor." },
      ],
    },
    {
      title: "Checksum validation is preference-gated",
      blocks: [
        { t: "note", kind: "warn", text: "Wireshark leaves TCP/IP checksum validation <b>OFF by default</b> — modern NICs do checksum offloading, so outgoing packets legitimately show \"wrong\" checksums. Validating by default would flood you with false errors." },
        { t: "steps", items: [
          "Switch to a profile that enables validation (room uses <b>Checksum Control</b>) — right-click the profile name at the <b>bottom-right of the status bar</b>.",
          "That profile turns ON \"Validate the TCP checksum if possible\" in TCP preferences.",
          "Then filter bad checksums:",
        ]},
        { t: "cmd", code: "tcp.checksum.status == \"Bad\"" },
        { t: "txt", text: "Numeric equivalent: <code>== 0</code>. Without validation enabled, the filter returns nothing." },
      ],
    },
    {
      title: "Reading results correctly",
      blocks: [
        { t: "note", kind: "danger", title: "never hand-count rows", text: "Always take the count from <code>Displayed: N</code> in the bottom status bar — the packet list pane scrolls and silently hides matches above/below the viewport." },
        { t: "txt", text: "<b>Filter buttons</b> (right end of the display-filter toolbar) are one-click saved filters — <b>profile-specific</b>. Create via <code>Analyze → Display Filter Buttons</code>. <b>Expression builder</b>: <code>Analyze → Display Filter Expression</code> lists every protocol's fields and valid value types." },
      ],
    },
  ],
};
