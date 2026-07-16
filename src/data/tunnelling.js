export default {
  id: "tunnelling",
  title: "Wireshark — Tunnelling Traffic (ICMP & DNS)",
  src: "Wireshark: Traffic Analysis",
  icon: "🕳️",
  cards: [
    {
      title: "The core idea — legit protocol, illegitimate payload",
      span2: true,
      blocks: [
        { t: "txt", text: "ICMP and DNS are almost never blocked outbound (ping and name resolution have to work), which makes them ideal covert channels. Both attacks smuggle arbitrary data inside a protocol that firewalls wave through — <b>the protocol looks fine; the payload is the tell.</b>" },
        { t: "table", head: ["Channel", "Where the data hides", "The tell"], rows: [
          ["ICMP tunnel", "The echo request/reply data field", "Abnormally large / variable payload size"],
          ["DNS tunnel", "The query name (subdomain labels)", "Long, high-entropy labels + one dominant parent domain"],
        ]},
        { t: "note", kind: "info", title: "same root lesson as ARP/MITM", text: "IP looked fine during the MITM — MAC told the truth. Here the protocol looks fine — <b>payload size/shape</b> tells the truth." },
      ],
    },
    {
      title: "ICMP tunnelling — the size tell",
      blocks: [
        { t: "txt", text: "A normal ping carries a small, fixed filler payload — Windows ≈ 32 bytes, Linux ≈ 48 bytes. A tunnel (e.g. <code>icmpsh</code>, <code>ptunnel</code>) stuffs real data into that field instead." },
        { t: "cmd", label: "abnormally large ICMP payload", code: "icmp && data.len > 64" },
        { t: "note", kind: "warn", text: "Also watch for high <b>volume/frequency</b> of ICMP between the same two hosts — a real ping conversation is bursty and short; a tunnel is a sustained, regular stream." },
      ],
    },
    {
      title: "DNS tunnelling — the query-name tell",
      blocks: [
        { t: "txt", text: "Data gets hex/base32/base64-encoded into <b>subdomain labels</b>. Because a single DNS label caps at <b>63 bytes</b>, a large chunk of stolen data gets split across <b>several long labels</b> chained together before the real domain." },
        { t: "cmd", label: "start wide — legit long domains WILL show up too", code: "dns.qry.name.len > 15 and !mdns" },
        { t: "note", kind: "danger", title: "false positives at low thresholds", text: "Real telemetry/connectivity-check domains (<code>v10.events.data.microsoft.com</code>, <code>connectivity-check.ubuntu.com</code>) are also \"long\" — don't stop at the first hits. Push the threshold higher to cut past them:" },
        { t: "cmd", label: "narrower — skips most legit domains", code: "dns.qry.name.len > 40 and !mdns" },
        { t: "note", kind: "ok", title: "the reliable method: pivot by parent domain", text: "Group queries by their <b>last two labels</b> (the registrable domain) and count occurrences — same <code>sort | uniq -c</code> pattern as CLI log pivoting. A tunnel shows one parent domain with a <b>massive number of unique subdomain queries</b>; nothing legitimate does that." },
        { t: "cmd", label: "terminal pivot — find the dominant parent domain", code: "tshark -r dns.pcap -T fields -e dns.qry.name -Y \"dns.flags.response==0 and !mdns\" \\\n  | awk -F. '{print $(NF-1)\".\"$NF}' \\\n  | sort | uniq -c | sort -nr | head -20" },
      ],
    },
    {
      title: "Worked example — dataexfil.com",
      desc: "Real query name pulled from an exercise pcap.",
      span2: true,
      blocks: [
        { t: "cmd", label: "the anomalous query (truncated)", code: "A8D603B0DE...9AF29E902AB2....2030742EDA1B513B....441119E94628EA35FFF9.dataexfil.com   (MX)\nName Length: 162   Label Count: 5" },
        { t: "note", kind: "danger", title: "reading the structure", text: "3 near-maximal hex-encoded labels (~63 bytes each, the DNS label ceiling) chained before the real domain <code>dataexfil.com</code>. Each label = one chunk of exfiltrated data; the attacker's own authoritative nameserver for that domain receives, logs, and decodes every query." },
        { t: "note", kind: "warn", title: "why MX/CNAME instead of plain A", text: "Real tools (<code>dnscat2</code>, <code>iodine</code>) rotate record types — some carry more payload per response, and rotation helps the traffic blend in / route around resolvers that restrict certain query types. Don't assume tunneling only rides on TXT or A." },
        { t: "txt", text: "<b>Answer:</b> suspicious main domain = <code>dataexfil[.]com</code> (defanged). The random subdomain is the payload; the registrable domain (last two labels) is the actual answer to \"which domain.\"" },
      ],
    },
  ],
};
