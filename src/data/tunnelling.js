export default {
  id: "tunnelling",
  title: "Wireshark — Tunnelling Traffic (ICMP, DNS, Telnet & UDP)",
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
    {
      title: "ICMP tunnel — more tells beyond size",
      blocks: [
        { t: "table", head: ["Trait", "Normal ping", "Tunnel"], rows: [
          ["Data length", "48 bytes (98 on wire)", "Larger, or fragmented"],
          ["ICMP id", "Fixed per session", "Often 0x0000, or constant on every packet"],
          ["ICMP seq", "Counts 1, 2, 3", "Stuck at 0/0"],
          ["Direction", "Small request, echo back", "Payload in BOTH request and reply"],
          ["Cadence", "Bursty, short", "Regular heartbeat (about 1 per second) plus bursts"],
        ]},
        { t: "note", kind: "danger", title: "read the payload — a whole protocol can ride inside", text: "In the hex/ASCII pane of a reassembled reply, a full <code>HTTP/1.1 200 OK</code> response with <code>Content-Disposition: attachment; filename=...tgz</code> was visible: a file download carried inside ICMP echo replies. Always look at the bytes, not just the size." },
        { t: "cmd", label: "decode a base64 payload copied from the data field", code: "echo '<string>' | base64 -d" },
        { t: "note", kind: "warn", text: "Base64 needs a whole unit starting on a boundary. A mid-buffer slice decodes to garbage; copy one clean repetition." },
      ],
    },
    {
      title: "DNS — record types, decode layers, enumeration",
      span2: true,
      blocks: [
        { t: "table", head: ["Filter", "Finds"], rows: [
          ["dns.qry.type == 10", "NULL records. Almost never legitimate; iodine-style tunnels use them"],
          ["dns.qry.type == 16", "TXT records. Data smuggling, also SPF/verification noise"],
          ["dns.qry.type == 255", "ANY queries. Enumeration, or amplification when spoofed"],
          ["dns.qry.type == 252", "AXFR zone transfer requests. Asks for the whole zone"],
          ["dns.flags.rcode == 3", "NXDOMAIN storms. Flooding or subdomain guessing"],
        ]},
        { t: "note", kind: "info", title: "base64 layer tells for flag-style or HTB text", text: "One layer of <code>HTB{...}</code> starts <code>SFRC</code>. Two layers start <code>U0ZSQ</code>. Three layers start <code>VTBaU</code>. Seeing the prefix tells you how many decodes to chain (CyberChef: chain From Base64, keep Remove non-alphabet chars on)." },
        { t: "note", kind: "warn", title: "enumeration vs tunneling", text: "<b>Enumeration</b> = many queries from one host, guessed subdomains, ANY/PTR/AXFR types. <b>Tunneling</b> = payload in the names or record data (long high-entropy labels, TXT/NULL, blobs), often modest volume to one parent domain. Also watch IPFS gateway lookups (<code>cloudflare-ipfs.com/ipfs/...</code>), used to host payloads peer-to-peer." },
      ],
    },
    {
      title: "Telnet, IPv6 and UDP as tunnels",
      span2: true,
      blocks: [
        { t: "txt", text: "Same idea, different carrier. <b>Protocols are not tied to ports</b>: identify by content, not by port number." },
        { t: "cmd", label: "Telnet on the standard port, and on any odd port", code: "telnet\ntcp.port == 9999" },
        { t: "cmd", label: "Telnet over IPv6 for one host (fill in the address)", code: "(ipv6.src_host == <ipv6> or ipv6.dst_host == <ipv6>) and telnet" },
        { t: "cmd", label: "any UDP that is not an expected service", code: "udp and !dns and !dhcp and !snmp" },
        { t: "table", head: ["Carrier", "Why attackers use it", "How to read it"], rows: [
          ["Telnet, any port", "Plaintext, easy tunnel; port can be changed", "Follow TCP Stream. Real Telnet negotiates options (0xFF IAC) at the start"],
          ["IPv6 link-local", "Unwatched side channel on an IPv4-only network", "Follow TCP Stream; ICMPv6 neighbor discovery around it is a hint"],
          ["UDP", "Connectionless (no handshake), often monitored less than TCP", "Follow UDP Stream; sustained uniform flows to an unknown port"],
        ]},
        { t: "note", kind: "info", title: "legitimate UDP to baseline against", text: "Real-time media and gaming, DNS, DHCP, SNMP, TFTP. Anything outside that list, or unusual volume to one peer, needs a look." },
        { t: "note", kind: "ok", title: "EUI-64 link-local addresses leak the MAC", text: "<code>fe80::468a:5bff:fe95:682a</code> has <code>ff:fe</code> in the middle; drop it, flip the universal/local bit of the first byte (<code>46</code> becomes <code>44</code>) and you get <code>44:8a:5b:95:68:2a</code>. The initiator's random-looking address is the privacy-style variant, which does not embed a MAC." },
      ],
    },
    {
      title: "Classify it: flooding vs tunneling vs Smurf vs amplification",
      desc: "From the Skills Assessment. Shape first, payload second, then eliminate.",
      span2: true,
      blocks: [
        { t: "table", head: ["Attack", "Shape", "Payload / tell"], rows: [
          ["ICMP flooding", "One source to one target at a high rate", "Ordinary small echoes, nothing meaningful inside"],
          ["ICMP tunneling", "Two peers, request and reply pairs, heartbeat", "Fixed id, seq 0/0, varying sizes, readable or encoded data"],
          ["ICMP Smurf", "Victim receives echo REPLIES it never requested", "No matching request from the victim; reflectors reply to a spoofed source"],
          ["DNS flooding", "Huge query volume at a server", "Random or non-existent names, NXDOMAIN storm, no payload"],
          ["DNS amplification", "Small spoofed ANY queries, big answers to a victim", "Response size much larger than query, answers land on a host that never asked"],
          ["DNS tunneling", "Two hosts, query/response pairs", "NULL/TXT types, long random labels under one parent domain, payload in answers"],
        ]},
        { t: "note", kind: "danger", title: "verify against the data, not the textbook", text: "Course Smurf file had exactly ONE reflector (Statistics, Conversations, then Endpoints showed one pair), even though the theory describes many. Count with <code>Statistics &gt; Conversations</code> and <code>Endpoints</code> before assuming a pattern. Also: answer with the option text exactly as written." },
      ],
    },
  ],
};
