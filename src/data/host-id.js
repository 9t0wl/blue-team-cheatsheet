export default {
  id: "host-id",
  title: "Wireshark — Host & User Identification (DHCP / NetBIOS / Kerberos)",
  src: "Wireshark: Traffic Analysis",
  icon: "🪪",
  cards: [
    {
      title: "Why & which protocols",
      blocks: [
        { t: "txt", text: "Beyond IP↔MAC, you often need to pin traffic to a <b>named host or user</b> — the starting point of an investigation. Enterprises name hosts/users by convention, which cuts both ways (easy to inventory, easy for an adversary to blend in)." },
        { t: "table", head: ["Protocol", "Gives you"], rows: [
          ["DHCP", "Hostname, requested/assigned IP, domain, client MAC"],
          ["NetBIOS (NBNS)", "Host name ↔ IP (+ TTL) on the local segment"],
          ["Kerberos", "Usernames, machine accounts, realm (domain), services"],
        ]},
      ],
    },
    {
      title: "DHCP — filter the message type FIRST",
      desc: "Only Option 53 (message type) has fixed values; filter it, then read the rest.",
      span2: true,
      blocks: [
        { t: "cmd", label: "global (older captures use bootp)", code: "dhcp        # or: bootp" },
        { t: "table", head: ["Message", "Option 53 filter", "Carries"], rows: [
          ["DHCP Request", "dhcp.option.dhcp == 3", "Hostname — the client asking for a lease"],
          ["DHCP ACK", "dhcp.option.dhcp == 5", "Accepted — domain name assigned"],
          ["DHCP NAK", "dhcp.option.dhcp == 6", "Denied — read the message (option 56)"],
        ]},
        { t: "note", kind: "info", title: "workflow", text: "Filter the <b>type</b> (opt 53) first, then surface the other options via <b>right-click → Apply as Column</b> or <code>contains</code>/<code>matches</code>. The other options have no fixed enum, so column-and-read beats guessing." },
        { t: "cmd", label: "find a host by name (Request, opt 12)", code: "dhcp.option.hostname contains \"keyword\"" },
        { t: "cmd", label: "find the domain (ACK, opt 15)", code: "dhcp.option.domain_name contains \"keyword\"" },
        { t: "table", head: ["Option", "Meaning", "In"], rows: [
          ["12", "Hostname", "Request"],
          ["50", "Requested IP address", "Request"],
          ["51", "IP lease time", "Request / ACK"],
          ["61", "Client MAC address", "Request"],
          ["15", "Domain name", "ACK"],
          ["56", "Message / rejection reason", "NAK (read, don't filter)"],
        ]},
      ],
    },
    {
      title: "NetBIOS (NBNS)",
      blocks: [
        { t: "txt", text: "Legacy Windows name service — maps a <b>host name ↔ IP</b> on the local segment. Query packets carry the name, TTL, and IP." },
        { t: "cmd", label: "global", code: "nbns" },
        { t: "cmd", label: "find a host by name", code: "nbns.name contains \"keyword\"" },
      ],
    },
    {
      title: "Kerberos — user vs machine account",
      desc: "The AD auth protocol you already know from the attack side.",
      span2: true,
      blocks: [
        { t: "cmd", label: "global", code: "kerberos" },
        { t: "cmd", label: "search an account name", code: "kerberos.CNameString contains \"keyword\"" },
        { t: "note", kind: "warn", title: "the $ trick (key gotcha)", text: "<code>CNameString</code> holds the account name — but values ending in <code>$</code> are <b>machine accounts</b> (hostnames), not users. Same rule as AD: <code>WKSTN01$</code> = computer, <code>jsmith</code> = human. Exclude machines to get real users:" },
        { t: "cmd", label: "users only (drop machine accounts)", code: "kerberos.CNameString and !(kerberos.CNameString contains \"$\")" },
        { t: "table", head: ["Field", "Gives you", "Filter"], rows: [
          ["pvno", "Kerberos version (5)", "kerberos.pvno == 5"],
          ["realm", "Domain name for the ticket", "kerberos.realm contains \".org\""],
          ["sname", "Service + domain of the ticket", "kerberos.SNameString == \"krbtgt\""],
          ["addresses", "Client IP + NetBIOS name (requests only)", "—"],
        ]},
        { t: "note", kind: "danger", title: "room typo", text: "The room writes <code>kerberos.SNameString == \"krbtg\"</code> — the real service is <b><code>krbtgt</code></b> (the ticket-granting service, the same one you Kerberoast/AS-REP against). Use <code>krbtgt</code>." },
        { t: "note", kind: "info", title: "addresses = requests only", text: "The <code>addresses</code> field (client IP + NetBIOS name) appears only in <b>request</b> packets, not responses — so identity mapping comes from the AS-REQ/TGS-REQ side." },
      ],
    },
  ],
};
