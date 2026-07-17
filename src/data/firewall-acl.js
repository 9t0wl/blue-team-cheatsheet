export default {
  id: "firewall-acl",
  title: "Bonus — Actionable Results (Firewall ACL Rules)",
  src: "Wireshark: Traffic Analysis (room capstone)",
  icon: "🧱",
  cards: [
    {
      title: "From detection to action — generating real firewall rules",
      span2: true,
      blocks: [
        { t: "txt", text: "Not every investigation ends with a report to another team — sometimes the analyst who spots the anomaly is also the one who has to block it. Wireshark can generate ready-to-implement firewall rules directly from a selected packet, based on its IP, port, and/or MAC address." },
        { t: "cmd", label: "menu path — select a packet first, then:", code: "Tools → Firewall ACL Rules" },
        { t: "note", kind: "danger", title: "these target an OUTSIDE firewall interface", text: "Rules are generated for implementation on a perimeter/external firewall device — not Wireshark's own host. Review before deploying; this is a drafting tool, not an enforcement point." },
        { t: "table", head: ["Supported target", "Syntax family"], rows: [
          ["Netfilter (iptables)", "Linux"],
          ["Cisco IOS (standard/extended)", "Cisco ACLs"],
          ["IP Filter (ipfilter)", "Solaris/BSD"],
          ["IPFirewall (ipfw)", "FreeBSD/BSD"],
          ["Packet filter (pf)", "OpenBSD/BSD"],
          ["Windows Firewall", "netsh, old or new format"],
        ]},
      ],
    },
    {
      title: "The window mechanics",
      blocks: [
        { t: "txt", text: "Pick a target syntax from the <b>Create rules for</b> dropdown. Wireshark then lists rule combinations for that packet: source/destination IPv4, source/destination port, and combinations of the two." },
        { t: "note", kind: "info", title: "Allow/Deny and Inbound/Outbound checkboxes flip the generated syntax", text: "The same underlying address/port data gets rewritten as either an <b>allow</b> or <b>deny</b> rule, and either <b>in</b> or <b>out</b> direction, purely based on which checkboxes are ticked at the bottom of the window — you don't need to hand-edit the generated line, just toggle the checkbox for the variant you need." },
      ],
    },
    {
      title: "Example — Netfilter (iptables) output",
      blocks: [
        { t: "cmd", label: "IPv4 source address, deny+inbound", code: "iptables --append INPUT --in-interface eth0 --source 10.234.125.254/32 --jump DROP" },
        { t: "cmd", label: "source port, deny+inbound", code: "iptables --append INPUT --in-interface eth0 --protocol tcp --source-port 2235 --jump DROP" },
        { t: "note", kind: "info", text: "Notice the address gets a <code>/32</code> host mask automatically — a single-IP rule, not a subnet block." },
      ],
    },
    {
      title: "IPFirewall (ipfw) syntax — confirmed templates",
      desc: "BSD ipfw's rule grammar, derived from the exercise's own answer format.",
      span2: true,
      blocks: [
        { t: "cmd", label: "deny a source IPv4 address", code: "add deny ip from <source-ip> to any in" },
        { t: "cmd", label: "allow a destination MAC address", code: "add allow MAC <destination-mac> any in" },
        { t: "note", kind: "ok", title: "reading the grammar", text: "ipfw's shape is <code>add {allow|deny} &lt;proto&gt; from &lt;src&gt; to &lt;dst&gt; [in|out]</code> for IP-layer rules, and <code>add {allow|deny} MAC &lt;dst-mac&gt; &lt;src-mac&gt; [in|out]</code> for layer-2 rules — matching one side to <code>any</code> leaves the other unrestricted, which is how a single-sided (source-only or destination-only) rule gets expressed." },
      ],
    },
  ],
};
