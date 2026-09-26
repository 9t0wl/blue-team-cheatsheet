export default {
  id: "wireless-80211-frames",
  title: "Wireshark — 802.11 Frame Types & Subtypes",
  src: "Wireshark: Wireless (802.11) Traffic Analysis",
  icon: "📡",
  cards: [
    {
      title: "The Frame Control field — where type/subtype live",
      blocks: [
        { t: "txt", text: "Every 802.11 frame starts with a 2-byte <b>Frame Control</b> field. The first two sub-fields split every frame into a <b>Type</b> (2 bits — the big bucket) and a <b>Subtype</b> (4 bits — which specific kind within that bucket)." },
        { t: "table", head: ["Type value", "Category", "What it covers"], rows: [
          ["00", "Management", "Connect/disconnect/announce — beacons, probes, auth, (de)association, deauth"],
          ["01", "Control", "Low-level MAC handshaking that makes reliable delivery work — RTS/CTS, ACK, PS-Poll"],
          ["10", "Data", "Actual payload traffic — what you'd normally think of as \"the packet\""],
          ["11", "Extension", "Reserved / newer amendments (rare in older captures)"],
        ]},
        { t: "note", kind: "info", title: "why filter on both type AND subtype", text: "Subtype numbers repeat across categories (e.g. subtype 0 exists in every type). <code>wlan.fc.type == 00</code> narrows the bucket first, then <code>wlan.fc.type_subtype == 8</code> picks the specific kind inside it — same pattern as picking a folder, then a file." },
        { t: "note", kind: "warn", title: "gotcha — type_subtype is actually already unique on its own", text: "Wireshark's <code>wlan.fc.type_subtype</code> filter field is a <i>combined</i> value computed as <code>(type &lt;&lt; 4) | subtype</code>, so it already bakes the type in — e.g. Beacon is management(0)+8=8, but QoS Data is data(2)+8=40, never a collision. Courseware pairs it with <code>wlan.fc.type</code> for clarity, but <code>wlan.fc.type_subtype == 8</code> alone would already isolate beacons specifically." },
      ],
    },
    {
      title: "Management frame subtypes (type = 00)",
      span2: true,
      blocks: [
        { t: "table", head: ["Subtype #", "Name", "What it's for / blue-team relevance"], rows: [
          ["0", "Association Request", "Client → AP: \"let me join, here's what I support.\" Flood = possible association-flood DoS."],
          ["1", "Association Response", "AP → client: accept/reject. Repeated rejects can mean a client hammering an AP it can't join."],
          ["2 / 3", "Reassociation Request/Response", "Client roaming between APs on the same SSID (or reconnecting) — normal roaming vs. suspicious rapid re-auth."],
          ["4", "Probe Request", "Client actively asking \"is anyone named X here?\" — leaks a device's <i>saved network list</i>, a classic tracking/recon technique."],
          ["5", "Probe Response", "AP answering a probe. Compare an unexpected responder's BSSID against known-good APs — evil-twin tell."],
          ["8", "Beacon", "AP's constant \"here I am\" broadcast (SSID, channel, RSN/security capabilities). <b>Primary evil-twin/rogue-AP detection frame.</b>"],
          ["9", "ATIM", "Power-save announcement in ad-hoc (IBSS) networks — rare outside legacy peer-to-peer Wi-Fi."],
          ["10", "Disassociation", "Graceful \"I'm leaving\" — unlike deauth, implies a prior association existed."],
          ["11", "Authentication", "First step of connecting (open-system or shared-key). Flood = auth-flood DoS against an AP's client table."],
          ["12", "Deauthentication", "Forces a disconnect. <b>No cryptographic protection by default</b> — the entire basis of deauth attacks (Section 4)."],
          ["13", "Action", "Catch-all for extra negotiation (QoS, spectrum management, block-ack setup, etc.)."],
        ]},
        { t: "note", kind: "danger", title: "why management frames are the abuse magnet", text: "Unless 802.11w (Management Frame Protection) is enabled, management frames carry <b>no signature</b> — anything in radio range can forge one with a spoofed source MAC. Deauth (12) and disassociation (10) are the two most commonly weaponized subtypes for exactly this reason." },
      ],
    },
    {
      title: "Control frame subtypes (type = 01)",
      blocks: [
        { t: "table", head: ["Subtype #", "Name", "Purpose"], rows: [
          ["8", "Block Ack Request (BAR)", "Requests a batch acknowledgment for several frames at once (802.11n+ efficiency)"],
          ["9", "Block Ack (BA)", "The batched ack response to a BAR"],
          ["10", "PS-Poll", "Client waking from power-save mode, polling the AP for buffered frames"],
          ["11", "RTS", "Request To Send — reserves the air before a data burst (collision avoidance)"],
          ["12", "CTS", "Clear To Send — the AP/peer's go-ahead in response to an RTS"],
          ["13", "ACK", "Acknowledges receipt of the previous frame — the most common frame type in any capture by raw count"],
          ["14", "CF-End", "Ends a contention-free period"],
        ]},
        { t: "note", kind: "info", title: "blue-team relevance", text: "Control frames are rarely the attack itself — they're mostly reliability plumbing. Their main investigative use is volume/anomaly context (e.g. an abnormal RTS/CTS storm can indicate a hidden-node problem or a deliberate airtime-exhaustion DoS)." },
      ],
    },
    {
      title: "Data frame subtypes (type = 10)",
      blocks: [
        { t: "table", head: ["Subtype #", "Name", "Purpose"], rows: [
          ["0", "Data", "Legacy plain data frame"],
          ["4", "Null (no data)", "Carries no payload — used to signal power-save state changes to the AP"],
          ["8", "QoS Data", "Modern data frame with QoS priority tagging — what almost all real traffic looks like today"],
          ["12", "QoS Null (no data)", "QoS-tagged version of the power-save signal — commonly seen right around a device sleeping/waking"],
        ]},
        { t: "note", kind: "warn", title: "encryption lives here, not in the type field", text: "Whether a data frame's contents are readable depends on the <b>Protected Flags</b> bit in Frame Control plus the actual cipher (WEP/TKIP/CCMP), not on the subtype. An <b>open</b> network's (no RSN in its beacon) data frames are fully cleartext — this is what let Section 5's evil-twin victim's ARP traffic show up unencrypted." },
      ],
    },
    {
      title: "Quick filter cookbook (this module's actual detection filters)",
      span2: true,
      blocks: [
        { t: "cmd", label: "all beacons (evil-twin / rogue-AP hunting — Section 5)", code: "(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)" },
        { t: "cmd", label: "all deauthentication frames (Section 4)", code: "(wlan.bssid == <bssid>) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12)" },
        { t: "cmd", label: "deauth frames using the attack-tool default reason code", code: "(wlan.bssid == <bssid>) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 7)" },
        { t: "cmd", label: "failed-auth / association flood hunting", code: "(wlan.bssid == <bssid>) and (wlan.fc.type == 00) and ((wlan.fc.type_subtype == 0) or (wlan.fc.type_subtype == 1) or (wlan.fc.type_subtype == 11))" },
        { t: "cmd", label: "scope everything to one specific AP/BSSID (evil-twin or legit)", code: "wlan.bssid == <bssid>" },
        { t: "note", kind: "danger", title: "precedence gotcha in the failed-auth filter above", text: "Note the subtype disjunction is fully parenthesized as its own group. Without those inner parens, <code>and X or Y or Z</code> only ANDs the first clause — the last two <code>or</code>s apply globally, not scoped to the BSSID/type anymore. Always wrap a multi-value OR in its own parens when it follows an AND chain." },
      ],
    },
    {
      title: "Reason codes — deauth's \"why\" field",
      blocks: [
        { t: "table", head: ["Code", "Meaning"], rows: [
          ["1", "Unspecified reason"],
          ["2", "Previous authentication no longer valid"],
          ["3", "Station is leaving (deauthenticating on purpose)"],
          ["4", "Disassociated due to inactivity"],
          ["5", "AP is too busy / can't handle more stations"],
          ["7", "\"Class 3 frame from a nonassociated station\" — <b>aireplay-ng/mdk4's hardcoded default</b>"],
          ["8", "Station is leaving the network (disassociating)"],
        ]},
        { t: "note", kind: "info", title: "why code 7 is the tell, not just trivia", text: "Code 7 is logically incoherent for a real AP to send an already-connected client — it only makes sense if something was already broken. Attack tools hardcode it because they need <i>a</i> valid code, not a realistic one. A more evasive attacker rotates codes 1→2→3... to dodge a detection rule that only checks for 7." },
      ],
    },
  ],
};
