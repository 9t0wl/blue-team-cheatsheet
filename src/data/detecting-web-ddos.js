export default {
  id: "detecting-web-ddos",
  title: "Detecting Web DoS/DDoS",
  src: "Detecting Web DDoS",
  icon: "🌊",
  cards: [
    {
      title: "The core mechanic",
      blocks: [
        { t: "txt", text: "DoS/DDoS overwhelms a web service either by <b>sheer volume</b> (flooding with requests) or by sending requests <b>crafted to be individually expensive</b> to process — both aim to exhaust a finite server resource (connections, CPU, DB query capacity) until legitimate users can no longer get served." },
      ],
    },
    {
      title: "Six log-based indicators — read together, not individually",
      span2: true,
      blocks: [
        { t: "table", head: ["Indicator", "What it looks like"], rows: [
          ["High request rate", "thousands of requests to one endpoint in a short window"],
          ["Suspicious User-Agent", "curl, scripting-library UAs, outdated/automated-looking strings"],
          ["Geographic anomalies", "traffic suddenly arriving from many unrelated global regions"],
          ["Burst timestamps", "dozens of requests packed into the same 1-second window — automation, not a human"],
          ["Spike in 5xx errors", "a surge of 503s is the server's own signal it's buckling"],
          ["Logic abuse", "requests engineered to be expensive per-request, e.g. ?limit=999999, rather than just high volume"],
        ]},
        { t: "note", kind: "info", title: "no single indicator is conclusive alone", text: "The room's own framing: correlate multiple signals before calling it an attack. A UA spike alone could be a legit new integration; a request-rate spike alone could be a viral traffic event." },
      ],
    },
    {
      title: "Why these endpoints get targeted",
      blocks: [
        { t: "txt", text: "<code>/login</code>, <code>/search</code>, <code>/api/*</code>, <code>/register</code>, <code>/cart</code>/<code>/checkout</code> all trigger disproportionately expensive backend work per request — auth checks, DB queries, session writes, payment processing — versus a static page. Same request volume against <code>/login</code> costs the server far more than against a static homepage, making these the highest-ROI targets for exhausting resources with minimal requests." },
      ],
    },
    {
      title: "Attack pattern in the logs",
      blocks: [
        { t: "steps", items: [
          "Normal baseline traffic.",
          "Attack onset at a specific timestamp — a single source IP hammering one endpoint (e.g. <code>/login.php</code>).",
          "Server resource exhaustion.",
          "<b>Legitimate users start receiving 503s</b> as collateral damage, even though they were never targeted directly.",
        ]},
        { t: "note", kind: "warn", title: "the investigative payoff", text: "A spike in 503s among <i>legitimate</i> clientips is downstream evidence of an attack in progress, not a bug or unrelated outage. \"Which legitimate IP got the first 503 post-attack\" is really asking you to find the moment collateral damage began." },
      ],
    },
    {
      title: "SPL pattern: exclude the known-bad signature, then find the payoff",
      span2: true,
      blocks: [
        { t: "cmd", label: "isolate 503s from non-attacking traffic (swap in the confirmed botnet UA/IP)", code: "index=\"main\" status=503 useragent!=\"<botnet_useragent>\"\n| sort _time\n| head 1\n| table _time clientip status" },
        { t: "note", kind: "info", title: "reusable shape", text: "Identify the bad signature from an earlier finding (UA, IP range, etc.) → exclude it → sort ascending by time → <code>head 1</code> for the first surviving event. Same \"confirm the rule, then filter for the exception\" pivot used in the Wireshark ARP/DNS spoofing investigations." },
        { t: "note", kind: "danger", title: "check the index first", text: "If this returns nothing, don't assume the filter is too aggressive — confirm the base search (<code>index=\"main\" status=503</code>, no exclusions) returns events at all first. See the Query Gotchas section for the full debugging-order breakdown." },
      ],
    },
  ],
};
