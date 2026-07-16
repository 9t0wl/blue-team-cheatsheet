export default {
  id: "email-auth",
  title: "Email Authentication — SPF / DKIM / DMARC",
  src: "The Greenholt Phish",
  icon: "🔐",
  cards: [
    {
      title: "SPF qualifiers (the -all family)",
      blocks: [
        { t: "txt", text: "SPF = DNS TXT record listing authorized sending servers. Qualifier before <code>all</code> sets what happens to anything NOT listed:" },
        { t: "table", head: ["Qualifier", "Result"], rows: [
          ["-all", "Fail / hard fail (reject)"],
          ["~all", "SoftFail (flag, don't block)"],
          ["?all", "Neutral (no opinion)"],
          ["+all", "Pass — anyone allowed (never use)"],
        ]},
        { t: "note", kind: "info", text: "SPF's qualifier is <b>advisory</b> — the receiving server decides how strictly to honor it. SPF validates the <b>Return-Path</b> (envelope MAIL FROM), NOT the visible <code>From:</code> header." },
      ],
    },
    {
      title: "DMARC policy + alignment",
      blocks: [
        { t: "txt", text: "Separate TXT record at <code>_dmarc.domain.com</code>, on top of SPF+DKIM. Adds alignment (does SPF/DKIM domain match visible From:) and a <code>p=</code> policy:" },
        { t: "table", head: ["p= value", "Action on fail"], rows: [
          ["p=none", "Report only (deliver anyway)"],
          ["p=quarantine", "Send to spam folder"],
          ["p=reject", "Bounce, don't deliver"],
        ]},
        { t: "note", kind: "warn", text: "SPF's <code>-all</code> and DMARC's <code>p=reject</code> sound identical but live in different records. A domain can have <code>-all</code> with zero DMARC — enforcement then depends entirely on each receiver." },
      ],
    },
    {
      title: "Terminal lookups",
      blocks: [
        { t: "note", kind: "danger", title: "DMARC lives at _dmarc.", text: "SPF is on the apex domain; DMARC is ALWAYS on the <code>_dmarc.</code> subdomain. Querying the apex will never show DMARC." },
        { t: "cmd", label: "SPF (apex)", code: "dig txt example.com +short" },
        { t: "cmd", label: "DMARC (_dmarc subdomain)", code: "dig txt _dmarc.example.com +short" },
        { t: "cmd", label: "resolve SPF+DMARC together, follow includes", code: "checkdmarc example.com   # pip install checkdmarc" },
      ],
    },
  ],
};
