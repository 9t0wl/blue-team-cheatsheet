export default {
  id: "smtp-email",
  title: "Wireshark — SMTP & Email Analysis",
  src: "Phishing Prevention",
  icon: "✉️",
  cards: [
    {
      title: "Bare field matches existence, not value",
      blocks: [
        { t: "note", kind: "danger", text: "<code>smtp.response.code</code> alone matches EVERY packet where the field exists (220, 421, 550…all mixed). Use an explicit comparison when asking about one value:" },
        { t: "cmd", code: "smtp.response.code == 220" },
      ],
    },
    {
      title: "Find Packet vs display filter",
      blocks: [
        { t: "txt", text: "<b>Display filter bar</b> — structured/dissected fields: <code>smtp.response.code == 220</code>, <code>imf contains \"invoice.scr\"</code>." },
        { t: "txt", text: "<b>Edit → Find Packet</b> (Ctrl+F, String/Regex) — free-text search across raw bytes when you don't know the field name, e.g. finding <code>spamhaus.org</code> inside a rejection message." },
      ],
    },
    {
      title: "IMF dissection (Internet Message Format)",
      blocks: [
        { t: "txt", text: "When SMTP DATA carries a full email, Wireshark nests an <b>IMF</b> sub-layer exposing parsed headers/body/MIME. Filter <code>imf</code> to isolate packets with full email bodies." },
        { t: "table", head: ["Looking for", "Where"], rows: [
          ["Attachment name", "IMF → MIME Multipart → Content-Disposition: attachment; filename=…"],
          ["Sending client/software", "X-Mailer header (under IMF)"],
        ]},
        { t: "note", kind: "warn", title: ".scr gotcha", text: "<code>.scr</code> (Windows screensaver) is a renamed executable — auto-executes like <code>.exe</code> but looks less alarming. Classic malware-delivery disguise." },
      ],
    },
  ],
};
