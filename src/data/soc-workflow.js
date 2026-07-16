export default {
  id: "soc-workflow",
  title: "SOC Workflow & Reporting",
  src: "SOC Simulator",
  icon: "🎯",
  cards: [
    {
      title: "Five Ws report template",
      blocks: [
        { t: "table", head: ["W", "Capture"], rows: [
          ["Who", "Sender/recipient + spoofing status (SPF/DKIM)"],
          ["What", "Attack vector + payload"],
          ["When", "Delivery / detection time"],
          ["Where", "Mailbox / system affected"],
          ["Why", "Attacker motive / social-engineering angle"],
        ]},
        { t: "note", kind: "danger", title: "grading gotcha", text: "Graders check each W is <b>visibly, explicitly</b> labeled in every report — don't let \"obvious\" ones (affected mailbox/asset) collapse into implied text, even when it feels repetitive." },
      ],
    },
    {
      title: "TP/FP vs escalation — two separate decisions",
      blocks: [
        { t: "note", kind: "info", text: "<b>TP/FP judges the artifact, not the outcome.</b> A phishing email with zero evidence of a click is still a True Positive if the email itself is malicious — \"no click found\" is a finding, not grounds for FP." },
        { t: "note", kind: "warn", text: "<b>Escalation is driven by realized risk.</b> All alerts can be TP but only some escalate — e.g. when the malicious connection was <b>allowed through</b> rather than blocked, creating real exposure." },
        { t: "txt", text: "<b>Correlate across alerts</b> (shared URL/IP + close timestamps). <b>Reason around missing telemetry</b> — make a risk-based call and document the gap, don't hunt a log source that doesn't exist." },
      ],
    },
  ],
};
