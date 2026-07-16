export default {
  id: "ioc-defang",
  title: "IOC Handling — Defanging",
  src: "Phishing / CTI rooms",
  icon: "☣️",
  cards: [
    {
      title: "What & why",
      span2: true,
      blocks: [
        { t: "txt", text: "Converting a live indicator into inert text so it can't be auto-linked, auto-resolved, or accidentally visited. Convention: <code>.</code> → <code>[.]</code>, and <code>http</code> → <code>hxxp</code>." },
        { t: "cmd", label: "example", code: "103.234.236.83   →   103[.]234[.]236[.]83\nhttp://evil.com  →   hxxp://evil[.]com" },
        { t: "note", kind: "info", title: "failure modes it prevents", text: "(1) Auto-linking in Slack/Jira/Outlook → teammate clicks out of habit. (2) Link-preview bots / SIEM integrations auto-fetching the URL. (3) Tipping off the attacker when your infra connects to their C2. (4) Keeps the indicator readable/shareable while inert — trivially re-fanged in a sandbox." },
        { t: "note", kind: "ok", text: "Tool: CyberChef's \"Defang IP Addresses\" / URL recipes. This is a defender convention — attackers want their infra live." },
      ],
    },
  ],
};
