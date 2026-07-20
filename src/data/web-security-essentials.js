export default {
  id: "web-security-essentials",
  title: "Web Security Essentials",
  src: "Web Security Essentials",
  icon: "🌐",
  cards: [
    {
      title: "Why web apps get targeted",
      blocks: [
        { t: "txt", text: "Unlike a desktop app, a web app is <b>internet-reachable by default</b> and usually sits in front of sensitive data (customer records, auth tokens, payment info). That makes it both a <b>data source</b> and an <b>entry point</b> into whatever backend/internal systems it talks to — attacking the web app is often the cheapest way in, not the end goal itself." },
      ],
    },
    {
      title: "Core protection toolkit",
      span2: true,
      blocks: [
        { t: "table", head: ["Control", "Specific risk it addresses"], rows: [
          ["CDN / edge caching", "serves cached content from edge servers close to the user — cuts latency AND shields the origin from direct exposure"],
          ["Access logging", "maintain logs so unusual traffic patterns can be investigated later — visibility/forensics, not blocking"],
          ["System hardening", "disable unused ports/services — unused attack surface is still attack surface, exploited or not"],
          ["Antivirus / endpoint protection", "blocks harmful or unauthorized software on the endpoint itself"],
          ["Principle of least privilege", "web server should never run with admin/root — limits blast radius if the process is compromised (e.g. via RCE)"],
        ]},
        { t: "note", kind: "info", title: "why these get quizzed against each other", text: "Several sound similar in isolation — <b>logging vs. AV</b> (audit trail vs. blocking malware), <b>hardening vs. least privilege</b> (shrink attack surface vs. limit privilege level). Each answers a different specific trigger question; don't collapse them into one undifferentiated \"best practices\" bucket." },
      ],
    },
    {
      title: "Further resources (post-path)",
      blocks: [
        { t: "note", kind: "info", title: "for after SOC L1 / SAL1", text: "PortSwigger Web Security Academy (free, huge attack-technique/lab library), APIsec University (free API security courses), TCM Security's web track (Practical Web Hacking / API Hacking / Bug Bounty courses, PWPA/PWP certs)." },
      ],
    },
  ],
};
