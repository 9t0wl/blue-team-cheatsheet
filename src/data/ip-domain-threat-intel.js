export default {
  id: "ip-domain-threat-intel",
  title: "IP & Domain Threat Intel",
  src: "IP and Domain Threat Intel",
  icon: "🛰️",
  cards: [
    {
      title: "Enrichment workflow — raw indicator to actionable intel",
      span2: true,
      blocks: [
        { t: "txt", text: "The goal is turning a bare IP or domain into a full picture an analyst can act on during alert triage: who owns it, where it's hosted, what services are exposed, and whether the infrastructure pattern looks suspicious or benign." },
        { t: "steps", items: [
          "WHOIS / RDAP — ownership + domain age",
          "ASN lookup — who owns the network, what else is hosted there",
          "DNS records — how the domain is configured",
          "TLS certificate details — issuer, validity window, SANs",
          "Service exposure check — what's actually listening",
          "VPN/proxy detection — is the source IP hiding its origin",
        ]},
      ],
    },
    {
      title: "WHOIS / RDAP",
      blocks: [
        { t: "table", head: ["Field", "Why it matters"], rows: [
          ["Registrant / org", "ownership attribution — legitimate business vs. privacy-shielded/anonymous"],
          ["Creation date", "domain age — young domains (days/weeks old) are a strong risk indicator, common for phishing infra"],
          ["Registrar", "some registrars are known to be lax on abuse takedowns"],
          ["Name servers", "can link seemingly-unrelated domains back to the same infrastructure operator"],
        ]},
      ],
    },
    {
      title: "DNS record enrichment — worked example",
      span2: true,
      blocks: [
        { t: "table", head: ["Record", "Finding", "Read"], rows: [
          ["A", "3.222.192.211 — Amazon.com Inc., Ashburn VA, ASN AS14618", "geolocation + hosting-provider attribution; AWS is common for both legit and malicious infra, not conclusive alone"],
          ["AAAA / CNAME", "none present", "IPv4-only, simple hosting setup"],
          ["TXT (SPF)", "includes Mailspike, ends ?all (neutral)", "a neutral SPF policy doesn't hard-fail spoofed mail — worth flagging in a phishing investigation"],
          ["NS", "hosted on csof.net nameservers", "third-party DNS management, not self-hosted"],
          ["MX", "two mail servers, equal priority", "standard redundant mail setup"],
          ["SOA", "primary NS ns1.<domain>, standard refresh/retry/expire", "nothing anomalous in isolation"],
        ]},
        { t: "note", kind: "info", title: "simplicity cuts both ways", text: "No AAAA/CNAME and a straightforward NS/MX setup isn't inherently malicious, but minimal configuration can also indicate quickly-stood-up infrastructure rather than a mature, long-lived legitimate presence." },
      ],
    },
    {
      title: "ASN & hosting context",
      blocks: [
        { t: "txt", text: "The ASN (Autonomous System Number) identifies who owns the network block an IP sits in. Pulling the ASN lets you check what else is hosted on the same network — a cluster of known-bad domains sharing an ASN/IP range is a much stronger signal than any single domain looked at alone." },
      ],
    },
    {
      title: "TLS certificate & service exposure",
      blocks: [
        { t: "txt", text: "Certificate metadata (issuer, SANs, validity window) can reveal related domains under the same cert or a suspiciously short validity period typical of quickly-issued free certs (Let's Encrypt spun up for a short-lived phishing campaign). Service exposure checks (what ports/services actually respond) round out the picture of what an attacker-controlled or compromised host is actually running." },
      ],
    },
    {
      title: "SPF alignment quick reference",
      blocks: [
        { t: "table", head: ["SPF qualifier", "Meaning", "Risk"], rows: [
          ["-all", "hard fail — reject non-matching senders", "low — strict"],
          ["~all", "soft fail — accept but mark suspicious", "medium"],
          ["?all", "neutral — no policy stated", "high — effectively no spoofing protection"],
        ]},
      ],
    },
    {
      title: "Triage checklist — IP/domain enrichment",
      span2: true,
      blocks: [
        { t: "steps", items: [
          "WHOIS/RDAP — who owns it, how old is it",
          "ASN lookup — what network, what else lives there",
          "DNS records (A/AAAA/CNAME/TXT/NS/MX/SOA) — hosting + mail posture",
          "SPF/DKIM/DMARC policy strength if mail-related",
          "TLS cert issuer + validity window",
          "Service exposure — what's actually listening",
          "Cross-check IP/domain reputation (VirusTotal, passive DNS) before ruling benign or malicious",
        ]},
      ],
    },
  ],
};
