// Section registry. To add a new section:
//   1. create src/data/<your-section>.js exporting a default section object
//   2. import it here and add it to the `sections` array (order = page order)
import wiresharkFilters from "./wireshark-filters.js";
import nmapDetection from "./nmap-detection.js";
import arpMitm from "./arp-mitm.js";
import dnsSslMitm from "./dns-ssl-mitm.js";
import snortIds from "./snort-ids.js";
import webSecurityEssentials from "./web-security-essentials.js";
import detectingWebAttacks from "./detecting-web-attacks.js";
import detectingWebShells from "./detecting-web-shells.js";
import hostId from "./host-id.js";
import tunnelling from "./tunnelling.js";
import ftpAnalysis from "./ftp-analysis.js";
import httpAnalysis from "./http-analysis.js";
import exfilQuickref from "./exfil-quickref.js";
import httpsDecrypt from "./https-decrypt.js";
import cleartextCreds from "./cleartext-creds.js";
import firewallAcl from "./firewall-acl.js";
import smtpEmail from "./smtp-email.js";
import emailAuth from "./email-auth.js";
import iocDefang from "./ioc-defang.js";
import logPivot from "./log-pivot.js";
import socWorkflow from "./soc-workflow.js";
import pyramid from "./pyramid.js";
import queryGotchas from "./query-gotchas.js";

export const sections = [
  wiresharkFilters,
  nmapDetection,
  arpMitm,
  dnsSslMitm,
  snortIds,
  webSecurityEssentials,
  detectingWebAttacks,
  detectingWebShells,
  hostId,
  tunnelling,
  ftpAnalysis,
  httpAnalysis,
  exfilQuickref,
  httpsDecrypt,
  cleartextCreds,
  firewallAcl,
  smtpEmail,
  emailAuth,
  iocDefang,
  logPivot,
  socWorkflow,
  pyramid,
  queryGotchas,
];

export { config } from "./config.js";
