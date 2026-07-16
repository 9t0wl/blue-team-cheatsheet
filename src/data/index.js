// Section registry. To add a new section:
//   1. create src/data/<your-section>.js exporting a default section object
//   2. import it here and add it to the `sections` array (order = page order)
import wiresharkFilters from "./wireshark-filters.js";
import nmapDetection from "./nmap-detection.js";
import arpMitm from "./arp-mitm.js";
import hostId from "./host-id.js";
import tunnelling from "./tunnelling.js";
import ftpAnalysis from "./ftp-analysis.js";
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
  hostId,
  tunnelling,
  ftpAnalysis,
  smtpEmail,
  emailAuth,
  iocDefang,
  logPivot,
  socWorkflow,
  pyramid,
  queryGotchas,
];

export { config } from "./config.js";
