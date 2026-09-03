export default {
  id: "query-gotchas",
  title: "Query Language Gotchas — SPL & KQL",
  src: "Splunk / Elastic rooms",
  icon: "🔎",
  cards: [
    {
      title: "Splunk SPL — pipe semantics",
      blocks: [
        { t: "note", kind: "warn", text: "The pipe <code>|</code> feeds matched events into a processing command (<code>stats</code>, <code>table</code>, <code>spath</code>) — it is <b>never</b> used to add filter conditions. All filters go in the base search, space-separated for implicit AND." },
        { t: "cmd", label: "correct", code: "datasource=\"firewall\" URL=\"*domain*\" | stats count" },
        { t: "cmd", label: "force JSON field extraction if fields don't show", code: "... | spath" },
      ],
    },
    {
      title: "Splunk SPL — an unscoped search can silently return zero results",
      span2: true,
      blocks: [
        { t: "note", kind: "danger", title: "the trap", text: "A query with no/wrong <code>index=</code> can match <b>zero events total</b> — and Splunk doesn't loudly distinguish that from \"your filter correctly excluded everything.\" <code>sort | head 1</code> on an empty result set just returns nothing, which looks identical to \"my exclusion logic was too aggressive.\" Natural instinct is to debug the filter — but the real problem is upstream." },
        { t: "cmd", label: "list every index with any data at all", code: "index=* | stats count by index" },
        { t: "note", kind: "info", title: "debugging order", text: "When a query returns unexpected/empty results: verify the <b>base search alone</b> (no pipes, no exclusions) returns events and is scoped to the right index/sourcetype <i>before</i> troubleshooting filter logic. Check via Data Summary → Indexes, or the query above, rather than assuming <code>main</code> (Splunk's default) is correct." },
      ],
    },
    {
      title: "Timestamps — SIEM-normalized zone vs. your local zone",
      span2: true,
      blocks: [
        { t: "note", kind: "warn", title: "not delayed ingestion, a display mismatch", text: "Logs are normalized to the SIEM's configured time zone, which may not match yours. If you're in UTC-2 but Splunk is normalized to UTC+2, an event at 5:00 PM your time shows as 9:00 PM in Splunk — a 4-hour gap that looks like ingestion lag but is purely a display artifact." },
        { t: "note", kind: "info", title: "check before you build a timeline", text: "Confirm which zone you and the SIEM are each reading in before correlating timestamps across sources — a timeline built on a mismatched assumption puts events in the wrong order relative to each other." },
      ],
    },
    {
      title: "Log normalization — one schema, many raw formats",
      span2: true,
      blocks: [
        { t: "txt", text: "Raw sources arrive in JSON, XML, or plain text, each with its own field names for the same concept. Normalization maps them all into one consistent schema so a single query/table can span multiple log types without re-learning field names per source." },
        { t: "note", kind: "danger", title: "a silent search killer", text: "Bad normalization doesn't error loudly — a field that's clearly present in the raw event text can just not show up in your <code>table</code> output if the parser mapped it under a different field name than you expected. If a field you can see in the raw event won't populate in a table, suspect normalization before suspecting your query syntax." },
      ],
    },
    {
      title: "Elastic time-range picker — a narrow window looks identical to \"nothing here\"",
      span2: true,
      blocks: [
        { t: "note", kind: "danger", title: "the trap", text: "A search that should obviously return a hit can come back with <b>zero results</b> purely because the time-range picker (top-right) doesn't cover it — Kibana gives no warning that events exist just outside the window. This looks exactly like a wrong query or missing data, and the natural instinct is to debug the search terms first." },
        { t: "note", kind: "warn", title: "worked example (Boogeyman 3)", text: "A window set to end exactly at midnight silently hid a credential-dumping-tool download that happened <b>nine minutes past</b> the cutoff — a keyword search for the tool's own name returned nothing, which read as \"this data doesn't exist\" rather than \"my window doesn't cover it.\"" },
        { t: "note", kind: "ok", title: "the fix as a reflex, not a last resort", text: "Whenever a search that should clearly hit comes back empty, <b>widen or check the time range before touching the query</b>. Setting it to a generous multi-day span while exploring unfamiliar data (then narrowing once you've found your footing) avoids the trap entirely." },
      ],
    },
    {
      title: "Wide keyword searches catch real leads and legitimate noise together",
      blocks: [
        { t: "note", kind: "warn", title: "the trap", text: "A broad wildcard like <code>*share*</code> also matches unrelated legitimate software containing the substring — e.g. <code>Microsoft.SharePoint.exe</code> (a normal OneDrive component) shows up right alongside real SMB-share-access commands." },
        { t: "note", kind: "info", title: "validate before chasing a hit", text: "Check <b>integrity level</b> (attacker activity is often elevated; routine background services are usually Medium), <b>publisher/signature</b> (a signed Microsoft binary in its expected install path is a strong benign signal), and whether the path is a normal install location vs. a user-writable temp/staging directory. Once a hit is confirmed real, narrow to a specific suspected cmdlet (<code>cat</code>, <code>Get-Content</code>, <code>Copy-Item</code>) rather than continuing to search broadly." },
      ],
    },
    {
      title: "Elastic KQL — precedence & case",
      blocks: [
        { t: "note", kind: "danger", text: "<code>AND</code> binds tighter than <code>OR</code>. <code>Country:\"US\" and User:\"Albert\" or User:\"james\"</code> parses as <code>(US AND Albert) OR james</code>. Always parenthesize mixed AND/OR." },
        { t: "note", kind: "warn", text: "<code>keyword</code> fields are <b>case-sensitive</b> — a lowercase value silently matches zero docs, quietly collapsing your query. Match field case exactly." },
      ],
    },
  ],
};
