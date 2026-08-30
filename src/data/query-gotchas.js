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
      title: "Elastic KQL — precedence & case",
      blocks: [
        { t: "note", kind: "danger", text: "<code>AND</code> binds tighter than <code>OR</code>. <code>Country:\"US\" and User:\"Albert\" or User:\"james\"</code> parses as <code>(US AND Albert) OR james</code>. Always parenthesize mixed AND/OR." },
        { t: "note", kind: "warn", text: "<code>keyword</code> fields are <b>case-sensitive</b> — a lowercase value silently matches zero docs, quietly collapsing your query. Match field case exactly." },
      ],
    },
  ],
};
