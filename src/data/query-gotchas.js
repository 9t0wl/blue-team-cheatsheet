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
      title: "Elastic KQL — precedence & case",
      blocks: [
        { t: "note", kind: "danger", text: "<code>AND</code> binds tighter than <code>OR</code>. <code>Country:\"US\" and User:\"Albert\" or User:\"james\"</code> parses as <code>(US AND Albert) OR james</code>. Always parenthesize mixed AND/OR." },
        { t: "note", kind: "warn", text: "<code>keyword</code> fields are <b>case-sensitive</b> — a lowercase value silently matches zero docs, quietly collapsing your query. Match field case exactly." },
      ],
    },
  ],
};
