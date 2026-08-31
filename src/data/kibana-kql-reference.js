export default {
  id: "kibana-kql-reference",
  title: "Kibana / KQL — Query Language Reference",
  src: "General reference, growing as SIEM Triage for SOC progresses",
  icon: "🔷",
  cards: [
    {
      title: "Kibana has no pipe chain — that's the biggest mental shift from Splunk",
      span2: true,
      blocks: [
        { t: "txt", text: "SPL builds a query as base search followed by a chain of processing commands (<code>| table</code>, <code>| stats</code>, <code>| eval</code>...). KQL is just the base-search half — a single filter expression. Everything else (adding columns, sorting, aggregating) happens through the Kibana UI instead of more query syntax." },
        { t: "table", head: ["Task", "Splunk (SPL)", "Kibana (KQL + UI)"], rows: [
          ["Scope to a source", "index=<idx>", "_index:<name> (data view may span multiple indices)"],
          ["Add a column", "| table field1 field2", "click the + next to a field in the left-hand field list"],
          ["Sort oldest-first", "| sort + _time", "click the arrow on the @timestamp column header"],
          ["Filter a computed value", "| where <expr>", "no direct equivalent — KQL filters raw/parsed fields only, not eval'd values"],
          ["Aggregate/count", "| stats count by field", "Field statistics tab, or a Lens/visualization panel — not inline in the query bar"],
        ]},
        { t: "note", kind: "info", title: "field discovery leans on the UI more than Splunk does", text: "With no <code>stats</code> pivot to type, finding what fields exist and what values they hold happens by browsing the left-hand field panel (click a field to see its top values) rather than composing an aggregation query." },
      ],
    },
    {
      title: "Setting up the environment before you query anything",
      span2: true,
      blocks: [
        { t: "table", head: ["Setting", "What to do", "Why"], rows: [
          ["Data view", "select the correct data view (e.g. \"Alert Triage With Elastic\") from the dropdown", "a data view can span multiple underlying indices — picking the wrong one silently limits what you can search"],
          ["Time range", "set to Entire data range before investigating unfamiliar data", "same trap as Splunk's default time-range picker — a narrow window silently drops events outside it with no error"],
          ["Index scoping within a data view", "_index:<name> in the query bar", "narrows a multi-index data view to just the source you're investigating (e.g. weblogs vs. the Windows/Sysmon index)"],
        ]},
      ],
    },
    {
      title: "KQL syntax essentials",
      span2: true,
      blocks: [
        { t: "table", head: ["Syntax", "Meaning"], rows: [
          ["field:value", "exact/term match"],
          ["field:\"exact phrase\"", "phrase match — needed when the value contains spaces"],
          ["field1:value1 and field2:value2", "implicit AND written explicitly — required in KQL, unlike Splunk's space-separated implicit AND"],
          ["field1:value1 or field2:value2", "OR — lowercase, unlike SPL where OR must be uppercase"],
          ["not field:value", "negation"],
          ["field:*", "field exists (any value)"],
          ["field >= value / field <= value", "range comparison — works on numbers and ISO 8601 timestamps alike"],
        ]},
        { t: "note", kind: "warn", title: "lowercase booleans — the trap when switching stacks mid-session", text: "Typing <code>OR</code> in KQL doesn't error, but muscle memory from SPL (where OR must be uppercase) can make you second-guess correct KQL syntax. KQL's and/or/not are case-insensitive in practice but conventionally written lowercase." },
      ],
    },
    {
      title: "Timestamp range filtering — reads almost like SQL",
      span2: true,
      blocks: [
        { t: "cmd", label: "everything from a known alert time forward", code: "@timestamp >= \"2025-07-20T05:11:22\"" },
        { t: "cmd", label: "bounded range", code: "@timestamp >= \"2025-07-20T05:11:22\" and @timestamp <= \"2025-07-20T05:30:00\"" },
        { t: "note", kind: "info", title: "no earliest=/latest= modifier syntax needed", text: "Unlike SPL's <code>earliest=</code>/<code>latest=</code> query modifiers, KQL timestamp filtering is a direct comparison against an ISO 8601 string, inline with the rest of the filter expression. A common investigative pattern: take the timestamp confirmed by one query and feed it as the lower bound of the next, letting each subsequent query build on the last confirmed event rather than re-scoping by index/host every time." },
      ],
    },
    {
      title: "Cross-log-source correlation — a plain `or`, no join needed",
      span2: true,
      blocks: [
        { t: "cmd", label: "pull two structurally different event types into one time-ordered view", code: "@timestamp >= \"2025-07-20T05:13:15\" and (winlog.event_id:4732 or process.parent.name:cmd.exe)" },
        { t: "note", kind: "info", title: "why this works without a join/transaction command", text: "ECS (Elastic Common Schema) normalizes field names across log types before they ever hit the index — <code>user.name</code>, <code>process.parent.name</code> mean the same thing whether the event came from Sysmon, PowerShell logging, or Windows Security. That shared schema is what makes an <code>or</code> across two different event sources produce a coherent combined table, something SPL usually needs <code>rex</code>-extracted custom field names to line up." },
      ],
    },
    {
      title: "winlog.task — filter by human-readable category, not just event ID",
      blocks: [
        { t: "cmd", label: "find account-management activity without knowing the exact event ID first", code: "winlog.channel:Security and winlog.task:\"User Account Management\"" },
        { t: "note", kind: "info", text: "Useful when you know <i>what kind</i> of activity you're hunting (account creation, group management, logon) but don't have the exact numeric event ID memorized yet — <code>winlog.task</code> gives a plain-English category to filter on directly." },
      ],
    },
    {
      title: "Splunk ↔ Kibana quick-translate",
      span2: true,
      blocks: [
        { t: "table", head: ["Concept", "Splunk (SPL)", "Kibana (KQL)"], rows: [
          ["Source scoping", "index=<idx>", "_index:<name>"],
          ["Event-code filter", "EventCode=4624", "winlog.event_id:4624"],
          ["Sourcetype", "sourcetype=<st>", "mostly implicit — ECS pre-normalizes via _index / event.module"],
          ["Field extraction from raw text", "rex field=_raw \"...\"", "largely unnecessary — ECS fields (process.*, winlog.*, powershell.*) arrive pre-parsed"],
          ["Build a table", "| table f1 f2 f3", "click + next to each field in the left panel"],
          ["Sort oldest first", "| sort + _time", "click the @timestamp column header arrow"],
          ["Time-bound the query", "earliest=... latest=...", "@timestamp >= \"...\" and @timestamp <= \"...\""],
          ["AND / OR case", "OR must be uppercase", "and/or conventionally lowercase"],
        ]},
        { t: "note", kind: "warn", title: "one real gap: no where-style post-aggregation filter", text: "SPL's <code>| where count > N</code> (filtering on a value computed by an earlier <code>stats</code>) has no direct KQL equivalent in the query bar — that kind of thresholding moves into a Lens visualization or a scripted/runtime field instead of staying inline in the search." },
      ],
    },
  ],
};
