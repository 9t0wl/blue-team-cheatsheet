export default {
  id: "splunk-spl-reference",
  title: "Splunk SPL — Query Language Reference",
  src: "General reference, growing as SIEM Triage for SOC progresses",
  icon: "🧮",
  cards: [
    {
      title: "How a search is built — anatomy of the pipe chain",
      span2: true,
      blocks: [
        { t: "txt", text: "Everything before the first <code>|</code> is the <b>base search</b> — it hits the index and filters raw events. Everything after a <code>|</code> is a <b>processing command</b> (stats, eval, table, rex...) that transforms whatever the previous stage handed it. Filters belong in the base search, space-separated for implicit AND; a pipe never adds a filter condition, it only reshapes results." },
        { t: "cmd", label: "shape", code: "index=<idx> sourcetype=<st> field=value \"exact phrase\"\n| <command 1>\n| <command 2>\n| ..." },
        { t: "table", head: ["Base-search syntax", "Meaning"], rows: [
          ["field=value", "exact field match"],
          ["\"exact phrase\"", "literal substring match anywhere in the raw event"],
          ["value1 OR value2", "OR is case-sensitive, must be uppercase"],
          ["NOT value / field!=value", "exclusion"],
          ["field=value*", "wildcard — leading/trailing/both"],
        ]},
        { t: "note", kind: "info", title: "see also", text: "Index-scoping and normalization pitfalls that trip up an otherwise-correct pipe chain are covered in the <b>Query Language Gotchas</b> section — check there first if a query returns nothing unexpected." },
      ],
    },
    {
      title: "rex — pulling structured fields out of raw text",
      span2: true,
      blocks: [
        { t: "txt", text: "Not every source is pre-parsed into clean fields — plain-text logs (auth.log, syslog) usually aren't. <code>rex</code> runs a regex against a field (default <code>_raw</code>) and creates a new field per named capture group <code>(?&lt;name&gt;...)</code>. Once extracted, that field works in every later pipe stage exactly like a native field — filterable, groupable, tableable." },
        { t: "cmd", label: "extract hostname from an ISO timestamp prefix", code: "| rex field=_raw \"^\\d{4}-\\d{2}-\\d{2}T[^\\s]+\\s+(?<log_hostname>\\S+)\"" },
        { t: "cmd", label: "extract action/username/source IP from an sshd auth line", code: "| rex field=_raw \"sshd\\[\\d+\\]:\\s*(?<action>Failed|Accepted)\\s+\\S+\\s+for(?: invalid user)? (?<username>\\S+) from (?<src_ip>\\d{1,3}(?:\\.\\d{1,3}){3})\"" },
        { t: "note", kind: "warn", title: "extracted fields don't retroactively filter the base search", text: "A field created by <code>rex</code> only exists from that pipe stage onward — you can't reference it in the base search before the <code>rex</code> line. Filter on it with a <code>| search field=value</code> stage placed <i>after</i> the rex." },
      ],
    },
    {
      title: "stats — the aggregation workhorse",
      span2: true,
      blocks: [
        { t: "table", head: ["Function", "Returns"], rows: [
          ["count", "number of matching events"],
          ["dc(field)", "distinct count — how many unique values a field took"],
          ["values(field)", "every unique value, as a multivalue list"],
          ["list(field)", "every value including duplicates, in order"],
          ["sum(field) / avg(field)", "total / mean of a numeric field"],
          ["min(field) / max(field)", "smallest / largest value"],
          ["earliest(_time) / latest(_time)", "oldest / newest timestamp in the result set (epoch seconds)"],
          ["range(_time)", "latest − earliest in one step — the duration shortcut"],
        ]},
        { t: "cmd", label: "shape — aggregate, grouped by a field", code: "| stats count values(src_ip) as src_ip by username" },
        { t: "note", kind: "info", title: "\"by\" is a group-by, not a filter", text: "<code>stats ... by username</code> produces one row per distinct username with the aggregates computed per group — same mental model as SQL <code>GROUP BY</code>. Chain <code>| where count &gt; N</code> or <code>| sort -count</code> afterward to narrow or rank the grouped results." },
      ],
    },
    {
      title: "Duration / \"how long did this last\" — the reusable pattern",
      span2: true,
      blocks: [
        { t: "txt", text: "Any question phrased as duration, how many minutes/hours, or time elapsed reduces to the same shape: scope down to just the events that bound the activity, then let stats do the subtraction — never hand-calculate timestamps." },
        { t: "cmd", label: "two-field version — readable start/end plus the delta", code: "| stats earliest(_time) as first_seen, latest(_time) as last_seen\n| eval duration_min = round((last_seen - first_seen) / 60, 2)\n| eval first_seen = strftime(first_seen, \"%Y-%m-%d %H:%M:%S\"), last_seen = strftime(last_seen, \"%Y-%m-%d %H:%M:%S\")" },
        { t: "cmd", label: "one-line version — range() does max−min for you", code: "| stats range(_time) as duration_sec\n| eval duration_min = round(duration_sec / 60, 2)" },
        { t: "note", kind: "info", title: "why this works", text: "<code>_time</code> is stored as Unix epoch seconds even though Splunk displays it formatted — subtracting two epoch values yields elapsed seconds directly. Divide by 60 for minutes, 3600 for hours, 86400 for days." },
        { t: "note", kind: "danger", title: "the part that actually matters: which events bound it", text: "<code>earliest()</code>/<code>latest()</code>/<code>range()</code> only give you the right number if the events feeding them are the right events. \"Span of everything matching my search\" and \"span of just one action type within it\" are different questions with different answers — e.g. for a brute-force alert, <b>first-failed-guess → last-successful-login</b> measures the whole session (guessing phase + every later re-login), while <b>first-successful-login → last-successful-login</b> measures just the compromise/access window. Filter to the specific <code>action</code>/event type the question is actually asking about (<code>| search action=\"Accepted\"</code>, say) <i>before</i> the stats call — don't assume the broadest possible match is the intended scope." },
      ],
    },
    {
      title: "eval — computed and reformatted fields",
      span2: true,
      blocks: [
        { t: "table", head: ["Function", "Use"], rows: [
          ["round(x, n)", "round a number to n decimal places"],
          ["strftime(epoch, fmt)", "epoch seconds → human-readable string, e.g. \"%Y-%m-%d %H:%M:%S\""],
          ["strptime(string, fmt)", "human-readable string → epoch seconds (reverse of strftime)"],
          ["now()", "current epoch time at search run"],
          ["if(cond, valT, valF)", "inline conditional — single branch"],
          ["case(cond1, val1, cond2, val2, ...)", "multi-branch conditional, evaluated top to bottom"],
          ["len(field)", "string length — useful for anomalously long values (DNS tunneling, long URIs)"],
          ["mvcount(field)", "number of values in a multivalue field"],
        ]},
        { t: "cmd", label: "example — flag suspiciously long DNS queries", code: "| eval is_long = if(len(query) > 40, \"suspicious\", \"normal\")" },
      ],
    },
    {
      title: "Shaping & narrowing the result set",
      blocks: [
        { t: "table", head: ["Command", "Use"], rows: [
          ["table f1 f2 f3", "keep only these fields, in this column order"],
          ["sort -field / sort +field", "descending / ascending sort"],
          ["dedup field", "keep only the first event per distinct field value"],
          ["where <expr>", "filter on a computed or extracted field — unlike the base search, works on eval/stats output"],
          ["rename old AS new", "relabel a field for display"],
          ["head N / tail N", "keep only the first / last N results"],
        ]},
        { t: "note", kind: "warn", title: "where vs. base-search filtering", text: "The base search filters raw events before they're processed; <code>where</code> filters <i>after</i> stats/eval, on fields that may not have existed at ingest time (e.g. a computed <code>count</code> or <code>duration_min</code>). Use base-search filters when you can — they're cheaper — and <code>where</code> only when the field you need doesn't exist yet at that point." },
      ],
    },
    {
      title: "top / rare — fast ranking without writing stats by hand",
      blocks: [
        { t: "cmd", label: "most common value of a field", code: "| top limit=10 src_ip" },
        { t: "cmd", label: "least common — often where the interesting outlier hides", code: "| rare limit=10 uri_path" },
        { t: "note", kind: "info", text: "Shorthand for <code>stats count by field | sort -count</code> (top) or <code>sort count</code> (rare) — reach for these first, drop to full <code>stats</code> once you need multiple aggregate fields alongside the count." },
      ],
    },
    {
      title: "Time range vs. SPL time filtering — two different mechanisms",
      blocks: [
        { t: "txt", text: "The time-range picker (top-right of the search bar) scopes which events Splunk even reads — set it to <b>All time</b> when investigating unfamiliar data, since a narrow default window silently drops events outside it with no error." },
        { t: "cmd", label: "SPL-level time filtering, when needed inside the query itself", code: "index=... earliest=-24h latest=now\nindex=... earliest=\"09/17/2025:09:00:00\" latest=\"09/17/2025:10:00:00\"" },
        { t: "note", kind: "danger", title: "an empty result can mean either", text: "\"my filter logic is too strict\" or \"the time range/index scope excluded everything before my filter ever ran\" — these look identical in the UI. Always verify the base search alone (no pipes) returns events before debugging downstream commands. Full debugging-order breakdown in Query Language Gotchas." },
      ],
    },
  ],
};
