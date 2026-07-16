# BLUE//TEAM — SOC Analyst Cheatsheet

A single-file, searchable blue team / SOC field reference. Built alongside the TryHackMe **SOC L1 → SAL1** path — detection filters, phishing forensics, log-pivoting, and framework references, read from the defender's side.

**Live site:** `https://<your-username>.github.io/blue-team-cheatsheet/` (after Pages setup below)

## Features
- 🔍 **Live search** — press `/` to jump to the filter box, `Esc` to clear
- 📋 **Click-to-copy** on every filter/command
- 🧭 Sticky section nav with scroll tracking
- 📱 Responsive (works on phone)
- ⚡ **Zero dependencies** — one `index.html`, no build step, works offline (open the file directly, or copy to the Kali box)
- 🎨 Dark SOC/terminal aesthetic

## How to add notes as you progress

All content lives in the **`cheatsheetData`** array near the top of the `<script>` block in `index.html`. No build, no framework — edit the array, refresh the page.

### Add a whole new section (e.g. after finishing a room)
```js
{
  id:"windows-logging", title:"Windows Logging for SOC", src:"Windows Logging for SOC",
  cards:[
    { title:"Key Event IDs", blocks:[
      { t:"table", head:["ID","Meaning"], rows:[["4624","Successful logon"],["4625","Failed logon"]] },
    ]},
  ]
},
```
Then add an emoji for it in the `ICONS` map (optional — falls back to `▪`).

### Block types you can put in `blocks:[ ... ]`
| Type | Shape | Renders as |
|---|---|---|
| `cmd` | `{ t:"cmd", label?, code:"..." }` | Copyable code block (syntax-tinted) |
| `note` | `{ t:"note", kind:"warn\|info\|danger\|ok", title?, text:"..." }` | Colored callout |
| `txt` | `{ t:"txt", text:"..." }` | Paragraph |
| `table` | `{ t:"table", head:[...], rows:[[...]] }` | Reference table |
| `steps` | `{ t:"steps", items:[...] }` | Numbered list |

`text` fields accept inline HTML — use `<code>…</code>`, `<b>…</b>`. Add `span2:true` to a card to make it double-width.

## Deploy to GitHub Pages

```bash
# from this folder, after git init + first commit:
gh repo create blue-team-cheatsheet --public --source=. --push

# then enable Pages (serves the root of the default branch):
gh api -X POST repos/{owner}/blue-team-cheatsheet/pages -f "source[branch]=main" -f "source[path]=/"
```
Or via the web UI: **Settings → Pages → Source: Deploy from a branch → `main` / `/ (root)`**. Site goes live at `https://<user>.github.io/blue-team-cheatsheet/` within a minute.

The `.nojekyll` file tells Pages to skip Jekyll processing and serve the HTML as-is.

## Local preview
Just open `index.html` in a browser — it's fully self-contained, no server needed.

---
*Red team → blue team. Detection you understand because you've run the attack.*
