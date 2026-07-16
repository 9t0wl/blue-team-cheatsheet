# BLUE//TEAM — SOC Analyst Cheatsheet

A modular, searchable blue team / SOC field reference. Built alongside the TryHackMe **SOC L1 → SAL1** path — detection filters, phishing forensics, log-pivoting, and framework references, read from the defender's side.

**Live site:** `https://<your-username>.github.io/blue-team-cheatsheet/` (after Pages setup below)

## Stack
- **Vite** (vanilla JS) — fast dev server + optimized production build, no framework
- Content is **modular**: one file per section in `src/data/`
- Deploys to **GitHub Pages** automatically via GitHub Actions

## Project structure
```
blue-team-cheatsheet/
├─ index.html               # static shell (sidebar, topbar, hero) — no content
├─ vite.config.js           # base:'./' + build-date injection
├─ package.json
├─ src/
│  ├─ main.js               # boot: render + search + copy + nav + mobile
│  ├─ render.js             # blocks → HTML (pure functions)
│  ├─ style.css             # all styling (dark SOC theme)
│  └─ data/
│     ├─ index.js           # section registry (import order = page order)
│     ├─ config.js          # path name + progress %
│     └─ <section>.js       # one file per section  ← add notes here
└─ .github/workflows/deploy.yml
```

## Develop
```bash
npm install
npm run dev       # localhost:5173, hot reload as you edit
npm run build     # -> dist/
npm run preview   # serve the production build locally
```

## How to add notes as you progress

### Add a whole new section (after finishing a room)
1. Create `src/data/windows-logging.js`:
   ```js
   export default {
     id: "windows-logging",
     title: "Windows Logging for SOC",
     src: "Windows Logging for SOC",
     icon: "🪟",
     cards: [
       { title: "Key Event IDs", blocks: [
         { t: "table", head: ["ID","Meaning"], rows: [
           ["4624","Successful logon"], ["4625","Failed logon"],
         ]},
       ]},
     ],
   };
   ```
2. Register it in `src/data/index.js` (import + add to the `sections` array).

That's it — `npm run dev` hot-reloads it.

### Block types for `blocks:[ ... ]`
| Type | Shape | Renders as |
|---|---|---|
| `cmd` | `{ t:"cmd", label?, code:"..." }` | Copyable code block (syntax-tinted) |
| `note` | `{ t:"note", kind:"warn\|info\|danger\|ok", title?, text:"..." }` | Colored callout |
| `txt` | `{ t:"txt", text:"..." }` | Paragraph |
| `table` | `{ t:"table", head:[...], rows:[[...]] }` | Reference table |
| `steps` | `{ t:"steps", items:[...] }` | Numbered list |

`text` fields accept inline HTML (`<code>`, `<b>`). Add `span2:true` to a card for double width.

### Update path progress
Edit `src/data/config.js` → `progress: 40`. The sidebar bar + label update on next build.

## Deploy to GitHub Pages
```bash
gh repo create blue-team-cheatsheet --public --source=. --push
```
Then in the repo: **Settings → Pages → Source: GitHub Actions**. The included workflow (`.github/workflows/deploy.yml`) builds on every push to `main` and publishes `dist/`. Live at `https://<user>.github.io/blue-team-cheatsheet/`.

## Features
- 🔍 Live search — press `/`, `Esc` to clear
- 📋 Click-to-copy on every filter/command
- 🧭 Sticky section nav with scroll tracking
- 📱 Responsive
- 🎨 Dark SOC/terminal aesthetic

---
*Red team → blue team. Detection you understand because you've run the attack.*
