// Pure rendering: turns section/card/block data into HTML strings.
// Content in data files is trusted (authored in-repo), so inline HTML in
// `text` fields is passed through; only code + table cells are escaped.

export function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Lightweight syntax tint for code blocks (approximate, not a real parser).
export function highlight(code) {
  return esc(code)
    .replace(/(&quot;[^&]*?&quot;|"[^"]*")/g, '<span class="tok-str">$1</span>')
    .replace(/\b(and|or|not|matches|contains)\b/g, '<span class="tok-op">$1</span>')
    .replace(/\b(\d+)\b/g, '<span class="tok-num">$1</span>')
    .replace(/(#[^\n]*)/g, '<span class="tok-cmt">$1</span>');
}

function renderBlock(b) {
  switch (b.t) {
    case "cmd": {
      const label = b.label ? `<div class="clabel">${b.label}</div>` : "";
      const copy = `<button class="copy" data-copy="${esc(b.code)}">copy</button>`;
      return `<div class="cmd">${label}<pre><code>${highlight(b.code)}</code></pre>${copy}</div>`;
    }
    case "note": {
      const nt = b.title ? `<span class="nt">${b.title}</span>` : "";
      return `<div class="note ${b.kind || "info"}">${nt}${b.text}</div>`;
    }
    case "txt":
      return `<p class="txt">${b.text}</p>`;
    case "table": {
      const th = b.head.map((h) => `<th>${esc(h)}</th>`).join("");
      const tr = b.rows
        .map(
          (r) =>
            `<tr>${r
              .map((c, i) => (i === 0 ? `<td>${esc(c)}</td>` : `<td>${c}</td>`))
              .join("")}</tr>`
        )
        .join("");
      return `<table class="tbl"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>`;
    }
    case "steps":
      return `<ol class="steps">${b.items.map((i) => `<li>${i}</li>`).join("")}</ol>`;
    default:
      return "";
  }
}

function renderCard(c) {
  const desc = c.desc ? `<p class="desc">${c.desc}</p>` : "";
  const body = c.blocks.map(renderBlock).join("");
  const searchText = (
    c.title +
    " " +
    (c.desc || "") +
    " " +
    JSON.stringify(c.blocks)
  ).toLowerCase();
  return `<div class="card${c.span2 ? " span2" : ""}" data-search="${esc(searchText)}"><h3>${c.title}</h3>${desc}${body}</div>`;
}

export function renderSection(sec) {
  const cards = sec.cards.map(renderCard).join("");
  return `<section id="${sec.id}" data-sec="${sec.id}">
    <div class="sec-head"><h2>${sec.title}</h2><span class="src">${sec.icon || "▪"} ${sec.src}</span></div>
    <div class="cards">${cards}</div>
  </section>`;
}

export function renderNavLink(sec) {
  const short = sec.title.replace(/^.*?— /, "");
  return `<a href="#${sec.id}"><span class="ic">${sec.icon || "▪"}</span>${short}</a>`;
}

export function countEntries(sections) {
  return sections.reduce((n, s) => n + s.cards.length, 0);
}
