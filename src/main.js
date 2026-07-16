import "./style.css";
import { sections, config } from "./data/index.js";
import { renderSection, renderNavLink, countEntries } from "./render.js";

// __BUILD_DATE__ is injected by Vite (see vite.config.js); fallback for safety.
const BUILD_DATE =
  typeof __BUILD_DATE__ !== "undefined" ? __BUILD_DATE__ : "dev";

function boot() {
  // ---- render content + nav ----
  document.getElementById("content").innerHTML = sections
    .map(renderSection)
    .join("");
  document.getElementById("nav").innerHTML = sections
    .map(renderNavLink)
    .join("");

  // ---- header/sidebar stats ----
  document.getElementById("secCount").textContent = sections.length;
  document.getElementById("entryCount").textContent = countEntries(sections);
  document.getElementById("buildDate").textContent = BUILD_DATE;
  document.getElementById("progPct").textContent = config.progress + "%";
  document.getElementById("progFill").style.width = config.progress + "%";
  document.querySelector(".prog .lbl span").textContent = config.pathName;

  wireCopy();
  wireSearch();
  wireKeyboard();
  wireScrollSpy();
  wireMobile();
}

// ---- click-to-copy ----
function wireCopy() {
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".copy");
    if (!btn) return;
    const text = btn
      .getAttribute("data-copy")
      .replace(/&amp;/g, "&")
      .replace(/&quot;/g, '"')
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">");
    navigator.clipboard
      .writeText(text)
      .then(() => {
        btn.textContent = "✓ copied";
        btn.classList.add("ok");
        setTimeout(() => {
          btn.textContent = "copy";
          btn.classList.remove("ok");
        }, 1200);
      })
      .catch(() => {
        btn.textContent = "⌘C";
      });
  });
}

// ---- live search ----
function wireSearch() {
  const search = document.getElementById("search");
  const countEl = document.getElementById("count");
  const noRes = document.getElementById("noResults");

  function doSearch() {
    const q = search.value.trim().toLowerCase();
    let shown = 0,
      total = 0;
    document.querySelectorAll("section").forEach((sec) => {
      let secShown = 0;
      sec.querySelectorAll(".card").forEach((card) => {
        total++;
        const match = !q || card.getAttribute("data-search").includes(q);
        card.style.display = match ? "" : "none";
        if (match) {
          shown++;
          secShown++;
        }
      });
      sec.style.display = secShown ? "" : "none";
    });
    countEl.textContent = q ? `${shown}/${total} entries` : `${total} entries`;
    noRes.style.display = q && shown === 0 ? "block" : "none";
  }

  search.addEventListener("input", doSearch);
  doSearch();
  window.__doSearch = doSearch; // used by keyboard handler
}

// ---- keyboard: '/' focus, Esc clear ----
function wireKeyboard() {
  const search = document.getElementById("search");
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== search) {
      e.preventDefault();
      search.focus();
    }
    if (e.key === "Escape" && document.activeElement === search) {
      search.value = "";
      window.__doSearch();
      search.blur();
    }
  });
}

// ---- active nav on scroll ----
function wireScrollSpy() {
  const navLinks = [...document.querySelectorAll("#nav a")];
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) {
          const id = en.target.id;
          navLinks.forEach((a) =>
            a.classList.toggle("active", a.getAttribute("href") === "#" + id)
          );
        }
      });
    },
    { rootMargin: "-40% 0px -55% 0px" }
  );
  document.querySelectorAll("section").forEach((s) => io.observe(s));
}

// ---- mobile sidebar toggle ----
function wireMobile() {
  const sidebar = document.getElementById("sidebar");
  document
    .getElementById("menuBtn")
    .addEventListener("click", () => sidebar.classList.toggle("open"));
  document
    .querySelectorAll("#nav a")
    .forEach((a) =>
      a.addEventListener("click", () => sidebar.classList.remove("open"))
    );
}

boot();
