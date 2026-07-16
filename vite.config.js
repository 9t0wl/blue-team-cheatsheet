import { defineConfig } from "vite";

export default defineConfig({
  // Relative base so the build works on GitHub Pages under /<repo>/ AND
  // when opening dist/index.html directly, regardless of repo name.
  base: "./",
  define: {
    // injected at build time → shown as "last build" in the header
    __BUILD_DATE__: JSON.stringify(new Date().toISOString().slice(0, 10)),
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
