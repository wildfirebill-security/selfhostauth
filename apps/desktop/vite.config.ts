import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  base: "./",
  build: {
    outDir: "dist/renderer",
    emptyOutDir: true,
    target: "es2022",
    rollupOptions: {
      input: "index.html",
    },
  },
  server: {
    port: 5173,
    strictPort: true,
  },
});