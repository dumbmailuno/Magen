#!/usr/bin/env node
// Design-system guard (CLAUDE.md §10, design-system §14). Fails on:
//   1. hex colors anywhere in frontend/src except styles/tokens.css
//   2. Tailwind arbitrary values such as bg-[#123456], p-[13px], w-[var(--x)]
//   3. Tailwind default-palette colors (bg-red-500, text-white): the preset extends the
//      theme, so these still compile but bypass the semantic tokens
// Pure Node so it runs identically on Windows and Linux (no rg/grep dependency).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../frontend/src", import.meta.url));
const allowed = new Set([join("styles", "tokens.css")]);
const exts = [".ts", ".tsx", ".css", ".html"];

const HEX = /#[0-9a-fA-F]{3,8}\b/g;
const ARBITRARY = /(?<![\w-])[a-z][\w:-]*-\[[^\]\s]+\]/g;
const PALETTE_PROPS =
  "bg|text|border|ring|ring-offset|fill|stroke|from|via|to|outline|divide|placeholder|accent|caret|decoration|shadow";
const PALETTE_COLORS =
  "slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|white|black";
const PALETTE = new RegExp(
  `(?<![\\w-])(?:[a-z-]+:)*(?:${PALETTE_PROPS})-(?:${PALETTE_COLORS})(?:-\\d{2,3})?(?:/\\d+)?(?![\\w-])`,
  "g",
);

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (exts.some((e) => p.endsWith(e))) yield p;
  }
}

const problems = [];
for (const file of walk(root)) {
  const rel = relative(root, file);
  if (allowed.has(rel)) continue;
  readFileSync(file, "utf8")
    .split(/\r?\n/)
    .forEach((line, i) => {
      for (const re of [HEX, ARBITRARY, PALETTE]) {
        for (const m of line.matchAll(re)) {
          problems.push(`frontend/src/${rel.split(sep).join("/")}:${i + 1}: ${m[0]}`);
        }
      }
    });
}

if (problems.length) {
  console.error("Design-token lint failed (use semantic tokens, not raw values):");
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log("Design-token lint passed.");
