import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = process.cwd();

const RULES = [
  {
    name: "client",
    targets: ["client", "index.client.tsx"],
    forbidden: [
      /document\./,
      /window\./,
      /\blocalStorage\b/,
      /navigator\./,
      /className=/,
      /onClick=/,
      /["']node:/,
      /\/server\//,
    ],
  },
  {
    name: "shared",
    targets: ["shared"],
    forbidden: [/["']node:/, /["']react-native["']/, /\/server\//, /\/client\//],
  },
  {
    name: "server",
    targets: ["server", "index.server.ts"],
    forbidden: [/["']react-native["']/, /\/client\//],
  },
];

function collectFiles(targetPath) {
  const fullPath = join(ROOT, targetPath);
  const st = statSync(fullPath, { throwIfNoEntry: false });
  if (!st) return [];
  if (st.isFile()) return [fullPath];

  const out = [];
  for (const entry of readdirSync(fullPath, { withFileTypes: true })) {
    const child = join(fullPath, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectFiles(relative(ROOT, child)));
    } else if (/\.(?:ts|tsx|js|jsx|mjs|cjs)$/.test(entry.name)) {
      out.push(child);
    }
  }
  return out;
}

const violations = [];

for (const rule of RULES) {
  for (const target of rule.targets) {
    for (const file of collectFiles(target)) {
      const content = readFileSync(file, "utf8");
      const lines = content.split(/\r?\n/);
      for (let idx = 0; idx < lines.length; idx++) {
        const line = lines[idx];
        for (const rx of rule.forbidden) {
          if (rx.test(line)) {
            violations.push({
              scope: rule.name,
              file: relative(ROOT, file),
              line: idx + 1,
              pattern: rx.source,
              snippet: line.trim(),
            });
          }
        }
      }
    }
  }
}

if (violations.length > 0) {
  console.error("Runtime boundary violations detected:");
  for (const v of violations) {
    console.error(`  [${v.scope}] ${v.file}:${v.line} matched ${v.pattern} -> ${v.snippet}`);
  }
  process.exit(1);
}

console.log("Runtime boundary checks passed (client, shared, server).");
