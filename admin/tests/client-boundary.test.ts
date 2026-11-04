import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

// A Server Component may render the components of a "use client" module,
// but calling one of its functions (or reading one of its constants) fails
// at run time only: "Attempted to call offsetParam() from the server but
// offsetParam is on the client". Neither tsc nor the build sees it, so this
// test reads the code: a server module imports only components (rendered as
// JSX) from a client module.

const SRC = join(__dirname, "..", "src");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return files(p);
    return /\.tsx?$/.test(n) ? [p] : [];
  });
}

function isClient(code: string): boolean {
  const first = code
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l && !l.startsWith("//"));
  return /^["']use client["'];?$/.test(first ?? "");
}

const moduleOf = (p: string) =>
  "@/" +
  relative(SRC, p)
    .replaceAll("\\", "/")
    .replace(/\.tsx?$/, "");

describe("server / client boundary", () => {
  it("server modules take only components from client modules", () => {
    const all = files(SRC).map((p) => ({ p, code: readFileSync(p, "utf8") }));
    const clientModules = new Set(all.filter((f) => isClient(f.code)).map((f) => moduleOf(f.p)));
    expect(clientModules.size).toBeGreaterThan(5); // the reading still works

    const problems: string[] = [];
    for (const { p, code } of all) {
      if (isClient(code)) continue;
      for (const [, names, mod] of code.matchAll(/import\s+(?!type\b)\{([^}]*)\}\s+from\s+"([^"]+)"/g)) {
        if (!clientModules.has(mod!)) continue;
        for (const raw of names!.split(",")) {
          const name = raw
            .trim()
            .split(/\s+as\s+/)[0]!
            .trim();
          if (!name || name.startsWith("type ")) continue;
          const rendered = new RegExp(`<${name}[\\s/>]`).test(code);
          if (/^[A-Z]/.test(name) && rendered) continue;
          problems.push(`${relative(SRC, p)}: ${name} from ${mod} ("use client")`);
        }
      }
    }
    expect(problems).toEqual([]);
  });
});
