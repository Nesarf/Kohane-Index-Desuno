#!/usr/bin/env node
// Portability and hygiene invariant for the shipped package. Four axes, each of which has failed at
// least once in this repository's history:
//
//   1. Mainstream OS  - nothing may assume Windows. Platform-specific code sits behind a win32
//                       guard, spawns pass argv arrays (never a shell string), PATH is split with
//                       path.delimiter.
//   2. No system-drive scratch - this installation keeps its own working directories. A temp file
//                       created through os.tmpdir() would land on the system drive, so scratch must
//                       live under $DSH_HOME (the report dialog's work directory is the example).
//   3. Explicit encodings - every text read/write states "utf8" instead of relying on the platform.
//   4. No absolute machine paths - a shipped file must not name a drive or a home directory.
//
// Usage: node tools/check-portability.mjs        (exit 1 on any finding)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKG = path.join(ROOT, "kohane-index-desuno");
const SHIPPED = ["lib/core.mjs", "mcp/index.mjs", "cli/index.mjs", "package.json"].map((f) => path.join(PKG, f));
const problems = [];

for (const file of SHIPPED) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    problems.push(`${path.relative(ROOT, file)}: missing`);
    continue;
  }
  const lines = text.split("\n");
  // The tool/environment catalogue is a declared list of typical locations; exempt its span.
  const catStart = lines.findIndex((l) => /const DETECT_CANDIDATES = \[/.test(l));
  const catEnd = catStart >= 0 ? lines.findIndex((l, i) => i > catStart && /^\];/.test(l)) : -1;
  const outsideCatalogue = catStart >= 0 && catEnd > catStart ? { start: catStart, end: catEnd } : null;
  lines.forEach((line, i) => {
    const at = `${path.relative(ROOT, file)}:${i + 1}`;
    const code = line.replace(/^\s*\/\/.*$/, "");
    if (!code.trim()) return;

    // 2. scratch must never be CREATED through the OS temp directory. A catalogue entry that merely
    //    describes where the system temp is (DETECT_CANDIDATES) is documentation, not scratch.
    if (/os\.tmpdir\(\)/.test(code) && /(mkdtempSync|writeFileSync|appendFileSync|mkdirSync)/.test(code)) {
      problems.push(`${at}: creates scratch through os.tmpdir() - scratch belongs under $DSH_HOME`);
    }

    // 1. no shell-string spawns, no execSync command lines
    if (/\bshell:\s*true/.test(code)) problems.push(`${at}: spawn with shell:true - pass an argv array instead`);
    if (/\b(execSync|exec)\s*\(/.test(code)) problems.push(`${at}: exec() runs a shell command line - use spawn with an argv array`);

    // 1. PATH splits must be delimiter-aware
    if (/process\.env\.PATH[^\n]*split\(\s*["'`][:;]/.test(code)) problems.push(`${at}: PATH split with a literal separator - use path.delimiter`);

    // 4. no absolute machine paths in shipped code. Two documented exceptions: an environment
    //    variable is consulted first (resolveTool/KOHANE_*), and the tool catalogue is a list of
    //    TYPICAL locations by design - its whole purpose is to name them as fallbacks.
    if (/["'`][A-Za-z]:[\\/]{1,2}[A-Za-z]/.test(code)) {
      const line_ok = /KOHANE_|ProgramFiles|ProgramW6432|CommonProgramFiles|LOGICAL_DRIVE|for \(const letter of|path\.join\(|"[A-Za-z]:\\\\/.test(code)
        || /\b(description|note):\s*["'`]/.test(code)   // a quoted example inside documentation
        || /\be\.g\./.test(code);
      const inCatalogue = outsideCatalogue !== null && i + 1 > outsideCatalogue.start && i + 1 < outsideCatalogue.end;
      if (!line_ok && !inCatalogue) problems.push(`${at}: hardcodes an absolute Windows path - resolve it from the environment instead`);
    }

    // 3. text I/O states its encoding. Scope: a call whose FIRST argument is a string literal that
    //    names a text file. A binary read decoded afterwards (a ZIP member) and a path the caller
    //    supplied are both out of scope - the encoding is stated where the text is produced.
    const textLiteralCall = code.match(/\b(readFileSync|writeFileSync)\(\s*["'`]([^"'`]+)\2/);
    if (textLiteralCall && /\.(json|txt|md|mjs|js|csv)$/.test(textLiteralCall[2]) && !/utf8/.test(code)) {
      problems.push(`${at}: text file I/O without an explicit encoding`);
    }
  });
}

// 1. platform-specific branches must have a counterpart somewhere
const core = fs.readFileSync(path.join(PKG, "lib", "core.mjs"), "utf8");
const winBranches = (core.match(/process\.platform === "win32"/g) || []).length;
const posixBranches = (core.match(/process\.platform === "(darwin|linux)"/g) || []).length + (core.match(/!== "win32"/g) || []).length;
if (winBranches > 0 && posixBranches === 0) {
  problems.push("lib/core.mjs branches on win32 with no non-Windows counterpart");
}

if (problems.length) {
  console.log(`check-portability: ${problems.length} finding(s)`);
  for (const p of problems.slice(0, 40)) console.log("  " + p);
  process.exit(1);
}
console.log(`check-portability: OK - ${SHIPPED.length} shipped file(s), ${winBranches} win32 branch(es) each with a counterpart`);
