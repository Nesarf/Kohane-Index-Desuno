// KID as a host for Himeyuri (SPEC M5): the engine runs a description written in the language, inside
// an effect envelope it chooses itself.
//
//   node tools/check-himeyuri.mjs
//
// The language lives outside this repository, so the script reports an honest zero when it is not
// installed here - the same rule the container and corpus checks follow. What it does check is the
// thing that matters: that the host grants an effect set, that a script asking for more is refused, and
// that reading a file is impossible without the file effect.
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const HIMEYURI = process.env.HIMEYURI_HOME || "D:/himeyuri";
const EMBED = path.join(HIMEYURI, "src/embed.mjs");

if (!fs.existsSync(EMBED)) {
  console.log("  Himeyuri is not installed here (" + HIMEYURI + "): 0 assertion(s), nothing claimed");
  process.exit(0);
}

let passed = 0, failed = 0;
const ok = (label, condition, detail = "") => {
  if (condition) { passed++; console.log("  通过  " + label); }
  else { failed++; console.log("  不通过  " + label + (detail ? "  " + detail : "")); }
};

function talk(requests, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [EMBED], { stdio: ["pipe", "pipe", "inherit"] });
    let out = "";
    const timer = setTimeout(() => { child.kill(); reject(new Error("the host did not answer in time")); }, timeoutMs);
    child.stdout.on("data", (c) => { out += c; });
    child.on("close", () => {
      clearTimeout(timer);
      try { resolve(out.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))); }
      catch (e) { reject(new Error("the host's answers were not JSON: " + out.slice(0, 200))); }
    });
    for (const r of requests) child.stdin.write(JSON.stringify(r) + "\n");
    child.stdin.end();
  });
}

const sample = path.join(process.env.TEMP || ".", "kid-himeyuri-sample.txt");
fs.writeFileSync(sample, "湯の岡\n", "utf8");

try {
  const replies = await talk([
    { jsonrpc: "2.0", id: 1, method: "describe" },
    { jsonrpc: "2.0", id: 2, method: "run", params: { source: 'fn main() effects(file) {\n  print(read_text(' + JSON.stringify(sample) + '))\n}\n', granted: ["file"] } },
    { jsonrpc: "2.0", id: 3, method: "run", params: { source: 'fn main() effects(net) {\n  print("no")\n}\n', granted: ["file"] } },
    { jsonrpc: "2.0", id: 4, method: "run", params: { source: 'fn main() {\n  print(read_text(' + JSON.stringify(sample) + '))\n}\n', granted: ["file"] } },
    { jsonrpc: "2.0", id: 5, method: "run", params: { file: path.join(HIMEYURI, "kpb/piece.hmyr"), granted: [] } },
  ]);

  ok("the host answers describe", !!replies[0].result && Array.isArray(replies[0].result.builtins));
  ok("KID's grant of file lets a script read", replies[1].result.ok && replies[1].result.output.join("").trim() === "湯の岡",
    JSON.stringify(replies[1].result.diagnostics));
  ok("a script declaring net is refused before it runs", replies[2].result.ok === false &&
    replies[2].result.diagnostics.some((d) => d.code === "HMYR-R0202"), JSON.stringify(replies[2].result));
  ok("reading without the effect is refused", replies[3].result.ok === false &&
    replies[3].result.diagnostics.some((d) => d.code === "HMYR-R0201"), JSON.stringify(replies[3].result));
  ok("the engine can load a piece written in the language", replies[4].result.ok &&
    replies[4].result.value && replies[4].result.value.score && replies[4].result.value.score.tracks.length === 3,
    JSON.stringify(replies[4].result.diagnostics));
} catch (e) {
  ok("the host answered", false, e.message);
} finally {
  fs.rmSync(sample, { force: true });
}

console.log("");
console.log(passed + " passed, " + failed + " failed");
process.exit(failed === 0 ? 0 : 1);
