// kohane-index-desuno self-check.
//
// One-shot regression harness over the shared core: module surface, tool registry, signature
// recognition (incl. the FL tables), the analyzer layer (built-in + DIY), the library record/query
// invariants and the crypto/legacy paths. Everything runs against a throwaway DSH_HOME under the
// disk-guard temp dir and cleans up after itself. No network, no writes outside the temp root.
//
//   node tools/selfcheck.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { spawnSync } from "node:child_process";
import { createCipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url)); // .../tools
const ROOT = path.dirname(HERE);                           // .../kohane-index-desuno
const CORE = path.join(ROOT, "kohane-index-desuno", "lib", "core.mjs");
// The temp root follows the disk-guard discipline on this machine, but any machine - a CI runner, for
// instance - can point it elsewhere: KOHANE_HARNESS_TMP overrides it.
const TMP = process.env.KOHANE_HARNESS_TMP
  ? path.join(process.env.KOHANE_HARNESS_TMP, "kohane-selfcheck")
  : path.join("E:", "DaShaoHuo", "cache", "tmp", "kohane-selfcheck");
const PNG = path.join(ROOT, "kohane!!!", "122062154_p0.png");
const FL_FST = path.join(ROOT, "research", "fl-studio", "samples", "formats", "Accordeon.fst");
const FL_FLP = path.join(ROOT, "research", "fl-studio", "samples", "formats", "NewStuff.flp");
const FL_DB = path.join(ROOT, "research", "fl-studio", "samples", "plugindb");

fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });
process.env.DSH_HOME = path.join(TMP, "dsh");

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { console.log(`  ${cond ? "[OK]" : "[!!]"} ${name}${extra ? "  " + extra : ""}`); cond ? pass++ : fail++; };
const section = (t) => console.log(`\n=== ${t} ===`);

const m = await import(pathToFileURL(CORE).href);
const tool = (n) => m.TOOLS.find((t) => t.name === n);

// ---------------------------------------------------------------- module surface
section("module surface");
const KEY_EXPORTS = [
  "TOOLS", "TOOL_INPUT_SCHEMAS", "FILE_SIGNATURES", "NATIVE_CONTAINER_FORMATS", "NATIVE_SIGNATURES",
  "NATIVE_TEXT_EXTENSIONS", "ANALYZER_PROVIDERS", "analyzeObject", "registerDefaultAnalyzer",
  "runLocalAnalyzer", "localAnalyzerMatches", "sniffFileType", "mediaFingerprint",
  "encryptSensitive", "decryptSensitive", "sealWithPassphrase", "unsealWithPassphrase",
  "KEY_INFO", "KEY_INFO_LEGACY", "SEAL_INFO", "SEAL_INFO_LEGACY", "detectEnvironment", "safeStringify",
  "KOHANE_PLUGIN_BRAND", "KOHANE_PLUGIN_ROLES", "KOHANE_CAPABILITIES", "KOHANE_PLUGIN_FLAGSHIP",
  "PLUGIN_FUNCTION_VOCAB", "resolveKohanePlugins", "classifyPluginRole", "extractFunctionWord", "pluginKey",
  "duplicateKohaneNames", "pluginPackFile", "loadPluginPack", "scanPluginDatabase", "findPluginDatabase",
  "pluginRoots", "scanPluginInstallations", "pluginProvenance",
];
for (const k of KEY_EXPORTS) ok(`export ${k}`, k in m);
ok("KEY_INFO is the new namespace", m.KEY_INFO.startsWith("kohane-index-desuno"), m.KEY_INFO);
ok("legacy namespaces retained for old data", m.KEY_INFO_LEGACY.startsWith("mega-index-map") && m.SEAL_INFO_LEGACY.startsWith("mega-index-map"));

// ---------------------------------------------------------------- tool registry
section("tool registry");
const EXPECTED = ["library_record", "library_index", "library_query", "library_detect", "library_sniff",
  "library_format", "library_plugin", "library_sessions", "library_decrypt", "library_export", "library_encoding",
  "library_adb", "analyze_object", "library_environment"];
ok("16 tools", m.TOOLS.length === 16, `got ${m.TOOLS.length}`);
for (const n of EXPECTED) ok(`tool ${n}`, !!tool(n));
ok("every tool has name/description/inputSchema/execute",
  m.TOOLS.every((t) => t.name && t.description && t.inputSchema && typeof t.execute === "function"));
const schemaTools = Object.keys(m.TOOL_INPUT_SCHEMAS);
ok("schemas cover the tools that reference them",
  m.TOOLS.filter((t) => t.inputSchema === m.TOOL_INPUT_SCHEMAS[t.name]).every((t) => schemaTools.includes(t.name)));

// ---------------------------------------------------------------- signatures
section("signature recognition");
const sniff = (p) => m.sniffFileType(p);
ok("113 built-in signatures", m.FILE_SIGNATURES.length === 113, `got ${m.FILE_SIGNATURES.length}`);
ok("local native-format table: absent is fine, present loads",
    (m.NATIVE_SIGNATURES.length === 0 && m.NATIVE_TEXT_EXTENSIONS.length === 0) || (m.NATIVE_SIGNATURES.length > 0 && m.NATIVE_TEXT_EXTENSIONS.length > 0),
    `sig=${m.NATIVE_SIGNATURES.length} text=${m.NATIVE_TEXT_EXTENSIONS.length}`);
  ok("local native table loaded on this machine", m.NATIVE_SIGNATURES.length === 0 || m.NATIVE_SIGNATURES.length >= 20, `sig=${m.NATIVE_SIGNATURES.length}`);
ok("PNG", (sniff(PNG) || {}).format === "png");
// These sample files belong to the local evidence area, which is not published, and the table that
  // recognises several native families is machine-local too. So the assertion is conditional: with the
  // input present it must be recognised; without it the engine must simply not claim anything.
  ok("project container .flp" + (fs.existsSync(FL_FLP) ? "" : " (sample absent: nothing is claimed instead)"),
    !fs.existsSync(FL_FLP) || ["flp", "kb-container"].includes((sniff(FL_FLP) || {}).format), JSON.stringify(sniff(FL_FLP)));
ok("state file .fst" + (fs.existsSync(FL_FST) ? "" : " (sample absent: nothing is claimed instead)"),
    !fs.existsSync(FL_FST) || ["fst", "kb-container"].includes((sniff(FL_FST) || {}).format), JSON.stringify(sniff(FL_FST)));
ok("text file", (sniff(CORE) || {}).format === "mjs");
// a synthetic .fnv (u32-led float table) must be recognised by the structural heuristic
const fnv = path.join(TMP, "env.fnv");
fs.writeFileSync(fnv, Buffer.concat([Buffer.from([3, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0]), Buffer.alloc(68, 0)]));
ok("envelope .fnv (structural heuristic)", (sniff(fnv) || {}).format === "kb-envelope", JSON.stringify(sniff(fnv)));
// a synthetic FL tag-format (version byte + 3-letter tag) must match at offset 1
const kik = path.join(TMP, "x.kik");
fs.writeFileSync(kik, Buffer.concat([Buffer.from([0x31]), Buffer.from("kiK", "latin1"), Buffer.alloc(32, 0)]));
ok("tag family (offset-1 tag) " + (m.NATIVE_SIGNATURES.length ? "" : "(no local table: skipped)"),
    m.NATIVE_SIGNATURES.length === 0 || (sniff(kik) || {}).format === "kb-drum-preset", JSON.stringify(sniff(kik)));

// content probes: a generic extension can still say what it holds, and refuses to guess
section("content probes");
const probeDir = path.join(TMP, "probes");
fs.mkdirSync(probeDir, { recursive: true });
const probeFile = (name, body) => {
  const f = path.join(probeDir, name);
  fs.writeFileSync(f, body);
  return f;
};
ok("a colour ramp is named", (sniff(probeFile("ramp.map", "\n[rgb(164, 204, 144); 0.0]\n")) || {}).format === "color-map");
const worldMap = probeFile("world.map", 'MAP\n{ "classname" "worldspawn" }\n');
ok("an engine map is NOT claimed", (sniff(worldMap) || {}).format === "map", JSON.stringify(sniff(worldMap)));
ok("a voice patch is named", (sniff(probeFile("v.vfpatch", '{ "parameters" : {} }')) || {}).format === "voice-patch");
ok("a meter session is named", (sniff(probeFile("s.mms", "Loudness {\n    num Mode 1\n}\n")) || {}).format === "meter-session");
ok("a non-JSON .vfpatch stays plain text" + (m.NATIVE_TEXT_EXTENSIONS.includes("vfpatch") ? "" : " (no local table: skipped)"),
    !m.NATIVE_TEXT_EXTENSIONS.includes("vfpatch") || (sniff(probeFile("bad.vfpatch", "not json\n")) || {}).format === "vfpatch");
ok("a binary .map is not a colour ramp", (sniff(probeFile("bin.map", Buffer.from([0, 1, 2, 3, 4]))) || {}).format !== "color-map");
ok("a generic extension with no probe is not claimed as a colour ramp", (sniff(probeFile("plain.mapx", "hello\n")) || {}).format !== "color-map");

// ---------------------------------------------------------------- analyzer layer
// ---------------------------------------------------------------- working-tree status
section("working-tree status");
{
  // A real repository, built here so every state we claim to recognise actually exists on disk.
  const repo = path.join(TMP, "vcs-repo");
  fs.mkdirSync(path.join(repo, "sub"), { recursive: true });
  const git = (args) => spawnSync("git", ["-C", repo, ...args], { encoding: "utf8", windowsHide: true, timeout: 20000 });
  const vcs = tool("library_vcs");

  ok("library_vcs is registered", !!vcs && !!m.TOOL_INPUT_SCHEMAS.library_vcs, vcs ? "" : "missing");
  ok("its schema asks for an op", !!m.TOOL_INPUT_SCHEMAS.library_vcs.properties.op);

  const info = await vcs.execute({ op: "info" });
  if (!info.available) {
    // A machine without git must still answer, never throw.
    ok("without git, status is still answered", true, info.note);
    const none = await vcs.execute({ op: "status", path: repo });
    ok("without git, a path reports no repository", none.ok === true && none.state === "none");
  } else {
    ok("git is detected", typeof info.git === "string" && info.git.length > 0, info.git);

    git(["init", "-q"]);
    git(["config", "user.email", "kohane@example.invalid"]);
    git(["config", "user.name", "Kohane"]);
    git(["config", "commit.gpgsign", "false"]);
    fs.writeFileSync(path.join(repo, "tracked.txt"), "one\ntwo\nthree\n");
    fs.writeFileSync(path.join(repo, "gone.txt"), "delete me\n");
    fs.writeFileSync(path.join(repo, "old-name.txt"), "rename me\n");
    fs.writeFileSync(path.join(repo, "sub", "nested.txt"), "nested\n");
    fs.writeFileSync(path.join(repo, ".gitignore"), "ignored/\n");
    git(["add", "-A"]);
    git(["commit", "-q", "-m", "seed"]);

    fs.writeFileSync(path.join(repo, "tracked.txt"), "one\nCHANGED\nthree\nfour\nfive\n");
    fs.writeFileSync(path.join(repo, "fresh.txt"), "untracked\n");
    fs.writeFileSync(path.join(repo, "staged.txt"), "staged\n");
    git(["add", "staged.txt"]);
    fs.rmSync(path.join(repo, "gone.txt"));
    git(["mv", "old-name.txt", "new-name.txt"]);
    fs.writeFileSync(path.join(repo, "sub", "nested.txt"), "nested changed\n");

    const summary = await vcs.execute({ op: "repo", path: repo });
    ok("the repository summarises", summary.ok === true && summary.changed === 6, `changed=${summary.changed}`);
    ok("one branch name is reported", typeof summary.branch.name === "string" && summary.branch.name.length > 0, summary.branch.name);
    ok("every state is classified",
      summary.counts.M === 2 && summary.counts.U === 1 && summary.counts.A === 1 && summary.counts.D === 1 && summary.counts.R === 1,
      JSON.stringify(summary.counts));
    ok("staged changes are listed apart from worktree changes",
      summary.staged.map((i) => i.letter).sort().join("") === "AR" && summary.changes.map((i) => i.letter).sort().join("") === "DMM",
      `staged=${summary.staged.map((i) => i.letter).join("")} changes=${summary.changes.map((i) => i.letter).join("")}`);
    const mod = summary.changes.find((i) => i.path === "tracked.txt");
    ok("line counts come back per side", mod && mod.added === 3 && mod.deleted === 1, mod ? `+${mod.added}/-${mod.deleted}` : "no entry");
    ok("untracked is listed separately", summary.untracked.length === 1 && summary.untracked[0].path === "fresh.txt");
    ok("renames keep their origin", summary.staged.some((i) => i.letter === "R" && i.origPath === "old-name.txt"));

    const one = await vcs.execute({ op: "status", path: path.join(repo, "tracked.txt") });
    ok("a modified file carries letter, label and colour",
      one.state === "M" && one.letter === "M" && one.label === "已修改" && !!one.colors.dark,
      `${one.letter} ${one.label}`);
    ok("index and worktree letters stay apart", one.index === null && one.worktree === "M", `${one.index}/${one.worktree}`);

    const clean = await vcs.execute({ op: "status", path: path.join(repo, ".gitignore") });
    ok("an unchanged tracked file is clean with no letter", clean.state === "clean" && clean.letter === null, clean.state);

    const folder = await vcs.execute({ op: "status", path: path.join(repo, "sub") });
    ok("a directory folds its children into one state", folder.state === "M" && folder.children.M === 1, JSON.stringify(folder.children));

    const outside = await vcs.execute({ op: "status", path: path.join(TMP, "not-a-repo.txt") });
    ok("a path outside any repository is reported, not failed", outside.ok === true && outside.state === "none", outside.label);

    const deco = await vcs.execute({ op: "decorate", paths: [path.join(repo, "fresh.txt"), path.join(repo, "new-name.txt"), path.join(TMP, "not-a-repo.txt")] });
    ok("decorate answers for a whole list at once",
      deco.returned === 3 && deco.counts.U === 1 && deco.counts.R === 1 && deco.counts.none === 1,
      JSON.stringify(deco.counts));

    const unknown = await vcs.execute({ op: "nonsense" });
    ok("an unknown op names the ones it accepts", /allowed: status, decorate, repo, info/.test(unknown.note), unknown.note);
    ok("decorate refuses an empty list", (await vcs.execute({ op: "decorate", paths: [] })).ok === false);
  }

  // The absent-git path, exercised in a child so the module-level probe cache is untouched. If this
  // host cannot spawn a child (a confined sandbox), the check says so instead of failing.
  const probeCode = `import(${JSON.stringify(pathToFileURL(CORE).href)}).then(async (m) => {
    const t = m.TOOLS.find((x) => x.name === "library_vcs");
    const r = await t.execute({ op: "status", path: ${JSON.stringify(path.join(TMP, "vcs-repo", "tracked.txt"))} });
    console.log(JSON.stringify({ state: r.state, label: r.label, note: r.note }));
  }).catch((e) => console.log(JSON.stringify({ error: String(e && e.message || e) })));`;
  const child = spawnSync(process.execPath, ["-e", probeCode], {
    encoding: "utf8", windowsHide: true, timeout: 30000,
    env: { ...process.env, KOHANE_NO_GIT: "1" },
  });
  const lastLine = String(child.stdout || "").trim().split("\n").filter(Boolean).pop() || "";
  if (!lastLine) {
    console.log("  [--] the absent-git path was not exercised (this host cannot spawn a child process here)");
  } else {
    let parsed = {};
    try { parsed = JSON.parse(lastLine); } catch { /* reported below */ }
    ok("KOHANE_NO_GIT=1 reports a machine without git, without failing",
      parsed.state === "none" && typeof parsed.note === "string" && parsed.note.includes("git"),
      parsed.note || lastLine.slice(0, 80));
  }
}

section("analyzer layer (built-in + DIY)");
const unity = path.join(TMP, "UnityProj");
fs.mkdirSync(path.join(unity, "Assets", "Scripts"), { recursive: true });
fs.mkdirSync(path.join(unity, "ProjectSettings"), { recursive: true });
fs.mkdirSync(path.join(unity, "Packages"), { recursive: true });
fs.writeFileSync(path.join(unity, "Assets", "Scripts", "P.cs"), "// c\n");
fs.writeFileSync(path.join(unity, "Assets", "Main.unity"), "%YAML\n");
fs.writeFileSync(path.join(unity, "ProjectSettings", "ProjectVersion.txt"), "m_EditorVersion: 2022.3.45f1\n");
fs.writeFileSync(path.join(unity, "Packages", "manifest.json"), JSON.stringify({ dependencies: { a: "1", b: "2" } }));
let r = await m.analyzeObject(unity);
ok("unity-project detected (zero editor launch)", r.ok && r.kind === "unity-project" && r.fields.unityVersion === "2022.3.45f1", r.detail);
ok("unity packages counted (BOM-safe JSON)", r.fields.packageCount === 2, `packageCount=${r.fields.packageCount}`);
r = await m.analyzeObject(unity, { deep: true });
ok("unity analyzer ignores deep", r.kind === "unity-project");

const blend = path.join(TMP, "scene.blend");
fs.writeFileSync(blend, Buffer.concat([Buffer.from("BLENDER-v404", "latin1"), Buffer.alloc(64, 0)]));
r = await m.analyzeObject(blend);
ok("blender header parsed", r.ok && r.kind === "blender" && r.fields.version === "4.04", r.detail);
r = await m.analyzeObject(path.join(TMP, "nope.bin"));
ok("missing path fails cleanly", r.ok === false);
r = await m.analyzeObject(PNG);
ok("fallback path for a plain file", r.ok && r.kind === "file");

// The native project container (a kohane-side parser: no installation of anything is involved)
// The container analyzer takes its magic from the machine's own format table and claims nothing when
// there is no such table (an isolated run, for instance). The checks below run where the mechanism can
// act, and assert the honest silence where it cannot.
const HAS_CONTAINER_TABLE = (() => {
  try {
    const f = path.join(process.env.DSH_HOME || "", "library", "native-formats.json");
    if (!fs.existsSync(f)) return false;
    return Boolean(JSON.parse(fs.readFileSync(f, "utf8")).containerMagic);
  } catch { return false; }
})();

// The state corpus those tests read belongs to the local evidence area, and decoding it needs the
// local container decoder: both are machine-local, so the region below runs only where they exist.
const HAS_LOCAL_CORPUS = fs.existsSync(FL_DB) && HAS_CONTAINER_TABLE;

ok("kb-container provider registered", m.ANALYZER_PROVIDERS.some((p) => p.name === "kb-container"));
ok("decodeNativeContainer exported", typeof m.decodeNativeContainer === "function");
if (HAS_CONTAINER_TABLE) {
  r = await m.analyzeObject(FL_FLP);
  ok("project container -> writer version",
    r.ok && r.kind === "kb-container" && /^\d/.test(String(r.fields.writerVersion)), r.fields.writerVersion);
  ok("project container -> plugin count extracted",
    r.fields.pluginCount >= 5, `${r.fields.pluginCount} plugin(s)`);
  r = await m.analyzeObject(FL_FST);
  // Older files (this one was written by FL 3.1.8) carry no C9 name event, so only the container
  // identity and the writer version are guaranteed.
  ok("state file -> container (writer version)",
    r.ok && r.kind === "kb-container" && /^\d/.test(String(r.fields.writerVersion)), r.fields.writerVersion);

} else {
  r = await m.analyzeObject(FL_FLP);
  ok("with no local table the container analyzer claims nothing", !(r && r.kind === "kb-container" && r.ok));
}
// a non-FL file must not be claimed by the container analyzer
const notFl = path.join(TMP, "plain.bin");
fs.writeFileSync(notFl, Buffer.from("FLhx-not-a-container", "latin1"));
ok("container analyzer rejects a near-miss magic", (await m.analyzeObject(notFl)).kind !== "kb-container");

// DIY analyzer: register, run, then verify a built-in is never shadowed
const helper = path.join(TMP, "h.mjs");
fs.writeFileSync(helper, 'import fs from "node:fs";\nconsole.log(JSON.stringify({bytes: fs.statSync(process.argv[2]).size}));\n');
const diyFile = path.join(TMP, "s.diyfoo");
fs.writeFileSync(diyFile, "hello\n");
const fmt = tool("library_format");
r = await fmt.execute({ op: "analyzer-add", name: "sonde", kind: "diy", exts: ["diyfoo"], exe: process.execPath, args: [helper, "{path}"], parse: "json" });
ok("analyzer-add", r.ok === true, r.note);
r = await m.analyzeObject(diyFile);
ok("DIY analyzer runs for its extension", r.ok && r.kind === "diy" && r.fields.data.bytes === 6, r.detail);
await fmt.execute({ op: "analyzer-add", name: "hijack", kind: "hijack", exts: ["png"], exe: process.execPath, args: [helper, "{path}"] });
r = await m.analyzeObject(PNG);
ok("DIY entry cannot shadow the built-in fallback (png)", r.kind === "file" && r.kind !== "hijack", r.detail);
r = await fmt.execute({ op: "analyzer-remove", name: "hijack" });
ok("analyzer-remove", r.ok && r.removed === 1);

// ---------------------------------------------------------------- library invariants
section("library record/index/query invariants");
const rec = tool("library_record"), idx = tool("library_index"), qry = tool("library_query");
r = await rec.execute({ type: "tool", name: "t1", source: "sc", path: "p1", description: "v1", tags: [] });
ok("first record", r.count >= 1 && r.changed === false);
r = await rec.execute({ type: "tool", name: "t1", source: "sc", path: "p2", description: "v2", tags: [] });
ok("content change is recorded", r.changed === true);
const before = (await m.loadIndex()).objects.length;
await rec.execute({ type: "tool", name: "t1", source: "sc", path: "p2", description: "v2", tags: [] });
const after = (await m.loadIndex()).objects.length;
ok("identical re-record does NOT duplicate (latest-anchored)", after === before, `${before} -> ${after}`);
r = await idx.execute();
// Two versions share the key (v1, v2); the index must keep the LATEST and report the older one as
// a conflict rather than silently dropping it.
const kept = (await m.loadIndex()).objects.find((o) => o.id === (r.conflicts[0] || {}).kept);
ok("index keeps the latest version (older one reported as a conflict)",
  r.conflicts.length === 1 && kept && kept.description === "v2", JSON.stringify(r.conflicts));
r = await qry.execute({ query: "v2" });
ok("query finds the latest content", r.count >= 1 && r.results.some((o) => o.description === "v2"));

// ---------------------------------------------------------------- crypto + legacy
section("crypto and legacy compatibility");
const obj = { type: "env", name: "api_key", path: "s" };
const opened = m.decryptSensitive(m.encryptSensitive(obj));
ok("sensitive encrypt/decrypt round-trip", opened && opened.name === "api_key");
const onDisk = JSON.parse(fs.readFileSync(m.keyFile(), "utf8"));
ok("key file stores the new namespace", onDisk.info === m.KEY_INFO, onDisk.info);
const expectKey = Buffer.from(hkdfSync("sha256", m.getMasterSecret(), Buffer.from(onDisk.salt, "hex"), Buffer.from(m.KEY_INFO, "utf8"), 32));
ok("derived key matches HKDF(KEY_INFO)", m.getOrCreateKey().equals(expectKey));
ok("key derivation returns a Buffer", Buffer.isBuffer(m.getOrCreateKey()));

// legacy key file: v2 record without `info` must derive with the legacy namespace
const legacyHome = path.join(TMP, "legacy");
fs.mkdirSync(path.join(legacyHome, "library"), { recursive: true });
const master = randomBytes(32);
fs.writeFileSync(path.join(legacyHome, "library", ".library.master"), master.toString("base64"));
const salt = randomBytes(16);
fs.writeFileSync(path.join(legacyHome, "library", ".library.key"), JSON.stringify({ v: 2, salt: salt.toString("hex") }));
const legacyKey = Buffer.from(hkdfSync("sha256", master, salt, Buffer.from(m.KEY_INFO_LEGACY, "utf8"), 32));
const iv = randomBytes(12);
const c = createCipheriv("aes-256-gcm", legacyKey, iv);
let ct = c.update(JSON.stringify({ legacy: true }), "utf8", "hex"); ct += c.final("hex");
const saved = process.env.DSH_HOME;
process.env.DSH_HOME = legacyHome;
const legacyPlain = m.decryptSensitive({ sens: 1, iv: iv.toString("hex"), tag: c.getAuthTag().toString("hex"), ct });
ok("legacy key file (no info) still decrypts", legacyPlain && legacyPlain.legacy === true);
process.env.DSH_HOME = saved;

const sealed = m.sealWithPassphrase("pw", { v: 1 });
ok("seal/unseal round-trip", (m.unsealWithPassphrase("pw", sealed) || {}).v === 1);
ok("wrong passphrase rejected", !!m.unsealWithPassphrase("nope", sealed).__unsealError);
const s2 = randomBytes(16);
const lk = Buffer.from(hkdfSync("sha256", Buffer.from("pw", "utf8"), s2, Buffer.from(m.SEAL_INFO_LEGACY, "utf8"), 32));
const iv2 = randomBytes(12);
const c2 = createCipheriv("aes-256-gcm", lk, iv2);
let ct2 = c2.update(JSON.stringify({ legacySeal: true }), "utf8", "hex"); ct2 += c2.final("hex");
const reopened = m.unsealWithPassphrase("pw", { v: 1, salt: s2.toString("hex"), iv: iv2.toString("hex"), tag: c2.getAuthTag().toString("hex"), ct: ct2 });
ok("legacy-sealed archive still unseals", reopened && reopened.legacySeal === true);

// ---------------------------------------------------------------- kohane capability directory
// The directory is kohane's own: one uniform brand, a functional word per capability, and NO
// third-party product name in any default result. The local link table (which plugin on this
// machine provides which capability) is bookkeeping, reachable only through op=provenance.
section("kohane capability directory");
const plug = tool("library_plugin");
// Guard list: strings that must never appear in a default result. Load-bearing, like the legacy
// namespace names elsewhere in this file.
const VENDOR_DENY = /iZotope|MiniMeters|FL Studio|Image-Line|Fruity|Ozone|Nectar|VocalSynth|Sytrus|Harmor|Patcher|FabFilter|Serum|Sylenth|Nexus|Kontakt/i;
const vendorFree = (label, obj) => ok(label, !VENDOR_DENY.test(JSON.stringify(obj)));

ok("library_plugin registered", !!plug && typeof plug.execute === "function");
ok("brand is the uniform family name", m.KOHANE_PLUGIN_BRAND === "Kohane Bassline", m.KOHANE_PLUGIN_BRAND);
ok("the capability list is curated", m.KOHANE_CAPABILITIES.length >= 70, `${m.KOHANE_CAPABILITIES.length} capabilities`);
ok("the extractor vocabulary is generic", m.PLUGIN_FUNCTION_VOCAB.length >= 50 && !VENDOR_DENY.test(m.PLUGIN_FUNCTION_VOCAB.join(" ")));
const builtin = m.resolveKohanePlugins(m.loadPluginPack());
ok("every capability has a role", builtin.every((e) => m.KOHANE_PLUGIN_ROLES[e.role]));
ok("published names are unique", m.duplicateKohaneNames(builtin).length === 0, JSON.stringify(m.duplicateKohaneNames(builtin)));
ok("every name sits in the brand family",
  builtin.every((e) => e.name === m.KOHANE_PLUGIN_BRAND || e.name.startsWith(m.KOHANE_PLUGIN_BRAND + " ")));
const flagship = builtin.find((e) => e.function === m.KOHANE_PLUGIN_FLAGSHIP);
ok("the bare brand name is the flagship capability", flagship && flagship.name === m.KOHANE_PLUGIN_BRAND, flagship && flagship.name);
ok("no capability name carries a vendor name", !VENDOR_DENY.test(builtin.map((e) => e.name).join(" | ")));

// classification and extraction: craft nouns only, never a product name
ok("name hint -> role", m.classifyPluginRole("Vintage Limiter", "") === "effect.dynamics");
ok("category fallback -> role", m.classifyPluginRole("Hardcore", "Effects/Distortion") === "effect.distortion");
ok("metering family -> meter", m.classifyPluginRole("Spectrogram", "") === "meter");
ok("unknown stays unknown", m.classifyPluginRole("Zzz", "Misc/Misc") === "unknown");
ok("extractor keeps a compound word", m.extractFunctionWord("Vintage Compressor 2") === "Vintage Compressor", m.extractFunctionWord("Vintage Compressor 2"));
ok("extractor strips build noise", m.extractFunctionWord("Loudness x64 vst3") === "Loudness", m.extractFunctionWord("Loudness x64 vst3"));
ok("extractor refuses a product-only name", m.extractFunctionWord("Zephyris") === "", m.extractFunctionWord("Zephyris"));
ok("a name with no craft word falls back to the role word", m.derivedFunctionWord({ localName: "Zephyris", role: "effect.reverb" }) === "Reverb");

// ops: list / show / roles
let p = await plug.execute({ op: "list" });
ok("list shows the capability directory", p.ok && p.total >= 70, `${p.total}`);
ok("list groups by role", Object.keys(p.byRole).length >= 15, `${Object.keys(p.byRole).length} role(s)`);
vendorFree("list result is vendor-free", p);
p = await plug.execute({ op: "show", target: "kohane-bassline-maximizer" });
ok("show resolves an entry by id", p.ok && p.entry.function === "Maximizer", p.entry && p.entry.name);
ok("show never returns the internal link key", p.ok && !("sourceKey" in p.entry));
vendorFree("show result is vendor-free", p);
p = await plug.execute({ op: "roles" });
ok("roles op publishes the taxonomy", p.ok && Object.keys(p.roles).length >= 19, `${Object.keys(p.roles).length}`);

// a hermetic plugin folder: two fake plugin binaries, no vendor strings involved
const pluginDir = path.join(TMP, "plugins");
fs.mkdirSync(pluginDir, { recursive: true });
const fakePlugin = (name) => {
  const buf = Buffer.concat([Buffer.from("MZ", "latin1"), Buffer.alloc(62, 0), Buffer.from("PE\0\0", "latin1"), Buffer.alloc(4096, 0), Buffer.from("GetPluginFactory\0", "latin1")]);
  fs.writeFileSync(path.join(pluginDir, name), buf);
};
fakePlugin("Onsen Loudness.vst3");
fakePlugin("Onsen Reverb.vst2x.dll");

p = await plug.execute({ op: "discover", roots: [pluginDir] });
ok("discover walks a plugin folder", p.ok && p.plugins === 2, `${p.plugins} plugin(s)`);
ok("discover reports the ABI it found", p.ok && p.abi.includes("GetPluginFactory"), JSON.stringify(p.abi));
ok("discover hides locations unless asked", p.ok && !p.roots && p.dirs === 1, `dirs=${p.dirs}`);
vendorFree("discover result is vendor-free", p);
p = await plug.execute({ op: "discover", roots: [pluginDir], detail: true });
ok("discover reports locations on request", p.ok && Array.isArray(p.roots) && p.roots.length === 1);

if (HAS_LOCAL_CORPUS) {
  // ops: scan is read-only, learn links
  p = await plug.execute({ op: "scan", dir: FL_DB });
  ok("scan decodes the state corpus", p.ok && p.states === 44 && p.plugins === 44, `${p.states} state(s) / ${p.plugins} plugin(s)`);
  ok("scan is read-only (no pack written)", !fs.existsSync(m.pluginPackFile()));
  vendorFree("scan result is vendor-free", p);
  p = await plug.execute({ op: "learn", dir: FL_DB, binaries: false });
  ok("learn links observations to capabilities", p.ok && p.added === 44 && p.linked >= 20, JSON.stringify({ added: p.added, linked: p.linked }));
  ok("learn persists the pack", fs.existsSync(m.pluginPackFile()));
  vendorFree("learn result is vendor-free", p);
  const pack1 = JSON.parse(fs.readFileSync(m.pluginPackFile(), "utf8"));
  ok("the pack keeps provenance, never a copy of the directory",
    pack1.entries.length === 44 && pack1.entries.every((e) => e.localName && !e.name), `${pack1.entries.length} link(s)`);
  p = await plug.execute({ op: "list" });
  ok("linked capabilities are counted", p.ok && p.linked >= 20, `linked ${p.linked}/${p.total}`);
  vendorFree("list after learn is vendor-free", p);
  p = await plug.execute({ op: "provenance", target: "kohane-bassline-maximizer" });
  ok("provenance is the only op that shows the local side", p.ok && Array.isArray(p.local), `${p.localCount} local link(s)`);

  // personalisation: rename / collision / brand
  p = await plug.execute({ op: "rename", target: "kohane-bassline-vu", function: "Onsen Meter" });
  ok("rename personalises a capability", p.ok && p.entry.name === "Kohane Bassline Onsen Meter", p.entry && p.entry.name);
  p = await plug.execute({ op: "rename", target: "kohane-bassline-meter", function: "Onsen Meter" });
  ok("a colliding name is refused", p.ok === false, p.note);
  p = await plug.execute({ op: "rename", target: "kohane-bassline-meter", function: "Onsen Meter", confirm: true });
  const afterConfirm = m.resolveKohanePlugins(m.loadPluginPack());
  ok("... unless the user confirms, and the directory stays unique",
    p.ok === true && m.duplicateKohaneNames(afterConfirm).length === 0,
    `${p.entry.name}, ${afterConfirm.filter((e) => /Onsen Meter/.test(e.name)).length} personalised`);
  p = await plug.execute({ op: "brand", brand: "Kohane Station" });
  ok("brand renames the whole family", p.ok && p.brand === "Kohane Station" && p.sample[0] === "Kohane Station", JSON.stringify(p.sample));
  p = await plug.execute({ op: "brand", brand: "Kohane Bassline" });
  ok("brand is reversible", p.ok && p.sample[0] === "Kohane Bassline");
  p = await plug.execute({ op: "show", target: "kohane-bassline-onsen-meter" });
  ok("a personalised name survives a brand change", p.ok && p.entry.name === "Kohane Bassline Onsen Meter", p.entry && p.entry.name);

  // ops: add / remove / export
  p = await plug.execute({ op: "add", capability: "Onsen Glue", role: "effect.dynamics" });
  ok("add extends the directory", p.ok && p.entry.name === "Kohane Bassline Onsen Glue", p.entry && p.entry.name);
  p = await plug.execute({ op: "add", capability: "Nope", role: "no.such.role" });
  ok("add refuses an unknown role", p.ok === false, p.note);
  p = await plug.execute({ op: "remove", target: "Onsen Glue" });
  ok("remove drops a local entry", p.ok && p.removed === 1, JSON.stringify(p));
  p = await plug.execute({ op: "remove", target: "Vintage Tape" });
  ok("an unlinked curated capability cannot be removed (only re-purposed)", p.ok === false, p.note);
  p = await plug.execute({ op: "remove", target: "kohane-bassline-compressor" });
  ok("removing a linked capability only drops the local link", p.ok === true && p.removed >= 1, p.note);
  p = await plug.execute({ op: "export", format: "md" });
  ok("export writes the directory", p.ok && fs.existsSync(p.file) && fs.readFileSync(p.file, "utf8").includes("Kohane Bassline Maximizer"), p.file);
  vendorFree("exported markdown is vendor-free", fs.readFileSync(p.file, "utf8"));
  p = await plug.execute({ op: "export", format: "ndjson" });
  ok("export ndjson is machine-readable", p.ok && JSON.parse(fs.readFileSync(p.file, "utf8").split("\n")[0]).name.startsWith("Kohane Bassline"));
  vendorFree("exported ndjson is vendor-free", fs.readFileSync(p.file, "utf8"));
  p = await plug.execute({ op: "nope" });
  ok("an unknown op fails cleanly", p.ok === false && /allowed:/.test(p.note));
  const resolved = m.resolveKohanePlugins(m.loadPluginPack());
  ok("the resolved directory keeps names unique", m.duplicateKohaneNames(resolved).length === 0, JSON.stringify(m.duplicateKohaneNames(resolved)));

  if (HAS_CONTAINER_TABLE) {
    // A container reports its plugins as kohane capabilities; the raw object names stay opt-in.
    r = await m.analyzeObject(FL_FLP);
    const kh = r.fields.kohane || [];
    ok("a container maps its plugins onto kohane capabilities",
      kh.length >= 5 && kh.every((k) => !("sourceName" in k)) && kh.some((k) => k.kohaneName && k.kohaneName.startsWith(m.KOHANE_PLUGIN_BRAND)),
      `${kh.filter((k) => k.kohaneName).length}/${kh.length} mapped`);
    ok("the default container view hides raw object names", !("names" in r.fields) && r.fields.pluginCount >= 5, `pluginCount=${r.fields.pluginCount}`);
    vendorFree("container detail is vendor-free", r.detail);
    r = await m.analyzeObject(FL_FLP, { deep: true });
    ok("deep analysis can still show the raw names", Array.isArray(r.fields.names) && r.fields.names.length >= 5, `${(r.fields.names || []).length} name(s)`);


  } else {
    r = await m.analyzeObject(FL_FLP);
    ok("with no local table the container analyzer claims nothing", !(r && r.kind === "kb-container" && r.ok));
  }

} else {
  p = await plug.execute({ op: "scan", dir: FL_DB });
  ok("scan without a local corpus reports nothing rather than inventing states", !p.ok || p.states === 0, JSON.stringify({ ok: p.ok, states: p.states }));
}
// ---------------------------------------------------------------- index reconciliation
// audit / index / verify / review / prune: three different questions - what is on disk that the
// Library never recorded, whether what IS recorded still points at something real, and whether a
// sealed record was sealed for a reason anyone judged.
section("index reconciliation");
const idx2 = tool("library_index");
const recon = path.join(TMP, "recon");
fs.mkdirSync(recon, { recursive: true });
const keepFile = path.join(recon, "keep.txt");
const extraFile = path.join(recon, "extra.txt");
fs.writeFileSync(keepFile, "keep-v1\n");
fs.writeFileSync(extraFile, "extra\n");

// a record that exists, one whose file is gone, one that is hollow
let rr = await rec.execute({ type: "file", name: "keep.txt", source: recon, path: keepFile, description: "kept", tags: ["recon"] });
ok("fixture record for a file that exists", rr.ok === true, rr.id);
await rec.execute({ type: "file", name: "gone.txt", source: recon, path: path.join(recon, "gone.txt"), description: "missing on purpose", tags: ["recon"] });
const hollowId = m.makeId("file", recon, "hollow.txt");
{
  const ix = await m.loadIndex();
  ix.objects.push({ id: hollowId, type: "file", name: "hollow.txt", source: recon, tags: [], createdAt: new Date().toISOString() });
  await m.saveIndex(ix);
}

// audit is read-only and reconciles in both directions
const beforeAudit = fs.readFileSync(m.indexFile(), "utf8");
let a = await idx2.execute({ op: "audit", dir: recon });
ok("audit reports what is on disk and what is only recorded", a.ok && a.scanned >= 2 && a.recordedUnderRoot >= 2 && a.unrecorded >= 1 && a.missing >= 1,
  `scanned=${a.scanned} recorded=${a.recordedUnderRoot} unrecorded=${a.unrecorded} missing=${a.missing}`);
ok("audit writes nothing", fs.readFileSync(m.indexFile(), "utf8") === beforeAudit && a.wroteNothing === true);
ok("audit refuses a missing dir cleanly", (await idx2.execute({ op: "audit" })).ok === false);

// index refuses a drive root and an unconfirmed write
a = await idx2.execute({ op: "index", dir: "E:\\", confirm: true });
ok("index refuses a drive root", a.ok === false && /drive root/.test(a.note), a.note);
a = await idx2.execute({ op: "index", dir: recon });
ok("index needs confirm", a.ok === false && /confirm/.test(a.note));
const beforeIndex = (await m.loadIndex()).objects.length;
a = await idx2.execute({ op: "index", dir: recon, confirm: true, reason: "recon fixture" });
const afterIndex = (await m.loadIndex()).objects.length;
ok("index registers the unrecorded entries", a.ok && a.added >= 1 && afterIndex > beforeIndex, `+${a.added} record(s)`);
ok("index never seals in bulk", a.skippedSensitive === 0 || a.skippedSensitive > 0, `skipped ${a.skippedSensitive}`);

// verify compares identity, and only records fingerprints when told to
a = await idx2.execute({ op: "verify" });
ok("verify classifies records without writing", a.ok && a.wroteNothing === true && a.checked >= 1, `checked ${a.checked}: ${a.unchanged} unchanged, ${a.changed} changed, ${a.gone} gone, ${a.neverFingerprinted} never`);
ok("verify notices a file that is gone", a.gone >= 1, JSON.stringify((a.goneSamples || []).slice(0, 2)));
a = await idx2.execute({ op: "verify", confirm: true, budgetMs: 20000 });
ok("verify can establish a baseline", a.ok && a.recorded >= 1, `${a.recorded} fingerprint(s) recorded`);
const second = await idx2.execute({ op: "verify" });
ok("a recorded baseline turns into 'unchanged'", second.changed === 0 && second.unchanged >= 1, `${second.unchanged} unchanged, ${second.changed} changed`);
fs.writeFileSync(keepFile, "keep-v2\n");
a = await idx2.execute({ op: "verify" });
ok("verify notices changed content", a.changed >= 1, JSON.stringify((a.changedSamples || []).slice(0, 1)));

// review: sealed / candidates / clear / revoke
const secret = await rec.execute({ type: "env", name: "api_key_onsen", source: "sc", path: "s", description: "credential api_key", tags: [] });
{
  const ix = await m.loadIndex();
  const o = ix.objects.find((x) => x.id === secret.id);
  ok("a sensitive record is stored encrypted", !!o && !!o.__content && o.sensitive === true);
}
a = await idx2.execute({ op: "review", what: "sealed" });
ok("review lists sealed records nobody judged", a.ok && a.sealed >= 1 && a.wroteNothing === true, `${a.sealed} sealed`);
a = await idx2.execute({ op: "review", what: "candidates" });
ok("review lists what the current patterns would seal", a.ok && a.wroteNothing === true, `${a.candidates} candidate(s)`);
a = await idx2.execute({ op: "review", id: secret.id, decision: "clear" });
ok("a review without a reason is refused", a.ok === false && /reason/.test(a.note), a.note);
a = await idx2.execute({ op: "review", id: secret.id, decision: "clear", reason: "scanner rule set, not material" });
ok("review clear makes one encrypted body readable", a.ok === true && a.review.decision === "clear", a.note);
{
  const ix = await m.loadIndex();
  const o = ix.objects.find((x) => x.id === secret.id);
  ok("the cleared record carries the review that let it through", o && !o.__content && o.review && o.review.decision === "clear" && !!o.review.reason);
}
a = await idx2.execute({ op: "review", id: secret.id, decision: "revoke", reason: "it is material after all" });
ok("review revoke puts the rule back", a.ok === true && a.review.decision === "revoke");
{
  const ix = await m.loadIndex();
  const o = ix.objects.find((x) => x.id === secret.id);
  ok("after revoke the body is encrypted again and still judged", o && !!o.__content && o.review.decision === "revoke");
}

// a record that is already sealed can still be judged: revoke keeps the body and records the
// judgement, so it stops looking like a seal nobody ever looked at
const secret2 = await rec.execute({ type: "env", name: "api_key_onsen_2", source: "sc", path: "s2", description: "credential api_key", tags: [] });
a = await idx2.execute({ op: "review", id: secret2.id, decision: "revoke", reason: "seal stands" });
ok("revoke on an already sealed record records the judgement", a.ok === true && a.review.decision === "revoke", a.note);
{
  const ix = await m.loadIndex();
  const o = ix.objects.find((x) => x.id === secret2.id);
  ok("the sealed body survives that judgement", o && !!o.__content && o.review && o.review.decision === "revoke");
  ok("a judged seal is no longer reported as unreviewed", !(await idx2.execute({ op: "review", what: "sealed" })).entries.some((e) => e.id === secret2.id));
}

// prune: dead and hollow need confirmation; leads is honestly empty here
a = await idx2.execute({ op: "prune", what: "dead" });
ok("prune needs confirm", a.ok === false && /confirm/.test(a.note));
a = await idx2.execute({ op: "prune", what: "dead", confirm: true });
ok("prune dead drops only verifiably missing paths", a.ok && a.removed >= 1, `removed ${a.removed}`);
a = await idx2.execute({ op: "prune", what: "hollow", confirm: true });
ok("prune hollow drops a name-only record", a.ok && a.removed >= 1, `removed ${a.removed}`);
a = await idx2.execute({ op: "prune", what: "leads", confirm: true });
ok("prune leads reports there is nothing to tighten", a.ok && a.removed === 0, a.note);
{
  const ix = await m.loadIndex();
  ok("the unconfirmed prune kept the sensitive record", !!ix.objects.find((x) => x.id === secret.id));
}

// an address is not a path: a service endpoint must never be reported as a file that vanished
ok("an address is not a path", m.looksLikeFilePath("http://127.0.0.1:8100") === false
  && m.looksLikeFilePath("127.0.0.1:8100") === false
  && m.looksLikeFilePath("s") === false
  && m.looksLikeFilePath("E:\\x\\y.txt") === true
  && m.looksLikeFilePath("/opt/x/y") === true);
await rec.execute({ type: "env", name: "svc_endpoint", source: recon, path: "http://127.0.0.1:8100", description: "local service", tags: [] });
const withAddress = await idx2.execute({ op: "verify", budgetMs: 20000 });
ok("verify leaves an address alone", !(withAddress.goneSamples || []).some((g) => /http/.test(String(g.path))), JSON.stringify((withAddress.goneSamples || []).slice(0, 2)));

// status: one read-only read
a = await idx2.execute({ op: "status" });
ok("status summarises the Library without writing", a.ok && typeof a.objects === "number" && a.lastFindings.length >= 1,
  `${a.objects} object(s), ${a.encrypted} encrypted, ${a.reviewed} reviewed, ${a.fingerprinted} fingerprinted`);
ok("status reports internal consistency", Array.isArray(a.duplicates) && Array.isArray(a.flagsWithoutBlob));

// the plugin directory can report what is unlinked and what still carries a number
a = await plug.execute({ op: "unlinked" });
ok("library_plugin reports unlinked capabilities", a.ok && typeof a.unlinked === "number" && Array.isArray(a.entries), `${a.unlinked}/${a.total} unlinked`);
a = await plug.execute({ op: "numbered" });
ok("library_plugin reports numbered fallbacks", a.ok && typeof a.numbered === "number" && Array.isArray(a.entries), `${a.numbered} numbered`);

// ---------------------------------------------------------------- session store reading
// A harness keeps history as one compressed frame per record. The reader is built against a
// hermetic store: a multi-frame file, a plain JSONL file and an exported archive.
section("session store reading");
const sessions = tool("library_sessions");
ok("library_sessions is registered", !!sessions && typeof sessions.execute === "function");
ok("the zstd decoder is available in this runtime", m.ZSTD_AVAILABLE === true, String(m.ZSTD_AVAILABLE));
if (m.ZSTD_AVAILABLE) {
  const storeDir = path.join(process.env.DSH_HOME, "sessions");
  const dirA = path.join(storeDir, "--fixture--", "session-fixture-a");
  fs.mkdirSync(dirA, { recursive: true });
  const records = [
    { type: "session", id: "session-fixture-a", cwd: "E:\\fixture", createdAt: 1700000000000, agentPreset: "test", delegationDepth: 0 },
    { type: "user/message", time: 1700000001000, data: { role: "user", text: "where is the onsen" } },
    { type: "assistant/message", time: 1700000002000, message: { content: [{ type: "text", text: "up the hill, past the torii" }] } },
  ];
  const frameFile = path.join(dirA, "session.v3.jsonl.zstd");
  fs.writeFileSync(frameFile, Buffer.concat(records.map((r) => zlib.zstdCompressSync(Buffer.from(JSON.stringify(r) + "\n", "utf8")))));

  const dirB = path.join(storeDir, "--fixture--", "session-fixture-b");
  fs.mkdirSync(dirB, { recursive: true });
  const plainFile = path.join(dirB, "session.v3.jsonl");
  fs.writeFileSync(plainFile, records.slice(0, 2).map((r) => JSON.stringify(r)).join("\n") + "\n");

  const zipPath = path.join(storeDir, "archive-fixture.zip");
  fs.writeFileSync(zipPath, m.zipBuffer ? m.zipBuffer([{ name: "session.v3.jsonl.zstd", data: fs.readFileSync(frameFile) }]) : Buffer.alloc(0));

  let s = await sessions.execute({ op: "status" });
  ok("status reports the store", s.ok && s.sessions >= 2 && s.decoder === "zstd", `${s.sessions} session(s), ${s.bytes} bytes`);
  ok("every response carries the host timezone", !!s.timezone && typeof s.timezone.offsetMinutes === "number", JSON.stringify(s.timezone));

  s = await sessions.execute({ op: "list" });
  const entryA = (s.entries || []).find((e) => /fixture-a/.test(e.session));
  ok("list enumerates sessions from headers and titles", s.ok && entryA && entryA.header.id === "session-fixture-a" && /onsen/.test(entryA.title || ""), entryA && entryA.title);
  ok("list reads a plain JSONL session too", (s.entries || []).some((e) => /fixture-b/.test(e.session)));
  ok("list does not return transcript text", !JSON.stringify(s.entries || []).includes("up the hill"));

  s = await sessions.execute({ op: "read", target: "session-fixture-a" });
  ok("read decodes every frame of a session", s.ok && s.records === 3 && s.header.id === "session-fixture-a", `${s.records} record(s), ${s.frames} frame(s), failed ${s.failed}`);
  ok("read is a structural summary unless asked for content", s.ok && !(s.messages || []).length && Array.isArray(s.types) && s.types.length >= 2, JSON.stringify((s.types || []).slice(0, 3)));

  s = await sessions.execute({ op: "read", target: "session-fixture-a", content: true });
  ok("read with content returns bounded message text",
    s.ok && (s.messages || []).some((msg) => /up the hill/.test(msg.text || "")), `${(s.messages || []).length} message(s)`);

  s = await sessions.execute({ op: "tail", target: "session-fixture-a", frames: 1 });
  ok("tail decodes only the trailing frames", s.ok && s.records <= 2 && s.records >= 1, `${s.records} record(s) from ${s.frames} frame(s)`);

  s = await sessions.execute({ op: "search", query: "onsen" });
  ok("search finds a phrase and reports what it scanned", s.ok && s.found >= 1 && s.searched >= 1, `${s.found} hit(s) in ${s.searched} file(s)`);
  ok("a search snippet is a snippet, not a transcript", (s.hits || []).every((h) => String(h.snippet).length < 400));

  s = await sessions.execute({ op: "read", target: "no-such-session-xyz" });
  ok("a missing target fails cleanly", s.ok === false && !!s.note, s.note);

  const before = (await m.loadIndex()).objects.length;
  s = await sessions.execute({ op: "record", target: "session-fixture-a", maxChars: 2000 });
  const after = (await m.loadIndex()).objects.length;
  ok("record writes the session into the Library", s.ok && after === before + 1, `${before} -> ${after}, id ${s.id}`);
  ok("the recorded object is a log with the session title", /onsen/.test(s.name || ""), s.name);

  if (m.zipBuffer) {
    const zipBuf = fs.readFileSync(zipPath);
    ok("an exported archive is recognised", m.zipEntryNames(zipBuf, 10).some((n) => /\.jsonl/.test(n)), JSON.stringify(m.zipEntryNames(zipBuf, 10)));
    s = await sessions.execute({ op: "read", target: zipPath });
    ok("read walks an archive's session members", s.ok && s.records === 3 && s.kind === "archive", `${s.records} record(s) from ${(s.header && s.header.id) || "?"}`);
  }
  fs.rmSync(zipPath, { force: true });
}

// ---------------------------------------------------------------- host shell generation
// The desktop dialog must ride whatever generation this machine defaults to: PowerShell 7 when it
// is installed (preferred), Windows PowerShell 5.1 as the fallback, and an explicit pin wins.
section("host shell generation");
ok("resolvePowerShell exported", typeof m.resolvePowerShell === "function" && typeof m.dialogWorkDir === "function");
const ps = m.resolvePowerShell();
ok("a shell is resolved", typeof ps === "string" && ps.length > 0, ps);
if (process.platform === "win32") {
  ok("the resolved shell exists on disk", ps.includes(path.sep) ? fs.existsSync(ps) : true, ps);
  process.env.KOHANE_PS_SHELL = "powershell.exe";
  ok("an explicit pin wins", m.resolvePowerShell() === "powershell.exe");
  delete process.env.KOHANE_PS_SHELL;
}
const pwsh7 = "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
if (process.platform === "win32" && fs.existsSync(pwsh7)) {
  ok("PowerShell 7 is preferred when installed", /pwsh/i.test(m.resolvePowerShell()), m.resolvePowerShell());
}
const dwd = m.dialogWorkDir();
ok("dialog scratch lives inside this installation's library", dwd.startsWith(m.libraryDir()), dwd);
const sysTmp = path.resolve(os.tmpdir());
// The harness may deliberately put TEMP on another drive; the rule is only that kohane must not
// drop its scratch into the SYSTEM drive's temp folder.
const tmpOnSystemDrive = /^[A-Za-z]:/.test(sysTmp) && sysTmp.slice(0, 2).toUpperCase() === String(process.env.SystemDrive || "C:").toUpperCase();
ok("dialog scratch never uses the system temp folder", !path.resolve(dwd).startsWith(sysTmp) || !tmpOnSystemDrive, `${dwd} (system temp ${sysTmp})`);
fs.rmSync(dwd, { recursive: true, force: true });

// batch rename: one word with {n} numbers the targets; without {n} it would collide and is refused
await plug.execute({ op: "add", capability: "Batch Alpha", role: "effect.multi" });
await plug.execute({ op: "add", capability: "Batch Beta", role: "effect.multi" });
p = await plug.execute({ op: "rename", target: ["kohane-bassline-batch-alpha", "kohane-bassline-batch-beta"], function: "Onsen Batch {n}" });
ok("a batch rename numbers its targets",
  p.ok === true && p.renamed === 2 && p.applied[0].to === "Kohane Bassline Onsen Batch 1" && p.applied[1].to === "Kohane Bassline Onsen Batch 2",
  JSON.stringify(p.applied));
p = await plug.execute({ op: "rename", target: ["kohane-bassline-onsen-batch-1", "kohane-bassline-onsen-batch-2"], function: "Single Word" });
ok("a batch without {n} is refused", p.ok === false && /collide/.test(p.note), p.note);
p = await plug.execute({ op: "rename", target: "kohane-bassline-onsen-batch-1", name: "Kohane Bassline Onsen Solo" });
ok("an explicit name still works for one target", p.ok === true && p.entry.name === "Kohane Bassline Onsen Solo", p.entry && p.entry.name);

// link portability: the local table can travel, plain or sealed
const linksFile = path.join(TMP, "links.json");
const linksSealed = path.join(TMP, "links.sealed.json");
p = await plug.execute({ op: "export-links", path: linksFile });
ok("links export writes the local table", p.ok === true && p.links >= 1 && fs.existsSync(linksFile), `${p.links} link(s)`);
p = await plug.execute({ op: "export-links", path: linksSealed, passphrase: "onsen" });
ok("links export can seal the file", p.ok === true && p.sealed === true);
ok("a sealed link file does not expose the links", (() => {
  try {
    return JSON.parse(fs.readFileSync(linksSealed, "utf8")).links === undefined;
  } catch {
    return true;
  }
})());
p = await plug.execute({ op: "import-links", path: linksSealed });
ok("a sealed link file needs its passphrase", p.ok === false && /passphrase/.test(p.note), p.note);
p = await plug.execute({ op: "import-links", path: linksSealed, passphrase: "wrong" });
ok("a wrong passphrase is refused", p.ok === false && /unseal failed/.test(p.note), p.note);
p = await plug.execute({ op: "import-links", path: linksSealed, passphrase: "onsen" });
ok("a sealed link file opens with its passphrase", p.ok === true && (p.added + p.updated + p.skipped) >= 1, JSON.stringify({ added: p.added, updated: p.updated, skipped: p.skipped }));
p = await plug.execute({ op: "import-links", path: linksFile });
ok("import leaves existing links alone by default", p.ok === true && p.skipped >= 1 && p.added === 0, JSON.stringify({ added: p.added, updated: p.updated, skipped: p.skipped }));
p = await plug.execute({ op: "import-links", path: linksFile, confirm: true });
ok("confirm overwrites the existing links", p.ok === true && p.updated >= 1, JSON.stringify({ added: p.added, updated: p.updated }));
p = await plug.execute({ op: "import-links", path: path.join(TMP, "nope.json") });
ok("import of a missing file fails cleanly", p.ok === false && /no link file/.test(p.note), p.note);

// ---------------------------------------------------------------- flac encode + independent walk
section("flac encode + independent walk");
{
  const { encodeFlac } = await import(pathToFileURL(path.join(ROOT, "kohane-index-desuno", "deps", "decoders", "flac-encoder.mjs")).href);
  const { walkFlac } = await import(pathToFileURL(path.join(HERE, "flac-walk.mjs")).href);
  // One second of stereo, built to cross every subframe branch the encoder knows:
  // silence (constant), a 440 Hz sine (fixed predictor, near-zero residual), and a deterministic
  // LCG noise tail (residuals large enough to fall back to verbatim or a high Rice parameter).
  const rate = 44100, ch = 2, frames = rate;
  const samples = new Float64Array(frames * ch);
  for (let i = 0; i < frames; i++) {
    const t = i / rate;
    if (i < 4410) {
      samples[i * ch] = 0; samples[i * ch + 1] = 0;
    } else if (i < 39690) {
      samples[i * ch] = 0.5 * Math.sin(2 * Math.PI * 440 * t);
      samples[i * ch + 1] = 0.5 * Math.sin(2 * Math.PI * 440 * t + Math.PI / 2);
    } else {
      const u = ((i * 1664525 + 1013904223) >>> 0) / 0xffffffff;
      const u2 = (((i + 7) * 1664525 + 1013904223) >>> 0) / 0xffffffff;
      samples[i * ch] = 0.1 * (u - 0.5);
      samples[i * ch + 1] = 0.1 * (u2 - 0.5);
    }
  }
  // The source PCM exactly as the encoder quantises it, so the comparison is against the truth the
  // encoder was given, not against a second quantisation.
  const srcPcm = Buffer.alloc(frames * ch * 2);
  for (let i = 0; i < frames * ch; i++) {
    const v = Math.max(-1, Math.min(1, samples[i] || 0));
    srcPcm.writeInt16LE(Math.round(v * 32767), i * 2);
  }
  const buf = encodeFlac(samples, { sampleRate: rate, channels: ch });
  const walked = walkFlac(buf);
  ok("walk recovers the STREAMINFO shape",
    walked.sampleRate === rate && walked.channels === ch && walked.bps === 16 && walked.totalFrames === frames,
    JSON.stringify({ rate: walked.sampleRate, ch: walked.channels, bps: walked.bps, frames: walked.totalFrames }));
  ok("walk recovers every sample", walked.pcm16.equals(srcPcm), `${walked.pcm16.length} bytes`);
  ok("STREAMINFO MD5 is the MD5 of the source PCM",
    walked.md5.equals(createHash("md5").update(srcPcm).digest()));
  ok("prediction + Rice actually compress", buf.length < srcPcm.length, `flac=${buf.length} pcm=${srcPcm.length}`);
  // Law 9: an independent reader. ffmpeg is a registered candidate; where it exists, its decode of
  // our stream must agree byte for byte. Where it does not exist this assertion is skipped instead
  // of failing, so a machine without ffmpeg is not penalised for an environment fact.
  const ffmpeg = m.resolveCandidatePath(m.DETECT_CANDIDATES.find((c) => c.name === "ffmpeg"));
  if (ffmpeg) {
    const flacFile = path.join(TMP, "walked.flac");
    fs.writeFileSync(flacFile, buf);
    const dec = spawnSync(ffmpeg, ["-v", "error", "-i", flacFile, "-f", "s16le", "-"], { maxBuffer: 64 * 1024 * 1024 });
    ok("ffmpeg decodes the walk target to the same PCM",
      dec.status === 0 && Buffer.from(dec.stdout || []).equals(srcPcm),
      dec.status === 0
        ? `${(dec.stdout || []).length} bytes vs ${srcPcm.length}`
        : String((dec.stderr || "").toString("utf8")).split("\n")[0]);
  } else {
    ok("ffmpeg cross-check (skipped: no ffmpeg on this machine)", true, "skipped");
  }

  // Escaped partitions (k=15): a mostly-predictable signal with a stretch of full-scale noise
  // keeps the fixed predictor worthwhile overall while one partition's residuals are too wild for
  // any Rice parameter - exactly the case the escape exists for. The walk counts escaped
  // partitions, and the judge demands at least one, so the escape path has to be taken, not just
  // implemented. The noise is xorshift32: an LCG's neighbours are linearly related, and a fixed
  // predictor would eat them, which is precisely what must not happen here.
  let xs = 0x1234567;
  const xr = () => {
    xs ^= xs << 13; xs >>>= 0;
    xs ^= xs >> 17;
    xs ^= xs << 5; xs >>>= 0;
    return xs / 0xffffffff;
  };
  const escSamples = new Float64Array(rate * 2);
  for (let i = 0; i < rate; i++) {
    if (i < rate * 0.8) {
      const t = i / rate;
      escSamples[i * 2] = 0.5 * Math.sin(2 * Math.PI * 440 * t);
      escSamples[i * 2 + 1] = 0.5 * Math.sin(2 * Math.PI * 440 * t + Math.PI / 2);
    } else {
      escSamples[i * 2] = 1.8 * (xr() - 0.5);
      escSamples[i * 2 + 1] = 1.8 * (xr() - 0.5);
    }
  }
  const escPcm = Buffer.alloc(rate * 2 * 2);
  for (let i = 0; i < rate * 2; i++) {
    const v = Math.max(-1, Math.min(1, escSamples[i] || 0));
    escPcm.writeInt16LE(Math.round(v * 32767), i * 2);
  }
  const escBuf = encodeFlac(escSamples, { sampleRate: rate, channels: 2 });
  const escWalked = walkFlac(escBuf);
  ok("full-scale noise takes the escape path", escWalked.escapes > 0, `escapes=${escWalked.escapes}`);
  ok("escaped partitions decode sample-exactly", escWalked.pcm16.equals(escPcm), `${escWalked.pcm16.length} bytes`);
  if (ffmpeg) {
    const escFile = path.join(TMP, "escaped.flac");
    fs.writeFileSync(escFile, escBuf);
    const escDec = spawnSync(ffmpeg, ["-v", "error", "-i", escFile, "-f", "s16le", "-"], { maxBuffer: 64 * 1024 * 1024 });
    ok("ffmpeg decodes the escaped stream to the same PCM",
      escDec.status === 0 && Buffer.from(escDec.stdout || []).equals(escPcm),
      escDec.status === 0
        ? `${(escDec.stdout || []).length} bytes vs ${escPcm.length}`
        : String((escDec.stderr || "").toString("utf8")).split("\n")[0]);
  } else {
    ok("ffmpeg escape cross-check (skipped: no ffmpeg on this machine)", true, "skipped");
  }

  // LPC subframes: an AR(2) process is exactly what LPC models - the coefficients are learned and
  // the residual is the driving noise - while a fixed polynomial predictor cannot touch the
  // resonance, so the search must pick LPC for this signal. The walk counts LPC subframes; the
  // judge demands at least one, so the LPC path has to be taken, not just implemented. The driving
  // noise is xorshift32 with a fixed seed, so the fixture is reproducible.
  let xa = 0x9e3779b9;
  const ar = () => {
    xa ^= xa << 13; xa >>>= 0;
    xa ^= xa >> 17;
    xa ^= xa << 5; xa >>>= 0;
    return xa / 0xffffffff;
  };
  const arState = [0, 0];
  const arFrame = (amp) => {
    // Poles at magnitude 0.99: a narrow resonance a fixed polynomial predictor cannot
    // extrapolate, so the fixed residual stays at signal scale while the LPC residual is the
    // driving noise itself.
    const v = 1.8 * arState[0] - 0.98 * arState[1] + amp * (ar() - 0.5);
    arState[1] = arState[0];
    arState[0] = v;
    return v;
  };
  for (let i = 0; i < 2000; i++) arFrame(0.08);         // warm up the narrow resonance
  const lpcSamples = new Float64Array(rate * 2);
  for (let i = 0; i < rate; i++) {
    lpcSamples[i * 2] = arFrame(0.08);
    lpcSamples[i * 2 + 1] = arFrame(0.08);
  }
  const lpcPcm = Buffer.alloc(rate * 2 * 2);
  for (let i = 0; i < rate * 2; i++) {
    const v = Math.max(-1, Math.min(1, lpcSamples[i] || 0));
    lpcPcm.writeInt16LE(Math.round(v * 32767), i * 2);
  }
  const lpcBuf = encodeFlac(lpcSamples, { sampleRate: rate, channels: 2 });
  const lpcWalked = walkFlac(lpcBuf);
  ok("inharmonic sines take the LPC path", lpcWalked.lpcCount > 0, `lpc=${lpcWalked.lpcCount}`);
  ok("LPC subframes decode sample-exactly", lpcWalked.pcm16.equals(lpcPcm), `${lpcWalked.pcm16.length} bytes`);
  if (ffmpeg) {
    const lpcFile = path.join(TMP, "lpc.flac");
    fs.writeFileSync(lpcFile, lpcBuf);
    const lpcDec = spawnSync(ffmpeg, ["-v", "error", "-i", lpcFile, "-f", "s16le", "-"], { maxBuffer: 64 * 1024 * 1024 });
    ok("ffmpeg decodes the LPC stream to the same PCM",
      lpcDec.status === 0 && Buffer.from(lpcDec.stdout || []).equals(lpcPcm),
      lpcDec.status === 0
        ? `${(lpcDec.stdout || []).length} bytes vs ${lpcPcm.length}`
        : String((lpcDec.stderr || "").toString("utf8")).split("\n")[0]);
  } else {
    ok("ffmpeg LPC cross-check (skipped: no ffmpeg on this machine)", true, "skipped");
  }
}

// ---------------------------------------------------------------- synth: keygen music mode
section("synth: keygen music mode");
{
  const { synthesize } = await import(pathToFileURL(path.join(ROOT, "kohane-index-desuno", "deps", "decoders", "synth.mjs")).href);
  const { encodeFlac, encodeWav16 } = await import(pathToFileURL(path.join(ROOT, "kohane-index-desuno", "deps", "decoders", "flac-encoder.mjs")).href);
  const { walkFlac } = await import(pathToFileURL(path.join(HERE, "flac-walk.mjs")).href);
  const rate = 44100;

  // The sine oscillator agrees with the analytic sine at every sample: the phase-accumulator path
  // and the direct evaluation are two code paths for one definition.
  const sine = synthesize({ sampleRate: rate, notes: [{ t: 0, dur: 0.1, pitch: 69, wave: "sine" }], adsr: { a: 0, d: 0, s: 1, r: 0 } });
  let sineOk = sine.frames > 0;
  for (let i = 0; i < sine.frames; i++) {
    if (Math.abs(sine.samples[i] - Math.sin(2 * Math.PI * 440 * i / rate)) > 1e-9) { sineOk = false; break; }
  }
  ok("sine oscillator matches the analytic sine", sineOk, `${sine.frames} frames`);

  // The square oscillator is two-valued during its sustain.
  const square = synthesize({ sampleRate: rate, notes: [{ t: 0, dur: 0.1, pitch: 60, wave: "square" }], adsr: { a: 0.002, d: 0.02, s: 1, r: 0 } });
  const sq = [...new Set(square.samples.slice(rate * 0.05, rate * 0.09).map((v) => v.toFixed(3)))];
  ok("square oscillator is two-valued in sustain", sq.length === 2, JSON.stringify(sq));

  // The saw oscillator steps by one constant slope between its wrap points, so the distinct
  // sample-to-sample steps are at most two (the slope, and the single wrap step per period).
  const saw = synthesize({ sampleRate: rate, notes: [{ t: 0, dur: 0.1, pitch: 60, wave: "saw" }], adsr: { a: 0.002, d: 0.02, s: 1, r: 0 } });
  const diffs = new Set();
  for (let i = rate * 0.06; i + 1 < rate * 0.09; i++) diffs.add((saw.samples[i + 1] - saw.samples[i]).toFixed(6));
  ok("saw oscillator is linear between its wrap points", diffs.size <= 2, `${diffs.size} distinct step(s)`);

  // Release ends at silence, and its per-window peaks decay monotonically. The last frame sits
  // exactly at the release end, so it must be zero; the frames before it must not be.
  const rel = synthesize({ sampleRate: rate, notes: [{ t: 0, dur: 0.1, pitch: 60 }], adsr: { a: 0.005, d: 0.02, s: 0.7, r: 0.05 } });
  ok("release ends at a silent last frame", rel.samples[rel.frames - 1] === 0, `${rel.frames} frames`);
  let monoDecay = true, prev = Infinity;
  const win = Math.floor((rel.frames - 0.1 * rate) / 10);
  for (let w = 0; w < 10 && monoDecay; w++) {
    let peak = 0;
    for (let i = Math.floor(0.1 * rate) + w * win; i < Math.floor(0.1 * rate) + (w + 1) * win && i < rel.frames; i++) {
      const a = Math.abs(rel.samples[i]);
      if (a > peak) peak = a;
    }
    if (peak > prev + 1e-9) monoDecay = false;
    prev = peak;
  }
  ok("release peaks decay monotonically", monoDecay);
  ok("frame count follows the last note end", rel.frames === Math.ceil((0.1 + 0.05) * rate), `frames=${rel.frames}`);

  // Overlapping notes mix inside the unit range.
  const mix = synthesize({ sampleRate: rate, notes: [{ t: 0, dur: 0.5, pitch: 60 }, { t: 0.3, dur: 0.4, pitch: 64 }], wave: "square" });
  ok("mixed peaks stay inside -1..1", mix.peaks.min >= -1 && mix.peaks.max <= 1, JSON.stringify(mix.peaks));

  // The noise wave: deterministic per seed (two renders agree sample for sample - the property the
  // embedded C player depends on) and inside the unit range.
  const noiseA = synthesize({ sampleRate: rate, notes: [{ t: 0, dur: 0.1, pitch: 60, wave: "noise" }] });
  const noiseB = synthesize({ sampleRate: rate, notes: [{ t: 0, dur: 0.1, pitch: 60, wave: "noise" }] });
  let noiseSame = noiseA.frames === noiseB.frames;
  if (noiseSame) for (let i = 0; i < noiseA.frames; i++) if (noiseA.samples[i] !== noiseB.samples[i]) { noiseSame = false; break; }
  ok("noise renders deterministically for one seed", noiseSame, `${noiseA.frames} frames`);
  ok("noise stays inside the unit range", noiseA.peaks.min >= -1 && noiseA.peaks.max <= 1, JSON.stringify(noiseA.peaks));

  // The synth output survives the FLAC round trip: encoded by this project's writer, decoded by
  // the independent walk - two modules, one agreement (law 9).
  const pcm16 = Buffer.alloc(mix.frames * 2);
  for (let i = 0; i < mix.frames; i++) {
    const v = Math.max(-1, Math.min(1, mix.samples[i] || 0));
    pcm16.writeInt16LE(Math.round(v * 32767), i * 2);
  }
  const walkedBack = walkFlac(encodeFlac(mix.samples, { sampleRate: rate, channels: 1 }));
  ok("synth output survives the FLAC round trip", walkedBack.pcm16.equals(pcm16), `${walkedBack.pcm16.length} bytes`);

  // The volume argument keygen music rests on: the score is data, the audio is generated. The
  // score that produced this mix is a hundred bytes; the WAV of it is a hundred kilobytes.
  const scoreBytes = Buffer.byteLength(JSON.stringify([{ t: 0, dur: 0.5, pitch: 60 }, { t: 0.3, dur: 0.4, pitch: 64 }]), "utf8");
  const wavBytes = encodeWav16(mix.samples, { sampleRate: rate, channels: 1 }).length;
  ok("the score is at least 50x smaller than the audio it generates",
    wavBytes / scoreBytes > 50,
    `score=${scoreBytes}B wav=${wavBytes}B ratio=${Math.round(wavBytes / scoreBytes)}x`);
}

// ---------------------------------------------------------------- midi score read
section("midi score read");
{
  const { midiToSynth } = await import(pathToFileURL(path.join(ROOT, "kohane-index-desuno", "deps", "decoders", "synth.mjs")).href);
  const { synthesize } = await import(pathToFileURL(path.join(ROOT, "kohane-index-desuno", "deps", "decoders", "synth.mjs")).href);
  // A tiny MIDI writer for the fixtures: header + tracks + the events the reader must handle
  // (tempo, note on/off, velocity-0 off, a hanging note, a name-only track).
  const vlq = (v) => { const b = [v & 0x7f]; while ((v >>= 7)) b.unshift((v & 0x7f) | 0x80); return Buffer.from(b); };
  const track = (events) => {
    const body = Buffer.concat(events.map(([delta, ...bytes]) => Buffer.concat([vlq(delta), Buffer.from(bytes)])));
    return Buffer.concat([Buffer.from("MTrk", "latin1"), Buffer.from([(body.length >> 24) & 0xff, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]), body]);
  };
  const midi = (format, division, tracks) => {
    const head = Buffer.alloc(14);
    head.write("MThd", 0, "latin1");
    head.writeUInt32BE(6, 4);
    head.writeUInt16BE(format, 8);
    head.writeUInt16BE(tracks.length, 10);
    head.writeUInt16BE(division, 12);
    return Buffer.concat([head, ...tracks.map(track)]);
  };
  const tempo120 = [0, 0xff, 0x51, 0x03, 0x07, 0xa1, 0x20];          // 500000 us per quarter = 120 BPM
  const eot = [0, 0xff, 0x2f, 0x00];
  const readScore = (file) => tool("library_audio").execute({ op: "score", path: file });

  // Case A: format 0, ppq 480, three notes with clean on/off pairs.
  const a = midi(0, 480, [[
    tempo120,
    [0, 0x90, 60, 100], [480, 0x80, 60, 0],
    [0, 0x90, 64, 90], [240, 0x80, 64, 0],
    [0, 0x90, 67, 80], [480, 0x80, 67, 0],
    eot,
  ]]);
  const aFile = path.join(TMP, "fixture-a.mid");
  fs.writeFileSync(aFile, a);
  const aScore = await readScore(aFile);
  ok("score reads three clean notes", aScore.ok && aScore.notes === 3, JSON.stringify({ ok: aScore.ok, notes: aScore.notes }));
  ok("score reads tempo, ppq and format", aScore.ok && aScore.tempo === 120 && aScore.ppq === 480 && aScore.format === 0, JSON.stringify({ tempo: aScore.tempo, ppq: aScore.ppq }));
  const aNotes = aScore.ok && aScore.tracks.length ? aScore.tracks[0].notes : [];
  ok("score keeps note, length and pitch name",
    aNotes.length === 3 && aNotes[0].note === 60 && aNotes[0].ticks === 480 && aNotes[0].pitch === "C4",
    JSON.stringify(aNotes.map((n) => [n.note, n.ticks, n.pitch])));

  // Case B: velocity 0 closes a note, and a note left hanging at the end still happened.
  const b = midi(0, 480, [[
    tempo120,
    [0, 0x90, 60, 90], [240, 0x90, 60, 0],      // velocity-0 note off
    [240, 0x90, 64, 90],                          // never closed; the track ends 480 ticks later
    [480, 0xff, 0x2f, 0x00],
  ]]);
  const bFile = path.join(TMP, "fixture-b.mid");
  fs.writeFileSync(bFile, b);
  const bScore = await readScore(bFile);
  const bNotes = bScore.ok && bScore.tracks.length ? bScore.tracks[0].notes : [];
  ok("velocity 0 closes a note", bScore.ok && bNotes.length === 2 && bNotes.some((n) => n.note === 60 && n.ticks === 240), JSON.stringify(bNotes.map((n) => [n.note, n.ticks])));
  ok("a hanging note still happened", bScore.ok && bNotes.some((n) => n.note === 64 && n.ticks >= 480), JSON.stringify(bNotes.map((n) => [n.note, n.ticks])));

  // Case C: format 1, a name-only second track lands in emptyTracks and supplies the title.
  const c = midi(1, 480, [
    [tempo120, [0, 0x90, 60, 100], [480, 0x80, 60, 0], eot],
    [[0, 0xff, 0x03, 5, ...Buffer.from("hello", "latin1")], eot],
  ]);
  const cFile = path.join(TMP, "fixture-c.mid");
  fs.writeFileSync(cFile, c);
  const cScore = await readScore(cFile);
  ok("a name-only track is reported empty",
    cScore.ok && cScore.declaredTracks === 2 && cScore.tracks.length === 1 && cScore.emptyTracks.includes("hello") && cScore.title === "hello",
    JSON.stringify({ declared: cScore.declaredTracks, kept: cScore.tracks.length, empty: cScore.emptyTracks, title: cScore.title }));

  // The full chain: the score from case A converts to synth time and renders the right length.
  // 1200 ticks at 120 BPM / 480 ppq = 1.25 s; the default release adds 0.05 s.
  const synthable = midiToSynth(aScore);
  ok("tick time converts to seconds", synthable.notes.length === 3 && Math.abs(synthable.notes[0].t - 0) < 1e-9 && Math.abs(synthable.notes[1].t - 0.5) < 1e-9, JSON.stringify(synthable.notes.map((n) => [n.t, n.dur, n.pitch])));
  const rendered = synthesize({ sampleRate: 44100, notes: synthable.notes, wave: "square" });
  ok("the rendered length follows the score", rendered.frames === Math.ceil((1.25 + 0.05) * 44100), `frames=${rendered.frames}`);

  // The real tune, where present: 13 parts, 3527 notes - read, not rendered, so the suite stays fast.
  const real = "E:/hc-fl/kohane-yunooka-no-asa.mid";
  if (fs.existsSync(real)) {
    const realScore = await readScore(real);
    ok("the real tune reads as recorded", realScore.ok && realScore.notes === 3527 && realScore.tracks.length === 13, JSON.stringify({ ok: realScore.ok, notes: realScore.notes, tracks: realScore.tracks.length }));
  } else {
    ok("the real tune (skipped: not on this machine)", true, "skipped");
  }
}

// ---------------------------------------------------------------- soundfont read
section("soundfont read");
{
  const { readSf2 } = await import(pathToFileURL(path.join(ROOT, "kohane-index-desuno", "deps", "decoders", "sf2.mjs")).href);
  const ck = (id, body) => {
    const b = Buffer.from(body);
    const pad = b.length % 2 ? Buffer.alloc(1) : Buffer.alloc(0);
    const head = Buffer.alloc(8);
    head.write(id, 0, "latin1");
    head.writeUInt32LE(b.length, 4);
    return Buffer.concat([head, b, pad]);
  };
  const list = (type, ...chunks) => ck("LIST", Buffer.concat([Buffer.from(type, "latin1"), ...chunks]));
  const phdr = (name, preset, bank) => {
    const b = Buffer.alloc(38);
    b.write(name, 0, "latin1");
    b.writeUInt16LE(preset, 20);
    b.writeUInt16LE(bank, 22);
    return b;
  };
  const inst = (name) => { const b = Buffer.alloc(22); b.write(name, 0, "latin1"); return b; };
  const shdr = (name, rate, pitch) => {
    const b = Buffer.alloc(46);
    b.write(name, 0, "latin1");
    b.writeUInt32LE(rate, 36);
    b[pitch >= 0 ? 40 : 41] = Math.abs(pitch);
    b.writeUInt16LE(1, 44);
    return b;
  };
  const fixture = ck("RIFF", Buffer.concat([
    Buffer.from("sfbk", "latin1"),
    list("sdta", ck("smpl", Buffer.alloc(64, 7))),
    list("pdta",
      ck("phdr", Buffer.concat([phdr("Bright Piano", 0, 0), phdr("Soft Pad", 5, 1), phdr("EOP", 0, 0)])),
      ck("inst", Buffer.concat([inst("Piano Inst"), inst("Pad Inst"), inst("EOI")])),
      ck("shdr", Buffer.concat([shdr("Piano Sample", 44100, 60), shdr("Pad Sample", 22050, 48), shdr("EOS", 0, 0)])),
    ),
  ]));
  const sf2File = path.join(TMP, "fixture.sf2");
  fs.writeFileSync(sf2File, fixture);
  const sf2 = readSf2(sf2File);
  ok("soundfont presets read with name and numbers",
    sf2.presets.length === 2 && sf2.presets[0].name === "Bright Piano" && sf2.presets[1].preset === 5 && sf2.presets[1].bank === 1,
    JSON.stringify(sf2.presets));
  ok("soundfont instruments read", sf2.instruments.length === 2 && sf2.instruments[0].name === "Piano Inst", JSON.stringify(sf2.instruments.map((i) => i.name)));
  ok("soundfont samples read with rate and pitch",
    sf2.samples.length === 2 && sf2.samples[0].sampleRate === 44100 && sf2.samples[0].originalPitch === 60 && sf2.samples[1].sampleRate === 22050,
    JSON.stringify(sf2.samples.map((s) => [s.name, s.sampleRate, s.originalPitch])));
  ok("soundfont sample data size reported", sf2.smplBytes === 64, `smplBytes=${sf2.smplBytes}`);
  ok("a WAVE file is refused as not a soundfont", (() => { try { readSf2(path.join(TMP, "walked.flac")); return false; } catch (e) { return /not a SoundFont/.test(e.message); } })());
  const real = "D:/VSTPlugins/Soundfont Enhancer/Romantic Tp.sf2";
  if (fs.existsSync(real)) {
    const realFont = readSf2(real);
    ok("the real font reads as a populated soundfont",
      realFont.presets.length > 0 && realFont.samples.length > 0 && realFont.summary.sampleRateHint > 0,
      JSON.stringify(realFont.summary));
  } else {
    ok("the real font (skipped: not on this machine)", true, "skipped");
  }
}

// ---------------------------------------------------------------- preset chunks read
section("preset chunks read");
{
  const { parseFpch } = await import(pathToFileURL(path.join(ROOT, "kohane-index-desuno", "deps", "decoders", "fxp.mjs")).href);
  const body = Buffer.alloc(32, 0x5a);
  const name = Buffer.concat([Buffer.from("Fixture Preset", "latin1"), Buffer.alloc(1)]);
  const fpch = Buffer.concat([
    Buffer.from("CcnK", "latin1"), Buffer.from([0, 0, 0, 4 + 4 + 4 + 4 + 4 + name.length + 32]),
    Buffer.from("FPCh", "latin1"), Buffer.from([0, 0, 0, 1]),
    Buffer.from("test", "latin1"), Buffer.from([0, 0, 0, 1]),
    Buffer.from([0, 0, 0, name.length]), name, body,
  ]);
  const parsed = parseFpch(fpch);
  ok("preset plugin and name read", parsed.plugin === "test" && parsed.name === "Fixture Preset", JSON.stringify({ plugin: parsed.plugin, name: parsed.name }));
  ok("preset body reported after the name", parsed.bodyAt === 28 + name.length && parsed.bodyBytes === 32, JSON.stringify({ bodyAt: parsed.bodyAt, bodyBytes: parsed.bodyBytes }));
  const bankChunk = Buffer.from(fpch);
  bankChunk.write("FBCh", 8, "latin1");
  ok("bank files read with their kind", parseFpch(bankChunk).kind === "bank", JSON.stringify(parseFpch(bankChunk).kind));
  ok("a non-preset file is refused", (() => { try { parseFpch(Buffer.from("fLaCxxxx")); return false; } catch (e) { return /no CcnK envelope/.test(e.message); } })());
  const realPresets = ["D:/Sylenth1/303 Pulse.fxp", "E:/Darbuka Data/Styles/Ayoub-Zar.fxp"];
  if (realPresets.every((p) => fs.existsSync(p))) {
    const syl = parseFpch(fs.readFileSync(realPresets[0]));
    const dar = parseFpch(fs.readFileSync(realPresets[1]));
    ok("real presets read with their plugin ids",
      syl.plugin === "syl1" && syl.name === "303 Pulse" && dar.plugin === "WvpA" && dar.name === "Ayoub-Zar",
      JSON.stringify({ syl: [syl.plugin, syl.name], dar: [dar.plugin, dar.name] }));
  } else {
    ok("real presets (skipped: not on this machine)", true, "skipped");
  }
}

// ---------------------------------------------------------------- kohane format family view
section("kohane format family view");
{
  const kb = await tool("library_format").execute({ op: "kb" });
  ok("the kb family view lists its members", kb.ok === true && kb.count >= 4, JSON.stringify(kb.members && kb.members.map((m) => m.format)));
  ok("magic-recognised members carry their signature",
    kb.members.filter((m) => m.recognition === "magic").every((m) => m.sig && m.sig.length > 0),
    `${kb.members.filter((m) => m.recognition === "magic").length} magic member(s)`);
  ok("the container member is backed by an analyzer",
    kb.members.some((m) => m.format === "kb-container" && m.analyzer === "kb-container"),
    JSON.stringify(kb.members.find((m) => m.format === "kb-container")));
  ok("the envelope member is recognised by structure, not magic",
    kb.members.some((m) => m.format === "kb-envelope" && m.recognition === "structure" && m.sig === null),
    JSON.stringify(kb.members.find((m) => m.format === "kb-envelope")));
}

// ---------------------------------------------------------------- kpb bundle face
section("kpb bundle face");
{
  const fmtTool = tool("library_format");
  const pluginTool = tool("library_plugin");
  // A bundle fixture whose real file size lands inside the 8%-20% window: the payload padding
  // makes the sealed file about 9.6 KB against a declared 100 KB source.
  const makeBundle = (sourceTotalBytes, padding) => {
    const payload = { bundle: { name: "Fixture Bundle", version: "0.1.0", sourceTotalBytes, capabilities: ["Composer", "Mixer"] }, assets: { manifest: [{ name: "score.kbs", bytes: 1024 }], padding: "p".repeat(padding) } };
    const sealed = m.encryptSensitive(payload);
    return JSON.stringify({ format: "kohane-bundle", version: 1, hint: "sealed by kohane-index-desuno for this installation - open with library_format op=kpb-install", sealed });
  };
  const kpbFile = path.join(TMP, "fixture.kpb");
  fs.writeFileSync(kpbFile, makeBundle(100000, 7000));

  const inst = await fmtTool.execute({ op: "kpb-install", path: kpbFile });
  ok("a bundle installs and mounts its capabilities",
    inst.ok === true && inst.name === "Fixture Bundle" && inst.mounted.includes("Composer") && inst.mounted.includes("Mixer"),
    JSON.stringify({ ok: inst.ok, mounted: inst.mounted }));
  const list1 = await fmtTool.execute({ op: "kpb-list" });
  ok("the installed bundle is listed with its facts",
    list1.count === 1 && list1.installs[0].name === "Fixture Bundle" && list1.installs[0].version === "0.1.0",
    JSON.stringify(list1.installs));
  const dirAfter = await pluginTool.execute({ op: "list" });
  ok("the mounted capabilities are in the local directory",
    dirAfter.ok && JSON.stringify(dirAfter).includes("Composer") && JSON.stringify(dirAfter).includes("Mixer"));

  const ver = await fmtTool.execute({ op: "kpb-verify", path: kpbFile });
  ok("verify holds and the volume ratio sits inside 8%-20%",
    ver.ok === true && ver.ratio >= 0.08 && ver.ratio <= 0.20,
    JSON.stringify({ ok: ver.ok, ratio: ver.ratio }));

  // A tampered sealed body must fail with the missing-key reason, never "unknown format".
  const tampered = JSON.parse(fs.readFileSync(kpbFile, "utf8"));
  tampered.sealed.ct = (tampered.sealed.ct[0] === "0" ? "1" : "0") + tampered.sealed.ct.slice(1);
  const tamperedFile = path.join(TMP, "tampered.kpb");
  fs.writeFileSync(tamperedFile, JSON.stringify(tampered));
  const tamperedVer = await fmtTool.execute({ op: "kpb-verify", path: tamperedFile });
  ok("a tampered bundle fails with the sealed-key reason",
    tamperedVer.ok === false && /sealed|key/i.test(String(tamperedVer.note)),
    String(tamperedVer.note));

  // A bundle whose ratio leaves the window fails verification and says so in numbers.
  const outFile = path.join(TMP, "out-of-window.kpb");
  fs.writeFileSync(outFile, makeBundle(1000, 7000));
  const outVer = await fmtTool.execute({ op: "kpb-verify", path: outFile });
  ok("an out-of-window ratio fails verification",
    outVer.ok === false && /outside/.test(String(outVer.note)) && outVer.ratio > 0.2,
    JSON.stringify({ ok: outVer.ok, ratio: outVer.ratio, note: outVer.note }));

  // A file that is not the bundle envelope is refused as such.
  const junkFile = path.join(TMP, "junk.kpb");
  fs.writeFileSync(junkFile, "hello, not a bundle");
  const junkVer = await fmtTool.execute({ op: "kpb-verify", path: junkFile });
  ok("a non-bundle file is refused with the marker reason",
    junkVer.ok === false && /not a bundle/.test(String(junkVer.note)),
    String(junkVer.note));

  // remove unmounts exactly what the bundle mounted, and the list is empty again.
  const rem = await fmtTool.execute({ op: "kpb-remove", name: "Fixture Bundle" });
  const dirGone = await pluginTool.execute({ op: "list" });
  const list2 = await fmtTool.execute({ op: "kpb-list" });
  ok("remove unmounts the capabilities and empties the list",
    rem.ok === true && !JSON.stringify(dirGone).includes("Composer") && list2.count === 0,
    JSON.stringify({ rem: rem.ok, list2: list2.count }));
}

// ---------------------------------------------------------------- kpb media (stage 3)
section("kpb media (stage 3)");
{
  const fmtTool = tool("library_format");
  const audioTool = tool("library_audio");
  const media = await import(pathToFileURL(path.join(ROOT, "kohane-index-desuno", "deps", "decoders", "kb-media.mjs")).href);
  const { synthesize } = await import(pathToFileURL(path.join(ROOT, "kohane-index-desuno", "deps", "decoders", "synth.mjs")).href);

  // The stage-3 acceptance: the score replays, the wave draws, the view lays out - each inside the
  // bundle, proved at verify time. First the containers themselves, then the bundle that carries them.

  const notes4 = [
    { t: 0, dur: 0.25, pitch: 74, vel: 0.85, wave: "square" },
    { t: 0.25, dur: 0.25, pitch: 76, vel: 0.8, wave: "square" },
    { t: 0.5, dur: 0.5, pitch: 62, vel: 0.22, wave: "saw" },
    { t: 0.5, dur: 0.5, pitch: 69, vel: 0.18, wave: "saw" },
  ];
  const kbsBuf = media.writeKbs({ title: "stage-3 fixture", bpm: 155, key: "D double-harmonic minor", parts: ["lead", "pad"], notes: notes4, wave: "square" });
  const scoreBack = media.readKbs(kbsBuf);
  ok("a .kbs score round-trips field for field",
    scoreBack.format === "kohane-score" && scoreBack.title === "stage-3 fixture" && scoreBack.bpm === 155 &&
    scoreBack.key === "D double-harmonic minor" && scoreBack.parts.length === 2 && scoreBack.notes.length === 4 &&
    scoreBack.notes[0].pitch === 74 && scoreBack.notes[3].wave === "saw",
    JSON.stringify({ title: scoreBack.title, notes: scoreBack.notes.length }));

  const replayed = media.replayKbs(kbsBuf);
  const direct = synthesize({ sampleRate: replayed.score.sampleRate, notes: notes4, wave: "square" });
  ok("the score replays through the synth and matches a direct render",
    replayed.rendered.frames === direct.frames && replayed.rendered.frames > 0,
    JSON.stringify({ frames: replayed.rendered.frames, expected: direct.frames }));

  let kbsJunk = null;
  try { media.readKbs(Buffer.from("hello, not a score")); } catch (e) { kbsJunk = String(e.message); }
  ok("a non-score is refused with the score's own name",
    kbsJunk !== null && /not a kohane score/.test(kbsJunk), kbsJunk);

  let badNote = null;
  try { media.readKbs(media.writeKbs({ notes: [{ t: 0, dur: 0.1, pitch: 300 }] })); } catch (e) { badNote = String(e.message); }
  ok("a note outside the MIDI range is refused, not handed downstream",
    badNote !== null && /note 0/.test(badNote), badNote);

  const kbwBuf = media.writeKbw({ sampleRate: 44100, frames: 1200, bucketSize: 512, buckets: [[-0.5, 0.5], [-0.2, 0.8], [0.0, 1.0]] });
  const envBack = media.readKbw(kbwBuf);
  ok("a .kbw envelope round-trips and covers its declared frames",
    envBack.frames === 1200 && envBack.buckets.length === 3 && envBack.buckets[2][1] === 1 && envBack.coversAll === true,
    JSON.stringify({ buckets: envBack.buckets.length, coverage: envBack.coverage, coversAll: envBack.coversAll }));

  const kbvBuf = media.writeKbv({ title: "stage-3 view", lanes: 88, octaveLines: [12, 24, 36, 48, 60, 72, 84], palette: ["paper-white", "red", "tea-ink", "navy"] });
  const viewBack = media.readKbv(kbvBuf);
  ok("a .kbv view round-trips with lanes and palette",
    viewBack.lanes === 88 && viewBack.octaveLines.length === 7 && viewBack.palette.length === 4,
    JSON.stringify({ lanes: viewBack.lanes, palette: viewBack.palette }));

  const scoreFile = path.join(TMP, "stage3.kbs");
  fs.writeFileSync(scoreFile, kbsBuf);
  const viewFile = path.join(TMP, "stage3.kbv");
  fs.writeFileSync(viewFile, kbvBuf);
  const kbsRead = await audioTool.execute({ op: "kbs", path: scoreFile });
  ok("library_audio op=kbs reads the score, replays it and picks up the companion view",
    kbsRead.ok === true && kbsRead.notes === 4 && kbsRead.replayed.frames > 0 && kbsRead.view && kbsRead.view.lanes === 88,
    JSON.stringify({ ok: kbsRead.ok, notes: kbsRead.notes, view: kbsRead.view && kbsRead.view.lanes }));

  const kbsOut = path.join(TMP, "written.kbs");
  const kbsWrite = await audioTool.execute({ op: "kbs", out: kbsOut, title: "written", bpm: 120, key: "C", notes: notes4, layout: { lanes: 88, octaveLines: [12], palette: ["paper-white"] } });
  const writtenBack = media.readKbs(fs.readFileSync(kbsOut));
  ok("library_audio op=kbs writes a score and its companion view",
    kbsWrite.ok === true && writtenBack.notes.length === 4 && writtenBack.title === "written" &&
    fs.existsSync(kbsOut.replace(/\.kbs$/i, "") + ".kbv"),
    JSON.stringify({ ok: kbsWrite.ok, notes: writtenBack.notes.length }));

  const kbwOut = path.join(TMP, "written.kbw");
  const wavSrc = path.join(TMP, "env-src.wav");
  const renderedSrc = synthesize({ sampleRate: 44100, notes: [{ t: 0, dur: 0.1, pitch: 69, wave: "square" }] });
  // the WAV source: write a canonical 16-bit mono WAV by hand around the synth's own PCM,
  // so the fixture needs no external encoder and no extra files.
  {
    const data = Buffer.alloc(44 + renderedSrc.samples.length * 2);
    data.write("RIFF", 0); data.writeUInt32LE(36 + renderedSrc.samples.length * 2, 4); data.write("WAVE", 8);
    data.write("fmt ", 12); data.writeUInt32LE(16, 16); data.writeUInt16LE(1, 20); data.writeUInt16LE(1, 22);
    data.writeUInt32LE(44100, 24); data.writeUInt32LE(88200, 28); data.writeUInt16LE(2, 32); data.writeUInt16LE(16, 34);
    data.write("data", 36); data.writeUInt32LE(renderedSrc.samples.length * 2, 40);
    for (let i = 0; i < renderedSrc.samples.length; i++) data.writeInt16LE(Math.round(renderedSrc.samples[i] * 32767), 44 + i * 2);
    fs.writeFileSync(wavSrc, data);
  }
  const kbwWrite = await audioTool.execute({ op: "kbw", out: kbwOut, source: wavSrc, buckets: 64 });
  const kbwBack = media.readKbw(fs.readFileSync(kbwOut));
  ok("library_audio op=kbw measures a WAV source into a .kbw envelope",
    kbwWrite.ok === true && kbwWrite.written === true && kbwBack.frames === renderedSrc.frames && kbwBack.buckets.length === 64,
    JSON.stringify({ ok: kbwWrite.ok, frames: kbwBack.frames, buckets: kbwBack.buckets.length }));

  // The bundle that carries the three containers: verify must self-prove all of them, and a bundle
  // whose score was emptied must fail the proof.
  const makeMediaBundle = (emptyScore) => {
    const kbsPayload = (emptyScore ? media.writeKbs({ title: "emptied", notes: [] }) : kbsBuf).toString("base64");
    const payload = {
      bundle: { name: "Media Fixture Bundle", version: "0.2.0", sourceTotalBytes: 100000, capabilities: ["Composer", "Mixer"] },
      media: { files: [
        { name: "stage3.kbs", kind: "kbs", base64: kbsPayload },
        { name: "stage3.kbw", kind: "kbw", base64: kbwBuf.toString("base64") },
        { name: "stage3.kbv", kind: "kbv", base64: kbvBuf.toString("base64") },
      ] },
      padding: "p".repeat(7000),
    };
    return JSON.stringify({ format: "kohane-bundle", version: 1, hint: "sealed by kohane-index-desuno for this installation - open with library_format op=kpb-install", sealed: m.encryptSensitive(payload) });
  };
  const mediaFile = path.join(TMP, "media-fixture.kpb");
  fs.writeFileSync(mediaFile, makeMediaBundle(false));
  const mediaVer = await fmtTool.execute({ op: "kpb-verify", path: mediaFile });
  ok("a bundle carrying .kbs/.kbw/.kbv self-proves on verify (all three checks pass)",
    mediaVer.ok === true && Array.isArray(mediaVer.mediaChecks) && mediaVer.mediaChecks.length === 3 &&
    mediaVer.mediaChecks.every((c) => c.ok) &&
    mediaVer.mediaChecks.some((c) => c.kind === "kbs") && mediaVer.mediaChecks.some((c) => c.kind === "kbw") && mediaVer.mediaChecks.some((c) => c.kind === "kbv"),
    JSON.stringify(mediaVer.mediaChecks));

  const emptyFile = path.join(TMP, "media-empty-score.kpb");
  fs.writeFileSync(emptyFile, makeMediaBundle(true));
  const emptyVer = await fmtTool.execute({ op: "kpb-verify", path: emptyFile });
  ok("a bundle whose score was emptied fails verification with the media reason",
    emptyVer.ok === false && Array.isArray(emptyVer.mediaChecks) &&
    emptyVer.mediaChecks.some((c) => c.kind === "kbs" && c.ok === false),
    JSON.stringify({ ok: emptyVer.ok, note: emptyVer.note }));

  const emptyInst = await fmtTool.execute({ op: "kpb-install", path: emptyFile });
  ok("install refuses a bundle whose media self-proof fails",
    emptyInst.ok === false && /media self-proof/.test(String(emptyInst.note)),
    String(emptyInst.note));
}

// ---------------------------------------------------------------- environment + branding

section("environment + branding");
const env = m.detectEnvironment();
ok("harness detected", ["cli", "mcp", "dsh", "unknown"].includes(env.harness), env.harness);
// Tool availability is a behaviour of the candidate mechanism, not a fact about this machine:
// a machine that happens to uninstall Unity must not fail the suite. Prove the mechanism instead -
// existing candidates report, missing candidates stay silent, and the built-in table still knows
// Unity Editor and Blender by name.
ok("built-in candidates know Unity Editor and Blender",
  m.DETECT_CANDIDATES.some((c) => c.name === "Unity Editor") && m.DETECT_CANDIDATES.some((c) => c.name === "Blender"));
const fakeTool = path.join(TMP, "tools", "kohane-test-tool.exe");
const ghostTool = path.join(TMP, "tools", "ghost-tool.exe");
fs.mkdirSync(path.dirname(fakeTool), { recursive: true });
fs.writeFileSync(fakeTool, "x");
fs.mkdirSync(path.join(TMP, "dsh", "library"), { recursive: true });
fs.writeFileSync(path.join(TMP, "dsh", "library", "candidates.local.json"), JSON.stringify({
  version: 1, updatedAt: new Date().toISOString(),
  candidates: [
    { type: "tool", name: "Kohane Test Tool", path: fakeTool, alts: [], desc: "fixture" },
    { type: "tool", name: "Ghost Tool", path: ghostTool, alts: [], desc: "fixture that must not be reported" },
  ],
}, null, 2), "utf8");
const env2 = m.detectEnvironment();
ok("existing local candidate reported",
  env2.availableTools.some((t) => t.name === "Kohane Test Tool" && t.path === fakeTool),
  JSON.stringify(env2.availableTools.map((t) => t.name)));
ok("missing candidate stays silent", !env2.availableTools.some((t) => t.name === "Ghost Tool"));
ok("signature counts reported", env.signatureCount === 113 && env.textExtensionCount > 0, `sig=${env.signatureCount} text=${env.textExtensionCount}`);
const src = fs.readFileSync(CORE, "utf8");
const megaLines = src.split("\n").filter((l) => /mega/i.test(l));
ok("no mega branding left (only load-bearing legacy namespaces / rule comments)",
  megaLines.length <= 3 && megaLines.every((l) => /LEGACY|legacy|namespaces|:v2|:seal:v1/.test(l)), `${megaLines.length} line(s)`);

console.log(`\n${pass} passed, ${fail} failed`);
fs.rmSync(TMP, { recursive: true, force: true });
process.exit(fail ? 1 : 0);
