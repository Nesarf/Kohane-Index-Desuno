# kohane-index-desuno

A cross-harness interop Library: an **MCP server** + **CLI** exposing 16 tools to any agent
framework that supports Model Context Protocol (Claude Code, Cursor, opencode, Copilot CLI, etc.).
Runtime environment self-aware: detects the harness, platform, encoding, available tools, and
library state, and reports what it can/cannot do here.

## Tools

- `library_record` - record an object
- `library_index` - three jobs on the index, kept apart: `rebuild` (default) dedupes by type+name+source, sorts by createdAt and reports the versions it merged; `audit dir=<path>` reconciles a directory against the Library in both directions and writes nothing; `index dir=<path> confirm=true` registers the entries that have no record (a drive root is refused, a sensitive name is skipped rather than bulk-encrypted); `verify` recomputes a sha256 per record and reports unchanged/changed/gone/never, recording a baseline only with `confirm:true`; `review` lists the sealed records nobody judged (`what=sealed`), what the current patterns would seal (`what=candidates`), and settles one record with `id` + `decision clear|revoke` + `reason`; `prune confirm=true` drops `what=dead` (path verifiably gone) or `what=hollow` (a name and nothing else); `status` answers what the Library holds in one read-only read
- `library_query` - search (keyword/type/tags, cursor pagination)
- `library_detect` - scan & register machine tools/environments/toolchains (built-in list + this machine's local candidate pack in `$DSH_HOME/library/candidates.local.json`); `list`/`add`/`remove` manage the pack and `propose dir=<directory>` only suggests executables; built-ins always win, collisions are refused unless `confirm:true`, and no candidate is ever executed
- `library_sniff` - true type from magic header bytes (113 signatures) + declared-vs-actual forgery check; `dir` mode sweeps a directory for mismatches
- `library_vcs` - a path's working-tree state the way an editor's source-control view reports it, read-only: `status` for one file or directory (the letter `M`/`A`/`D`/`R`/`C`/`T`/`U`/`I`/`!`/`S`, the index and worktree letters kept apart, the `+N/-M` line counts for each side, the colours an editor's light and dark themes use for that state, rename origin, conflict and submodule flags, and for a directory the union of everything under it), `decorate` for many paths in one call, `repo` for a whole repository as a source-control panel shows it (branch, upstream, ahead/behind, then staged / changed / untracked / conflicted / submodule lists), and `info` for whether git exists here. One git call per repository, cached for two seconds; a path outside any repository or a machine without git is reported as such rather than failing; `KOHANE_NO_GIT=1` refuses to start a git process at all.
- `library_format` - personalise this install's format library: `scan` proposes unidentified types, `learn`/`add` register signatures / text extensions / name rules into `$DSH_HOME/library/formats.local.json`, `analyzer-add`/`analyzer-remove` register an external command as a user-defined analyzer for chosen extensions or file names, `remove` drops one, `deps` maps format→format references, `draft` writes a reviewable checklist, `report` builds a local contribution archive the user may choose to send, `deliver` shows that archive in the platform's own window (Send by e-mail / Save a copy / Open folder / Delete, or manual instructions with `headless:true`), `unseal` reopens a sealed layer
- `library_plugin` - kohane's own capability directory: every plugin capability kohane adopts is named inside one family (**uniform brand + functional word**), so kohane depends on no third-party plugin or host at runtime and **no third-party product name appears in any result**. `list`/`show`/`roles` read the directory, `scan` reads a native plugin database and `discover` walks the machine's plugin folders (VST3/CLAP/VST2 - headers and version strings only, nothing is loaded, registered or executed), `learn` links both into `$DSH_HOME/library/plugins.local.json`, `add`/`remove`/`rename`/`brand` personalise it, `unlinked` and `numbered` report what this machine provides nothing for and which capabilities still carry a numbered fallback name, `export` writes it out (json/ndjson/md) and `provenance` shows the local cross-check for one entry when explicitly asked
- `library_sessions` - read this machine's own harness sessions: the conversation store under `$DSH_HOME/sessions` (one compressed frame per record) plus any exported session-log ZIP archives. `list` enumerates sessions from headers and titles, `read` returns a structural summary unless `content:true`, `tail` decodes only the last frames, `search` scans frames for a phrase, `record` writes a session into the Library as a log object, `status` reports what the store holds. A torn tail is counted, never guessed, and a runtime without a decoder says so instead of reporting an empty history
- `library_decrypt` - manually decrypt a sensitive object
- `library_export` - export to JSON/NDJSON
- `library_encoding` - detect system encoding + regional advice
- `library_adb` - Android device management over ADB (developer subset)
- `analyze_object` - run registered analyzers over an object (built-in Unity / Blender / native-plugin-container providers + any local analyzer), returning per-provider findings with a content fingerprint; a container reports its plugins as kohane capabilities, and the raw object names only under `deep`
- `library_audio` - measure audio the way a waveform display needs it, and use the machine's cores instead of one: `peaks` returns a min/max envelope plus channels / sample rate / bit depth / frames for a PCM WAV or AIFF, `sweep` walks a directory and measures every audio file through a resident worker pool (reporting the cores actually used, and with `compare:true` what one core would have cost), `info` reports the cores, the pool's task table and the containers it decodes. `pcm` decodes an uncompressed file to samples and stages a canonical WAV, and `play` hands that to the system player; `score` returns the notes of a Standard MIDI File (including same-pitch retriggers, which need a stack per pitch rather than an overwrite). Compressed formats are refused rather than guessed; nothing is written.
- `library_environment` - self-awareness report (harness/platform/encoding/tools/library)

## Verification

Everything below is dependency-free and offline; none of it writes into a sibling checkout.

```
node tools/selfcheck.mjs          # behaviour regression harness (tool registry, signatures, analyzers,
                                  # the Library invariants, crypto, the capability directory, sessions)
node tools/check-unicode.mjs      # shipped files are valid UTF-8 Unicode: any script, no broken text
node tools/check-contract.mjs     # every tool is the shape it advertises; unknown ops are refused
node tools/check-deps.mjs         # every dependency is declared, licensed and hashed; no unlisted import
node tools/bench.mjs              # measures the engine and records the machine's conditions beside the numbers
node tools/check-consistency.mjs  # README vs tool registry, schema op lists vs dispatch, self-claims
node tools/check-portability.mjs  # no Windows-only assumptions, no shell strings, scratch off the system drive
node tools/check-isolation.mjs    # this checkout and the sibling build may read, never write, each other
```

`npm run verify` runs the four checks and then the regression harness. The sibling build is declared
locally (`KOHANE_SIBLING` or `.isolation.local.json` beside the checkout) so no shipped file has to
name a machine-specific path; `check-isolation.mjs snapshot` / `verify` additionally hash the
checkout, the sibling tree and the Library index, so a session can prove that running the tests
moved nothing.

## MCP

After installing (`npm i -g kohane-index-desuno`, or `npm link` in the repo), the MCP server is
on `PATH` as `kohane-index-desuno-mcp`:

```json
{ "mcpServers": { "kohane-index-desuno": { "command": "kohane-index-desuno-mcp", "args": [] } } }
```

Local repo development (run from the repo root):

```json
{ "mcpServers": { "kohane-index-desuno": { "command": "node", "args": ["./mcp/index.mjs"] } } }
```

In Claude Code: `claude mcp add kohane-index-desuno -- kohane-index-desuno-mcp`
In Cursor: add to `~/.cursor/mcp.json`. In opencode: add to `opencode.json`.

> The `./mcp/index.mjs` (cwd-relative) form is only for running from the repo root; a globally
> installed package should always use the `kohane-index-desuno-mcp` command name so the harness
> can launch it regardless of the working directory.

## CLI

```bash
node ./cli/index.mjs library_environment
node ./cli/index.mjs library_record --type tool --name foo --source bar
node ./cli/index.mjs sniff "path/to/file"
```

## Notes

- The library lives at `$DSH_HOME/library` (default `~/.dsh/library`). Built-in format signatures
  are fixed; whatever this machine adds lives in `library/formats.local.json` — built-ins always win.
- Format reports are **local and manual**: `library_format op=report` writes a ~1.5 KB archive under
  `$DSH_HOME/library/reports` and prints what is inside it. Nothing is uploaded and no network I/O
  happens; delivery is entirely the user's choice. Directory information is omitted by default,
  sanitised (…`<drive>`/`<user>`/`<host>`/`<uuid>`/`<date>`…) when requested, or sealed with a
  passphrase the user holds (reopen with `op=unseal`) — encryption protects the user's own data and
  is never a way to hide anything from them.
- Sensitive content (credentials, keys, etc.) is AES-256-GCM encrypt-isolated; only manual
  `library_decrypt` exposes it.
- `lib/core.mjs` is pure Node (no DSH dependency).
- MIT License. See [LICENSE](LICENSE).
