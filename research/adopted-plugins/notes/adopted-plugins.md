# Adopted plugins: static survey + kohanization (metering, mastering, voice-processing suites)

Date: 2026-09-11　Tooling: `analyze-binaries.mjs` (read-only) + `dumpbin`-free pure node
Nature: **purely static** - nothing is loaded, linked, registered or executed; the scanner reads
file headers, the export-name region and version strings only.

Scope requested: the non-editor plugins of the iZotope installation and the MiniMeters
installation. The audio-editor family (standalone editor application and its modules) is **out of
scope by request** and was not adopted.

---

## 1. Where plugin binaries actually live
The vendor program folder only holds stand-alone applications and resources; the plugins are in the
platform plugin folders:

| Location | Content |
|---|---|
| `C:\Program Files\Common Files\VST3\<vendor>\` | VST3 (single-file wrappers + shared implementation DLLs) |
| `C:\Program Files\Common Files\CLAP\<vendor>\` | CLAP builds of the same engine |
| `C:\Program Files\Steinberg\VstPlugins\<vendor>\` | VST2 builds |
| `C:\Program Files\Common Files\VST2\` | VST2 (machine-wide) |
| `C:\Program Files\VSTPlugins\` | VST2 (legacy machine-wide) |
| `C:\Program Files\<vendor>\...` | stand-alone applications, web-UI resources, fonts, caches |

→ kohane must scan the **plugin folders**, not the vendor program folder: `pluginRoots()` in
`lib/core.mjs` covers the platform-standard locations above plus `KOHANE_PLUGIN_ROOTS`.

## 2. Inventory (this machine)
| Kind | Count | Note |
|---|---:|---|
| VST3 | 51 | single-file `.vst3`; large implementation DLLs sit beside them |
| VST2 | 42 | `.dll`, both "wrapper" (≈3 MB) and "engine" (24–68 MB) flavours |
| CLAP | 9 | same engine as the VST3 set, one file per capability |
| Stand-alone | 2 | a metering application and a mastering application (44.7 MB, exports `VSTPluginMain`) |

**Requested scope in detail**

| Family | Entries | Capability words derived by kohane |
|---|---|---|
| Mastering suite | main processor + 13 modules | Maximizer, Exciter, Imager, Dynamics, Dynamic EQ, Equalizer, Match EQ, Vintage Compressor, Vintage EQ, Vintage Limiter, Vintage Tape, Rebalance, Spectral (from Spectral Shaper), Filter (from Low End Focus) |
| Metering / analysis | 2 products | Meter (from Insight-class meter), Tone Reference (from tonal-balance control) |
| Voice processing | 2 products | Vocal Synth, Equalizer/Compressor/… (syllable-aware chain maps onto the generic slots) |
| Utility | 1 product | Routing/utility (auto gain-staging helper) |
| Meter suite (second vendor) | 9 capabilities + app | Audio Server, Loudness, Oscilloscope, Spectrogram, Spectrum, Stereometer, VU, Waveform |

## 3. Plugin ABI observed statically
| Container | Exported entry point | Evidence |
|---|---|---|
| VST2 `.dll` | **`VSTPluginMain`** (+ `main`) | wrappers and engines alike |
| VST3 `.vst3` | **`GetPluginFactory`** (+ `main`) | single-file VST3 modules |
| CLAP `.clap` | **`clap_entry`** (+ `main`) | all 9 metering builds |
| Stand-alone `.exe` | often still exports the plugin entry points | e.g. the mastering app exports `VSTPluginMain` |

Findings worth keeping:
- The "wrapper vs engine" split: a small VST2/VST3 file exports the plugin entry points and loads a
  much larger **implementation library** (24–68 MB) that exports only `main`. So a plugin's
  *capability* is not readable from the big file's name — always read the **wrapper**'s name.
- Version resources are present in the wrapper files (`ProductName`, `FileVersion`); the CLAP/VST3
  metering builds carry **no** version resource at all, so their identity comes from the file name.
- Everything is x64; one legacy x86 VST2 exists in the wider census.

## 4. Data formats found (became kohane recognition rules)
| Extension | Nature | Head bytes | kohane rule |
|---|---|---|---|
| `.wavetable` | binary wavetable container | `1E AB F7 FF` + u16/u32 frame counters + float32 frames | `FILE_SIGNATURES` → `wavetable` |
| `.mms` | block-language session/preset (`Loudness {`, `num Mode 1`, `bool …`) | starts with a `Name {` block, so no fixed magic | native **text** extension hint |
| `.vfpatch` | JSON patch (`{"parameters": {…}}`) | `7B 0D 0A 20 20 20 22 70 61 72…` | native **text** extension hint |
| `.map` | text colour ramp (`[rgb(164, 204, 144); 0.0]`) | leading newline/space + `[rgb` | name-rule candidate (extension is too generic for a magic) |
| `.ini` | theme (colour assignments) | `credit = "…"` / `[All]` | plain text |
| `.dat`, `.xml`, `.html/.css/.js`, `.otf/.png` | app config, web-UI resources, fonts | — | not adopted (application internals) |

## 5. Kohanization: one capability layer, local links kept separate
The adopted model replaces the earlier "one directory entry per observed plugin" with two layers:

1. **Capability layer (product, vendor-free)** — `lib/core.mjs`
   - `KOHANE_CAPABILITIES`: the curated capability slots (`[functional word, role, note]`), e.g.
     `Maximizer`, `Vintage Tape`, `Dynamic EQ`, `Loudness`, `Spectrogram`, `Stereometer`, `VU`,
     `Audio Server`, `Movement Filter`, `Image Synth`, `Tone Reference`.
   - `PLUGIN_FUNCTION_VOCAB`: generic craft nouns used to *extract* a word from an observed
     binary's own name (`Vintage Compressor 2` → `Vintage Compressor`; `Loudness x64 vst3` →
     `Loudness`; a product-only name extracts nothing and falls back to the role word).
   - Nothing in this layer contains a third-party product name, so no default result can print one.
2. **Local link layer (`$DSH_HOME/library/plugins.local.json`)** — which binary on *this* machine
   provides which capability (`localName`, `kind`, `localCategory`, `localVersion`, `localFile`).
   Written by `learn`, read by the resolver, exposed **only** by `op=provenance` for one entry.

### Measured result (this machine)
| Step | Result |
|---|---|
| `discover` (all plugin folders) | 220 binaries: 134 VST2, 77 VST3, 9 CLAP; ABI `VSTPluginMain`/`GetPluginFactory`/`clap_entry` |
| `scan` (native plugin database) | 107 distinct plugins from 115 state files |
| `learn` | 327 observations → **255 capabilities, 226 linked**, 0 unmatched |
| `export format=md` | `$DSH_HOME/library/plugins.md` (255 rows, capability names only) |

Vendor leakage check: `list`, `show`, `scan`, `discover`, `learn`, `add`, `rename`, `brand`,
`remove`, `export` and the container analyzer detail are asserted **vendor-free** by
`tools/selfcheck.mjs` (guard regex over the serialized result).

## 6. Deliberate exclusions
- The audio-editor family (stand-alone editor application and its modules) - out of scope by
  request; left unadopted.
- Application internals (`.xml` web-UI, `.dat` caches, fonts) - not capability-bearing.
- `.map` colour ramps: kept as a *candidate* name rule only, because `.map` is a very common
  extension (engine maps, symbol maps) and deserves a content check rather than a magic.

## 7. Follow-ups
1. **Unknown-role tail**: 69 of 220 observations classify as `unknown` (their names carry no craft
   noun). Reading the VST3 `moduleinfo.json` categories, or bundle-side metadata, would place them.
2. **Numbered fallbacks**: the unchanged generic words produce `Delay 2`, `Meter 2`… — a
   personalisation pass (`op=rename`) or richer vocabulary would avoid them.
3. **`.map` name rule** (`[rgb(` content probe) to be added through `library_format add` once a
   content-checking name rule kind exists.
