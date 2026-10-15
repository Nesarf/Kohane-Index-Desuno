// The external decoder bridge: the long tail is borrowed, but declared.
//
// This module is the only place in the engine that reaches outside Node's own abilities for media.
// It reads the dependency ledger (deps/manifest.json) to find a recorded external decoder, or takes
// one from KOHANE_FFMPEG, and it refuses in plain words when there is none - a missing decoder is
// reported as missing, never as a broken file.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** The ledger is the source of truth for what external tools KID may use. */
export function externalDecoders() {
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(HERE, "manifest.json"), "utf8"));
    return (manifest.entries || []).filter((e) => e.kind === "binary" || e.kind === "decoder-external");
  } catch {
    return [];
  }
}

/**
 * Resolves an external decoder: an explicit environment override first, then a recorded entry whose
 * recorded path still exists. Nothing is guessed and nothing is searched for across the disk.
 */
export function resolveExternalDecoder(id = "external-ffmpeg") {
  const override = process.env.KOHANE_FFMPEG;
  if (override) return { id, path: override, source: "KOHANE_FFMPEG" };
  const entry = externalDecoders().find((e) => e.id === id);
  if (entry && entry.path && fs.existsSync(entry.path)) return { id, path: entry.path, source: "deps/manifest.json" };
  return null;
}

/**
 * Decodes anything the external decoder understands into interleaved 16-bit PCM.
 * Returns the samples as floats in -1..1, the same shape the engine's own decoders produce.
 */
export function decodeExternally(file) {
  const decoder = resolveExternalDecoder();
  if (!decoder) {
    throw new Error(
      "no decoder for this container, and no external decoder is installed or recorded " +
      "(set KOHANE_FFMPEG to one, or record it in deps/manifest.json)",
    );
  }
  // WAV rather than raw PCM, and no -ar/-ac: asking for a fixed rate would resample the audio and then
  // report OUR number as if it were the file's. The header the decoder writes tells us what the file
  // really is, and it is small enough to parse here.
  const result = spawnSync(decoder.path, [
    "-v", "error",
    "-i", file,
    "-f", "wav",
    "-acodec", "pcm_s16le",
    "pipe:1",
  ], { maxBuffer: 512 * 1024 * 1024, windowsHide: true });

  if (result.error) throw new Error(`the external decoder could not be started: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = String(result.stderr || "").trim().split("\n").slice(-2).join(" ");
    throw new Error(`the external decoder refused this file (exit ${result.status})${detail ? ": " + detail : ""}`);
  }
  const wav = result.stdout;
  if (!wav || wav.length < 44) throw new Error("the external decoder produced no samples");
  if (wav.toString("latin1", 0, 4) !== "RIFF" || wav.toString("latin1", 8, 12) !== "WAVE") {
    throw new Error("the external decoder did not return a WAV stream");
  }
  let at = 12;
  let sampleRate = 0;
  let channels = 0;
  let data = null;
  while (at + 8 <= wav.length) {
    const id = wav.toString("latin1", at, at + 4);
    const size = wav.readUInt32LE(at + 4);
    const body = at + 8;
    if (id === "fmt ") {
      channels = wav.readUInt16LE(body + 2);
      sampleRate = wav.readUInt32LE(body + 4);
      if (wav.readUInt16LE(body + 14) !== 16) throw new Error("the external decoder returned samples that are not 16-bit");
    } else if (id === "data") {
      data = wav.subarray(body, Math.min(body + size, wav.length));
      break;
    }
    at = body + size + (size % 2);
  }
  if (!data || !channels || !sampleRate) throw new Error("the external decoder's WAV stream has no fmt or data chunk");

  const frames = Math.floor(data.length / 2 / channels);
  const samples = new Float32Array(frames * channels);
  for (let i = 0; i < frames * channels; i++) samples[i] = data.readInt16LE(i * 2) / 32768;
  return { format: "external", decoder: decoder.path, decoderSource: decoder.source, sampleRate, channels, frames, samples };
}
