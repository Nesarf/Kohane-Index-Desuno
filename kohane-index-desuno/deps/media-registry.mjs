// The media registry: one place that answers "what can KID open, read, decode and write".
//
// It is built from what each decoder declares about itself, so adding a decoder is a matter of
// writing it and listing it here - not of remembering to update a sentence somewhere else. The
// distinction it keeps is the one that matters: READING a container's description, DECODING frames to
// samples, and ENCODING samples back are three different claims, and a module states which it makes.
import { capabilities as flac } from "./decoders/flac.mjs";
import { capabilities as matroska } from "./decoders/matroska.mjs";
import { capabilities as isobmff } from "./decoders/isobmff.mjs";
import { capabilities as ogg } from "./decoders/ogg.mjs";
import { capabilities as riff } from "./decoders/riff.mjs";
import { capabilities as flacWriter } from "./decoders/flac-encoder.mjs";

/** Every decoder KID owns. A decoder not listed here is not part of the surface, whatever it does. */
export const MEDIA_MODULES = [flac, matroska, isobmff, ogg, riff, flacWriter];

const LEVEL_ORDER = { none: 0, metadata: 1, partial: 2, full: 3 };

export function mediaCapabilities() {
  const containers = [];
  for (const m of MEDIA_MODULES) {
    containers.push({
      id: m.id,
      kohaneName: m.kohaneName || `Kohane Bassline ${m.container} reader`,
      container: m.container,
      read: m.read,
      decode: m.decode,
      encode: m.encode,
      verifiedAgainst: m.verifiedAgainst,
    });
  }
  const count = (level) => containers.filter((c) => (c.decode?.level || "none") === level).length;
  return {
    ok: true,
    op: "capabilities",
    modules: containers.length,
    containers,
    summary: {
      readableMetadata: containers.filter((c) => LEVEL_ORDER[c.read?.level || "none"] >= 1).length,
      decodableToSamples: count("full") + count("partial"),
      encodable: containers.filter((c) => LEVEL_ORDER[c.encode?.level || "none"] >= 1).length,
      units: "levels: metadata (describes the file) < partial < full (samples in hand)",
    },
    plainAudio: {
      note: "uncompressed PCM is handled by the engine's own readers rather than by a module here",
      containers: ["wav (PCM, 8/16/24/32-bit and float32)", "aiff/aifc (including 80-bit extended sample rate)"],
      decode: "full",
      encode: "wav staging only (used to hand a file to the system player)",
    },
    naming: "a container is named by its format because that is the file's nature; everything KID offers is named in its own vocabulary, and everything KID stores uses its own containers (the .kb family) - third-party formats are read as input and produced only as exports",
    pending: "none of these modules decodes compressed frames itself: compressed families are served by a declared external decoder when one is recorded (or KOHANE_FFMPEG points at one), and refused in plain words when none is; video frames are not decoded at all",
  };
}
