// SoundFont 2 (.sf2), read natively.
//
// A SoundFont is a RIFF form 'sfbk' holding three things: the sample data (LIST 'sdta' / 'smpl',
// raw 16-bit PCM), the preset-and-instrument tables (LIST 'pdta' with 'phdr' / 'inst' / 'shdr'
// records), and optional INFO metadata. This reader reports the tables - preset names and numbers,
// instrument names, sample names with rate and pitch - so a whole font can be indexed without
// decoding a sample. The samples themselves are plain PCM; decoding them is the engine's own
// readers' job, not this module's.
export const capabilities = {
  id: "sf2",
  kohaneName: "Kohane Bassline SoundFont Reader",
  container: "sf2",
  read: { level: "metadata", detail: "the sfbk form, the pdta tables (phdr presets, inst instruments, shdr samples with name/rate/pitch) and the smpl data size" },
  decode: { level: "none", detail: "sample data is 16-bit PCM and is decoded by the engine's own readers when needed" },
  encode: { level: "none", detail: "writing SoundFonts is not a goal" },
  verifiedAgainst: "a synthesised sfbk whose table values were chosen in advance, plus real fonts where present",
};

import fs from "node:fs";

const fourcc = (buf, at) => buf.toString("latin1", at, at + 4);
const cstr = (buf, at, len) => {
  let end = at;
  while (end < at + len && buf[end] !== 0) end++;
  return buf.toString("latin1", at, end);
};

// Each sub-chunk inside a LIST; chunk bodies are padded to an even boundary, as RIFF everywhere.
function walkList(buf, from, to, visit) {
  let at = from;
  while (at + 8 <= to) {
    const id = fourcc(buf, at);
    const size = buf.readUInt32LE(at + 4);
    const body = at + 8;
    if (size < 0 || body + size > to) break;
    visit(id, body, body + size);
    at = body + size + (size % 2);
  }
}

export function readSf2(file, options = {}) {
  const buf = fs.readFileSync(file);
  if (buf.length < 12 || fourcc(buf, 0) !== "RIFF" || fourcc(buf, 8) !== "sfbk") {
    throw new Error("not a SoundFont (no RIFF/sfbk marker)");
  }
  // The tables live AFTER the sample data, at the tail of the file: a small probe window like the
  // other readers use would always miss them on any real font (hundreds of megabytes). The file is
  // already in memory, so the default walks to the end; an explicit limit still applies.
  const limit = Math.min(buf.length, options.limit || buf.length);
  const out = { container: "sf2", size: buf.length, presets: [], instruments: [], samples: [], smplBytes: 0 };

  let at = 12;
  while (at + 8 <= limit) {
    const id = fourcc(buf, at);
    const size = buf.readUInt32LE(at + 4);
    const body = at + 8;
    if (size < 0 || body + size > limit) break;
    const end = body + size;
    if (id === "LIST") {
      const listType = fourcc(buf, body);
      if (listType === "sdta" || listType === "pdta") {
        walkList(buf, body + 4, end, (cid, cbody, cend) => {
          if (cid === "smpl") out.smplBytes += cend - cbody;
          else if (cid === "phdr" && cend - cbody >= 38) {
            // Records of 38 bytes; the last one is the EOP terminator ('EOP' name, kept out).
            for (let p = cbody; p + 38 <= cend; p += 38) {
              const name = cstr(buf, p, 20);
              if (name === "EOP" || name === "eop") break;
              out.presets.push({
                name,
                preset: buf.readUInt16LE(p + 20),
                bank: buf.readUInt16LE(p + 22),
                bagIndex: buf.readUInt16LE(p + 24),
              });
            }
          } else if (cid === "inst" && cend - cbody >= 22) {
            for (let p = cbody; p + 22 <= cend; p += 22) {
              const name = cstr(buf, p, 20);
              if (name === "EOI" || name === "eoi") break;
              out.instruments.push({ name, bagIndex: buf.readUInt16LE(p + 20) });
            }
          } else if (cid === "shdr" && cend - cbody >= 46) {
            for (let p = cbody; p + 46 <= cend; p += 46) {
              const name = cstr(buf, p, 20);
              if (name === "EOS" || name === "eos") break;
              out.samples.push({
                name,
                start: buf.readUInt32LE(p + 20),
                end: buf.readUInt32LE(p + 24),
                startLoop: buf.readUInt32LE(p + 28),
                endLoop: buf.readUInt32LE(p + 32),
                sampleRate: buf.readUInt32LE(p + 36),
                originalPitch: buf[p + 40],
                pitchCorrection: buf.readInt8(p + 41),
                sampleType: buf.readUInt16LE(p + 44),
              });
            }
          }
        });
      }
    }
    at = end + (size % 2);
  }

  out.summary = {
    presets: out.presets.length,
    instruments: out.instruments.length,
    samples: out.samples.length,
    sampleRateHint: out.samples.length ? out.samples[0].sampleRate : null,
  };
  return out;
}
