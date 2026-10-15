// Ogg containers, read natively.
//
// KID's own decoder, registered in deps/manifest.json. An Ogg file is a chain of pages; what it
// actually carries is decided by the first page's payload, which is why this reader identifies the
// codec from the payload rather than trusting an extension or a stream name.
//
// Naming note, and the reason this module reports a kohaneName: the format identity ("ogg") is the
// file's own nature and is used to read it, while anything KID *offers* is named in its own
// vocabulary. Read side may say what the file is; the surface says what we do.
import fs from "node:fs";
import { pathToFileURL } from "node:url";

const CAPTURE = "OggS";

export const capabilities = {
  id: "ogg",
  kohaneName: "Kohane Bassline Stream Reader (Ogg)",
  container: "ogg (Ogg page chain)",
  read: { level: "metadata", detail: "page chain walk, granule positions, serial numbers, and codec identification from the first page payload (Vorbis, Opus, FLAC-in-Ogg, Theora, Skeleton)" },
  decode: { level: "none", detail: "page payloads are not decoded: packets are located, not decompressed" },
  encode: { level: "none", detail: "no page writer yet" },
  verifiedAgainst: "a synthesised page chain carrying an Opus header and a Vorbis header",
};

const CODECS = [
  { id: "vorbis", tag: [0x01, 0x76, 0x6f, 0x72, 0x62, 0x69, 0x73], name: "Vorbis" },
  { id: "opus", tag: [...Buffer.from("OpusHead", "latin1")], name: "Opus" },
  { id: "flac", tag: [0x7f, ...Buffer.from("FLAC", "latin1")], name: "FLAC in Ogg" },
  { id: "theora", tag: [0x80, ...Buffer.from("theora", "latin1")], name: "Theora" },
  { id: "skeleton", tag: [...Buffer.from("fishead", "latin1")], name: "Skeleton" },
  { id: "speex", tag: [...Buffer.from("Speex   ", "latin1")], name: "Speex" },
];

const startsWith = (buf, at, tag) => tag.every((b, i) => buf[at + i] === b);

export function readOgg(file, options = {}) {
  const buf = fs.readFileSync(file);
  if (!startsWith(buf, 0, [...Buffer.from(CAPTURE, "latin1")])) throw new Error("not an Ogg stream (no OggS capture pattern)");
  const maxPages = options.maxPages || 64;              // bounded probing: enough to identify, not to index

  const out = { container: "ogg", streams: [], pages: [], codec: null, decoded: false };
  let at = 0;
  let pages = 0;
  const streams = new Map();

  while (at + 27 <= buf.length && pages < maxPages) {
    if (!startsWith(buf, at, [...Buffer.from(CAPTURE, "latin1")])) break;
    const version = buf[at + 4];
    const headerType = buf[at + 5];
    const granule = Number(buf.readBigUInt64LE(at + 6));
    const serial = buf.readUInt32LE(at + 14);
    const sequence = buf.readUInt32LE(at + 18);
    const segments = buf[at + 26];
    const tableAt = at + 27;
    if (tableAt + segments > buf.length) break;
    let payload = 0;
    for (let i = 0; i < segments; i++) payload += buf[tableAt + i];
    const payloadAt = tableAt + segments;
    if (payloadAt + payload > buf.length) break;

    const first = headerType & 0x02;                    // beginning of stream
    const continued = (headerType & 0x01) !== 0;
    let stream = streams.get(serial);
    if (!stream) {
      stream = { serial, sequenceStart: sequence, granule, codec: null, pages: 0, sampleRate: null, channels: null, firstPageBytes: payload };
      streams.set(serial, stream);
      out.streams.push(stream);
    }
    stream.pages++;
    stream.granule = granule;

    if (first && payload > 0) {
      const codec = CODECS.find((c) => startsWith(buf, payloadAt, c.tag));
      if (codec) {
        stream.codec = codec.id;
        stream.codecName = codec.name;
        if (!out.codec) out.codec = codec.id;
        // the identification headers both carry channels and a rate, in their own encodings
        if (codec.id === "opus" && payload >= 19) {
          stream.channels = buf[payloadAt + 9];
          stream.sampleRate = buf.readUInt32LE(payloadAt + 12);   // input rate; Opus decodes at 48 kHz
          stream.preSkip = buf.readUInt16LE(payloadAt + 10);
        } else if (codec.id === "vorbis" && payload >= 30) {
          stream.channels = buf[payloadAt + 11];
          stream.sampleRate = buf.readUInt32LE(payloadAt + 12);
          stream.bitrateNominal = buf.readInt32LE(payloadAt + 20);
        }
      }
    }

    out.pages.push({ serial, sequence, granule, bytes: payload, segments, first: Boolean(first), continued });
    at = payloadAt + payload;
    pages++;
  }

  out.pageCount = pages;
  out.readBytes = at;
  out.lastGranule = out.streams.reduce((m, s) => Math.max(m, s.granule), 0);
  out.truncatedProbe = at < buf.length;
  out.pending = "packets are located, not decoded and not decoded-to-samples: this reports the stream chain and its codec identity";
  return out;
}

const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  const file = process.argv[2];
  if (!file) { console.log("usage: node ogg.mjs <file.ogg>"); process.exit(1); }
  const r = readOgg(file);
  console.log(file);
  console.log(`  ${r.pageCount} page(s) read, ${r.streams.length} logical stream(s), codec ${r.codec}`);
  for (const s of r.streams) console.log(`  serial ${s.serial} ${s.codecName || "?"} ${s.sampleRate ? s.sampleRate + " Hz " + s.channels + " ch" : ""} ${s.pages} page(s)`);
}
