// FLAC 独立走链器：只解析字节，与编码器（deps/decoders/flac-encoder.mjs）零共享代码。
//
// 它存在的理由：律 9（用独立的读者验收作者）。编码器自证不算数，得有一个不同视角的读者
// 把流解回样本，逐项核对。支持的范围就是编码器现在写出的子集：
//   constant / verbatim / fixed 0-4 + Rice（4 位参数）、16 bit、独立声道（无 decorrelation）。
// 超出范围的在入口就抛错 —— 判据需要知道「编码器写出了走链器不认得的东西」。
import fs from "node:fs";

export class BitReader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
    this.bit = 0; // 0..7, 从当前字节的高位往低位读
  }

  read(width) {
    let v = 0;
    for (let i = 0; i < width; i++) {
      v = (v << 1) | ((this.buf[this.pos] >> (7 - this.bit)) & 1);
      this.bit++;
      if (this.bit === 8) { this.bit = 0; this.pos++; }
    }
    return v;
  }

  signed(width) {
    const v = this.read(width);
    return v >= 1 << (width - 1) ? v - (1 << width) : v;
  }

  unary() {
    let q = 0;
    while (this.pos < this.buf.length && this.read(1) === 0) q++;
    if (this.pos >= this.buf.length) throw new Error("unary ran past the end of the stream");
    return q;
  }

  align() {
    if (this.bit !== 0) { this.bit = 0; this.pos++; }
  }
}

const crc8 = (buf) => {
  let crc = 0;
  for (const b of buf) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = crc & 0x80 ? ((crc << 1) ^ 0x07) & 0xff : (crc << 1) & 0xff;
  }
  return crc;
};

const crc16 = (buf) => {
  let crc = 0;
  for (const b of buf) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x8005) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
};

const BLOCK_SIZES = {
  1: 192, 2: 576, 3: 1152, 4: 2304, 5: 4608, 6: 8, 7: 16, 8: 256, 9: 512,
  10: 1024, 11: 2048, 12: 4096, 13: 8192, 14: 16384, 15: 32768,
};

export function walkFlac(buf) {
  if (buf.slice(0, 4).toString("latin1") !== "fLaC") throw new Error("not a FLAC stream (no fLaC marker)");

  let off = 4;
  let sampleRate = null, channels = null, bps = null, totalFrames = null, md5 = null;
  let last = false;
  while (!last) {
    const head = buf[off]; last = (head & 0x80) !== 0; const type = head & 0x7f;
    const len = (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];
    const body = buf.slice(off + 4, off + 4 + len);
    if (type === 0 && len >= 34) {
      sampleRate = (body.readUInt32BE(10) >>> 12) & 0xfffff;
      channels = ((body.readUInt32BE(10) >>> 9) & 0x7) + 1;
      bps = ((body.readUInt32BE(10) >>> 4) & 0x1f) + 1;
      const high = body.readUInt32BE(10) & 0xf;
      const low = body.readUInt32BE(14);
      totalFrames = high * 2 ** 32 + low;
      md5 = body.slice(18, 34);
    }
    off += 4 + len;
  }
  if (bps !== 16) throw new Error(`walk supports 16-bit streams only (got ${bps})`);
  if (channels > 2) throw new Error(`walk supports 1-2 independent channels (got ${channels})`);

  const pcm = Buffer.alloc(totalFrames * channels * 2);
  let written = 0;
  let escapes = 0;

  while (off < buf.length) {
    const frameStart = off;
    const r = new BitReader(buf.slice(frameStart));
    if (r.read(14) !== 0x3ffe) throw new Error(`bad sync at offset ${frameStart}`);
    r.read(1); // reserved
    r.read(1); // blocking strategy: encoder writes fixed blocking
    const blockCode = r.read(4);
    const rateCode = r.read(4);
    const chanCode = r.read(4);
    const sizeCode = r.read(3);
    r.read(1); // reserved
    if (sizeCode !== 4) throw new Error(`walk supports 16-bit sample size only (code ${sizeCode})`);
    // 帧号：UTF-8 编码的数；编码器按帧序号写 0,1,2,...。走链器只验证首字节的合法性，
    // 帧号本身不影响样本解出。它必须在块大小字段之前读 —— 帧头顺序里块大小字段跟在帧号后面。
    let n0 = r.buf[r.pos];
    if ((n0 & 0x80) === 0) r.read(8);
    else if ((n0 & 0xe0) === 0xc0) r.read(16);
    else if ((n0 & 0xf0) === 0xe0) r.read(24);
    else if ((n0 & 0xf8) === 0xf0) r.read(32);
    else if ((n0 & 0xfc) === 0xf8) r.read(40);
    else if ((n0 & 0xfe) === 0xfc) r.read(48);
    else throw new Error("bad UTF-8 frame number");
    let block;
    if (blockCode === 6) block = r.read(8) + 1;
    else if (blockCode === 7) block = r.read(16) + 1;
    else block = BLOCK_SIZES[blockCode];
    if (!block) throw new Error(`unsupported block size code ${blockCode}`);
    if (process.env.WALK_DEBUG) console.log(`frame @${frameStart}: block=${block} blockCode=${blockCode} rateCode=${rateCode} chanCode=${chanCode}`);
    r.align();
    const headerLen = r.pos;
    const gotCrc8 = r.buf[headerLen];
    const expectCrc8 = crc8(r.buf.slice(0, headerLen));
    if (gotCrc8 !== expectCrc8) throw new Error(`header CRC8 mismatch at offset ${frameStart} (got ${gotCrc8}, want ${expectCrc8})`);

    let bodyEnd;
    {
      // 帧体是一个贯穿所有通道的连续位流。RFC 9639 第 9.2 节：只有第一个子帧从字节
      // 边界开始，子帧之间不做对齐，帧尾才补零到字节边界。
      const rb = new BitReader(buf.slice(frameStart + headerLen + 1));
      for (let c = 0; c < channels; c++) {
        const zeroPad = rb.read(1);
        if (zeroPad !== 0) throw new Error("expected zero padding bit");
        const sft = rb.read(6);
        const wasted = rb.read(1);
        if (wasted !== 0) throw new Error("walk does not support wasted bits");
        const s = new Int32Array(block);
        if (sft === 0) {
          const v = rb.signed(bps);
          for (let i = 0; i < block; i++) s[i] = v;
        } else if (sft === 1) {
          for (let i = 0; i < block; i++) s[i] = rb.signed(bps);
        } else if (sft >= 8 && sft <= 12) {
          const order = sft - 8;
          if (block <= order) throw new Error("block too small for predictor order");
          for (let i = 0; i < order; i++) s[i] = rb.signed(bps);
          const method = rb.read(2);
          if (method !== 0) throw new Error(`walk supports Rice with 4-bit parameters only (method ${method})`);
          const p = rb.read(4);
          const parts = 1 << p;
          const per = block >> p;
          const rest = [];
          // RFC 9639 第 9.2.7 节：每个分区以它自己的参数开头，随后是该分区的残差。
          for (let part = 0; part < parts; part++) {
            const first = part === 0 ? per - order : per;
            const k = rb.read(4);
            if (k === 15) {
              // Escaped partition: a 5-bit per-sample width, then raw signed residuals.
              escapes++;
              const w = rb.read(5);
              for (let i = 0; i < first; i++) rest.push(w === 0 ? 0 : rb.signed(w));
            } else {
              for (let i = 0; i < first; i++) {
                const q = rb.unary();
                const lo = k > 0 ? rb.read(k) : 0;
                const u = (q << k) | lo;
                rest.push((u >>> 1) ^ -(u & 1));
              }
            }
          }
          if (rest.length !== block - order) throw new Error(`residual count mismatch (${rest.length} vs ${block - order})`);
          for (let i = 0; i < rest.length; i++) {
            const j = i + order;
            let pred = 0;
            if (order === 1) pred = s[j - 1];
            else if (order === 2) pred = 2 * s[j - 1] - s[j - 2];
            else if (order === 3) pred = 3 * s[j - 1] - 3 * s[j - 2] + s[j - 3];
            else if (order === 4) pred = 4 * s[j - 1] - 6 * s[j - 2] + 4 * s[j - 3] - s[j - 4];
            s[j] = pred + rest[i];
          }
        } else {
          throw new Error(`unsupported subframe type ${sft}`);
        }
        for (let i = 0; i < block; i++) pcm.writeInt16LE(s[i], (written + i) * channels * 2 + c * 2);
      }
      // 帧尾：RFC 9639 第 9.3 节，最后一个子帧之后补零到字节边界，再跟 16 位 CRC。
      rb.align();
      bodyEnd = rb.pos;
    }
    written += block;
    const frameBytes = frameStart + headerLen + 1 + bodyEnd;
    const gotCrc16 = buf.readUInt16BE(frameBytes);
    const expectCrc16 = crc16(buf.slice(frameStart, frameBytes));
    if (gotCrc16 !== expectCrc16) throw new Error(`frame CRC16 mismatch at offset ${frameStart}`);
    off = frameBytes + 2;
  }

  if (written !== totalFrames) throw new Error(`frame total mismatch (${written} vs ${totalFrames})`);
  return { sampleRate, channels, bps, totalFrames, pcm16: pcm, md5, escapes };
}

export function walkFlacFile(file) {
  return walkFlac(fs.readFileSync(file));
}
