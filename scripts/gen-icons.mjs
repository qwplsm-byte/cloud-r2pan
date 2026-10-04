// 一次性脚本：生成 PWA 图标（渐变圆角方块 + 白云），输出 src/icons.ts
// 运行：node scripts/gen-icons.mjs
import zlib from "node:zlib";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// ── PNG 编码 ──
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}
function encodePNG(size, rgba) {
  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (stride + 1)] = 0;
    Buffer.from(rgba.buffer, y * stride, stride).copy(raw, y * (stride + 1) + 1);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8bit RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// ── 绘制 ──
function drawIcon(size) {
  const px = new Uint8Array(size * size * 4);
  const radius = size * 0.22;
  const c1 = [56, 189, 248];   // #38bdf8
  const c2 = [139, 92, 246];   // #8b5cf6
  const inRounded = (x, y) => {
    const r = radius;
    const cx = Math.min(Math.max(x, r), size - r);
    const cy = Math.min(Math.max(y, r), size - r);
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r || (x >= r && x <= size - r) || (y >= r && y <= size - r);
  };
  const inCloud = (x, y) => {
    const s = size;
    const circles = [
      [0.38 * s, 0.56 * s, 0.15 * s],
      [0.55 * s, 0.47 * s, 0.19 * s],
      [0.71 * s, 0.57 * s, 0.13 * s],
    ];
    for (const [cx, cy, r] of circles) if ((x - cx) ** 2 + (y - cy) ** 2 <= r * r) return true;
    // 云底矩形
    return x >= 0.34 * s && x <= 0.74 * s && y >= 0.55 * s && y <= 0.68 * s;
  };
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4;
      if (!inRounded(x, y)) { px[i + 3] = 0; continue; }
      const t = (x + y) / (2 * size);
      px[i] = Math.round(c1[0] + (c2[0] - c1[0]) * t);
      px[i + 1] = Math.round(c1[1] + (c2[1] - c1[1]) * t);
      px[i + 2] = Math.round(c1[2] + (c2[2] - c1[2]) * t);
      px[i + 3] = 255;
      if (inCloud(x, y)) {
        px[i] = px[i + 1] = px[i + 2] = 255;
      }
    }
  }
  return encodePNG(size, px);
}

const b64 = (buf) => buf.toString("base64");
const out = `// 自动生成：node scripts/gen-icons.mjs —— PWA 图标（base64 PNG，勿手改）
export const ICON_192_B64 = "${b64(drawIcon(192))}";
export const ICON_512_B64 = "${b64(drawIcon(512))}";
`;
fs.writeFileSync(path.join(root, "src", "icons.ts"), out);
console.log("icons.ts written:", (out.length / 1024).toFixed(1) + " KB");
