/**
 * Tiny EXIF reader for JPEG photos: date taken, camera, lens and exposure. It only looks at the
 * APP1 "Exif" segment inside the first bytes of the file (the previewer fetches 64 KB) and
 * bounds-checks every read, so a malformed file simply yields no metadata.
 * @module features/viewers/exif
 */

const IFD0 = { 0x010f: 'make', 0x0110: 'model', 0x0112: 'orientation', 0x0132: 'dateTime', 0x8769: 'exifIfd' };
const EXIF = { 0x9003: 'dateTimeOriginal', 0x829a: 'exposureTime', 0x829d: 'fNumber', 0x8827: 'iso', 0x920a: 'focalLength', 0xa434: 'lensModel' };

/**
 * @param {ArrayBuffer} buffer
 * @returns {null|{make?:string, model?:string, dateTimeOriginal?:string, dateTime?:string, exposureTime?:number, fNumber?:number, iso?:number, focalLength?:number, lensModel?:string, orientation?:number}}
 */
export function parseExif(buffer) {
  try {
    const v = new DataView(buffer);
    if (v.byteLength < 4 || v.getUint16(0) !== 0xffd8) return null;
    let off = 2;
    while (off + 4 <= v.byteLength) {
      if (v.getUint8(off) !== 0xff) return null;
      const marker = v.getUint8(off + 1);
      if (marker === 0xd9 || marker === 0xda) return null; // end of image / start of scan
      const len = v.getUint16(off + 2);
      if (len < 2) return null;
      if (marker === 0xe1 && off + 10 <= v.byteLength && ascii(v, off + 4, 4) === 'Exif' && v.getUint16(off + 8) === 0) {
        return parseTiff(v, off + 10, Math.min(v.byteLength, off + 2 + len));
      }
      off += 2 + len;
    }
  } catch { /* truncated or malformed */ }
  return null;
}

function ascii(v, start, len) {
  let s = '';
  for (let i = 0; i < len && start + i < v.byteLength; i++) {
    const c = v.getUint8(start + i);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function parseTiff(v, start, end) {
  const order = v.getUint16(start);
  if (order !== 0x4949 && order !== 0x4d4d) return null;
  const le = order === 0x4949;
  const u16 = (o) => (o + 2 <= end ? v.getUint16(o, le) : 0);
  const u32 = (o) => (o + 4 <= end ? v.getUint32(o, le) : 0);
  const i32 = (o) => (o + 4 <= end ? v.getInt32(o, le) : 0);
  if (u16(start + 2) !== 42) return null;
  const out = {};

  const value = (entry, type, count) => {
    const size = ({ 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 })[type] || 0;
    if (!size || count === 0) return undefined;
    const dataOff = size * count <= 4 ? entry + 8 : start + u32(entry + 8);
    if (dataOff + size * Math.min(count, 1) > end) return undefined;
    switch (type) {
      case 2: return ascii(v, dataOff, Math.min(count, 128)).trim();
      case 3: return u16(dataOff);
      case 4: return u32(dataOff);
      case 9: return i32(dataOff);
      case 5: { const d = u32(dataOff + 4); return d ? u32(dataOff) / d : undefined; }
      case 10: { const d = i32(dataOff + 4); return d ? i32(dataOff) / d : undefined; }
      default: return undefined;
    }
  };

  const readIfd = (rel, tags) => {
    const base = start + rel;
    if (rel <= 0 || base + 2 > end) return;
    const n = Math.min(u16(base), 256);
    for (let i = 0; i < n; i++) {
      const e = base + 2 + i * 12;
      if (e + 12 > end) break;
      const name = tags[u16(e)];
      if (!name) continue;
      const val = value(e, u16(e + 2), u32(e + 4));
      if (val !== undefined && val !== '') out[name] = val;
    }
  };

  readIfd(u32(start + 4), IFD0);
  if (typeof out.exifIfd === 'number') readIfd(out.exifIfd, EXIF);
  delete out.exifIfd;
  return Object.keys(out).length ? out : null;
}

/** "2026:10:03 14:31:05" → Date in local time (EXIF times carry no time zone), or null. */
export function exifDate(s) {
  const m = /^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/.exec(String(s || ''));
  if (!m || m[1] === '0000') return null;
  const d = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  return isNaN(d.getTime()) ? null : d;
}

/** Human camera line, e.g. "Apple iPhone 15 Pro · f/1.8 · 1/120 s · ISO 50 · 6.9 mm". */
export function cameraLine(x) {
  if (!x) return '';
  const parts = [];
  const make = (x.make || '').trim();
  let model = (x.model || '').trim();
  if (make && model.toLowerCase().startsWith(make.toLowerCase())) model = model.slice(make.length).trim();
  const cam = [make, model].filter(Boolean).join(' ');
  if (cam) parts.push(cam);
  if (x.fNumber) parts.push('f/' + (Math.round(x.fNumber * 10) / 10));
  if (x.exposureTime) parts.push(x.exposureTime >= 1 ? Math.round(x.exposureTime * 10) / 10 + ' s' : '1/' + Math.round(1 / x.exposureTime) + ' s');
  if (x.iso) parts.push('ISO ' + x.iso);
  if (x.focalLength) parts.push(Math.round(x.focalLength * 10) / 10 + ' mm');
  return parts.join(' · ');
}
