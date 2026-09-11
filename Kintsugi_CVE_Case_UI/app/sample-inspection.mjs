// File identity for this teaching demo, not a general malware detector.
export function inspectSample(bytes, filename, complete = true) {
  const text = new TextDecoder('latin1').decode(bytes);
  const starts = (...values) => values.every((value, index) => bytes[index] === value);
  const format = text.startsWith('%!PS') ? 'EPS / PostScript'
    : starts(0xff, 0xd8, 0xff) ? 'JPEG'
      : starts(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a) ? 'PNG'
        : /^GIF8[79]a/.test(text) ? 'GIF' : text.startsWith('BM') ? 'BMP' : '未识别';
  const eps = format === 'EPS / PostScript';
  const hasPipe = eps && text.includes('%pipe%');
  const known = format !== '未识别' && (!eps || complete || hasPipe);
  const tokenLine = eps ? text.split(/\r?\n/).find((line) => line.includes('%pipe%'))?.slice(0, 180) : undefined;
  return {
    format, eps, hasPipe, known,
    classification: !known ? 'unknown' : hasPipe ? 'malicious' : 'normal',
    mismatch: eps && /\.(jpe?g|png|gif|bmp)$/i.test(filename),
    header: eps ? text.split(/\r?\n/)[0].slice(0, 120) : Array.from(bytes.slice(0, 16), (byte) => byte.toString(16).padStart(2, '0').toUpperCase()).join(' '),
    tokenLine,
  };
}

export async function inspectFile(file) {
  const limit = 1024 * 1024;
  return inspectSample(new Uint8Array(await file.slice(0, limit).arrayBuffer()), file.name, file.size <= limit);
}
