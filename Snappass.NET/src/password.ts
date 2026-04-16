const ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';

export function generatePassword(length = 24): string {
  const n = ALPHABET.length;
  const max = Math.floor(0x1_0000_0000 / n) * n;
  const out: string[] = [];
  const buf = new Uint32Array(64);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && out.length < length; i++) {
      const v = buf[i]!;
      if (v < max) {
        out.push(ALPHABET[v % n]!);
      }
    }
  }
  return out.join('');
}
