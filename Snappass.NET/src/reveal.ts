import { decrypt, fromBase64Url, importKey } from './crypto';
import { wireClipboard } from './clipboard';

function $<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`element #${id} missing`);
  return el as T;
}

function getIdFromPath(): string | null {
  const match = location.pathname.match(/^\/s\/([^/]+)\/?$/);
  return match ? decodeURIComponent(match[1]!) : null;
}

function getRawKeyFromFragment(): Uint8Array | null {
  const hash = location.hash.replace(/^#/, '');
  if (!hash) return null;
  try {
    return fromBase64Url(hash);
  } catch {
    return null;
  }
}

async function checkExists(id: string): Promise<boolean> {
  const res = await fetch(`/api/secrets/${encodeURIComponent(id)}/exists`);
  if (!res.ok) return false;
  const data = (await res.json()) as { exists: boolean };
  return data.exists;
}

async function consume(id: string): Promise<string | null> {
  const res = await fetch(`/api/secrets/${encodeURIComponent(id)}/consume`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`server error ${res.status}`);
  const data = (await res.json()) as { ciphertext: string };
  return data.ciphertext;
}

function showExpired() {
  $('preview').classList.add('hidden');
  $('revealed').classList.add('hidden');
  $('expired').classList.remove('hidden');
}

function showRevealed(plaintext: string) {
  $('preview').classList.add('hidden');
  const ta = $<HTMLTextAreaElement>('secret-text');
  ta.value = plaintext;
  $('revealed').classList.remove('hidden');
}

async function reveal(id: string, rawKey: Uint8Array) {
  const btn = $<HTMLButtonElement>('reveal-btn');
  btn.disabled = true;
  try {
    const ciphertextB64 = await consume(id);
    if (!ciphertextB64) {
      showExpired();
      return;
    }
    const key = await importKey(rawKey);
    const blob = fromBase64Url(ciphertextB64);
    const plain = await decrypt(blob, key);
    showRevealed(plain);
  } catch {
    showExpired();
  } finally {
    btn.disabled = false;
  }
}

async function init() {
  const id = getIdFromPath();
  const rawKey = getRawKeyFromFragment();
  if (!id || !rawKey) {
    showExpired();
    return;
  }
  if (!(await checkExists(id))) {
    showExpired();
    return;
  }
  $('preview').classList.remove('hidden');
  $('reveal-btn').addEventListener('click', () => reveal(id, rawKey));
  wireClipboard();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
