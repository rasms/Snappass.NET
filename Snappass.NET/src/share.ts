import { encrypt, exportKey, generateKey, toBase64Url } from './crypto';
import { generatePassword } from './password';
import { wireClipboard } from './clipboard';

const MAX_PLAINTEXT_BYTES = 64 * 1024;
const VALID_TTLS = new Set(['Hour', 'Day', 'Week', 'Month']);

function $<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`element #${id} missing`);
  return el as T;
}

async function createSecret(ciphertext: string, ttl: string): Promise<string> {
  const res = await fetch('/api/secrets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ciphertext, ttl }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`server rejected secret (${res.status}): ${body}`);
  }
  const data = (await res.json()) as { id: string };
  return data.id;
}

function showResult(url: string) {
  $('share-form').classList.add('hidden');
  const linkInput = $<HTMLInputElement>('password-link');
  linkInput.value = url;
  $('share-result').classList.remove('hidden');
  linkInput.select();
}

function showError(msg: string) {
  const err = $('share-error');
  err.textContent = msg;
  err.classList.remove('hidden');
}

function hideError() {
  $('share-error').classList.add('hidden');
}

async function onSubmit(e: SubmitEvent) {
  e.preventDefault();
  hideError();

  const password = $<HTMLTextAreaElement>('password').value;
  const ttl = $<HTMLSelectElement>('ttl').value;

  if (!password) {
    showError('Secret darf nicht leer sein.');
    return;
  }
  const bytes = new TextEncoder().encode(password).length;
  if (bytes > MAX_PLAINTEXT_BYTES) {
    showError(`Secret zu groß (${bytes} B, max ${MAX_PLAINTEXT_BYTES} B).`);
    return;
  }
  if (!VALID_TTLS.has(ttl)) {
    showError('Ungültige Gültigkeitsdauer.');
    return;
  }

  const submit = $<HTMLButtonElement>('share-submit');
  submit.disabled = true;

  try {
    const key = await generateKey();
    const blob = await encrypt(password, key);
    const rawKey = await exportKey(key);

    const id = await createSecret(toBase64Url(blob), ttl);
    const url = `${location.origin}/s/${encodeURIComponent(id)}#${toBase64Url(rawKey)}`;
    showResult(url);
  } catch (err) {
    showError(err instanceof Error ? err.message : 'Unbekannter Fehler.');
  } finally {
    submit.disabled = false;
  }
}

function init() {
  $('share-form').addEventListener('submit', onSubmit as EventListener);
  $('generate-pw').addEventListener('click', () => {
    $<HTMLTextAreaElement>('password').value = generatePassword();
  });
  wireClipboard();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
