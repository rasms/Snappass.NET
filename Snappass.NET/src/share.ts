import { encrypt, exportKey, generateKey, toBase64Url } from './crypto';
import { generatePassword } from './password';
import { wireClipboard } from './clipboard';

const MAX_PLAINTEXT_BYTES = 64 * 1024;
const VALID_TTLS = new Set(['Hour', 'Day', 'Week', 'Month']);
const VALID_VIEWS = new Set([1, 2, 3, 5, 10]);

function $<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`element #${id} missing`);
  return el as T;
}

async function createSecret(ciphertext: string, ttl: string, views: number): Promise<string> {
  const res = await fetch('/api/secrets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ciphertext, ttl, views }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`server rejected secret (${res.status}): ${body}`);
  }
  const data = (await res.json()) as { id: string };
  return data.id;
}

function showResult(url: string, views: number) {
  $('share-form').classList.add('hidden');
  const linkInput = $<HTMLInputElement>('password-link');
  linkInput.value = url;
  $('share-result-text').textContent = views === 1
    ? 'Send this URL to the intended recipient. It can only be opened once.'
    : `Send this URL to the intended recipient. It can be opened up to ${views} times.`;
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
  const views = Number($<HTMLSelectElement>('views').value);

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
  if (!VALID_VIEWS.has(views)) {
    showError('Ungültige View-Anzahl.');
    return;
  }

  const submit = $<HTMLButtonElement>('share-submit');
  submit.disabled = true;

  try {
    const key = await generateKey();
    const blob = await encrypt(password, key);
    const rawKey = await exportKey(key);

    const id = await createSecret(toBase64Url(blob), ttl, views);
    const url = `${location.origin}/s/${encodeURIComponent(id)}#${toBase64Url(rawKey)}`;
    showResult(url, views);
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
