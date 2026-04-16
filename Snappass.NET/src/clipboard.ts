export function wireClipboard(root: ParentNode = document): void {
  root.querySelectorAll<HTMLElement>('[data-clipboard-target]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const selector = btn.dataset.clipboardTarget;
      if (!selector) return;
      const target = document.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector);
      if (!target) return;
      try {
        await navigator.clipboard.writeText(target.value);
        flashLabel(btn, 'Copied!');
      } catch {
        flashLabel(btn, 'Copy failed');
      }
    });
  });
}

function flashLabel(btn: HTMLElement, text: string) {
  const original = btn.getAttribute('data-original-title') ?? btn.textContent ?? '';
  if (!btn.hasAttribute('data-original-title')) {
    btn.setAttribute('data-original-title', original);
  }
  btn.setAttribute('title', text);
  window.setTimeout(() => {
    btn.setAttribute('title', original);
  }, 1500);
}
