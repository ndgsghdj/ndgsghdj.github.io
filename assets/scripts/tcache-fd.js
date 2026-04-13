(function () {
  function parseHex(value) {
    const normalized = String(value || '')
      .trim()
      .replace(/_/g, '')
      .replace(/,/g, '')
      .toLowerCase();

    if (!normalized) {
      return null;
    }

    const stripped = normalized.startsWith('0x') ? normalized.slice(2) : normalized;
    if (!/^[0-9a-f]+$/.test(stripped)) {
      return null;
    }

    try {
      return BigInt(`0x${stripped}`);
    } catch {
      return null;
    }
  }

  function formatHex(value) {
    const hex = value.toString(16);
    const width = Math.max(1, Math.ceil(hex.length / 2) * 2);
    return `0x${hex.padStart(width, '0')}`;
  }

  function setText(root, role, value) {
    const node = root.querySelector(`[data-role="${role}"]`);
    if (node) {
      node.textContent = value;
    }
  }

  function updateWidget(root) {
    const entry = parseHex(root.dataset.tcacheEntry || '0x4058c0');
    const initialFd = parseHex(root.dataset.tcacheInitialFd || '0x000000405dd5');
    const input = root.querySelector('.tcache-fd-input');
    const target = parseHex(input ? input.value : root.dataset.tcacheTarget || '');

    if (target === null || entry === null || initialFd === null) {
      setText(root, 'mask', 'invalid input');
      setText(root, 'mangled-fd', '—');
      setText(root, 'xor-delta', '—');
      return;
    }

    const mask = entry >> 12n;
    const mangled = target ^ mask;
    const xorDelta = mangled ^ initialFd;

    setText(root, 'entry', formatHex(entry));
    setText(root, 'mask', formatHex(mask));
    setText(root, 'initial-fd', formatHex(initialFd));
    setText(root, 'mangled-fd', formatHex(mangled));
    setText(root, 'xor-delta', formatHex(xorDelta));
  }

  function initWidget(root) {
    const input = root.querySelector('.tcache-fd-input');
    if (!input) {
      return;
    }

    input.addEventListener('input', () => updateWidget(root));
    updateWidget(root);
  }

  function boot() {
    document.querySelectorAll('.component-tcache-fd').forEach(initWidget);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
})();
