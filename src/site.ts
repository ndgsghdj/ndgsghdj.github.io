import * as path from 'path';

export function repoRoot() {
  return path.join(__dirname, '..');
}

export function normalizeBasePath(basePath = process.env.SITE_BASE_PATH || '/'): string {
  const trimmed = basePath.trim();
  if (!trimmed || trimmed === '/') {
    return '/';
  }

  const withLeadingSlash = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  return withLeadingSlash.endsWith('/') ? withLeadingSlash : `${withLeadingSlash}/`;
}

export function joinUrl(basePath: string, target: string): string {
  if (!target) {
    return basePath;
  }

  if (/^(https?:|mailto:|tel:|#)/.test(target)) {
    return target;
  }

  if (basePath === '/') {
    return target.startsWith('/') ? target : `/${target}`;
  }

  const normalizedTarget = target.startsWith('/') ? target.slice(1) : target;
  return `${basePath}${normalizedTarget}`;
}

export function prefixRootRelativeUrls(html: string, basePath: string): string {
  if (basePath === '/') {
    return html;
  }

  return html.replace(
    /\b(href|src|action|poster)=("|\')\/(?!\/|#)([^"\']*)\2/g,
    (_, attr: string, quote: string, value: string) => `${attr}=${quote}${joinUrl(basePath, `/${value}`)}${quote}`,
  );
}

