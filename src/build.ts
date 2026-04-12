/* eslint-disable no-console */
import * as fs from 'fs';
import * as path from 'path';
import * as ejs from 'ejs';

import { readWriteups, Writeup } from './content';
import { joinUrl, normalizeBasePath, prefixRootRelativeUrls, repoRoot } from './site';

interface TemplateInput {
  title: string;
  description: string;
  pageClass: string;
  body: string;
  basePath: string;
  asset: (target: string) => string;
  siteName: string;
  siteDescription: string;
}

function readTemplate(name: string): string {
  return String(fs.readFileSync(path.join(repoRoot(), 'templates', `${name}.ejs`)));
}

function renderPage(templateName: string, input: Record<string, unknown>): string {
  return ejs.render(readTemplate(templateName), input);
}

function wrapLayout(input: TemplateInput): string {
  return ejs.render(readTemplate('layout'), input);
}

function writeFile(targetPath: string, content: string) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, content);
}

function copyDirectory(source: string, target: string) {
  if (!fs.existsSync(source)) {
    return;
  }

  fs.cpSync(source, target, { recursive: true });
}

function buildIndex(writeups: Writeup[], basePath: string) {
  const body = renderPage('index', {
    writeups,
    basePath,
    asset: (target: string) => joinUrl(basePath, target),
    siteName: 'Writeups',
    siteDescription: 'A writeups-only static blog with embedded components.',
  });

  return wrapLayout({
    title: 'Writeups',
    description: 'Writeups-only static blog with embedded components.',
    pageClass: 'page-home',
    body,
    basePath,
    asset: (target: string) => joinUrl(basePath, target),
    siteName: 'Writeups',
    siteDescription: 'A writeups-only static blog with embedded components.',
  });
}

function buildWriteup(writeup: Writeup, writeups: Writeup[], basePath: string, index: number) {
  const nextWriteup = writeups[index - 1];
  const prevWriteup = writeups[index + 1];
  const body = renderPage('writeup', {
    writeup,
    nextWriteup,
    prevWriteup,
    writeups,
    basePath,
    asset: (target: string) => joinUrl(basePath, target),
    siteName: 'Writeups',
    siteDescription: 'A writeups-only static blog with embedded components.',
  });

  return wrapLayout({
    title: `${writeup.title} · Writeups`,
    description: writeup.excerpt || writeup.subtitle || writeup.title,
    pageClass: 'page-writeup',
    body,
    basePath,
    asset: (target: string) => joinUrl(basePath, target),
    siteName: 'Writeups',
    siteDescription: 'A writeups-only static blog with embedded components.',
  });
}

export function buildSite() {
  const basePath = normalizeBasePath();
  const distDir = path.join(repoRoot(), 'dist');
  const stylesDir = path.join(distDir, 'styles');
  const writeupDistDir = path.join(distDir, 'writeups');

  fs.rmSync(distDir, { recursive: true, force: true });
  fs.mkdirSync(distDir, { recursive: true });
  fs.mkdirSync(stylesDir, { recursive: true });
  fs.mkdirSync(writeupDistDir, { recursive: true });

  copyDirectory(path.join(repoRoot(), 'styles'), stylesDir);
  copyDirectory(path.join(repoRoot(), 'images'), path.join(distDir, 'images'));
  copyDirectory(path.join(repoRoot(), 'assets'), path.join(distDir, 'assets'));

  const writeups = readWriteups();

  writeFile(
    path.join(distDir, 'index.html'),
    prefixRootRelativeUrls(buildIndex(writeups, basePath), basePath),
  );

  writeups.forEach((writeup, index) => {
    writeFile(
      path.join(writeupDistDir, `${writeup.slug}.html`),
      prefixRootRelativeUrls(buildWriteup(writeup, writeups, basePath, index), basePath),
    );
  });

  writeFile(
    path.join(distDir, 'robots.txt'),
    `User-agent: *\nAllow: /\nSitemap: ${joinUrl(basePath, 'sitemap.xml')}\n`,
  );

  writeFile(
    path.join(distDir, 'sitemap.xml'),
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
      `  <url><loc>${joinUrl(basePath, 'index.html')}</loc></url>\n` +
      writeups.map((writeup) => `  <url><loc>${joinUrl(basePath, `writeups/${writeup.slug}.html`)}</loc></url>`).join('\n') +
      `\n</urlset>\n`,
  );

  console.log(`Built ${writeups.length} writeup(s) to ${distDir}`);
}

if (require.main === module) {
  buildSite();
}

