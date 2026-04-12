import * as fs from 'fs';
import * as path from 'path';
import dayjs from 'dayjs';

import { parseFrontMatter } from './frontMatter';
import { repoRoot } from './site';
import { createMarkdownRenderer, renderMarkdown } from './markdown';
import { renderComponentShortcodes } from './components';

export interface Writeup {
  slug: string;
  title: string;
  subtitle?: string;
  date: string;
  tags: string[];
  excerpt: string;
  html: string;
  body: string;
}

const markdown = createMarkdownRenderer();

function stripHtml(value: string): string {
  return value
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, '\'')
    .replace(/\s+/g, ' ')
    .trim();
}

function buildToc(renderedHtml: string): string {
  const headings = [...renderedHtml.matchAll(/<h([1-3]) id="([^"]+)"[^>]*>([\s\S]*?)<\/h\1>/g)]
    .map((match) => ({
      level: Number(match[1]),
      id: match[2],
      text: stripHtml(match[3]),
    }));

  if (!headings.length) {
    return '';
  }

  const baseLevel = Math.min(...headings.map((heading) => heading.level));
  const items = headings
    .map((heading) => {
      const normalizedLevel = heading.level - baseLevel + 1;
      return `<li class="writeup-toc-item writeup-toc-level-${normalizedLevel}"><a href="#${heading.id}">${heading.text}</a></li>`;
    })
    .join('');

  const html = `<nav class="writeup-toc"><p class="component-label">Table of Contents</p><ul class="writeup-toc-list">${items}</ul></nav>`;
  return html;
}

function extractExcerpt(body: string): string {
  const rendered = renderMarkdown(markdown, body);
  const paragraph = rendered.match(/<p>([\s\S]*?)<\/p>/);
  if (paragraph) {
    return stripHtml(paragraph[1]).slice(0, 180);
  }

  return stripHtml(rendered).slice(0, 180);
}

function normalizeDate(value: string): string {
  const parsed = dayjs(value.replace(/\./g, '-'));
  if (parsed.isValid()) {
    return parsed.format('YYYY.MM.DD');
  }

  return value;
}

function renderBody(body: string): string {
  const withComponents = renderComponentShortcodes(body, renderBody);
  return renderMarkdown(markdown, withComponents);
}

export function readWriteups() {
  const writeupDir = path.join(repoRoot(), 'writeups');
  const files = fs.readdirSync(writeupDir).filter((file) => file.endsWith('.md'));

  const writeups = files.map((file) => {
    const slug = path.basename(file, '.md');
    const source = String(fs.readFileSync(path.join(writeupDir, file)));
    const { attributes, body } = parseFrontMatter(source);
    const title = String(attributes.title || slug);
    const subtitle = attributes.subtitle ? String(attributes.subtitle) : undefined;
    const date = normalizeDate(String(attributes.date || ''));
    const tags = Array.isArray(attributes.tags)
      ? attributes.tags.map(String)
      : String(attributes.tags || '').split(',').map((tag) => tag.trim()).filter(Boolean);
    const renderedBody = renderBody(body);
    const html = `${buildToc(renderedBody)}${renderedBody}`;
    const excerpt = extractExcerpt(body);

    return {
      slug,
      title,
      subtitle,
      date,
      tags,
      excerpt,
      html,
      body,
    } as Writeup;
  });

  return writeups.sort((left, right) => {
    const leftValue = dayjs(left.date.replace(/\./g, '-')).valueOf();
    const rightValue = dayjs(right.date.replace(/\./g, '-')).valueOf();
    return rightValue - leftValue;
  });
}
