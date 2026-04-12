/* eslint-disable import/no-dynamic-require */
import * as fs from 'fs';
import * as path from 'path';
import * as ejs from 'ejs';

import { repoRoot } from './site';

export interface ComponentAttributes {
  [key: string]: string;
}

const componentOpenCloseRegex = /\{\{<\s*(\/?)component\b([^>]*)>}}/g;
const componentSelfClosingRegex = /\{\{<\s*component\b([^>]*)\/>}}/g;

function parseAttributes(source: string): ComponentAttributes {
  const attrs: ComponentAttributes = {};
  const regex = /([a-zA-Z0-9_-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"']+))/g;

  let match: RegExpExecArray | null;
  while ((match = regex.exec(source)) !== null) {
    const key = match[1];
    const value = match[3] ?? match[4] ?? match[5] ?? '';
    attrs[key] = value;
  }

  return attrs;
}

function readTemplate(componentName: string): string {
  const templatePath = path.join(repoRoot(), 'components', `${componentName}.ejs`);
  if (!fs.existsSync(templatePath)) {
    throw new Error(`Unknown component '${componentName}'. Create ${templatePath} to add it.`);
  }

  return String(fs.readFileSync(templatePath));
}

function renderComponent(componentName: string, attributes: ComponentAttributes, content: string): string {
  const template = readTemplate(componentName);
  return ejs.render(template, {
    attributes,
    content,
    escapeHtml: ejs.escapeXML,
  });
}

function findMatchingClose(source: string, startIndex: number): RegExpExecArray | null {
  componentOpenCloseRegex.lastIndex = startIndex;
  let depth = 1;
  let match: RegExpExecArray | null;

  while ((match = componentOpenCloseRegex.exec(source)) !== null) {
    if (!match[1]) {
      depth += 1;
      continue;
    }

    depth -= 1;
    if (depth === 0) {
      return match;
    }
  }

  return null;
}

export function renderComponentShortcodes(source: string, renderNested: (input: string) => string): string {
  let output = '';
  let cursor = 0;

  while (cursor < source.length) {
    componentOpenCloseRegex.lastIndex = cursor;
    componentSelfClosingRegex.lastIndex = cursor;

    const openCloseMatch = componentOpenCloseRegex.exec(source);
    const selfClosingMatch = componentSelfClosingRegex.exec(source);

    const nextMatch = [openCloseMatch, selfClosingMatch]
      .filter(Boolean)
      .sort((a, b) => (a!.index - b!.index))[0];

    if (!nextMatch) {
      output += source.slice(cursor);
      break;
    }

    output += source.slice(cursor, nextMatch.index);

    const attrs = parseAttributes(nextMatch[2] || nextMatch[1] || '');
    const componentName = attrs.name;

    if (!componentName) {
      throw new Error('Missing component name in shortcode.');
    }

    if (nextMatch === selfClosingMatch) {
      output += renderComponent(componentName, attrs, '');
      cursor = nextMatch.index + nextMatch[0].length;
      continue;
    }

    const closeMatch = findMatchingClose(source, nextMatch.index + nextMatch[0].length);
    if (!closeMatch) {
      throw new Error(`Missing closing tag for component '${componentName}'.`);
    }

    const innerSource = source.slice(nextMatch.index + nextMatch[0].length, closeMatch.index);
    const renderedInner = renderNested(innerSource);
    output += renderComponent(componentName, attrs, renderedInner);
    cursor = closeMatch.index + closeMatch[0].length;
  }

  return output;
}

