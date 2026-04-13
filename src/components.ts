/* eslint-disable import/no-dynamic-require */
import * as fs from 'fs';
import * as path from 'path';
import * as ejs from 'ejs';

import { resolveColorToken } from './colors';
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
    resolveColorToken,
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

function isFenceLine(line: string): RegExpExecArray | null {
  return line.match(/^(\s*)(`{3,}|~{3,})(.*)$/);
}

function renderShortcodeChunk(
  source: string,
  renderNested: (input: string) => string,
  renderInlineNested: (input: string) => string,
): string {
  return renderChunk(source, renderNested, renderInlineNested);
}

function renderTerminalChunk(source: string, renderInlineNested: (input: string) => string): string {
  const normalized = source.replace(/^\r?\n+|\r?\n+$/g, '');

  return normalized
    .split(/\r?\n/)
    .map((line) => {
      let output = '';
      let cursor = 0;

      while (cursor < line.length) {
        componentOpenCloseRegex.lastIndex = cursor;
        componentSelfClosingRegex.lastIndex = cursor;

        const openCloseMatch = componentOpenCloseRegex.exec(line);
        const selfClosingMatch = componentSelfClosingRegex.exec(line);
        const nextMatch = [openCloseMatch, selfClosingMatch]
          .filter(Boolean)
          .sort((a, b) => (a!.index - b!.index))[0];

        if (!nextMatch) {
          output += ejs.escapeXML(line.slice(cursor));
          break;
        }

        output += ejs.escapeXML(line.slice(cursor, nextMatch.index));

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

        const closeMatch = findMatchingClose(line, nextMatch.index + nextMatch[0].length);
        if (!closeMatch) {
          throw new Error(`Missing closing tag for component '${componentName}'.`);
        }

        const innerSource = line.slice(nextMatch.index + nextMatch[0].length, closeMatch.index);
        const renderedInner = componentName === 'color'
          ? ejs.escapeXML(innerSource.trim())
          : ejs.escapeXML(innerSource);
        output += renderComponent(componentName, attrs, renderedInner);
        cursor = closeMatch.index + closeMatch[0].length;
      }

      return `<div class="component-terminal-line">${output}</div>`;
    })
    .join('');
}

export function renderComponentShortcodes(
  source: string,
  renderNested: (input: string) => string,
  renderInlineNested: (input: string) => string = renderNested,
): string {
  let output = '';
  let buffer = '';
  let inFence = false;
  let fenceMarker = '';
  let fenceLength = 0;

  const flushBuffer = () => {
    if (!buffer) {
      return;
    }

    output += renderShortcodeChunk(buffer, renderNested, renderInlineNested);
    buffer = '';
  };

  const lines = source.split(/(\r?\n)/);
  for (let index = 0; index < lines.length; index += 1) {
    const part = lines[index];

    if (part === '\n' || part === '\r\n') {
      if (inFence) {
        output += part;
      } else {
        buffer += part;
      }
      continue;
    }

    const fenceMatch = isFenceLine(part);
    if (fenceMatch) {
      const marker = fenceMatch[2][0];
      const length = fenceMatch[2].length;

      if (!inFence) {
        flushBuffer();
        inFence = true;
        fenceMarker = marker;
        fenceLength = length;
        output += part;
        continue;
      }

      const fenceBody = fenceMatch[3].trim();
      const isClosingFence = fenceBody === '' && marker === fenceMarker && length >= fenceLength;
      output += part;
      if (isClosingFence) {
        inFence = false;
        fenceMarker = '';
        fenceLength = 0;
      }
      continue;
    }

    if (inFence) {
      output += part;
      continue;
    }

    buffer += part;
  }

  flushBuffer();

  return output;
}

function renderChunk(source: string, renderNested: (input: string) => string, renderInlineNested: (input: string) => string): string {
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
    const renderedInner = componentName === 'color'
      ? renderInlineNested(innerSource.trim())
      : componentName === 'terminal'
        ? renderTerminalChunk(innerSource.trimEnd(), renderInlineNested)
        : renderNested(innerSource);
    output += renderComponent(componentName, attrs, renderedInner);
    cursor = closeMatch.index + closeMatch[0].length;
  }

  return output;
}
