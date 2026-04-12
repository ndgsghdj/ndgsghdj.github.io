export interface FrontMatterResult {
  attributes: Record<string, string | string[]>;
  body: string;
}

function parseTags(value: string): string[] {
  return value
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean);
}

export function parseFrontMatter(source: string): FrontMatterResult {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);

  if (!match) {
    return {
      attributes: {},
      body: source,
    };
  }

  const attributes: Record<string, string | string[]> = {};
  const lines = match[1].split(/\r?\n/).filter(Boolean);

  lines.forEach((line) => {
    const kv = line.match(/^([^:]+):\s*(.*)$/);
    if (!kv) {
      return;
    }

    const key = kv[1].trim();
    const rawValue = kv[2].trim().replace(/^['"]|['"]$/g, '');

    if (key === 'tags') {
      attributes[key] = parseTags(rawValue);
      return;
    }

    attributes[key] = rawValue;
  });

  return {
    attributes,
    body: source.slice(match[0].length),
  };
}

