import MarkdownIt from 'markdown-it';
import * as katex from 'katex';
import highlightJs from 'highlight.js';
import mdAnchor from 'markdown-it-anchor';
import mdContainer from 'markdown-it-container';
import mdFootnote from 'markdown-it-footnote';
import mdLazyImage from 'markdown-it-image-lazy-loading';
import mdInlineComment from 'markdown-it-inline-comments';
import mdMermaid from 'markdown-it-mermaid';
import mdTex from 'markdown-it-texmath';
import x86asm from 'highlight.js/lib/languages/x86asm';

const escapeHtml = new MarkdownIt().utils.escapeHtml;
highlightJs.registerLanguage('x86asm', x86asm);
highlightJs.registerLanguage('asm', x86asm);
highlightJs.registerLanguage('nasm', x86asm);

function normalizeLanguage(language?: string) {
  if (language === 'asm' || language === 'nasm') {
    return 'x86asm';
  }

  return language;
}

export function createMarkdownRenderer() {
  return new MarkdownIt({
    html: true,
    xhtmlOut: false,
    breaks: false,
    langPrefix: 'language-',
    linkify: true,
    typographer: true,
    quotes: '“”‘’',
    highlight: (str, language) => {
      const normalizedLanguage = normalizeLanguage(language);
      if (normalizedLanguage && highlightJs.getLanguage(normalizedLanguage)) {
        return `<pre class="hljs"><code>${highlightJs.highlight(str, { language: normalizedLanguage }).value}</code></pre>`;
      }

      return `<pre class="hljs"><code>${escapeHtml(str)}</code></pre>`;
    },
  })
    .use(mdFootnote)
    .use(mdInlineComment)
    .use(mdMermaid)
    .use(mdTex.use(katex), {
      delimiters: 'gitlab',
    })
    .use(mdAnchor)
    .use(mdContainer, 'toggle', {
      validate(params) {
        return params.trim().match(/^toggle\((.*)\)$/);
      },
      render(tokens, idx) {
        const content = tokens[idx].info.trim().match(/^toggle\((.*)\)$/);
        if (tokens[idx].nesting === 1) {
          return `<details class="writeup-toggle"><summary>${escapeHtml(content?.[1] || '')}</summary>\n`;
        }

        return '</details>\n';
      },
    })
    .use(mdLazyImage, {
      decoding: true,
      image_size: true,
      base_path: process.cwd(),
    });
}

export function renderMarkdown(renderer: MarkdownIt, source: string): string {
  return renderer.render(source);
}
