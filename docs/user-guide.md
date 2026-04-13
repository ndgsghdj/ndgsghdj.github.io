# User Guide

This repository is a writeups-only static blog generator for GitHub Pages.
It converts markdown files in `writeups/` into a publishable static site,
supports reusable HTML components inside markdown, and builds a single public
archive with individual writeup pages.

## What You Get

- A centered, static writeups site
- Markdown writeups with syntax-highlighted code blocks
- Component shortcodes for custom HTML blocks
- A `color` shortcode with Catppuccin aliases and hex fallback
- A `terminal` shortcode for preformatted terminal-style output
- Automatic table of contents generation
- GitHub Pages deployment through GitHub Actions

## Repository Layout

- `writeups/`
  - Source markdown files for each writeup
- `components/`
  - EJS templates for reusable content blocks
- `templates/`
  - Page shells for the index and writeup pages
- `styles/`
  - Global CSS for the site
- `images/`
  - Static assets referenced by writeups
- `assets/`
  - Shared site assets such as the favicon
- `src/`
  - Build pipeline, markdown rendering, and component parsing
- `dist/`
  - Generated static site output

## Setup

Install dependencies once:

```bash
npm install
```

If you are on GitHub Actions or want a clean install from the lockfile:

```bash
npm ci
```

## Local Workflow

Build the site:

```bash
npm run build
```

Preview the generated output:

```bash
npm run preview
```

The preview server serves `dist/` on port `4173`.

When you edit markdown, templates, styles, or components, rebuild the site to
see the changes:

```bash
npm run build
```

## Writing a New Writeup

Create a new markdown file in `writeups/`.

Example:

```md
---
id: 5
title: "Sample Writeup"
subtitle: "Short summary"
date: "2026.01.12"
tags: "writeups, pwn, ctf"
---

Your content goes here.
```

### Front Matter Fields

- `id`
  - Numeric identifier used for ordering and page generation
- `title`
  - Main writeup title
- `subtitle`
  - Optional subtitle displayed below the title
- `date`
  - Display date for the writeup
- `tags`
  - Comma-separated list of tags

## Markdown Features

The renderer supports the standard markdown features you would expect, plus
some extras used by the current content set.

Supported examples:

- Headings, lists, blockquotes, tables, and links
- Fenced code blocks with syntax highlighting
- Footnotes
- Mermaid diagrams
- Inline comments
- Math rendering through KaTeX-style delimiters
- Lazy-loaded images
- Collapsible `toggle(...)` blocks

### Code Blocks

Use fenced code blocks and provide the language name:

```md
```c
int main(void) {
  return 0;
}
```
```

Assembly examples work too. The renderer recognizes:

- `asm`
- `nasm`
- `x86asm`
- `armasm`

If a fence uses `asm` or `nasm`, it is normalized to `x86asm` for
highlighting.

### Automatic Table of Contents

The writeup page automatically injects a table of contents based on the
rendered headings in the article body.

You do not need to add a TOC manually.

## Custom Components

Custom components are defined as EJS templates in `components/` and embedded
from markdown using shortcodes.

### Basic Usage

```md
{{< component name="callout" tone="info" label="Tip" >}}
This block can contain **markdown**.
{{< /component >}}
```

### Self-Closing Components

Some components can be self-closing:

```md
{{< component name="figure" src="/images/example.png" alt="Example" caption="A sample figure" />}}
```

### Provided Components

The repository includes:

- `callout`
- `color`
- `figure`

The `color` component accepts Catppuccin Mocha aliases such as `blue`,
`rosewater`, and `surface0`, or any valid hex color like `#fab387`.

### Creating a New Component

1. Add a new `.ejs` file in `components/`
2. Reference it with `name="your-component"`
3. Use `attributes` and `content` inside the template

Example component template:

```ejs
<div class="component">
  <%- content %>
</div>
```

### Inline Color Marks

Use the `color` component when you want to color a short span of text in a
writeup.

Catppuccin aliases are supported directly:

```md
{{< component name="color" color="blue" >}}linked text{{< /component >}}
{{< component name="color" color="rosewater" >}}highlighted text{{< /component >}}
```

For custom values, use a hex code:

```md
{{< component name="color" color="#fab387" >}}orange text{{< /component >}}
```

Supported aliases follow the Catppuccin Mocha palette, including:

- `rosewater`, `flamingo`, `pink`, `mauve`
- `red`, `maroon`, `peach`, `yellow`
- `green`, `teal`, `sky`, `sapphire`
- `blue`, `lavender`
- `text`, `subtext1`, `subtext0`
- `overlay2`, `overlay1`, `overlay0`
- `surface2`, `surface1`, `surface0`
- `base`, `mantle`, `crust`

### Terminal Output Blocks

Use the `terminal` component when you want text to look like terminal output
but still allow inline color spans.

Example:

```md
{{< component name="terminal" >}}
[*] '/home/user/chal'
Arch:       amd64-64-little
RELRO:      {{< component name="color" color="yellow" >}}Partial RELRO{{< /component >}}
NX:         NX enabled
PIE:        No PIE (0x3fe000)
{{< /component >}}
```

This keeps the output preformatted and monospaced, while still letting the
`color` shortcode style specific tokens.

## Images and Assets

- Put reusable site assets in `assets/`
- Put writeup-specific screenshots and figures in `images/`
- Reference images from markdown with root-relative paths like:

```md
![Alt text](/images/screenshot.png)
```

During build, the files are copied into `dist/images/`.

## Build Output

The build generates:

- `dist/index.html`
- `dist/writeups/<slug>.html`
- `dist/sitemap.xml`
- `dist/robots.txt`
- `dist/styles/site.css`
- copied assets and images

The writeup slug is derived from the filename. For example:

- `writeups/umdctf25.md` -> `writeups/umdctf25.html`

## Styling Notes

The site uses a Catppuccin-inspired dark palette and a centered content layout.
The main writeup page is intentionally simple so the content remains the focus.

If you change the global visual language, update:

- `styles/site.css`
- `templates/layout.ejs`
- `templates/index.ejs`
- `templates/writeup.ejs`

## GitHub Pages Deployment

The repository includes a GitHub Actions workflow that:

1. Installs dependencies
2. Runs the build
3. Uploads `dist/`
4. Deploys to GitHub Pages

The workflow uses `SITE_BASE_PATH` automatically so project pages work without
manual path changes.

The workflow automatically detects user sites and project pages:

- `*.github.io` repositories use `/`
- other repositories use `/<repo-name>/`

If you are deploying a project page manually, keep the base path in mind:

- User site: `/`
- Project page: `/<repo-name>/`

## Common Tasks

### Add a New Writeup

1. Create a new file in `writeups/`
2. Add front matter
3. Write the content
4. Run `npm run build`
5. Check the generated page in `dist/writeups/`

### Add a New Component

1. Create a new file in `components/`
2. Add the shortcode in markdown
3. Rebuild the site

### Update Styling

1. Edit `styles/site.css`
2. Rebuild the site
3. Preview in the browser

## Troubleshooting

### Code Block Is Not Highlighted

- Make sure the fence has a language name
- Use `asm` or `nasm` for assembly
- Rebuild the site after changes

### Image Does Not Appear

- Confirm the file exists under `images/`
- Use a root-relative path like `/images/file.png`
- Rebuild the site so the image is copied into `dist/`

### Build Fails on GitHub Actions

- Confirm `package-lock.json` is committed
- Make sure the workflow is running on the correct branch
- Check that `npm ci` succeeds locally

### Page Looks Different After Editing CSS

- Rebuild the site
- Clear the browser cache
- Check whether the change is in `styles/site.css` or in a template

## Suggested Writing Pattern

A good writeup usually follows this order:

1. Title and summary
2. Challenge protections or setup
3. Problem statement
4. Analysis
5. Exploit development
6. Final solve or script

That structure matches the current content and keeps long technical writeups
easy to scan.
