---
name: Code Formatter
description: Automatically formats code using Prettier with sensible defaults.
author: DevTools Inc.
version: "2.3.1"
tags:
  - formatting
  - prettier
  - javascript
  - typescript
tools:
  - prettier
---

# Code Formatter

Formats JavaScript, TypeScript, CSS, and HTML files using Prettier.

## Prerequisites

Make sure Prettier is installed in your project:

```bash
npm install --save-dev prettier
```

## Usage

Format a single file:

```bash
npx prettier --write src/index.ts
```

Format your entire project:

```bash
npx prettier --write "src/**/*.{js,ts,jsx,tsx,css,html}"
```

## Configuration

Create a `.prettierrc` in your project root:

```json
{
  "semi": true,
  "singleQuote": true,
  "tabWidth": 2,
  "trailingComma": "es5",
  "printWidth": 100
}
```

## Links

- [Prettier Documentation](https://prettier.io/docs/en/index.html)
- [Configuration Options](https://prettier.io/docs/en/options.html)
