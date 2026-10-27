# Bundled PDF.js

Mozilla PDF.js (`pdfjs-dist` **6.4.299**), licensed under Apache-2.0. See [LICENSE](LICENSE), [upstream](https://github.com/mozilla/pdf.js), and [package](https://www.npmjs.com/package/pdfjs-dist/v/6.4.299).

The legacy browser builds are bundled as classic scripts using esbuild **0.28.2**, targeting Safari 16 syntax. This avoids module and worker cross-origin restrictions when the reader is opened through `file://`. Both bundles retain upstream legal comments. The worker bundle exposes `pdfjsWorker.WorkerMessageHandler`; PDF.js uses it in-process without creating a cross-origin worker. The viewer disables PDF JavaScript evaluation and XFA.

To reproduce from the repository root:

```sh
npm install --prefix /tmp/zero-trust-mcp-pdfjs --no-audit --no-fund pdfjs-dist@6.4.299 esbuild@0.28.2
/tmp/zero-trust-mcp-pdfjs/node_modules/.bin/esbuild /tmp/zero-trust-mcp-pdfjs/node_modules/pdfjs-dist/legacy/build/pdf.mjs --bundle --format=iife --global-name=pdfjsLib --platform=browser '--external:node:*' --target=safari16 --minify --legal-comments=eof --outfile=docs/assets/vendor/pdfjs/pdf.js
/tmp/zero-trust-mcp-pdfjs/node_modules/.bin/esbuild /tmp/zero-trust-mcp-pdfjs/node_modules/pdfjs-dist/legacy/build/pdf.worker.mjs --bundle --format=iife --global-name=pdfjsWorker --platform=browser '--external:node:*' --target=safari16 --minify --legal-comments=eof --outfile=docs/assets/vendor/pdfjs/pdf.worker.js
cp /tmp/zero-trust-mcp-pdfjs/node_modules/pdfjs-dist/LICENSE docs/assets/vendor/pdfjs/LICENSE
```

No npm installation or network fetch is needed to read local licensed PDFs or rebuild the reading pages. The page builder creates `.pdf.js` data wrappers from the unchanged local `.pdf` files; those are document data, not executable code from the papers. Remote PDFs remain hosted by their publishers and are not copied into this repository.
