#!/usr/bin/env python3
"""Build the README and static reader from checked-in sources. No dependencies."""

import base64
import html
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
DATA = json.loads((DOCS / "resources.json").read_text())
RESOURCES = DATA["resources"]


def esc(value):
    return html.escape(str(value), quote=True)


def has_source(resource):
    return (DOCS / "sources" / (resource["slug"] + ".html")).exists()


def page(title, content, nested=False, resource=None):
    prefix = "../" if nested else ""
    pdf_scripts = ""
    if resource and resource.get("pdf"):
        scripts = [
            f'<script src="{prefix}assets/vendor/pdfjs/pdf.worker.js" defer></script>',
            f'<script src="{prefix}assets/vendor/pdfjs/pdf.js" defer></script>',
        ]
        if resource["pdf"].get("local"):
            scripts.append(f'<script src="{prefix}assets/papers/{resource["slug"]}.pdf.js" defer></script>')
        scripts.append(f'<script src="{prefix}assets/pdf-reader.js" defer></script>')
        pdf_scripts = "\n  " + "\n  ".join(scripts)
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="color-scheme" content="light dark">
  <meta name="theme-color" content="#f8f6f0">
  <title>{esc(title)} · Zero Trust MCP Gateway</title>
  <link rel="stylesheet" href="{prefix}assets/reader.css">
  <script src="{prefix}assets/reader.js" defer></script>{pdf_scripts}
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header class="site-header">
    <a class="brand" href="{prefix}index.html"><span class="brand-mark" aria-hidden="true">↗</span> ZERO TRUST <span class="brand-detail">/ RESEARCH LIBRARY</span></a>
    <div class="reading-controls" role="group" aria-label="Text size" hidden>
      <button type="button" data-size="-1" aria-label="Decrease text size">A−</button>
      <button type="button" data-size="1" aria-label="Increase text size">A+</button>
    </div>
  </header>
  {content}
  <footer class="site-footer"><a href="{prefix}index.html">Zero Trust MCP Gateway</a><span>Reading collection · 27 October 2026</span></footer>
</body>
</html>
'''


def card(resource, number):
    details = resource.get("focus", resource.get("investigate", ""))
    badge = resource["format"] if has_source(resource) else "Notes + original"
    return f'''<li class="resource-card">
      <span class="resource-number">{number:02d}</span>
      <div><p class="eyebrow">{esc(resource['publisher'])}</p>
      <h3><a href="resources/{resource['slug']}.html">{esc(resource['title'])}</a></h3>
      <p>{esc(details)}</p><span class="tag">{esc(badge)}</span></div>
      <span class="card-arrow" aria-hidden="true">↗</span>
    </li>'''


def build_index():
    sections = []
    number = 0
    research_count = sum(r["kind"] == "Research" for r in RESOURCES)
    implementation_count = sum(r["kind"] == "Implementation" for r in RESOURCES)
    for kind, title, intro in [
        ("Research", "The research", f"{research_count} perspectives on controlling agent execution."),
        ("Implementation", "In practice", f"{implementation_count} projects and architectures to study for a prototype."),
    ]:
        cards = []
        for resource in RESOURCES:
            if resource["kind"] == kind:
                number += 1
                cards.append(card(resource, number))
        sections.append(f'''<section id="{kind.lower()}" class="collection" aria-labelledby="{kind.lower()}-heading">
          <div class="section-heading"><h2 id="{kind.lower()}-heading">{title}</h2><p>{intro}</p></div>
          <ol class="resource-list">{''.join(cards)}</ol></section>''')
    full_count = sum(has_source(resource) for resource in RESOURCES)
    content = f'''<main id="main">
      <section class="hero">
        <p class="eyebrow">FIELD NOTES / 001</p>
        <h1>Trust is a boundary.<br><em>Enforce it.</em></h1>
        <p class="lede">Research and practical implementations for a zero-trust MCP gateway that can intervene throughout agent execution.</p>
        <div class="collection-meta"><span>{research_count:02d} research papers</span><span>{implementation_count:02d} implementations</span></div>
        <nav class="jump-links" aria-label="Browse collection"><a href="#research">The research ↓</a><a href="#implementation">In practice ↓</a></nav>
      </section>
      <aside class="reader-note"><strong>A reading copy, with provenance.</strong>
        <p>Your supplied notes appear unchanged. {full_count} resources also include licensed source text. Paper pages include a zoomable original-PDF viewer for diagrams, tables and formulas. Licensed local PDFs work offline; other PDFs require internet access and publisher permission to load.</p>
      </aside>
      {''.join(sections)}
      <aside class="research-direction"><p class="eyebrow">WORKING RESEARCH HYPOTHESIS</p><p>{esc(DATA['research_note'])}</p><small>Supplied research perspective; relevance labels are editorial judgements.</small></aside>
    </main>'''
    (DOCS / "index.html").write_text(page("Research library", content))


def pdf_viewer(resource):
    pdf = resource.get("pdf")
    if not pdf:
        return ""
    local = bool(pdf.get("local"))
    pdf_link = f'../assets/papers/{pdf["local"]}' if local else pdf["url"]
    availability = "This licensed local copy works offline, including when opened as a file." if local else "This viewer loads the original PDF directly from its host. Internet access is required; publisher restrictions may prevent in-page loading."
    access_note = f'<p class="caption">{esc(pdf["access_note"])}</p>' if pdf.get("access_note") else ""
    return f'''<section id="paper-viewer" class="paper-viewer" aria-labelledby="paper-viewer-title"
        data-pdf-url="{esc(pdf['url'])}" data-local="{str(local).lower()}" data-start-page="{pdf.get('start_page', 1)}">
      <h2 id="paper-viewer-title">Diagrams &amp; formulas</h2>
      <p>Original PDF pages preserve the paper’s diagrams, equations and tables. Zoom in, then swipe inside the page to pan.</p>
      <p class="caption">{availability}</p>{access_note}
      <div class="pdf-links"><a href="{esc(pdf_link)}" target="_blank" rel="noopener">Open PDF at full size ↗</a><a href="{esc(resource['url'])}" target="_blank" rel="noopener">Original paper ↗</a></div>
      <button type="button" class="pdf-load" hidden>Load original pages</button>
      <div class="pdf-toolbar" role="group" aria-label="PDF page and zoom controls" hidden>
        <div class="pdf-page-controls">
          <button type="button" data-pdf-action="previous" aria-label="Previous PDF page">←</button>
          <label>Page <select class="pdf-page-select" aria-label="PDF page"></select><span class="pdf-total"></span></label>
          <button type="button" data-pdf-action="next" aria-label="Next PDF page">→</button>
        </div>
        <div class="pdf-zoom-controls">
          <button type="button" data-pdf-action="zoom-out" aria-label="Zoom out PDF">−</button>
          <output class="pdf-zoom" aria-label="PDF zoom">100%</output>
          <button type="button" data-pdf-action="zoom-in" aria-label="Zoom in PDF">+</button>
          <button type="button" data-pdf-action="fit">Fit width</button>
        </div>
      </div>
      <p class="pdf-status caption" role="status" aria-live="polite">Use the PDF link to read the original pages.</p>
      <div class="pdf-stage" tabindex="0" role="region" aria-label="Original PDF page; scroll to pan" hidden><canvas role="img"></canvas></div>
      <noscript><p class="caption">Open the PDF above to see diagrams and formulas. The in-page viewer needs JavaScript.</p></noscript>
    </section>'''


def build_resource(resource, index):
    slug = resource["slug"]
    original = f'<a class="source-button" href="{esc(resource["url"])}">Open original source ↗</a>'
    focus = resource.get("focus", resource.get("investigate", ""))
    label = "Focus" if resource["kind"] == "Research" else "What to investigate"
    source = ""
    if has_source(resource):
        source_html = (DOCS / "sources" / (slug + ".html")).read_text()
        if resource.get("pdf") and resource["format"].startswith("PDF text"):
            source_html = re.sub(
                r'(<h2 class="pdf-page-label">Original PDF · page (\d+) of \d+</h2>)',
                lambda match: match[1] + f'<p class="caption"><a href="#paper-viewer" data-pdf-page="{match[2]}">View this original page with diagrams and formulas ↑</a></p>',
                source_html,
            )
        source = f'''<section class="provenance" aria-labelledby="provenance-title">
          <h2 id="provenance-title">About this reading copy</h2>
          <p>{esc(resource['attribution'])}</p>
          <p>{esc(resource['changes'])}</p>
          <p><a href="{esc(resource['source_url'])}">Exact source version ↗</a> · <a href="{esc(resource['license_url'])}">{esc(resource['license'])}</a></p>
        </section>
        <section class="source-copy" aria-label="Original source text">{source_html}</section>'''
    else:
        full_text_link = f'<p><a href="{esc(resource["full_text_url"])}">Read the full original HTML ↗</a></p>' if resource.get("full_text_url") else ""
        source = f'<aside class="provenance"><h2>Read the original</h2><p>{esc(resource["availability"])}</p>{full_text_link}</aside>'
    related = ""
    if resource.get("related"):
        other = next(r for r in RESOURCES if r["slug"] == resource["related"])
        related = f'<p class="related">Related reading: <a href="{other["slug"]}.html">{esc(other["title"])}</a></p>'
    nav = []
    for offset, direction in [(-1, "Previous"), (1, "Next")]:
        target = index + offset
        if 0 <= target < len(RESOURCES):
            other = RESOURCES[target]
            nav.append(f'<a href="{other["slug"]}.html"><span class="eyebrow">{direction}</span><span>{esc(other["title"])}</span></a>')
    relevance = f'<span class="tag">{esc(resource["relevance"])} fit</span>' if resource.get("relevance") else ""
    viewer_link = '<a class="viewer-jump" href="#paper-viewer">Diagrams &amp; formulas ↓</a>' if resource.get("pdf") else ""
    notes_caption = resource.get("notes_caption", "Notes supplied for this project, preserved as written.")
    content = f'''<main id="main" class="article-main">
      <article>
        <header class="article-header">
          <a class="back-link" href="../index.html#{resource['kind'].lower()}">← All resources</a>
          <p class="eyebrow">{resource['kind']} / {index+1:02d} OF {len(RESOURCES):02d}</p>
          <h1>{esc(resource['title'])}</h1>
          <p class="publisher">{esc(resource['publisher'])}</p>{relevance}{original}{viewer_link}
        </header>
        <section class="supplied-notes" aria-labelledby="notes-title"><h2 id="notes-title">Research notes</h2>
          <p>{esc(resource['description'])}</p>
          <dl><dt>{label}</dt><dd>{esc(focus)}</dd></dl>
          <p class="caption">{esc(notes_caption)}</p>
        </section>
        {related}{pdf_viewer(resource)}{source}
      </article>
      <nav class="article-nav" aria-label="Reading order">{''.join(nav)}</nav>
      <a class="back-link" href="#main">Back to top ↑</a>
    </main>'''
    (DOCS / "resources" / (slug + ".html")).write_text(page(resource["title"], content, nested=True, resource=resource))


def build_readme():
    lines = [
        "# Zero Trust MCP Gateway", "",
        "Research and practical references for a zero-trust MCP gateway that enforces security policies at tool boundaries and coordinates corrective interventions throughout agent execution.", "",
        "This repository contains the research library and a minimal Go MCP gateway that forwards stdio messages unchanged and logs traffic in both directions. See [Running the gateway](GATEWAY.md) for build commands and MCP client configuration.", "",
        "## Reading on an iPhone", "",
        "Read the published library in Safari or any browser: [Zero Trust MCP Gateway reading library](https://zero-trust-mcp-reading.k-l-grigorov.chatgpt.site/).", "",
        "Open the [HTML reading library](docs/index.html) in a browser. It includes one page per resource, large adjustable text, a single-column layout, dark mode, and previous/next navigation. No build tools, account or JavaScript are required to read the pages.", "",
        "The supplied research notes are preserved as written; the added Policies on Paths entry is a source-based summary. Where redistribution permission is established and source text is available, the reader also includes the original text with attribution. Each paper has an original-PDF viewer with page selection, zoom and panning, so diagrams, formulas and tables keep their published layout. MathML formulas in HTML copies retain mathematical structure and scroll independently when wider than the screen. GitHub's file view shows HTML source rather than rendering the reader.", "",
        "The original PDFs for SAMOS, Task Shield, Governance by Construction, and Policies on Paths are included under CC BY 4.0 and work offline, including through `file://` pages. AgentTrust loads its PDF directly from arXiv. MDPI and IEEE may refuse in-page loading or require publisher access; their reader pages always provide links to the original paper and PDF. The viewer shows an explicit error if a remote source cannot load. JavaScript is required for the in-page PDF viewer; the original PDF links and reflowed text remain available without it.", "",
        "To read on an iPhone over the same trusted Wi-Fi network, start a local server from the repository folder:", "",
        "```sh", "python3 -m http.server 8000 --bind 0.0.0.0 --directory docs", "```", "",
        "In iPhone Safari, open `http://<your-Mac-local-IP>:8000`. The files in `docs` are served to devices that can reach your Mac; stop the server with Ctrl-C when finished.", "",
        "## Published website", "",
        "The reading library is hosted separately with Sites at the address above. Its deployment checkout is `~/Git/zero-trust-mcp-gateway-site`, serving the `dist/` directory. The [GitHub reading snapshot](https://github.com/kolygri/zero-trust-mcp-gateway-reading) retains the reading files, with GitHub Pages disabled. The gateway project repository remains private. Access to the new hosted site is private to the owner by default.", "",
        "To update the hosted library, rebuild it here, copy `docs/` into the separate Site checkout’s `dist/`, then publish through the Sites workflow using its existing `.openai/hosting.json` identity. Keep GitHub Pages disabled. Never modify or publish to `kolygri.github.io`, including project subpaths, without asking the user and receiving explicit approval; see `AGENTS.md`.", "",
        "## 1. The research most relevant to the gateway", "",
        "Descriptions below preserve the supplied research notes, except the source-based summary of the newly added Policies on Paths paper. Relevance ratings are editorial judgements; reported results belong to each paper's evaluation, not this project.", "",
    ]
    for index, resource in enumerate(r for r in RESOURCES if r["kind"] == "Research"):
        lines += [f"### {index+1}. [{resource['title']}]({resource['url']})", "", resource["publisher"], "", resource["description"], "", f"**Focus:** {resource['focus']}", "", f"**Relevance:** {resource['relevance']} · [iPhone reading page](docs/resources/{resource['slug']}.html)", ""]
    lines += ["### Working research hypothesis", "", DATA["research_note"], "", "## 2. Existing implementations worth studying", "", "These are practical starting points for a prototype, rather than just theoretical references.", "", "| Project | Existing capabilities | What to investigate | Reader |", "| --- | --- | --- | --- |"]
    for r in RESOURCES:
        if r["kind"] == "Implementation":
            lines.append(f"| [{r['title']}]({r['url']}) | {r['description']} | {r['investigate']} | [Read](docs/resources/{r['slug']}.html) |")
    lines += ["", "## Source copies and attribution", "", "Source links checked on 27 October 2026. The descriptions above preserve the supplied notes; link checking is not an independent reproduction of the research findings.", "", "| Resource | Local reading content | Source / licence |", "| --- | --- | --- |"]
    for r in RESOURCES:
        if has_source(r):
            license_url = r["license_url"].replace("../licenses/", "docs/licenses/")
            content = r["format"]
            source = f"[Source version]({r['source_url']}) · [{r['license']}]({license_url})"
        else:
            content = "Supplied notes + live original-PDF viewer" if r.get("pdf") else "Supplied notes + original link"
            source = r["availability"].replace("The supplied notes are reproduced below. ", "")
        lines.append(f"| {r['title']} | {content} | {source} |")
    lines += ["", "Third-party source copies retain their upstream licences; inclusion does not imply endorsement. Original project READMEs are reading material, and their commands are not automatically executed. The PDF viewer uses a bundled copy of Mozilla PDF.js; its version, build instructions, and licence are in `docs/assets/vendor/pdfjs/README.md`.", "", "## Updating the library", "", "Edit `docs/resources.json` for the supplied notes and metadata. Licensed reading snapshots live in `docs/sources/`, with applicable licence notices in `docs/licenses/`. Unmodified licensed PDFs live in `docs/assets/papers/`; the build also creates classic-script data copies so the viewer works through `file://` without cross-origin fetches or workers. Rebuild the README and reading pages using Python's standard library:", "", "```sh", "python3 scripts/build_reading.py", "```", "", "The build uses checked-in snapshots and does not fetch or execute anything from upstream sources.", ""]
    (ROOT / "README.md").write_text("\n".join(lines))


if __name__ == "__main__":
    for resource in RESOURCES:
        if resource.get("source_url") and not has_source(resource):
            raise FileNotFoundError(f"Missing licensed snapshot: {resource['slug']}")
        pdf = resource.get("pdf", {})
        if pdf.get("local"):
            path = DOCS / "assets" / "papers" / pdf["local"]
            data = base64.b64encode(path.read_bytes()).decode("ascii")
            path.with_suffix(".pdf.js").write_text(f'/* Unmodified PDF data; see resource attribution and licence. */\nwindow.ZT_PAPER_DATA = "{data}";\n')
    (DOCS / "resources").mkdir(exist_ok=True)
    build_index()
    for i, resource in enumerate(RESOURCES):
        build_resource(resource, i)
    build_readme()
    print(f"Built README, index and {len(RESOURCES)} reading pages.")
