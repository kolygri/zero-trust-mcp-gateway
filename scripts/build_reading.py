#!/usr/bin/env python3
"""Build the README and static reader from checked-in sources. No dependencies."""

import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
DATA = json.loads((DOCS / "resources.json").read_text())
RESOURCES = DATA["resources"]


def esc(value):
    return html.escape(str(value), quote=True)


def has_source(resource):
    return (DOCS / "sources" / (resource["slug"] + ".html")).exists()


def page(title, content, nested=False):
    prefix = "../" if nested else ""
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="color-scheme" content="light dark">
  <meta name="theme-color" content="#f8f6f0">
  <title>{esc(title)} · Zero Trust MCP Gateway</title>
  <link rel="stylesheet" href="{prefix}assets/reader.css">
  <script src="{prefix}assets/reader.js" defer></script>
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
    for kind, title, intro in [
        ("Research", "The research", "Six perspectives on controlling agent execution."),
        ("Implementation", "In practice", "Five projects and architectures to study for a prototype."),
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
        <div class="collection-meta"><span>06 research papers</span><span>05 implementations</span></div>
        <nav class="jump-links" aria-label="Browse collection"><a href="#research">The research ↓</a><a href="#implementation">In practice ↓</a></nav>
      </section>
      <aside class="reader-note"><strong>A reading copy, with provenance.</strong>
        <p>Your supplied notes appear unchanged. {full_count} resources also include licensed source text, with the source version and any conversion limits on each page. Other pages link to the original in full. Linked figures require an internet connection.</p>
      </aside>
      {''.join(sections)}
      <aside class="research-direction"><p class="eyebrow">WORKING RESEARCH HYPOTHESIS</p><p>{esc(DATA['research_note'])}</p><small>Supplied research perspective; relevance labels are editorial judgements.</small></aside>
    </main>'''
    (DOCS / "index.html").write_text(page("Research library", content))


def build_resource(resource, index):
    slug = resource["slug"]
    original = f'<a class="source-button" href="{esc(resource["url"])}">Open original source ↗</a>'
    focus = resource.get("focus", resource.get("investigate", ""))
    label = "Focus" if resource["kind"] == "Research" else "What to investigate"
    source = ""
    if has_source(resource):
        source_html = (DOCS / "sources" / (slug + ".html")).read_text()
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
    content = f'''<main id="main" class="article-main">
      <article>
        <header class="article-header">
          <a class="back-link" href="../index.html#{resource['kind'].lower()}">← All resources</a>
          <p class="eyebrow">{resource['kind']} / {index+1:02d} OF {len(RESOURCES):02d}</p>
          <h1>{esc(resource['title'])}</h1>
          <p class="publisher">{esc(resource['publisher'])}</p>{relevance}{original}
        </header>
        <section class="supplied-notes" aria-labelledby="notes-title"><h2 id="notes-title">Research notes</h2>
          <p>{esc(resource['description'])}</p>
          <dl><dt>{label}</dt><dd>{esc(focus)}</dd></dl>
          <p class="caption">Notes supplied for this project, preserved as written.</p>
        </section>
        {related}{source}
      </article>
      <nav class="article-nav" aria-label="Reading order">{''.join(nav)}</nav>
      <a class="back-link" href="#main">Back to top ↑</a>
    </main>'''
    (DOCS / "resources" / (slug + ".html")).write_text(page(resource["title"], content, nested=True))


def build_readme():
    lines = [
        "# Zero Trust MCP Gateway", "",
        "Research and practical references for a zero-trust MCP gateway that enforces security policies at tool boundaries and coordinates corrective interventions throughout agent execution.", "",
        "This repository currently contains the research library; the gateway implementation has not started.", "",
        "## Reading on an iPhone", "",
        "Open the [HTML reading library](docs/index.html) in a browser. It includes one page per resource, large adjustable text, a single-column layout, dark mode, and previous/next navigation. No build tools, account or JavaScript are required to read the pages.", "",
        "The supplied research notes are preserved as written. Where redistribution permission is established and source text is available, the reader also includes the original text with attribution. PDF extractions retain page boundaries and may not faithfully reproduce figures, tables or equations. Other pages contain the supplied notes and direct links to the full original; they are labelled accordingly. GitHub's file view shows HTML source rather than rendering the reader.", "",
        "To read on an iPhone over the same trusted Wi-Fi network, start a local server from the repository folder:", "",
        "```sh", "python3 -m http.server 8000 --bind 0.0.0.0 --directory docs", "```", "",
        "In iPhone Safari, open `http://<your-Mac-local-IP>:8000`. The files in `docs` are served to devices that can reach your Mac; stop the server with Ctrl-C when finished. Alternatively, copy the entire `docs` folder to a static host you control. This repository does not automatically publish it.", "",
        "## 1. The research most relevant to the gateway", "",
        "Descriptions and relevance ratings below are the supplied research notes. Ratings are editorial judgements; reported results belong to each paper's evaluation, not this project.", "",
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
            content = "Supplied notes + original link"
            source = r["availability"].replace("The supplied notes are reproduced below. ", "")
        lines.append(f"| {r['title']} | {content} | {source} |")
    lines += ["", "Third-party source copies retain their upstream licences; inclusion does not imply endorsement. Original project READMEs are reading material, and their commands are not automatically executed.", "", "## Updating the library", "", "Edit `docs/resources.json` for the supplied notes and metadata. Licensed reading snapshots live in `docs/sources/`, with applicable licence notices in `docs/licenses/`. Rebuild the README and reading pages using Python's standard library:", "", "```sh", "python3 scripts/build_reading.py", "```", "", "The build uses checked-in snapshots and does not fetch or execute anything from upstream sources.", ""]
    (ROOT / "README.md").write_text("\n".join(lines))


if __name__ == "__main__":
    for resource in RESOURCES:
        if resource.get("source_url") and not has_source(resource):
            raise FileNotFoundError(f"Missing licensed snapshot: {resource['slug']}")
    (DOCS / "resources").mkdir(exist_ok=True)
    build_index()
    for i, resource in enumerate(RESOURCES):
        build_resource(resource, i)
    build_readme()
    print(f"Built README, index and {len(RESOURCES)} reading pages.")
