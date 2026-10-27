/* Original-page rendering, including file:// pages. PDF.js is bundled locally. */
(() => {
  const viewer = document.querySelector(".paper-viewer");
  if (!viewer) return;
  const load = viewer.querySelector(".pdf-load");
  const toolbar = viewer.querySelector(".pdf-toolbar");
  const stage = viewer.querySelector(".pdf-stage");
  const canvas = stage.querySelector("canvas");
  const status = viewer.querySelector(".pdf-status");
  const select = viewer.querySelector(".pdf-page-select");
  const buttons = [...toolbar.querySelectorAll("button")];
  let pdf, pageNumber = 1, zoom = 1, rendering = false, pending = false;

  const updateControls = () => {
    for (const button of buttons) {
      const action = button.dataset.pdfAction;
      button.disabled = !pdf ||
        (action === "previous" && pageNumber === 1) ||
        (action === "next" && pageNumber === pdf.numPages) ||
        (action === "zoom-out" && zoom <= 1) ||
        (action === "zoom-in" && zoom >= 4);
    }
    select.value = String(pageNumber);
    viewer.querySelector(".pdf-zoom").value = `${Math.round(zoom * 100)}%`;
  };

  const render = async () => {
    if (!pdf) return;
    if (rendering) { pending = true; return; }
    rendering = true;
    try {
      do {
        pending = false;
        const number = pageNumber;
        status.textContent = `Rendering page ${number}…`;
        stage.setAttribute("aria-busy", "true");
        const page = await pdf.getPage(number);
        const original = page.getViewport({ scale: 1 });
        const scale = Math.max(1, stage.clientWidth - 2) / original.width * zoom;
        const viewport = page.getViewport({ scale });
        // Bound canvas memory on phones while retaining sharp mathematical notation.
        const ratio = Math.min(devicePixelRatio || 1, 2, Math.sqrt(16000000 / (viewport.width * viewport.height)));
        canvas.width = Math.ceil(viewport.width * ratio);
        canvas.height = Math.ceil(viewport.height * ratio);
        canvas.style.width = `${viewport.width}px`;
        canvas.style.height = `${viewport.height}px`;
        canvas.setAttribute("aria-label", `Original PDF page ${number} of ${pdf.numPages}. Diagrams, formulas and tables retain their original layout.`);
        await page.render({ canvasContext: canvas.getContext("2d"), viewport, transform: [ratio, 0, 0, ratio, 0, 0], background: "white" }).promise;
        status.textContent = `Page ${number} of ${pdf.numPages} · ${Math.round(zoom * 100)}% · Zoom in and swipe inside the page to pan.`;
        viewer.dataset.renderedPage = String(number);
        updateControls();
      } while (pending);
    } catch {
      status.textContent = "This page could not be rendered. Open the original PDF above to view its diagrams and formulas.";
    } finally {
      rendering = false;
      stage.removeAttribute("aria-busy");
    }
  };

  const start = async () => {
    if (load.disabled) return;
    load.disabled = true;
    status.textContent = "Loading original PDF…";
    let task, timeout;
    try {
      if (!globalThis.pdfjsLib || !globalThis.pdfjsWorker) throw new Error("PDF renderer unavailable");
      const options = { isEvalSupported: false, enableXfa: false, useSystemFonts: true };
      if (viewer.dataset.local === "true") {
        if (!globalThis.ZT_PAPER_DATA) throw new Error("Local PDF data unavailable");
        options.data = Uint8Array.from(atob(globalThis.ZT_PAPER_DATA), c => c.charCodeAt(0));
      } else {
        options.url = viewer.dataset.pdfUrl;
        options.withCredentials = false;
      }
      // The classic-script worker bundle lets PDF.js run in-process on file://.
      task = pdfjsLib.getDocument(options);
      pdf = await Promise.race([
        task.promise,
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("Source timed out")), 20000); })
      ]);
      clearTimeout(timeout);
      if (viewer.dataset.local === "true") delete globalThis.ZT_PAPER_DATA;
      pageNumber = Math.max(1, Math.min(pdf.numPages, Number(viewer.dataset.startPage) || 1));
      for (let n = 1; n <= pdf.numPages; n++) select.add(new Option(String(n), String(n)));
      viewer.querySelector(".pdf-total").textContent = ` / ${pdf.numPages}`;
      toolbar.hidden = false;
      stage.hidden = false;
      load.hidden = true;
      updateControls();
      await render();
    } catch {
      clearTimeout(timeout);
      if (task) task.destroy().catch(() => {});
      viewer.dataset.loadFailed = "true";
      status.textContent = "The original PDF could not be loaded here. The host may block in-page access or require a login. Use “Original paper” or “Open PDF at full size” above to see the diagrams and formulas.";
      load.textContent = "Retry loading original pages";
      load.disabled = false;
    }
  };

  buttons.forEach(button => button.addEventListener("click", () => {
    const action = button.dataset.pdfAction;
    if (action === "previous") pageNumber = Math.max(1, pageNumber - 1);
    if (action === "next") pageNumber = Math.min(pdf.numPages, pageNumber + 1);
    if (action === "zoom-in") zoom = Math.min(4, zoom + 0.5);
    if (action === "zoom-out") zoom = Math.max(1, zoom - 0.5);
    if (action === "fit") zoom = 1;
    stage.scrollTo(0, 0);
    updateControls();
    render();
  }));
  select.addEventListener("change", () => {
    pageNumber = Number(select.value);
    stage.scrollTo(0, 0);
    updateControls();
    render();
  });
  let resize;
  window.addEventListener("resize", () => {
    clearTimeout(resize);
    resize = setTimeout(render, 150);
  });
  load.hidden = false;
  load.addEventListener("click", start);
  document.querySelector(".viewer-jump")?.addEventListener("click", () => {
    if (!pdf) start();
  });
  document.querySelectorAll("[data-pdf-page]").forEach(link => link.addEventListener("click", async () => {
    if (!pdf) await start();
    if (!pdf) return;
    pageNumber = Math.max(1, Math.min(pdf.numPages, Number(link.dataset.pdfPage)));
    zoom = 1;
    stage.scrollTo(0, 0);
    updateControls();
    render();
  }));
  status.textContent = "Load the original pages, then use page and zoom controls to inspect diagrams and formulas.";
  // A visitor may follow the anchor before the deferred renderer finishes loading.
  if (location.hash === "#paper-viewer") start();
})();
