(() => {
  const sizes = [17, 19, 21, 23, 25];
  let index = 1;
  try {
    const saved = Number(localStorage.getItem("zt-mcp-reader-size"));
    if (sizes.includes(saved)) index = sizes.indexOf(saved);
  } catch { /* Reading controls also work when browser storage is unavailable. */ }

  const controls = document.querySelector(".reading-controls");
  const buttons = [...controls.querySelectorAll("button")];
  const update = () => {
    document.documentElement.style.setProperty("--reading-size", `${sizes[index]}px`);
    buttons.forEach(button => {
      button.disabled = Number(button.dataset.size) < 0 ? index === 0 : index === sizes.length - 1;
    });
  };
  buttons.forEach(button => button.addEventListener("click", () => {
    index = Math.max(0, Math.min(sizes.length - 1, index + Number(button.dataset.size)));
    update();
    try { localStorage.setItem("zt-mcp-reader-size", String(sizes[index])); } catch { /* Optional preference. */ }
  }));
  update();
  controls.hidden = false;
})();
