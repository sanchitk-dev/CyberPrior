document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("tr.clickable-row[data-href]").forEach((row) => {
    row.addEventListener("click", (event) => {
      if (event.target.closest("a, button, input, select")) return;
      window.location.href = row.dataset.href;
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && row.dataset.href) window.location.href = row.dataset.href;
    });
    row.setAttribute("tabindex", "0");
    row.setAttribute("role", "link");
    row.setAttribute("aria-label", `Open vulnerability details for ${row.dataset.label || "selected record"}`);
  });

});
